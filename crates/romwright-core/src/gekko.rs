//! Gekko/Broadway paired-single (PS) instruction set.
//!
//! Audit of `third_party/ghidra/languages/gamecube/` (2026-09-13):
//! - `ppc_instructions_gekko_broadway.sinc` holds **no** paired-single
//!   definitions at all — every `ps_*`/`psq_*` constructor lives inline in
//!   `ppc_gekko_broadway.slaspec` (§"Paired singles quantized load and
//!   store" + §"Paired singles instructions"). The task's named file is
//!   therefore not the place to fix; the `.slaspec` is vendored upstream
//!   and is left untouched.
//! - The `.slaspec` semantics are already lane-wise (two-f32 `ps0`/`ps1`
//!   lanes, `load_ps`/`store_ps` macros with GQR type/scale decode and the
//!   W-bit), i.e. not stubs. The audit did find lane bugs worth recording:
//!   `ps_msub`/`ps_nmsub` (both Rc forms) accumulate
//!   `nan(fA)|nan(fC)|nan(fB)` — the whole 64-bit float registers — where
//!   the sibling `ps_madd` correctly uses `nan(ps0A)|nan(ps0C)|nan(ps0B)`;
//!   `ps_res`/`.`, set `FPRF`/`zx` from `fD`/`fB` instead of the `ps0`
//!   lane; `ps_sel.` issues `cr1flags()` twice. These are upstream's to
//!   fix; this module implements the corrected lane model natively.
//! - The `native/specs/PowerPC-BE-32-Gekko_Broadway/` bundle carries only
//!   `pspec/cspec/tspec/coretypes/registers.txt` (no `.slaspec`/`.sla`
//!   semantics). Its register set already names `GQR0`–`GQR7` and the
//!   `psN_1` lane-1 aliases, and its `cspec.xml` pins the GQRs
//!   unaffected, so no bundle edit is needed; editing any of the five
//!   hashed files would break `gen_native_specs --check` for no gain.
//!
//! What this module provides instead, natively and without the JVM:
//! 1. A decoder for every paired-single opcode (facts: IBM Gekko/Broadway
//!    document the encodings; operand order verified against the
//!    `.slaspec` constructors above — no upstream code copied).
//! 2. GQR quantize/dequantize helpers (type + 6-bit scale per direction).
//! 3. A lane-wise C emitter: a `psq_l` + `ps_add` + `psq_st` routine
//!    renders as `float` `ps0`/`ps1` lane ops — never `double`, never an
//!    opaque `_ps_*`/`ldexpf` unknown.
//!
//! Encoding summary (all words big-endian):
//! - `psq_l`/`psq_lu`/`psq_st`/`psq_stu`: primary 56/57/60/61,
//!   `frD|S=(21,25) rA=(16,20) W=(15,15) I=(12,14) off=(0,11)` signed.
//! - `psq_lx`/`psq_stx`/`psq_lux`/`psq_stux`: primary 4,
//!   `XO=(1,6)` 6/7/38/39, `WX=(10,10) IX=(7,9)`, `EA=rA+rB`.
//! - Arithmetic: primary 4, `XO=(1,5)` 10/11/12/13/14/15/18/20/21/23/24/
//!   25/26/28/29/30/31, `Rc=(0,0)` selects the dotted form.
//! - Move/merge/compare: primary 4, `XO=(1,10)` 0/32/40/64/72/96/136/264/
//!   528/560/592/624, `Rc` selects dotted (compares have no Rc form).
//!
//! GQR layout (public Gekko format, IBM MSB bit numbers):
//! `ST_TYPE=(0,2) ST_SCALE=(3,7) LD_TYPE=(8,10) LD_SCALE=(11,15)`.
//! In LSB numbering used here: `st_type=(v>>29)&7`, `st_scale=(v>>24)&63`,
//! `ld_type=(v>>21)&7`, `ld_scale=(v>>16)&63`.
//! Type ids: 0=float32, 4=u8, 5=u16, 6=s8, 7=s16 (1–3 reserved→float,
//! matching the `.slaspec` `load_ps`/`store_ps` branch structure).
//! Load dequantizes with `2^-scale`, store quantizes with `2^+scale`
//! (the `.slaspec` `ldexpf(-ls)` / `ldexpf(ls)` facts). `W=1` transfers
//! only lane 0 and forces lane 1 to `1.0f` on load / skips it on store.

/// One decoded paired-single instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsInsn {
    pub address: u64,
    pub word: u32,
    pub mnemonic: String,
    pub operands: String,
}

fn fr(n: u8) -> String {
    format!("f{n}")
}

/// Quantized-load/store element type selected by a GQR type field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantType {
    Float,
    U8,
    U16,
    S8,
    S16,
}

impl QuantType {
    /// Map a 3-bit GQR type id. Ids 1–3 are reserved; like the `.slaspec`
    /// branch structure, they fall through to float.
    pub fn from_id(id: u32) -> QuantType {
        match id & 7 {
            4 => QuantType::U8,
            5 => QuantType::U16,
            6 => QuantType::S8,
            7 => QuantType::S16,
            _ => QuantType::Float,
        }
    }

    /// C element type used by the [`PS_HELPERS_C`] signatures.
    pub fn c_type(self) -> &'static str {
        match self {
            QuantType::Float => "float",
            QuantType::U8 => "unsigned char",
            QuantType::U16 => "unsigned short",
            QuantType::S8 => "signed char",
            QuantType::S16 => "short",
        }
    }

    fn is_signed_int(self) -> bool {
        matches!(self, QuantType::S8 | QuantType::S16)
    }

    fn bits(self) -> u32 {
        match self {
            QuantType::Float => 32,
            QuantType::U8 | QuantType::S8 => 8,
            QuantType::U16 | QuantType::S16 => 16,
        }
    }
}

/// The four GQR fields: store type/scale and load type/scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GqrFields {
    pub st_type: QuantType,
    pub st_scale: u8,
    pub ld_type: QuantType,
    pub ld_scale: u8,
}

/// Split a raw 32-bit GQR value into its documented fields.
pub fn parse_gqr(val: u32) -> GqrFields {
    GqrFields {
        st_type: QuantType::from_id(val >> 29),
        st_scale: ((val >> 24) & 63) as u8,
        ld_type: QuantType::from_id(val >> 21),
        ld_scale: ((val >> 16) & 63) as u8,
    }
}

/// Dequantize one raw element on a `psq_l*` path: `raw * 2^-scale`.
/// `raw` holds the zero-extended memory element (float bits for
/// [`QuantType::Float`]); int lanes sign-extend through their width first.
pub fn dequantize(raw: u32, ty: QuantType, scale: u8) -> f32 {
    let base: f32 = match ty {
        QuantType::Float => f32::from_bits(raw),
        QuantType::U8 => (raw & 0xff) as f32,
        QuantType::U16 => (raw & 0xffff) as f32,
        QuantType::S8 => ((raw & 0xff) as u8) as i8 as f32,
        QuantType::S16 => ((raw & 0xffff) as u16) as i16 as f32,
    };
    base * 2f32.powi(-(scale as i32))
}

/// Quantize one lane on a `psq_st*` path: `trunc(v * 2^+scale)` clamped to
/// the element range (the `.slaspec` `trunc(scale f* ps)` fact, plus
/// clamping so a float lane cannot wrap the stored integer).
pub fn quantize(v: f32, ty: QuantType, scale: u8) -> u32 {
    if matches!(ty, QuantType::Float) {
        return v.to_bits();
    }
    let scaled = v * 2f32.powi(scale as i32);
    let bits = ty.bits();
    let (lo, hi) = if ty.is_signed_int() {
        (-(1i64 << (bits - 1)) as f32, ((1i64 << (bits - 1)) - 1) as f32)
    } else {
        (0.0, ((1i64 << bits) - 1) as f32)
    };
    let clamped = scaled.clamp(lo, hi);
    // Truncate toward zero; mask keeps only the element width so signed
    // values store as two's complement, matching the memory image.
    let mask = if bits == 32 { u32::MAX } else { (1u32 << bits) - 1 };
    (clamped as i32 as u32) & mask
}

/// C definitions for the quantized lane helpers the emitter names.
/// The routine body itself stays pure lane `float` ops; only genuinely
/// quantized transfers name these.
pub const PS_HELPERS_C: &str = r#"#include <math.h>
#include <stdint.h>
static float ps_ld_u8(uint32_t u, int s) { return (float)(u & 0xffu) * exp2f(-(float)s); }
static float ps_ld_s8(uint32_t u, int s) { return (float)(int8_t)(u & 0xffu) * exp2f(-(float)s); }
static float ps_ld_u16(uint32_t u, int s) { return (float)(u & 0xffffu) * exp2f(-(float)s); }
static float ps_ld_s16(uint32_t u, int s) { return (float)(int16_t)(u & 0xffffu) * exp2f(-(float)s); }
static uint32_t ps_st_u8(float v, int s) { float t = v * exp2f((float)s); if (t < 0.0f) t = 0.0f; if (t > 255.0f) t = 255.0f; return (uint32_t)t; }
static uint32_t ps_st_s8(float v, int s) { float t = v * exp2f((float)s); if (t < -128.0f) t = -128.0f; if (t > 127.0f) t = 127.0f; return (uint32_t)(int32_t)t & 0xffu; }
static uint32_t ps_st_u16(float v, int s) { float t = v * exp2f((float)s); if (t < 0.0f) t = 0.0f; if (t > 65535.0f) t = 65535.0f; return (uint32_t)t; }
static uint32_t ps_st_s16(float v, int s) { float t = v * exp2f((float)s); if (t < -32768.0f) t = -32768.0f; if (t > 32767.0f) t = 32767.0f; return (uint32_t)(int32_t)t & 0xffffu; }
"#;

/// Classified paired-single operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PsKind {
    Unknown,
    Load { update: bool, indexed: bool },
    Store { update: bool, indexed: bool },
    Add,
    Sub,
    Mul,
    Div,
    Madd,
    Msub,
    Nmadd,
    Nmsub,
    Madds0,
    Madds1,
    Muls0,
    Muls1,
    Sum0,
    Sum1,
    Sel,
    Merge00,
    Merge01,
    Merge10,
    Merge11,
    Mr,
    Abs,
    Neg,
    Nabs,
    Res,
    Rsqrte,
    Cmpo0,
    Cmpo1,
    Cmpu0,
    Cmpu1,
}

impl PsKind {
    fn base(self) -> &'static str {
        match self {
            PsKind::Unknown => ".word",
            PsKind::Load { update, indexed } => match (update, indexed) {
                (false, false) => "psq_l",
                (true, false) => "psq_lu",
                (false, true) => "psq_lx",
                (true, true) => "psq_lux",
            },
            PsKind::Store { update, indexed } => match (update, indexed) {
                (false, false) => "psq_st",
                (true, false) => "psq_stu",
                (false, true) => "psq_stx",
                (true, true) => "psq_stux",
            },
            PsKind::Add => "ps_add",
            PsKind::Sub => "ps_sub",
            PsKind::Mul => "ps_mul",
            PsKind::Div => "ps_div",
            PsKind::Madd => "ps_madd",
            PsKind::Msub => "ps_msub",
            PsKind::Nmadd => "ps_nmadd",
            PsKind::Nmsub => "ps_nmsub",
            PsKind::Madds0 => "ps_madds0",
            PsKind::Madds1 => "ps_madds1",
            PsKind::Muls0 => "ps_muls0",
            PsKind::Muls1 => "ps_muls1",
            PsKind::Sum0 => "ps_sum0",
            PsKind::Sum1 => "ps_sum1",
            PsKind::Sel => "ps_sel",
            PsKind::Merge00 => "ps_merge00",
            PsKind::Merge01 => "ps_merge01",
            PsKind::Merge10 => "ps_merge10",
            PsKind::Merge11 => "ps_merge11",
            PsKind::Mr => "ps_mr",
            PsKind::Abs => "ps_abs",
            PsKind::Neg => "ps_neg",
            PsKind::Nabs => "ps_nabs",
            PsKind::Res => "ps_res",
            PsKind::Rsqrte => "ps_rsqrte",
            PsKind::Cmpo0 => "ps_cmpo0",
            PsKind::Cmpo1 => "ps_cmpo1",
            PsKind::Cmpu0 => "ps_cmpu0",
            PsKind::Cmpu1 => "ps_cmpu1",
        }
    }

    /// Whether the dotted (Rc) form exists.
    fn has_rc(self) -> bool {
        !matches!(
            self,
            PsKind::Unknown
                | PsKind::Load { .. }
                | PsKind::Store { .. }
                | PsKind::Cmpo0
                | PsKind::Cmpo1
                | PsKind::Cmpu0
                | PsKind::Cmpu1
        )
    }
}

/// Fully decoded fields shared by the disassembler and the lane emitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Decoded {
    kind: PsKind,
    dotted: bool,
    d: u8,
    a: u8,
    b: u8,
    c: u8,
    w: u8,
    i: u8,
    off: i32,
}

fn arith_kind(xo: u32) -> Option<PsKind> {
    Some(match xo {
        10 => PsKind::Sum0,
        11 => PsKind::Sum1,
        12 => PsKind::Muls0,
        13 => PsKind::Muls1,
        14 => PsKind::Madds0,
        15 => PsKind::Madds1,
        18 => PsKind::Div,
        20 => PsKind::Sub,
        21 => PsKind::Add,
        23 => PsKind::Sel,
        24 => PsKind::Res,
        25 => PsKind::Mul,
        26 => PsKind::Rsqrte,
        28 => PsKind::Msub,
        29 => PsKind::Madd,
        30 => PsKind::Nmsub,
        31 => PsKind::Nmadd,
        _ => return None,
    })
}

fn x10_kind(xo: u32) -> Option<PsKind> {
    Some(match xo {
        0 => PsKind::Cmpu0,
        32 => PsKind::Cmpo0,
        40 => PsKind::Neg,
        64 => PsKind::Cmpu1,
        72 => PsKind::Mr,
        96 => PsKind::Cmpo1,
        136 => PsKind::Nabs,
        264 => PsKind::Abs,
        528 => PsKind::Merge00,
        560 => PsKind::Merge01,
        592 => PsKind::Merge10,
        624 => PsKind::Merge11,
        _ => return None,
    })
}

fn is_cmp(kind: PsKind) -> bool {
    matches!(
        kind,
        PsKind::Cmpo0 | PsKind::Cmpo1 | PsKind::Cmpu0 | PsKind::Cmpu1
    )
}

/// Classify one big-endian instruction word. Unknown words yield
/// [`PsKind::Unknown`] (rendered `.word`, the `gte`/`vu`/`rsp` convention).
fn classify(word: u32) -> Decoded {
    let op = word >> 26;
    let d = ((word >> 21) & 31) as u8;
    let a = ((word >> 16) & 31) as u8;
    let b = ((word >> 11) & 31) as u8;
    let c = ((word >> 6) & 31) as u8;
    let rc = word & 1 != 0;
    let blank = Decoded {
        kind: PsKind::Unknown,
        dotted: false,
        d,
        a,
        b,
        c,
        w: 0,
        i: 0,
        off: 0,
    };
    // Quantized D-forms: psq_l/psq_lu/psq_st/psq_stu.
    let dform = match op {
        56 => Some(PsKind::Load { update: false, indexed: false }),
        57 => Some(PsKind::Load { update: true, indexed: false }),
        60 => Some(PsKind::Store { update: false, indexed: false }),
        61 => Some(PsKind::Store { update: true, indexed: false }),
        _ => None,
    };
    if let Some(kind) = dform {
        let raw = word & 0xfff;
        let off = if raw & 0x800 != 0 { (raw | 0xffff_f000) as i32 } else { raw as i32 };
        return Decoded {
            kind,
            w: ((word >> 15) & 1) as u8,
            i: ((word >> 12) & 7) as u8,
            off,
            ..blank
        };
    }
    if op != 4 {
        return blank;
    }
    // Indexed X-forms first would collide with XO-10 readers on bits 1–6,
    // but the PS XO-10 ids never have their low six bits in {6,7,38,39},
    // so either order classifies identically; XO-10 first keeps the
    // move/merge/compare constraints (fA==0, CRFD shape) authoritative.
    let xo10 = (word >> 1) & 0x3ff;
    if let Some(kind) = x10_kind(xo10) {
        if is_cmp(kind) {
            // Compares carry CRFD in the D field with its low two bits
            // zero (BITS_21_22=0) and never take Rc.
            if !rc && d & 3 == 0 {
                return Decoded { kind, ..blank };
            }
            return blank;
        }
        // Unary ops (mr/abs/neg/nabs/res/rsqrte) require fA (bits 16–20)
        // == 0; merges take frA as a real operand, so they do not.
        let unary = matches!(
            kind,
            PsKind::Mr | PsKind::Abs | PsKind::Neg | PsKind::Nabs | PsKind::Res | PsKind::Rsqrte
        );
        if !unary || a == 0 {
            return Decoded { kind, dotted: rc, ..blank };
        }
        return blank;
    }
    // Quantized indexed forms: XO=(1,6), BIT_0=0.
    if !rc {
        let xo6 = (word >> 1) & 0x3f;
        let xkind = match xo6 {
            6 => Some(PsKind::Load { update: false, indexed: true }),
            7 => Some(PsKind::Store { update: false, indexed: true }),
            38 => Some(PsKind::Load { update: true, indexed: true }),
            39 => Some(PsKind::Store { update: true, indexed: true }),
            _ => None,
        };
        if let Some(kind) = xkind {
            return Decoded {
                kind,
                w: ((word >> 10) & 1) as u8,
                i: ((word >> 7) & 7) as u8,
                ..blank
            };
        }
    }
    // Arithmetic: XO=(1,5).
    if let Some(kind) = arith_kind((word >> 1) & 0x1f) {
        return Decoded { kind, dotted: rc, ..blank };
    }
    blank
}

/// Decode one big-endian Gekko paired-single instruction word.
pub fn decode(word: u32, address: u64) -> PsInsn {
    let dec = classify(word);
    let (mnemonic, operands) = match dec.kind {
        PsKind::Unknown => (".word".into(), format!("{word:#010x}")),
        PsKind::Load { update: _, indexed: false } | PsKind::Store { update: _, indexed: false } => {
            let base = if dec.a == 0 { "0".to_string() } else { format!("r{}", dec.a) };
            (dec.kind.base().into(), format!("{}, {}({}), {}, {}", fr(dec.d), dec.off, base, dec.w, dec.i))
        }
        PsKind::Load { update: _, indexed: true } | PsKind::Store { update: _, indexed: true } => {
            let a = if dec.a == 0 { "0".to_string() } else { format!("r{}", dec.a) };
            (dec.kind.base().into(), format!("{}, {}, r{}, {}, {}", fr(dec.d), a, dec.b, dec.w, dec.i))
        }
        PsKind::Cmpo0 | PsKind::Cmpo1 | PsKind::Cmpu0 | PsKind::Cmpu1 => {
            let crfd = dec.d >> 2;
            (dec.kind.base().into(), format!("cr{crfd}, {}, {}", fr(dec.a), fr(dec.b)))
        }
        PsKind::Add | PsKind::Sub | PsKind::Div => {
            let name = dot(dec.kind.base(), dec.dotted);
            (name, format!("{}, {}, {}", fr(dec.d), fr(dec.a), fr(dec.b)))
        }
        PsKind::Mul | PsKind::Muls0 | PsKind::Muls1 => {
            let name = dot(dec.kind.base(), dec.dotted);
            (name, format!("{}, {}, {}", fr(dec.d), fr(dec.a), fr(dec.c)))
        }
        PsKind::Madd | PsKind::Msub | PsKind::Nmadd | PsKind::Nmsub | PsKind::Madds0
        | PsKind::Madds1 | PsKind::Sum0 | PsKind::Sum1 | PsKind::Sel => {
            let name = dot(dec.kind.base(), dec.dotted);
            (name, format!("{}, {}, {}, {}", fr(dec.d), fr(dec.a), fr(dec.c), fr(dec.b)))
        }
        PsKind::Merge00 | PsKind::Merge01 | PsKind::Merge10 | PsKind::Merge11 => {
            let name = dot(dec.kind.base(), dec.dotted);
            (name, format!("{}, {}, {}", fr(dec.d), fr(dec.a), fr(dec.b)))
        }
        PsKind::Mr | PsKind::Abs | PsKind::Neg | PsKind::Nabs | PsKind::Res | PsKind::Rsqrte => {
            let name = dot(dec.kind.base(), dec.dotted);
            (name, format!("{}, {}", fr(dec.d), fr(dec.b)))
        }
    };
    PsInsn { address, word, mnemonic, operands }
}

fn dot(base: &str, dotted: bool) -> String {
    if dotted { format!("{base}.") } else { base.into() }
}

/// Disassemble `count` big-endian words from `bytes` at `vaddr`.
pub fn disassemble(bytes: &[u8], vaddr: u64, count: usize) -> Vec<PsInsn> {
    (0..count)
        .filter_map(|ix| {
            let off = ix * 4;
            let word = u32::from_be_bytes(bytes.get(off..off + 4)?.try_into().ok()?);
            Some(decode(word, vaddr + off as u64))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Lane-wise C emission.
// ---------------------------------------------------------------------------
fn lane(reg: u8, lane: u8) -> String {
    format!("f{reg}_ps{lane}")
}

fn ea_text(a: u8, off: i32) -> String {
    if a == 0 {
        format!("{off}")
    } else {
        format!("r{a} + {off}")
    }
}

fn ea_lane1(a: u8, off: i32) -> String {
    if a == 0 {
        format!("{}", off + 4)
    } else if off == 0 {
        format!("r{a} + 4")
    } else {
        format!("r{a} + {}", off + 4)
    }
}

fn ld_helper(ty: QuantType) -> &'static str {
    match ty {
        QuantType::Float => "",
        QuantType::U8 => "ps_ld_u8",
        QuantType::S8 => "ps_ld_s8",
        QuantType::U16 => "ps_ld_u16",
        QuantType::S16 => "ps_ld_s16",
    }
}

fn st_helper(ty: QuantType) -> &'static str {
    match ty {
        QuantType::Float => "",
        QuantType::U8 => "ps_st_u8",
        QuantType::S8 => "ps_st_s8",
        QuantType::U16 => "ps_st_u16",
        QuantType::S16 => "ps_st_s16",
    }
}

fn mem_width(ty: QuantType) -> &'static str {
    match ty {
        QuantType::Float => "float",
        QuantType::U8 | QuantType::S8 => "uint8_t",
        QuantType::U16 | QuantType::S16 => "uint16_t",
    }
}

/// Emit one load lane: quantized paths name a [`PS_HELPERS_C`] helper,
/// float paths are direct `float` dereferences. Loads always dequantize
/// with the GQR LD field.
fn emit_load_lane(out: &mut Vec<String>, reg: u8, ln: u8, ea: &str, gqr: u32) {
    let fields = parse_gqr(gqr);
    let (ty, scale) = (fields.ld_type, fields.ld_scale);
    let dst = lane(reg, ln);
    if matches!(ty, QuantType::Float) {
        out.push(format!("{dst} = *(float *)({ea});"));
    } else {
        let w = mem_width(ty);
        out.push(format!("{dst} = {}(*({w} *)({ea}), {scale});", ld_helper(ty)));
    }
}

fn emit_store_lane(out: &mut Vec<String>, reg: u8, ln: u8, ea: &str, gqr: u32) {
    let fields = parse_gqr(gqr);
    let (ty, scale) = (fields.st_type, fields.st_scale);
    let src = lane(reg, ln);
    if matches!(ty, QuantType::Float) {
        out.push(format!("*(float *)({ea}) = {src};"));
    } else {
        let w = mem_width(ty);
        out.push(format!("*({w} *)({ea}) = {}({src}, {scale});", st_helper(ty)));
    }
}

/// Render a decoded word sequence as lane-wise `float` C.
///
/// `seq` holds `(address, big-endian word)` pairs; `gqrs` holds the eight
/// GQR values (`gqrs[i]` backs `I == i`), typically with `GQR0 = 0`
/// (float/float, scale 0) for MWCC float prologues. Every arithmetic op
/// emits one `float` expression per lane (`fD_ps0`/`fD_ps1`); quantized
/// transfers name a [`PS_HELPERS_C`] helper. The output never mentions
/// `double` and never emits opaque unknown calls.
pub fn emit_lane_c(seq: &[(u64, u32)], gqrs: &[u32; 8]) -> String {
    let mut out = Vec::new();
    for &(_, word) in seq {
        let dec = classify(word);
        match dec.kind {
            PsKind::Unknown => {
                out.push(format!("// .word {word:#010x} (not paired-single)"));
            }
            PsKind::Load { update, indexed } => {
                let gqr = gqrs[dec.i as usize];
                let ea = if indexed {
                    if dec.a == 0 { format!("r{}", dec.b) } else { format!("r{} + r{}", dec.a, dec.b) }
                } else {
                    ea_text(dec.a, dec.off)
                };
                emit_load_lane(&mut out, dec.d, 0, &ea, gqr);
                if dec.w == 1 {
                    out.push(format!("{} = 1.0f;", lane(dec.d, 1)));
                } else {
                    let ea1 = if indexed {
                        format!("({ea} + 4)")
                    } else {
                        ea_lane1(dec.a, dec.off)
                    };
                    emit_load_lane(&mut out, dec.d, 1, &ea1, gqr);
                }
                if update && dec.a != 0 {
                    out.push(format!("r{} = {ea};", dec.a));
                }
            }
            PsKind::Store { update, indexed } => {
                let gqr = gqrs[dec.i as usize];
                let ea = if indexed {
                    if dec.a == 0 { format!("r{}", dec.b) } else { format!("r{} + r{}", dec.a, dec.b) }
                } else {
                    ea_text(dec.a, dec.off)
                };
                emit_store_lane(&mut out, dec.d, 0, &ea, gqr);
                if dec.w == 0 {
                    let ea1 = if indexed {
                        format!("({ea} + 4)")
                    } else {
                        ea_lane1(dec.a, dec.off)
                    };
                    emit_store_lane(&mut out, dec.d, 1, &ea1, gqr);
                }
                if update && dec.a != 0 {
                    out.push(format!("r{} = {ea};", dec.a));
                }
            }
            PsKind::Add => binop(&mut out, dec, "+"),
            PsKind::Sub => binop(&mut out, dec, "-"),
            PsKind::Mul => mulop(&mut out, dec, 0),
            PsKind::Div => binop(&mut out, dec, "/"),
            PsKind::Muls0 => mulop(&mut out, dec, 0),
            PsKind::Muls1 => mulop(&mut out, dec, 1),
            PsKind::Madd => madd(&mut out, dec, false),
            PsKind::Msub => madd(&mut out, dec, true),
            PsKind::Nmadd => nmadd(&mut out, dec, false),
            PsKind::Nmsub => nmadd(&mut out, dec, true),
            PsKind::Madds0 => madds(&mut out, dec, 0),
            PsKind::Madds1 => madds(&mut out, dec, 1),
            PsKind::Sum0 => {
                out.push(format!("{} = {} + {};", lane(dec.d, 0), lane(dec.a, 0), lane(dec.b, 1)));
                out.push(format!("{} = {};", lane(dec.d, 1), lane(dec.c, 1)));
            }
            PsKind::Sum1 => {
                out.push(format!("{} = {};", lane(dec.d, 0), lane(dec.c, 0)));
                out.push(format!("{} = {} + {};", lane(dec.d, 1), lane(dec.a, 0), lane(dec.b, 1)));
            }
            PsKind::Sel => {
                out.push(format!(
                    "{} = ({} >= 0.0f) ? {} : {};",
                    lane(dec.d, 0), lane(dec.a, 0), lane(dec.c, 0), lane(dec.b, 0)
                ));
                out.push(format!(
                    "{} = ({} >= 0.0f) ? {} : {};",
                    lane(dec.d, 1), lane(dec.a, 1), lane(dec.c, 1), lane(dec.b, 1)
                ));
            }
            PsKind::Merge00 => mov2(&mut out, dec, 0, 0),
            PsKind::Merge01 => mov2(&mut out, dec, 0, 1),
            PsKind::Merge10 => mov2(&mut out, dec, 1, 0),
            PsKind::Merge11 => mov2(&mut out, dec, 1, 1),
            PsKind::Mr => {
                out.push(format!("{} = {};", lane(dec.d, 0), lane(dec.b, 0)));
                out.push(format!("{} = {};", lane(dec.d, 1), lane(dec.b, 1)));
            }
            PsKind::Abs => {
                out.push(format!("{} = fabsf({});", lane(dec.d, 0), lane(dec.b, 0)));
                out.push(format!("{} = fabsf({});", lane(dec.d, 1), lane(dec.b, 1)));
            }
            PsKind::Neg => {
                out.push(format!("{} = -{};", lane(dec.d, 0), lane(dec.b, 0)));
                out.push(format!("{} = -{};", lane(dec.d, 1), lane(dec.b, 1)));
            }
            PsKind::Nabs => {
                out.push(format!("{} = -fabsf({});", lane(dec.d, 0), lane(dec.b, 0)));
                out.push(format!("{} = -fabsf({});", lane(dec.d, 1), lane(dec.b, 1)));
            }
            PsKind::Res => {
                out.push(format!("{} = 1.0f / {};", lane(dec.d, 0), lane(dec.b, 0)));
                out.push(format!("{} = 1.0f / {};", lane(dec.d, 1), lane(dec.b, 1)));
            }
            PsKind::Rsqrte => {
                out.push(format!("{} = 1.0f / sqrtf({});", lane(dec.d, 0), lane(dec.b, 0)));
                out.push(format!("{} = 1.0f / sqrtf({});", lane(dec.d, 1), lane(dec.b, 1)));
            }
            PsKind::Cmpo0 | PsKind::Cmpo1 | PsKind::Cmpu0 | PsKind::Cmpu1 => {
                let lane_ix = if matches!(dec.kind, PsKind::Cmpo1 | PsKind::Cmpu1) { 1 } else { 0 };
                let crfd = dec.d >> 2;
                out.push(format!(
                    "cr{crfd} = ({} < {}) ? 8 : (({} > {}) ? 4 : 2);",
                    lane(dec.a, lane_ix), lane(dec.b, lane_ix),
                    lane(dec.a, lane_ix), lane(dec.b, lane_ix),
                ));
            }
        }
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

fn binop(out: &mut Vec<String>, dec: Decoded, op: &str) {
    out.push(format!("{} = {} {op} {};", lane(dec.d, 0), lane(dec.a, 0), lane(dec.b, 0)));
    out.push(format!("{} = {} {op} {};", lane(dec.d, 1), lane(dec.a, 1), lane(dec.b, 1)));
}

/// `ps_mul`/`ps_muls0`/`ps_muls1`: `sel` picks which lane of frC feeds lane 0.
fn mulop(out: &mut Vec<String>, dec: Decoded, sel: u8) {
    let (c0, c1) = if dec.kind == PsKind::Mul { (0, 1) } else { (sel, sel) };
    out.push(format!("{} = {} * {};", lane(dec.d, 0), lane(dec.a, 0), lane(dec.c, c0)));
    out.push(format!("{} = {} * {};", lane(dec.d, 1), lane(dec.a, 1), lane(dec.c, c1)));
}

/// `ps_madd` (`sub=true`: `ps_msub`).
fn madd(out: &mut Vec<String>, dec: Decoded, sub: bool) {
    let op = if sub { '-' } else { '+' };
    out.push(format!(
        "{} = {} * {} {op} {};",
        lane(dec.d, 0), lane(dec.a, 0), lane(dec.c, 0), lane(dec.b, 0)
    ));
    out.push(format!(
        "{} = {} * {} {op} {};",
        lane(dec.d, 1), lane(dec.a, 1), lane(dec.c, 1), lane(dec.b, 1)
    ));
}

/// `ps_nmadd` (`sub=true`: `ps_nmsub`): negated multiply-add/sub.
fn nmadd(out: &mut Vec<String>, dec: Decoded, sub: bool) {
    let op = if sub { '-' } else { '+' };
    out.push(format!(
        "{} = -({} * {} {op} {});",
        lane(dec.d, 0), lane(dec.a, 0), lane(dec.c, 0), lane(dec.b, 0)
    ));
    out.push(format!(
        "{} = -({} * {} {op} {});",
        lane(dec.d, 1), lane(dec.a, 1), lane(dec.c, 1), lane(dec.b, 1)
    ));
}

/// `ps_madds0` (`sel=0`) / `ps_madds1`: lane 1 reuses lane `sel` of frC.
fn madds(out: &mut Vec<String>, dec: Decoded, sel: u8) {
    out.push(format!(
        "{} = {} * {} + {};",
        lane(dec.d, 0), lane(dec.a, 0), lane(dec.c, sel), lane(dec.b, 0)
    ));
    out.push(format!(
        "{} = {} * {} + {};",
        lane(dec.d, 1), lane(dec.a, 1), lane(dec.c, sel), lane(dec.b, 1)
    ));
}

fn mov2(out: &mut Vec<String>, dec: Decoded, a_lane: u8, b_lane: u8) {
    out.push(format!("{} = {};", lane(dec.d, 0), lane(dec.a, a_lane)));
    out.push(format!("{} = {};", lane(dec.d, 1), lane(dec.b, b_lane)));
}

/// Wrap [`emit_lane_c`] in a C function frame.
pub fn emit_ps_function(name: &str, seq: &[(u64, u32)], gqrs: &[u32; 8]) -> String {
    let body = emit_lane_c(seq, gqrs);
    let mut text = format!("void {name}(void)\n{{\n");
    for line in body.lines() {
        text.push_str("  ");
        text.push_str(line);
        text.push('\n');
    }
    text.push_str("}\n");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const GQR_FLOAT: [u32; 8] = [0; 8];

    fn word(base: u32, d: u32, a: u32, b: u32, c: u32, xo_shifted: u32, rc: u32) -> u32 {
        (base << 26) | (d << 21) | (a << 16) | (b << 11) | (c << 6) | xo_shifted | rc
    }

    #[test]
    fn quant_d_forms_decode() {
        // psq_l f1, 0(r3), 0, 0
        let ins = decode(0xe023_0000, 0x8000_0000);
        assert_eq!(ins.mnemonic, "psq_l");
        assert_eq!(ins.operands, "f1, 0(r3), 0, 0");
        // psq_st f2, 0(r2), 0, 0 — 0xf042_0000 encodes rA=2.
        let ins = decode(0xf042_0000, 0x8000_0004);
        assert_eq!(ins.mnemonic, "psq_st");
        assert_eq!(ins.operands, "f2, 0(r2), 0, 0");
        // psq_lu with W=1, I=2, off=8: exercises W/I/offset parse.
        let w = (57 << 26) | (5 << 21) | (6 << 16) | (1 << 15) | (2 << 12) | 8;
        let ins = decode(w, 0);
        assert_eq!(ins.mnemonic, "psq_lu");
        assert_eq!(ins.operands, "f5, 8(r6), 1, 2");
        // psq_stu f2, -4(r4), 0, 0 (signed 12-bit offset).
        let w = (61 << 26) | (2 << 21) | (4 << 16) | 0xffc;
        let ins = decode(w, 0);
        assert_eq!(ins.mnemonic, "psq_stu");
        assert_eq!(ins.operands, "f2, -4(r4), 0, 0");
    }

    #[test]
    fn indexed_forms_decode() {
        // psq_lx f1, r3, r4, 0, 1
        let w = (4 << 26) | (1 << 21) | (3 << 16) | (4 << 11) | (1 << 7) | (6 << 1);
        let ins = decode(w, 0);
        assert_eq!(ins.mnemonic, "psq_lx");
        assert_eq!(ins.operands, "f1, r3, r4, 0, 1");
        // psq_stux f2, r3, r4, 1, 0
        let w = (4 << 26) | (2 << 21) | (3 << 16) | (4 << 11) | (1 << 10) | (39 << 1);
        let ins = decode(w, 0);
        assert_eq!(ins.mnemonic, "psq_stux");
        assert_eq!(ins.operands, "f2, r3, r4, 1, 0");
    }

    #[test]
    fn arith_and_dotted_decode() {
        // ps_add f2, f1, f1
        let ins = decode(word(4, 2, 1, 1, 0, 21 << 1, 0), 0);
        assert_eq!(ins.mnemonic, "ps_add");
        assert_eq!(ins.operands, "f2, f1, f1");
        // ps_mul. f3, f1, f2 (dotted; C-before-B operand order)
        let ins = decode(word(4, 3, 1, 0, 2, 25 << 1, 1), 0);
        assert_eq!(ins.mnemonic, "ps_mul.");
        assert_eq!(ins.operands, "f3, f1, f2");
        // ps_madd f4, f1, f2, f3
        let ins = decode(word(4, 4, 1, 3, 2, 29 << 1, 0), 0);
        assert_eq!(ins.mnemonic, "ps_madd");
        assert_eq!(ins.operands, "f4, f1, f2, f3");
        // ps_mr f2, f1 (fA must be zero)
        let w = (4 << 26) | (2 << 21) | (0 << 16) | (1 << 11) | (72 << 1);
        let ins = decode(w, 0);
        assert_eq!(ins.mnemonic, "ps_mr");
        // ps_merge01 f2, f3, f4
        let w = (4 << 26) | (2 << 21) | (3 << 16) | (4 << 11) | (560 << 1);
        let ins = decode(w, 0);
        assert_eq!(ins.mnemonic, "ps_merge01");
        // ps_cmpo0 cr2, f3, f4
        let w = (4 << 26) | (8 << 21) | (3 << 16) | (4 << 11) | (32 << 1);
        let ins = decode(w, 0);
        assert_eq!(ins.mnemonic, "ps_cmpo0");
        assert_eq!(ins.operands, "cr2, f3, f4");
    }

    #[test]
    fn invalid_is_word() {
        assert_eq!(decode(0x7c22_1a14, 0).mnemonic, "add".to_string().replace("add", ".word").replace(".word", ".word"));
        // Plain integer `add r3,r4,r5` (primary 31) is not paired-single.
        let ins = decode(0x7c62_2a14, 0);
        assert_eq!(ins.mnemonic, ".word");
        // Primary-4 word with an unclaimed XO is not paired-single either.
        let ins = decode(word(4, 1, 2, 3, 4, 9 << 1, 0), 0);
        assert_eq!(ins.mnemonic, ".word");
    }

    #[test]
    fn gqr_fields_and_round_trip() {
        assert_eq!(
            parse_gqr(0),
            GqrFields { st_type: QuantType::Float, st_scale: 0, ld_type: QuantType::Float, ld_scale: 0 }
        );
        // LD=u8 scale 3: (4<<21) | (3<<16).
        let g = parse_gqr((4 << 21) | (3 << 16));
        assert_eq!(g.ld_type, QuantType::U8);
        assert_eq!(g.ld_scale, 3);
        // Reserved ids fall through to float, like the .slaspec branches.
        assert_eq!(QuantType::from_id(2), QuantType::Float);
        // float is the identity in both directions.
        let bits = 1.5f32.to_bits();
        assert_eq!(quantize(1.5, QuantType::Float, 0), bits);
        assert_eq!(dequantize(bits, QuantType::Float, 0), 1.5);
        // u8 scale 3: 16 counts at 2^-3 per count.
        assert_eq!(dequantize(16, QuantType::U8, 3), 2.0);
        assert_eq!(quantize(2.0, QuantType::U8, 3), 16);
        // s8 sign-extends: 0xFE is -2.
        assert_eq!(dequantize(0xfe, QuantType::S8, 0), -2.0);
        // Stores clamp instead of wrapping: 1000.0f saturates u8.
        assert_eq!(quantize(1000.0, QuantType::U8, 0), 255);
        assert_eq!(quantize(-1000.0, QuantType::U8, 0), 0);
        // trunc, not round: 1.9f -> 1 count at scale 0.
        assert_eq!(quantize(1.9, QuantType::U16, 0), 1);
    }

    #[test]
    fn lane_emit_psq_add_stq() {
        // Synthetic MWCC-style float routine: GQR0=float, W=0.
        //   psq_l  f1, 0(r3), 0, 0
        //   ps_add f2, f1, f1
        //   psq_st f2, 0(r4), 0, 0
        let seq = vec![
            (0x8000_0000u64, 0xe023_0000u32),
            (0x8000_0004, word(4, 2, 1, 1, 0, 21 << 1, 0)),
            (0x8000_0008, 0xf044_0000),
        ];
        for (addr, w) in &seq {
            let ins = decode(*w, *addr);
            assert_ne!(ins.mnemonic, ".word", "{w:#010x} should decode as paired-single");
        }
        let c = emit_lane_c(&seq, &GQR_FLOAT);
        // Lane-wise float ops on both lanes...
        for want in [
            "f1_ps0 = *(float *)(r3 + 0);",
            "f1_ps1 = *(float *)(r3 + 4);",
            "f2_ps0 = f1_ps0 + f1_ps0;",
            "f2_ps1 = f1_ps1 + f1_ps1;",
            "*(float *)(r4 + 0) = f2_ps0;",
            "*(float *)(r4 + 4) = f2_ps1;",
        ] {
            assert!(c.contains(want), "missing {want:?} in:\n{c}");
        }
        // ...typed float, never double, never an opaque unknown op.
        assert!(!c.contains("double"), "lane C must not use double:\n{c}");
        for opaque in ["ldexpf", "psq_l(", "psq_st(", "unknown", "opaque", "UNIMPL"] {
            assert!(!c.contains(opaque), "lane C must not contain {opaque:?}:\n{c}");
        }
    }


    #[test]
    fn w_bit_is_single() {
        // psq_l f5, 8(r6), 1, 0: W=1 loads lane 0 only, lane 1 = 1.0.
        let w = (56 << 26) | (5 << 21) | (6 << 16) | (1 << 15) | 8;
        let c = emit_lane_c(&[(0, w)], &GQR_FLOAT);
        assert!(c.contains("f5_ps0 = *(float *)(r6 + 8);"), ":\n{c}");
        assert!(c.contains("f5_ps1 = 1.0f;"), ":\n{c}");
        assert!(!c.contains("r6 + 12"), "W=1 must not touch lane 1 memory:\n{c}");
        // psq_st f5, 8(r6), 1, 0: W=1 stores lane 0 only.
        let w = (60 << 26) | (5 << 21) | (6 << 16) | (1 << 15) | 8;
        let c = emit_lane_c(&[(0, w)], &GQR_FLOAT);
        assert!(c.contains("*(float *)(r6 + 8) = f5_ps0;"), ":\n{c}");
        assert!(!c.contains("ps1"), "W=1 store must not mention lane 1:\n{c}");
    }

    #[test]
    fn quantized_paths_name_helpers() {
        // GQR1: LD=u8 scale 0, ST=u8 scale 0.
        let mut gqrs = [0u32; 8];
        gqrs[1] = (4 << 29) | (4 << 21);
        // psq_l f1, 0(r3), 0, 1 / psq_st f1, 0(r4), 0, 1
        let l = (56 << 26) | (1 << 21) | (3 << 16) | (1 << 12);
        let s = (60 << 26) | (1 << 21) | (4 << 16) | (1 << 12);
        let c = emit_lane_c(&[(0, l), (4, s)], &gqrs);
        assert!(c.contains("ps_ld_u8(*(uint8_t *)(r3 + 0), 0)"), ":\n{c}");
        assert!(c.contains("ps_st_u8(f1_ps0, 0)"), ":\n{c}");
        assert!(!c.contains("double"), ":\n{c}");
    }

    #[test]
    fn disassemble_round_trip() {
        let bytes = [0xe0, 0x23, 0x00, 0x00, 0x10, 0x41, 0x08, 0x2a];
        let v = disassemble(&bytes, 0x8000_0000, 2);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mnemonic, "psq_l");
        assert_eq!(v[1].mnemonic, "ps_add");
        assert_eq!(v[1].address, 0x8000_0004);
    }
}
