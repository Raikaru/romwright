//! N64 F3DEX2 display-list (GBI) annotator.
//!
//! Each display-list command is 8 bytes (big-endian `w0, w1`); the opcode is
//! `w0 >> 24`. The opcode numbers and bit layouts below are the documented
//! F3DEX2 fast3D interface (public SDK headers / CC0 community headers):
//! numeric facts only, no ported code.
//!
//! Role: given a DL blob, return command boundaries + names + decoded
//! operands so graphics microcode stays annotated asm (P4.4 audio-first C
//! policy). RDP commands (`0xE4..=0xFF`) are named with raw words — full RDP
//! operand decode is out of scope.

/// One annotated 8-byte display-list command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GbiCmd {
    /// Byte offset of the command inside the annotated blob.
    pub offset: usize,
    /// Virtual address of the command (`base + offset`).
    pub vaddr: u64,
    /// Raw first word (opcode in the top byte).
    pub w0: u32,
    /// Raw second word.
    pub w1: u32,
    /// Opcode byte (`w0 >> 24`).
    pub op: u8,
    /// Command name (`"G_VTX"`, …, `"UNKNOWN"` for reserved opcodes).
    pub name: &'static str,
    /// Decoded operands, e.g. `v0=0 n=3 addr=0x06001230`.
    pub detail: String,
}

impl GbiCmd {
    /// `G_DL` with push: a display-list call (returns to the next command).
    pub fn is_call(&self) -> bool {
        self.op == OP_DL && (self.w0 >> 16) & 0xff == DL_PUSH
    }
    /// `G_DL` without push: a display-list branch (does not return).
    pub fn is_branch(&self) -> bool {
        self.op == OP_DL && (self.w0 >> 16) & 0xff != DL_PUSH
    }
    /// `G_ENDDL`: end of the display list.
    pub fn is_return(&self) -> bool {
        self.op == OP_ENDDL
    }
    /// Branch/call target address for `G_DL`, else `None`.
    pub fn target(&self) -> Option<u32> {
        (self.op == OP_DL).then_some(self.w1)
    }
}

pub const OP_DL: u8 = 0xDE;
pub const OP_ENDDL: u8 = 0xDF;
const DL_PUSH: u32 = 0x00;

/// F3DEX2/RDP opcode number → command name. `None` = reserved/unknown.
pub fn op_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x00 => "G_NOOP",
        0x01 => "G_VTX",
        0x02 => "G_MODIFYVTX",
        0x03 => "G_CULLDL",
        0x04 => "G_BRANCH_Z",
        0x05 => "G_TRI1",
        0x06 => "G_TRI2",
        0x07 => "G_QUAD",
        0x08 => "G_LINE3D",
        0xD3 => "G_SPECIAL_3",
        0xD4 => "G_SPECIAL_2",
        0xD5 => "G_SPECIAL_1",
        0xD6 => "G_DMA_IO",
        0xD7 => "G_TEXTURE",
        0xD8 => "G_POPMTX",
        0xD9 => "G_GEOMETRYMODE",
        0xDA => "G_MTX",
        0xDB => "G_MOVEWORD",
        0xDC => "G_MOVEMEM",
        0xDD => "G_LOAD_UCODE",
        0xDE => "G_DL",
        0xDF => "G_ENDDL",
        0xE0 => "G_SPNOOP",
        0xE1 => "G_RDPHALF_1",
        0xE2 => "G_SETOTHERMODE_L",
        0xE3 => "G_SETOTHERMODE_H",
        0xE4 => "G_TEXRECT",
        0xE5 => "G_TEXRECTFLIP",
        0xE6 => "G_RDPLOADSYNC",
        0xE7 => "G_RDPPIPESYNC",
        0xE8 => "G_RDPTILESYNC",
        0xE9 => "G_RDPFULLSYNC",
        0xEA => "G_SETKEYGB",
        0xEB => "G_SETKEYR",
        0xEC => "G_SETCONVERT",
        0xED => "G_SETSCISSOR",
        0xEE => "G_SETPRIMDEPTH",
        0xEF => "G_RDPSETOTHERMODE",
        0xF0 => "G_LOADTLUT",
        0xF1 => "G_RDPHALF_2",
        0xF2 => "G_SETTILESIZE",
        0xF3 => "G_LOADBLOCK",
        0xF4 => "G_LOADTILE",
        0xF5 => "G_SETTILE",
        0xF6 => "G_FILLRECT",
        0xF7 => "G_SETFILLCOLOR",
        0xF8 => "G_SETFOGCOLOR",
        0xF9 => "G_SETBLENDCOLOR",
        0xFA => "G_SETPRIMCOLOR",
        0xFB => "G_SETENVCOLOR",
        0xFC => "G_SETCOMBINE",
        0xFD => "G_SETTIMG",
        0xFE => "G_SETZIMG",
        0xFF => "G_SETCIMG",
        _ => return None,
    })
}

fn moveword_index_name(index: u32) -> &'static str {
    match index {
        0 => "MATRIX",
        2 => "NUMLIGHT",
        4 => "CLIP",
        6 => "SEGMENT",
        8 => "FOG",
        10 => "LIGHTCOL",
        12 => "FORCEMTX",
        14 => "PERSPNORM",
        _ => "UNKNOWN",
    }
}

fn movemem_index_name(index: u32) -> &'static str {
    match index {
        2 => "MMTX",
        6 => "PMTX",
        8 => "VIEWPORT",
        10 => "LIGHT",
        12 => "POINT",
        14 => "MATRIX",
        _ => "UNKNOWN",
    }
}

fn tri(w: u32) -> (u32, u32, u32) {
    (
        ((w >> 16) & 0xff) / 2,
        ((w >> 8) & 0xff) / 2,
        (w & 0xff) / 2,
    )
}

/// Decode one `(w0, w1)` pair into `(name, detail)`.
pub fn decode_pair(w0: u32, w1: u32) -> (&'static str, String) {
    let op = (w0 >> 24) as u8;
    let Some(name) = op_name(op) else {
        return ("UNKNOWN", format!("w0={w0:#010x} w1={w1:#010x}"));
    };
    let detail = match op {
        0x01 => {
            let n = (w0 >> 12) & 0xff;
            let v0 = ((w0 >> 1) & 0x7f).wrapping_sub(n);
            format!("v0={v0} n={n} addr={w1:#010x}")
        }
        0x02 => {
            let where_ = (w0 >> 16) & 0xff;
            let vtx = (w0 & 0xffff) / 2;
            format!("vtx={vtx} where={where_:#04x} val={w1:#010x}")
        }
        0x03 => {
            let v0 = (w0 & 0xffff) / 2;
            let vn = (w1 & 0xffff) / 2;
            format!("v0={v0} vn={vn}")
        }
        0x04 => {
            let by5 = (w0 >> 12) & 0xfff;
            let by2 = w0 & 0xfff;
            format!("vtx*5={by5} vtx*2={by2} w1={w1:#010x}")
        }
        0x05 => {
            let (a, b, c) = tri(w0);
            format!("v0={a} v1={b} v2={c}")
        }
        0x06 | 0x07 => {
            let (a, b, c) = tri(w0);
            let (d, e, f) = tri(w1);
            format!("t0=({a},{b},{c}) t1=({d},{e},{f})")
        }
        0x08 => {
            let (a, b, _) = tri(w0);
            let width = w0 & 0xff;
            format!("v0={a} v1={b} width={width}")
        }
        0xD3 | 0xD4 | 0xD5 => {
            format!("hi={:#08x} lo={w1:#010x}", w0 & 0xffffff)
        }
        0xD6 => {
            let dir = if (w0 >> 23) & 1 == 0 { "read" } else { "write" };
            let dmem = ((w0 >> 13) & 0x3ff) * 8;
            let size = (w0 & 0xfff) + 1;
            format!("{dir} dmem={dmem:#x} dram={w1:#010x} size={size}")
        }
        0xD7 => {
            let level = (w0 >> 11) & 7;
            let tile = (w0 >> 8) & 7;
            let on = (w0 >> 1) & 0x7f;
            let s = w1 >> 16;
            let t = w1 & 0xffff;
            format!("level={level} tile={tile} on={on} s={s:#06x} t={t:#06x}")
        }
        0xD8 => {
            let n = w1 / 64;
            format!("n={n} bytes={w1}")
        }
        0xD9 => {
            let clear = !w0 & 0xffffff;
            format!("clear={clear:#08x} set={w1:#010x}")
        }
        0xDA => {
            // F3DEX2 matrix flags: PUSH=1<<0, LOAD=1<<1, PROJECTION=1<<2.
            let param = (w0 & 0xff) ^ 0x01;
            let push = param & 1 != 0;
            let load = param & 2 != 0;
            let proj = param & 4 != 0;
            let mode = if proj { "projection" } else { "modelview" };
            let op = if load { "load" } else { "mul" };
            format!("{mode} {op} push={push} addr={w1:#010x}")
        }
        0xDB => {
            let index = (w0 >> 16) & 0xff;
            let offset = w0 & 0xffff;
            let iname = moveword_index_name(index);
            format!("{iname}({index:#04x}) offset={offset:#06x} data={w1:#010x}")
        }
        0xDC => {
            let size = (((w0 >> 19) & 0x1f) + 1) * 8;
            let offset = ((w0 >> 8) & 0xff) * 8;
            let index = w0 & 0xff;
            let iname = movemem_index_name(index);
            format!("{iname}({index:#04x}) offset={offset} size={size} addr={w1:#010x}")
        }
        0xDD => {
            let size = (w0 & 0xffff) + 1;
            format!("size={size} addr={w1:#010x}")
        }
        0xDE => {
            let kind = if (w0 >> 16) & 0xff == DL_PUSH {
                "call"
            } else {
                "branch"
            };
            format!("{kind} addr={w1:#010x}")
        }
        0xE1 | 0xF1 => format!("half={w1:#010x}"),
        0xE2 | 0xE3 => {
            let len = (w0 & 0xff) + 1;
            let shift = 32 - ((w0 >> 8) & 0xff) - len;
            format!("shift={shift} len={len} data={w1:#010x}")
        }
        _ => format!("w0={w0:#010x} w1={w1:#010x}"),
    };
    (name, detail)
}

/// Annotate a big-endian DL blob: one [`GbiCmd`] per 8-byte command.
///
/// A trailing partial word (< 8 bytes) is ignored. Reserved opcodes still
/// produce a (boundary-correct) `"UNKNOWN"` entry — annotation never fails.
pub fn annotate(bytes: &[u8], vaddr: u64) -> Vec<GbiCmd> {
    let mut out = Vec::with_capacity(bytes.len() / 8);
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        let w0 = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
        let w1 = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
        let op = (w0 >> 24) as u8;
        let (name, detail) = decode_pair(w0, w1);
        out.push(GbiCmd {
            offset: i * 8,
            vaddr: vaddr + (i * 8) as u64,
            w0,
            w1,
            op,
            name,
            detail,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Fixture encoders (documented layouts; used by tests and future fixtures).
// ---------------------------------------------------------------------------

/// `gsSPVertex(v, n, v0)`: load `n` vertices at `addr`, first index `v0`.
pub fn enc_vtx(n: u32, v0: u32, addr: u32) -> (u32, u32) {
    (0x01 << 24 | (n & 0xff) << 12 | ((v0 + n) & 0x7f) << 1, addr)
}

/// `gsSP1Triangle`: single triangle, flag-0 order.
pub fn enc_tri1(a: u32, b: u32, c: u32) -> (u32, u32) {
    (
        0x05 << 24 | (a * 2 & 0xff) << 16 | (b * 2 & 0xff) << 8 | (c * 2 & 0xff),
        0,
    )
}

/// `gsSP2Triangles`: two triangles, flag-0 order.
pub fn enc_tri2(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32) -> (u32, u32) {
    (
        0x06 << 24 | (a * 2 & 0xff) << 16 | (b * 2 & 0xff) << 8 | (c * 2 & 0xff),
        (d * 2 & 0xff) << 16 | (e * 2 & 0xff) << 8 | (f * 2 & 0xff),
    )
}

/// `gsSPMatrix`: `push`/`load`/`proj` select flags; matrix at `addr`.
pub fn enc_mtx(addr: u32, push: bool, load: bool, proj: bool) -> (u32, u32) {
    let mut param = 0u32;
    if push {
        param |= 1;
    }
    if load {
        param |= 2;
    }
    if proj {
        param |= 4;
    }
    (0xDA << 24 | 7 << 19 | ((param ^ 1) & 0xff), addr)
}

/// `gsSPDisplayList` (`push=true`) / `gsSPBranchList` (`push=false`).
pub fn enc_dl(addr: u32, push: bool) -> (u32, u32) {
    (0xDE << 24 | (u32::from(!push) & 0xff) << 16, addr)
}

/// `gsSPEndDisplayList`.
pub fn enc_enddl() -> (u32, u32) {
    (0xDF << 24, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words_to_bytes(words: &[(u32, u32)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(words.len() * 8);
        for &(w0, w1) in words {
            out.extend_from_slice(&w0.to_be_bytes());
            out.extend_from_slice(&w1.to_be_bytes());
        }
        out
    }

    fn names(cmds: &[GbiCmd]) -> Vec<&'static str> {
        cmds.iter().map(|c| c.name).collect()
    }

    #[test]
    fn synthetic_dl_parses_to_command_sequence() {
        // A typical F3DEX2 draw: matrix, vertices, two triangles, a call,
        // then end. RDP syncs ride in the same stream.
        let words = [
            enc_mtx(0x0600_1230, true, false, false),
            enc_vtx(3, 0, 0x0600_2000),
            enc_tri1(0, 1, 2),
            enc_tri2(3, 4, 5, 6, 7, 8),
            enc_dl(0x0600_3000, true),
            (0xE7 << 24, 0), // G_RDPPIPESYNC
            enc_enddl(),
        ];
        let cmds = annotate(&words_to_bytes(&words), 0x0600_0000);
        assert_eq!(
            names(&cmds),
            [
                "G_MTX",
                "G_VTX",
                "G_TRI1",
                "G_TRI2",
                "G_DL",
                "G_RDPPIPESYNC",
                "G_ENDDL",
            ]
        );
        // Boundaries: every command is 8 bytes, vaddrs advance by 8.
        for (i, c) in cmds.iter().enumerate() {
            assert_eq!(c.offset, i * 8);
            assert_eq!(c.vaddr, 0x0600_0000 + (i * 8) as u64);
        }
        assert_eq!(cmds[0].detail, "modelview mul push=true addr=0x06001230");
        assert_eq!(cmds[1].detail, "v0=0 n=3 addr=0x06002000");
        assert_eq!(cmds[2].detail, "v0=0 v1=1 v2=2");
        assert_eq!(cmds[3].detail, "t0=(3,4,5) t1=(6,7,8)");
        assert_eq!(cmds[4].detail, "call addr=0x06003000");
        assert!(cmds[4].is_call() && !cmds[4].is_branch());
        assert_eq!(cmds[4].target(), Some(0x0600_3000));
        assert!(cmds[6].is_return());
    }

    #[test]
    fn branch_dl_and_mtx_flags() {
        let cmds = annotate(
            &words_to_bytes(&[enc_dl(0x0600_4000, false), enc_mtx(0x0600_5000, false, true, true)]),
            0,
        );
        assert_eq!(cmds[0].detail, "branch addr=0x06004000");
        assert!(cmds[0].is_branch() && !cmds[0].is_call());
        assert_eq!(
            cmds[1].detail,
            "projection load push=false addr=0x06005000"
        );
    }

    #[test]
    fn moveword_movemem_texture_geomode_popmtx() {
        let words = [
            (0xDB << 24 | 6 << 16 | 0x00, 0x0600_0000), // MOVEWORD SEGMENT 0
            (0xDC << 24 | 1 << 19 | 0 << 8 | 8, 0x0600_1000), // MOVEMEM VIEWPORT, size 16
            (0xD7 << 24 | 0 << 11 | 0 << 8 | 1 << 1, 0xFFFF_03E0), // TEXTURE
            (0xD9 << 24 | 0xFFFF_FF, 0x0000_0201),       // GEOMETRYMODE
            (0xD8 << 24 | 7 << 19 | 2, 128),            // POPMTX n=2
        ];
        let cmds = annotate(&words_to_bytes(&words), 0);
        assert_eq!(
            names(&cmds),
            [
                "G_MOVEWORD",
                "G_MOVEMEM",
                "G_TEXTURE",
                "G_GEOMETRYMODE",
                "G_POPMTX",
            ]
        );
        assert_eq!(
            cmds[0].detail,
            "SEGMENT(0x06) offset=0x0000 data=0x06000000"
        );
        assert_eq!(
            cmds[1].detail,
            "VIEWPORT(0x08) offset=0 size=16 addr=0x06001000"
        );
        assert_eq!(cmds[2].detail, "level=0 tile=0 on=1 s=0xffff t=0x03e0");
        assert_eq!(cmds[3].detail, "clear=0x000000 set=0x00000201");
        assert_eq!(cmds[4].detail, "n=2 bytes=128");
    }

    #[test]
    fn culldl_modifyvtx_branchz_dma_loaducode_setothermode() {
        let words = [
            (0x03 << 24 | 0, 8),                        // CULLDL v0=0 vn=4
            (0x02 << 24 | 0x10 << 16 | 4, 0xFF00_0000), // MODIFYVTX vtx=2
            (0x04 << 24 | (3 * 5) << 12 | 3 * 2, 0x1234), // BRANCH_Z vtx=3
            (0xD6 << 24 | 1 << 23 | 2 << 13 | 15, 0x0600_6000), // DMA_IO write
            (0xDD << 24 | 0x7FF, 0x0400_1000),           // LOAD_UCODE
            (0xE2 << 24 | 4 << 8 | 15, 0x0050_0000),     // SETOTHERMODE_L
        ];
        let cmds = annotate(&words_to_bytes(&words), 0);
        assert_eq!(
            names(&cmds),
            [
                "G_CULLDL",
                "G_MODIFYVTX",
                "G_BRANCH_Z",
                "G_DMA_IO",
                "G_LOAD_UCODE",
                "G_SETOTHERMODE_L",
            ]
        );
        assert_eq!(cmds[0].detail, "v0=0 vn=4");
        assert_eq!(cmds[1].detail, "vtx=2 where=0x10 val=0xff000000");
        assert_eq!(cmds[2].detail, "vtx*5=15 vtx*2=6 w1=0x00001234");
        assert_eq!(
            cmds[3].detail,
            "write dmem=0x10 dram=0x06006000 size=16"
        );
        assert_eq!(cmds[4].detail, "size=2048 addr=0x04001000");
        assert_eq!(cmds[5].detail, "shift=12 len=16 data=0x00500000");
    }

    #[test]
    fn rdp_commands_named_with_raw_words() {
        let cmds = annotate(&words_to_bytes(&[(0xFC << 24, 0x1234_5678)]), 0);
        assert_eq!(cmds[0].name, "G_SETCOMBINE");
        assert_eq!(cmds[0].detail, "w0=0xfc000000 w1=0x12345678");
    }

    #[test]
    fn unknown_opcode_keeps_boundaries() {
        let words = [(0x42 << 24 | 0x11_2233, 0x4455_6677), enc_enddl()];
        let cmds = annotate(&words_to_bytes(&words), 0x1000);
        assert_eq!(names(&cmds), ["UNKNOWN", "G_ENDDL"]);
        assert_eq!(cmds[0].offset, 0);
        assert_eq!(cmds[1].offset, 8);
        assert_eq!(cmds[1].vaddr, 0x1008);
    }

    #[test]
    fn truncated_tail_ignored() {
        let mut bytes = words_to_bytes(&[enc_enddl()]);
        bytes.extend_from_slice(&[0xDE, 0x00, 0x11]); // 3 stray bytes
        let cmds = annotate(&bytes, 0);
        assert_eq!(names(&cmds), ["G_ENDDL"]);
        assert!(annotate(&[], 0).is_empty());
    }

    #[test]
    fn opcode_table_fully_covered() {
        // Every documented F3DEX2 + RDP opcode resolves to its name.
        let table: &[(u8, &str)] = &[
            (0x00, "G_NOOP"),
            (0x01, "G_VTX"),
            (0x02, "G_MODIFYVTX"),
            (0x03, "G_CULLDL"),
            (0x04, "G_BRANCH_Z"),
            (0x05, "G_TRI1"),
            (0x06, "G_TRI2"),
            (0x07, "G_QUAD"),
            (0x08, "G_LINE3D"),
            (0xD3, "G_SPECIAL_3"),
            (0xD4, "G_SPECIAL_2"),
            (0xD5, "G_SPECIAL_1"),
            (0xD6, "G_DMA_IO"),
            (0xD7, "G_TEXTURE"),
            (0xD8, "G_POPMTX"),
            (0xD9, "G_GEOMETRYMODE"),
            (0xDA, "G_MTX"),
            (0xDB, "G_MOVEWORD"),
            (0xDC, "G_MOVEMEM"),
            (0xDD, "G_LOAD_UCODE"),
            (0xDE, "G_DL"),
            (0xDF, "G_ENDDL"),
            (0xE0, "G_SPNOOP"),
            (0xE1, "G_RDPHALF_1"),
            (0xE2, "G_SETOTHERMODE_L"),
            (0xE3, "G_SETOTHERMODE_H"),
            (0xE4, "G_TEXRECT"),
            (0xE5, "G_TEXRECTFLIP"),
            (0xE6, "G_RDPLOADSYNC"),
            (0xE7, "G_RDPPIPESYNC"),
            (0xE8, "G_RDPTILESYNC"),
            (0xE9, "G_RDPFULLSYNC"),
            (0xEA, "G_SETKEYGB"),
            (0xEB, "G_SETKEYR"),
            (0xEC, "G_SETCONVERT"),
            (0xED, "G_SETSCISSOR"),
            (0xEE, "G_SETPRIMDEPTH"),
            (0xEF, "G_RDPSETOTHERMODE"),
            (0xF0, "G_LOADTLUT"),
            (0xF1, "G_RDPHALF_2"),
            (0xF2, "G_SETTILESIZE"),
            (0xF3, "G_LOADBLOCK"),
            (0xF4, "G_LOADTILE"),
            (0xF5, "G_SETTILE"),
            (0xF6, "G_FILLRECT"),
            (0xF7, "G_SETFILLCOLOR"),
            (0xF8, "G_SETFOGCOLOR"),
            (0xF9, "G_SETBLENDCOLOR"),
            (0xFA, "G_SETPRIMCOLOR"),
            (0xFB, "G_SETENVCOLOR"),
            (0xFC, "G_SETCOMBINE"),
            (0xFD, "G_SETTIMG"),
            (0xFE, "G_SETZIMG"),
            (0xFF, "G_SETCIMG"),
        ];
        assert_eq!(table.len(), 9 + 17 + 28);
        for &(op, name) in table {
            assert_eq!(op_name(op), Some(name), "opcode {op:#04x}");
        }
        // Reserved gaps stay unknown but boundary-correct.
        for op in [0x09u8, 0x42, 0xD2] {
            assert_eq!(op_name(op), None, "opcode {op:#04x}");
        }
    }
}
