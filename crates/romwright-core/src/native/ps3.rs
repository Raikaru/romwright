//! PlayStation 3 SELF/SPRX containers (PPU = 64-bit big-endian PowerPC).
//!
//! A PS3 executable ships as a SELF ("Signed ELF"): an `SCE` header plus an
//! extended header locating the embedded ELF's own headers and a map of its
//! sections inside the file. SPRX modules are the same container holding a
//! relocatable PPU ELF, which may embed standalone SPU (Cell synergistic
//! processor) ELF32 images as data. Layout and crypto facts below are a
//! clean-room port of documented behavior only — no code is copied — from:
//!
//! - fail0verflow ps3tools `unself.c` (Sven Peter, 2010): the SCE header
//!   field order, the `key_ver == 0x8000` plaintext rule, the `app_type`
//!   numbering (1 LV0, 2 LV1, 3 LV2, 4 APP, 5 ISO, 6 LDR, 8 NPDRM), the
//!   segment-map entry shape (`Self_PMhdr`: offset/size/compressed at
//!   +0x10/encrypted at +0x1c, stride 0x20), and the raw section reassembly
//!   (`read_sections` / `write_elf` / `check_elf`).
//! - RPCS3 `rpcs3/Crypto/unself.{h,cpp}`: the extended-header field order,
//!   the `MetadataInfo` / `MetadataHeader` / `MetadataSectionHeader`
//!   structs, the metadata chain (AES-256-CBC unwrap of the metadata info
//!   unless the 0x8000 DEBUG flag is set, AES-128-CTR decode of the metadata
//!   headers with the file's own key/iv, per-section AES-128-CTR with the
//!   vault's key/iv at `key_idx`/`iv_idx` for sections whose `encrypted`
//!   field is 3), the `WriteElf` reassembly (ehdr, then phdrs, then each
//!   type-2 section at its program header's `p_offset`), and
//!   `ET_SCE_PPURELEXEC` (0xFFA4, the PPU relocatable SPRX marker).
//! - PSL1GHT `tools/geohot/include/self.h`: the `Self_Shdr` / `Self_Ehdr`
//!   cross-check (extended header version 3, info/ELF/phdr/shdr/phdr-map
//!   offsets in that order).
//! - RPCS3 `rpcs3/Crypto/key_vault.cpp` (`KeyVault::LoadSelfAPPKeys`): the
//!   public per-revision APP vault keys (AES-256 `erk` + `riv`) the metadata
//!   unwrap tries in turn; the zero `key_pad`/`iv_pad` bytes are the oracle
//!   that says which revision key fits.
//!
//! Container integers are big-endian. All header offsets below are absolute
//! file offsets except where noted:
//!
//! ```text
//! 0x00  SCE header (32 bytes): magic u32, version u32, flags u16,
//!       type u16, metadata_offset u32, header_len u64, data_len u64.
//! 0x20  extended header (80 bytes): version u64, app_info u64, elf u64,
//!       phdr u64, shdr u64, segment_map u64, sce_version u64,
//!       control_info u64, control_size u64, padding u64.
//! ```
//!
//! Magic: retail headers carry `"SCE\0"` (0x53434500 — every tool above
//! checks exactly that). The harness contract additionally names an
//! `"SCE\x04"` variant, so both fourth bytes are accepted and everything
//! else is validated structurally (offsets in bounds, `\x7fELF` at the
//! named ELF offset — the embedded ELF header is stored plaintext even in
//! encrypted files, which is what lets `is_sprx` read its `e_type`).
//!
//! Encrypted sections need their revision's vault key; files whose metadata
//! unwraps with none of the embedded public keys (firmware newer than the
//! published vault, or an NPDRM title needing its per-title RAP license)
//! are reported as recognized-but-unreadable rather than misparsed.
//! zlib-compressed sections (flag 2) are likewise refused: the workspace
//! carries no inflate implementation, so reassembly would be guesswork.

use super::crypto::aes128_ctr;
use super::{err, NativeImport, Result};
use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::{Aes128, Aes256};

/// Ghidra language for the PPU image (task contract, not the install
/// opinion: the install would answer `PowerPC:BE:64:default`).
const PPU_LANGUAGE: &str = "PowerPC:BE:64:64-32addr";
/// Ghidra language for embedded SPU images (matches `opinion.rs`: machine
/// 23, big-endian → `SPU:BE:128:default`).
const SPU_LANGUAGE: &str = "SPU:BE:128:default";

/// SCE PPU relocatable executable: the `e_type` a decrypted SPRX carries
/// (RPCS3 `unself.h`).
const ET_SCE_PPURELEXEC: u16 = 0xFFA4;
/// SCE relocatable executable marker, accepted as SPRX alongside the PPU one.
const ET_SCE_RELEXEC: u16 = 0xFE04;
/// Plain shared-object `e_type`, likewise module-shaped.
const ET_DYN: u16 = 3;

/// `EM_PPC64`: the PPU machine.
const EM_PPC64: u16 = 21;
/// `EM_SPU`: the Cell SPU machine.
const EM_SPU: u16 = 23;

/// `app_type` of a plain application SELF (fail0verflow `unself.c`).
const APP_TYPE_APP: u32 = 4;
/// `app_type` of an NPDRM SELF: needs its per-title RAP license, supplied
/// by the user via `--keys` (`import_with`); without one the title reports
/// the key gap instead of decrypting.
const APP_TYPE_NPDRM: u32 = 8;

/// DEBUG/fSELF flag in the SCE flags halfword: the metadata info is stored
/// plaintext and sections are stored raw (fail0verflow skips `self_decrypt`
/// entirely, RPCS3 skips the metadata-info CBC layer).
const FLAG_DEBUG: u16 = 0x8000;

/// Metadata sections with `encrypted == 3` are AES-128-CTR ciphertext
/// (RPCS3 `SCEDecrypter::DecryptData`).
const META_ENCRYPTED: u32 = 3;
/// Metadata sections with `compressed == 2` are zlib streams (RPCS3
/// `WriteElf`); anything else is stored raw.
const META_COMPRESSED_ZLIB: u32 = 2;
/// Metadata sections with `type == 2` are program data: the payload for
/// `phdrs[program_idx]`.
const META_TYPE_PROGRAM: u32 = 2;

/// Segment-map entries with `compressed == 2` are zlib streams.
const SEG_COMPRESSED_ZLIB: u32 = 2;

/// Sanity caps so a corrupt header cannot balloon an allocation.
const MAX_PHNUM: usize = 64;
const MAX_SHNUM: usize = 2048;
const MAX_META_SECTIONS: usize = 256;
const MAX_META_KEYS: usize = 256;
const MAX_OUT: usize = 1 << 29; // 512 MiB reassembled ELF
const MAX_SPU_IMAGES: usize = 8;

// ---------------------------------------------------------------- readers

fn be16(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| super::ImportError::Bad("SELF header truncated".into()))
}

fn be32(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| super::ImportError::Bad("SELF header truncated".into()))
}

fn be64(data: &[u8], off: usize) -> Result<u64> {
    data.get(off..off + 8)
        .map(|s| u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| super::ImportError::Bad("SELF header truncated".into()))
}

fn u16e(data: &[u8], off: usize, be: bool) -> Result<u16> {
    data.get(off..off + 2)
        .map(|s| {
            if be {
                u16::from_be_bytes([s[0], s[1]])
            } else {
                u16::from_le_bytes([s[0], s[1]])
            }
        })
        .ok_or_else(|| super::ImportError::Bad("SELF ELF header truncated".into()))
}

fn u64e(data: &[u8], off: usize, be: bool) -> Result<u64> {
    data.get(off..off + 8)
        .map(|s| {
            if be {
                u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
            } else {
                u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
            }
        })
        .ok_or_else(|| super::ImportError::Bad("SELF ELF header truncated".into()))
}

/// A `u64` file offset plus `need` bytes, as a bounded `usize`.
fn bounded(data: &[u8], offset: u64, need: usize, what: &str) -> Result<usize> {
    let off = usize::try_from(offset)
        .ok()
        .filter(|o| o.checked_add(need).is_some_and(|end| end <= data.len()))
        .ok_or_else(|| super::ImportError::Bad(format!("SELF {what} outside file")))?;
    Ok(off)
}

// ---------------------------------------------------------------- headers

/// The 32-byte SCE header (fail0verflow `read_header` field order).
struct Sce {
    flags: u16,
    meta: u32,
    hsize: u64,
    esize: u64,
}

/// The extended header at file offset 0x20 (RPCS3 `ext_hdr`; only the
/// offsets this loader reads are kept).
struct Ext {
    app_info: u64,
    ehdr: u64,
    phdr: u64,
    shdr: u64,
    seg: u64,
}

/// The embedded ELF header's shape fields, in its own endianness.
struct ElfHead {
    class64: bool,
    machine: u16,
    phnum: usize,
    phentsize: usize,
    shnum: usize,
    shentsize: usize,
    ehsize: usize,
    shoff: u64,
}

fn parse_headers(data: &[u8]) -> Result<(Sce, Ext)> {
    if data.len() < 0x70 {
        return err("SELF header truncated");
    }
    let sce = Sce {
        flags: be16(data, 0x08)?,
        meta: be32(data, 0x0c)?,
        hsize: be64(data, 0x10)?,
        esize: be64(data, 0x18)?,
    };
    let ext = Ext {
        app_info: be64(data, 0x28)?,
        ehdr: be64(data, 0x30)?,
        phdr: be64(data, 0x38)?,
        shdr: be64(data, 0x40)?,
        seg: be64(data, 0x48)?,
    };
    Ok((sce, ext))
}

/// `(app_type, sceversion)` from the program-identification header
/// (fail0verflow: type at +0x0c, version at +0x10). Absent (offset zero)
/// means unknown: `(0, 0)`.
fn app_info(data: &[u8], ext: &Ext) -> Result<(u32, u64)> {
    if ext.app_info == 0 {
        return Ok((0, 0));
    }
    let at = bounded(data, ext.app_info, 24, "app info")?;
    Ok((be32(data, at + 0x0c)?, be64(data, at + 0x10)?))
}

fn elf_head(data: &[u8], off: usize) -> Result<ElfHead> {
    let hdr = data
        .get(off..off + 64)
        .ok_or_else(|| super::ImportError::Bad("SELF ELF header outside file".into()))?;
    if hdr[0..4] != *b"\x7fELF" {
        return err("SELF names bytes that are not an ELF header");
    }
    let class64 = match hdr[4] {
        1 => false,
        2 => true,
        _ => return err("SELF ELF has an unknown class"),
    };
    let be = match hdr[5] {
        1 => false,
        2 => true,
        _ => return err("SELF ELF has unknown data encoding"),
    };
    // e_ehsize is fixed per class (52 / 64); anything else is not an ELF
    // header this loader can place.
    let (phnum, phentsize, shnum, shentsize, ehsize, shoff) = if class64 {
        (
            u16e(data, off + 56, be)? as usize,
            u16e(data, off + 54, be)? as usize,
            u16e(data, off + 60, be)? as usize,
            u16e(data, off + 58, be)? as usize,
            u16e(data, off + 52, be)? as usize,
            u64e(data, off + 40, be)?,
        )
    } else {
        (
            u16e(data, off + 44, be)? as usize,
            u16e(data, off + 42, be)? as usize,
            u16e(data, off + 48, be)? as usize,
            u16e(data, off + 46, be)? as usize,
            u16e(data, off + 40, be)? as usize,
            u64e(data, off + 32, be)?,
        )
    };
    if ehsize != if class64 { 64 } else { 52 } {
        return err("SELF ELF header size is not its class size");
    }
    Ok(ElfHead {
        class64,
        machine: u16e(data, off + 18, be)?,
        phnum,
        phentsize,
        shnum,
        shentsize,
        ehsize,
        shoff,
    })
}

// ---------------------------------------------------------------- detectors

/// True for the SCE container family: `"SCE\0"` (retail, checked by every
/// reference tool) and the `"SCE\x04"` harness variant. Anything deeper is
/// `import`'s job to validate.
pub(crate) fn is_self(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == 0x53
        && data[1] == 0x43
        && data[2] == 0x45
        && (data[3] == 0x00 || data[3] == 0x04)
}

/// The embedded ELF header's `e_type`, when it is readable.
fn inner_etype(data: &[u8]) -> Option<u16> {
    let (_, ext) = parse_headers(data).ok()?;
    let off = usize::try_from(ext.ehdr).ok()?;
    let bytes = data.get(off..off + 20)?;
    if bytes[0..4] != *b"\x7fELF" {
        return None;
    }
    let be = match bytes[5] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let raw = [bytes[16], bytes[17]];
    Some(if be {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    })
}

/// True when the SELF wraps a relocatable module (SPRX): a PPU relocatable,
/// a generic SCE relocatable, or a shared object.
pub(crate) fn is_sprx(data: &[u8]) -> bool {
    match inner_etype(data) {
        Some(t) => t == ET_SCE_PPURELEXEC || t == ET_SCE_RELEXEC || t == ET_DYN,
        None => false,
    }
}

// ---------------------------------------------------------------- metadata crypto

/// One metadata section header: 48 bytes (RPCS3 `MetadataSectionHeader`).
struct MetaSection {
    offset: u64,
    size: u64,
    typ: u32,
    prog: u32,
    encrypted: u32,
    key_idx: usize,
    iv_idx: usize,
    compressed: u32,
}

/// Unwrapped metadata: the section map plus the section key vault
/// (`key_count` 16-byte entries back to back).
struct Meta {
    sections: Vec<MetaSection>,
    keys: Vec<u8>,
}

fn hex_val(h: u8) -> Option<u8> {
    match h {
        b'0'..=b'9' => Some(h - b'0'),
        b'a'..=b'f' => Some(h - b'a' + 10),
        b'A'..=b'F' => Some(h - b'A' + 10),
        _ => None,
    }
}

fn hex_arr<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = hex_val(b[i * 2])? << 4 | hex_val(b[i * 2 + 1])?;
    }
    Some(out)
}

/// Public APP vault keys: `(version_start, version_end, erk_hex, riv_hex)`
/// from RPCS3 `KeyVault::LoadSelfAPPKeys` (`rpcs3/Crypto/key_vault.cpp`).
/// `erk` is the AES-256 metadata key, `riv` its CBC IV.
const APP_KEYS: &[(u64, u64, &str, &str)] = &[
    (0x0000009200000000, 0x0000009200000000, "95F50019E7A68E341FA72EFDF4D60ED376E25CF46BB48DFDD1F080259DC93F04", "4A0955D946DB70D691A640BB7FAECC4C"),
    (0x0003003000000000, 0x0003003000000000, "79481839C406A632BDB4AC093D73D99AE1587F24CE7E69192C1CD0010274A8AB", "6F0F25E1C8C4B7AE70DF968B04521DDA"),
    (0x0003003000000000, 0x0003003000000000, "4F89BE98DDD43CAD343F5BA6B1A133B0A971566F770484AAC20B5DD1DC9FA06A", "90C127A9B43BA9D8E89FE6529E25206F"),
    (0x0003003000000000, 0x0003003000000000, "C1E6A351FCED6A0636BFCB6801A0942DB7C28BDFC5E0A053A3F52F52FCE9754E", "E0908163F457576440466ACAA443AE7C"),
    (0x0003004200000000, 0x0003004200000000, "838F5860CF97CDAD75B399CA44F4C214CDF951AC795298D71DF3C3B7E93AAEDA", "7FDBB2E924D182BB0D69844ADC4ECA5B"),
    (0x0003004200000000, 0x0003004200000000, "C109AB56593DE5BE8BA190578E7D8109346E86A11088B42C727E2B793FD64BDC", "15D3F191295C94B09B71EBDE088A187A"),
    (0x0003004200000000, 0x0003004200000000, "6DFD7AFB470D2B2C955AB22264B1FF3C67F180983B26C01615DE9F2ECCBE7F41", "24BD1C19D2A8286B8ACE39E4A37801C2"),
    (0x0003005000000000, 0x0003005000000000, "945B99C0E69CAF0558C588B95FF41B232660ECB017741F3218C12F9DFDEEDE55", "1D5EFBE7C5D34AD60F9FBC46A5977FCE"),
    (0x0003005000000000, 0x0003005000000000, "2C9E8969EC44DFB6A8771DC7F7FDFBCCAF329EC3EC070900CABB23742A9A6E13", "5A4CEFD5A9C3C093D0B9352376D19405"),
    (0x0003005000000000, 0x0003005000000000, "F69E4A2934F114D89F386CE766388366CDD210F1D8913E3B973257F1201D632B", "F4D535069301EE888CC2A852DB654461"),
    (0x0003005500000000, 0x0003005500000000, "29805302E7C92F204009161CA93F776A072141A8C46A108E571C46D473A176A3", "5D1FAB844107676ABCDFC25EAEBCB633"),
    (0x0003005500000000, 0x0003005500000000, "A4C97402CC8A71BC7748661FE9CE7DF44DCE95D0D58938A59F47B9E9DBA7BFC3", "E4792F2B9DB30CB8D1596077A13FB3B5"),
    (0x0003005500000000, 0x0003005500000000, "9814EFFF67B7074D1B263BF85BDC8576CE9DEC914123971B169472A1BC2387FA", "D43B1FA8BE15714B3078C23908BB2BCA"),
    (0x0003005600000000, 0x0003005600000000, "03B4C421E0C0DE708C0F0B71C24E3EE04306AE7383D8C5621394CCB99FF7A194", "5ADB9EAFE897B54CB1060D6885BE22CF"),
    (0x0003005600000000, 0x0003005600000000, "39A870173C226EB8A3EEE9CA6FB675E82039B2D0CCB22653BFCE4DB013BAEA03", "90266C98CBAA06C1BF145FF760EA1B45"),
    (0x0003005600000000, 0x0003005600000000, "FD52DFA7C6EEF5679628D12E267AA863B9365E6DB95470949CFD235B3FCA0F3B", "64F50296CF8CF49CD7C643572887DA0B"),
    (0x0003006100000000, 0x0003006100000000, "A5E51AD8F32FFBDE808972ACEE46397F2D3FE6BC823C8218EF875EE3A9B0584F", "7A203D5112F799979DF0E1B8B5B52AA4"),
    (0x0003006100000000, 0x0003006100000000, "0F8EAB8884A51D092D7250597388E3B8B75444AC138B9D36E5C7C5B8C3DF18FD", "97AF39C383E7EF1C98FA447C597EA8FE"),
    (0x0003006600000000, 0x0003006600000000, "DBF62D76FC81C8AC92372A9D631DDC9219F152C59C4B20BFF8F96B64AB065E94", "CB5DD4BE8CF115FFB25801BC6086E729"),
    (0x0003006600000000, 0x0003006600000000, "491B0D72BB21ED115950379F4564CE784A4BFAABB00E8CB71294B192B7B9F88E", "F98843588FED8B0E62D7DDCB6F0CECF4"),
    (0x0003007400000000, 0x0003007400000000, "A106692224F1E91E1C4EBAD4A25FBFF66B4B13E88D878E8CD072F23CD1C5BF7C", "62773C70BD749269C0AFD1F12E73909E"),
    (0x0003007400000000, 0x0003007400000000, "4E104DCE09BA878C75DA98D0B1636F0E5F058328D81419E2A3D22AB0256FDF46", "954A86C4629E116532304A740862EF85"),
    (0x0003007400000000, 0x0003007400000000, "1F876AB252DDBCB70E74DC4A20CD8ED51E330E62490E652F862877E8D8D0F997", "BF8D6B1887FA88E6D85C2EDB2FBEC147"),
    (0x0004001100000000, 0x0004001100000000, "3236B9937174DF1DC12EC2DD8A318A0EA4D3ECDEA5DFB4AC1B8278447000C297", "6153DEE781B8ADDC6A439498B816DC46"),
    (0x0004001100000000, 0x0004001100000000, "5EFD1E9961462794E3B9EF2A4D0C1F46F642AAE053B5025504130590E66F19C9", "1AC8FA3B3C90F8FDE639515F91B58327"),
    (0x0004001100000000, 0x0004001100000000, "66637570D1DEC098467DB207BAEA786861964D0964D4DBAF89E76F46955D181B", "9F7B5713A5ED59F6B35CD8F8A165D4B8"),
    (0x0004004600000000, 0x0004004600000000, "CFF025375BA0079226BE01F4A31F346D79F62CFB643CA910E16CF60BD9092752", "FD40664E2EBBA01BF359B0DCDF543DA4"),
    (0x0004004600000000, 0x0004004600000000, "D202174EB65A62048F3674B59EF6FE72E1872962F3E1CD658DE8D7AF71DA1F3E", "ACB9945914EBB7B9A31ECE320AE09F2D"),
];

/// Parsed vault keys, version-range matches first (mirrors
/// `KeyVault::FindSelfKey`'s version preference; every candidate is still
/// tried, since the pads — not the range — are the real oracle).
fn ordered_vault(sceversion: u64) -> Vec<([u8; 32], [u8; 16])> {
    let mut matching = Vec::new();
    let mut rest = Vec::new();
    for (start, end, erk_hex, riv_hex) in APP_KEYS {
        let (Some(erk), Some(riv)) = (hex_arr(erk_hex), hex_arr(riv_hex)) else {
            continue;
        };
        if sceversion != 0 && *start <= sceversion && sceversion <= *end {
            matching.push((erk, riv));
        } else {
            rest.push((erk, riv));
        }
    }
    matching.append(&mut rest);
    matching
}

/// AES-256-CBC decrypt in place (the metadata-info layer). The vault `riv`
/// seeds the chain, XEX-style.
fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    if data.is_empty() || data.len() % 16 != 0 {
        return err("SELF metadata info is not a whole number of blocks");
    }
    let cipher = Aes256::new(key.into());
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let cipher_block = block;
        cipher.decrypt_block((&mut block).into());
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        chunk.copy_from_slice(&block);
        prev = cipher_block;
    }
    Ok(())
}
/// Public NPDRM license constants from RPCS3 `key_vault.h` (the same openly
/// published research as `APP_KEYS` above): `RAP_KEY`/`RAP_PBOX`/`RAP_E1`/
/// `RAP_E2` drive `rap_to_rif`, and `NP_KLIC_KEY` unwraps its output the way
/// `SELFDecrypter::DecryptNPDRM` does before the vault unwrap below.
const RAP_KEY: [u8; 16] = [
    0x86, 0x9F, 0x77, 0x45, 0xC1, 0x3F, 0xD8, 0x90, 0xCC, 0xF2, 0x91, 0x88, 0xE3, 0xCC, 0x3E, 0xDF,
];
const RAP_PBOX: [u8; 16] = [
    0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09,
];
const RAP_E1: [u8; 16] = [
    0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29, 0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5,
];
const RAP_E2: [u8; 16] = [
    0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A, 0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74,
];
const NP_KLIC_KEY: [u8; 16] = [
    0xF2, 0xFB, 0xCA, 0x7A, 0x75, 0xB0, 0x4E, 0xDC, 0x13, 0x90, 0x63, 0x8C, 0xCD, 0xFD, 0xD1, 0xEE,
];
/// The NPDRM metadata layer uses a zero IV (RPCS3 `DecryptNPDRM`).
const NPDRM_ZERO_IV: [u8; 16] = [0u8; 16];

/// AES-128-CBC decrypt in place (the NPDRM metadata layer wrapped around
/// the AES-256 vault unwrap for per-title keys).
fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    if data.is_empty() || data.len() % 16 != 0 {
        return err("SELF metadata info is not a whole number of blocks");
    }
    let cipher = Aes128::new(key.into());
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let cipher_block = block;
        cipher.decrypt_block((&mut block).into());
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        chunk.copy_from_slice(&block);
        prev = cipher_block;
    }
    Ok(())
}

/// Converts a 16-byte user RAP license into the per-title intermediate key
/// (RPCS3 `rap_to_rif` in `key_vault.cpp`: AES-128 decrypt with the public
/// `RAP_KEY` under a zero IV, then five `RAP_PBOX`/`RAP_E1`/`RAP_E2`
/// rounds).
fn rap_to_rif(rap: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new((&RAP_KEY).into());
    // Single-block CBC decrypt under a zero IV: the IV XOR is a no-op.
    let mut key = *rap;
    cipher.decrypt_block((&mut key).into());
    for _ in 0..5 {
        for i in 0..16 {
            let p = RAP_PBOX[i] as usize;
            key[p] ^= RAP_E1[p];
        }
        for i in (1..16).rev() {
            let p = RAP_PBOX[i] as usize;
            let pp = RAP_PBOX[i - 1] as usize;
            key[p] ^= key[pp];
        }
        let mut o: u8 = 0;
        for i in 0..16 {
            let p = RAP_PBOX[i] as usize;
            let kc = key[p].wrapping_sub(o);
            let ec2 = RAP_E2[p];
            if o != 1 || kc != 0xFF {
                o = u8::from(kc < ec2);
                key[p] = kc.wrapping_sub(ec2);
            } else if kc == 0xFF {
                key[p] = kc.wrapping_sub(ec2);
            } else {
                key[p] = kc;
            }
        }
    }
    key
}

/// Unwraps the `rap_to_rif` output into the content key that decrypts an
/// NPDRM title's metadata layer (RPCS3 `SELFDecrypter::DecryptNPDRM`:
/// one AES-128-ECB decrypt with the public `NP_KLIC_KEY`).
fn npdrm_content_key(rap: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new((&NP_KLIC_KEY).into());
    let mut key = rap_to_rif(rap);
    cipher.decrypt_block((&mut key).into());
    key
}

/// Every 16-byte RAP the user supplied: the named `rap` entry (a
/// `rap = hex` line in a text dump) plus any raw 16-byte key file (a `.rap`
/// license is the key itself), de-duplicated. A RAP is matched to its title
/// by decryption succeeding, not by name.
fn rap_candidates(keys: &super::keys::KeyStore) -> Vec<[u8; 16]> {
    let mut out = Vec::new();
    if let Some(rap) = keys.get_array::<16>("rap") {
        out.push(rap);
    }
    for (_, raw) in keys.raw_keys() {
        if let Ok(bytes) = <[u8; 16]>::try_from(raw.as_slice()) {
            if !out.contains(&bytes) {
                out.push(bytes);
            }
        }
    }
    out
}

/// Tries every public vault key against the zero-pad oracle; `Some` is the
/// unwrapped metadata info when one fits.
fn try_vault_unwrap(info: &[u8], sceversion: u64) -> Option<Vec<u8>> {
    for (erk, riv) in ordered_vault(sceversion) {
        let mut candidate = info.to_vec();
        // `info` is always exactly 64 bytes, so a block-length error here
        // is impossible; skip rather than abort if it ever misbehaves.
        if aes256_cbc_decrypt(&erk, &riv, &mut candidate).is_err() {
            continue;
        }
        if candidate[0x10..0x20].iter().all(|b| *b == 0)
            && candidate[0x30..0x40].iter().all(|b| *b == 0)
        {
            return Some(candidate);
        }
    }
    None
}

/// Unwraps the file's metadata: reads the 64-byte info at
/// `meta + sizeof(SCE header)`, decrypts it unless the DEBUG flag says it
/// is plaintext, validates the pads, CTR-decodes the headers with the
/// file's own key/iv, and parses the section map plus key vault
/// (RPCS3 `SCEDecrypter::LoadMetadata`). NPDRM titles (`app_type` 8) wrap
/// that decrypt in a per-title AES-128-CBC layer keyed by the user's RAP
/// license, peeled first (RPCS3 `SELFDecrypter::DecryptNPDRM` runs before
/// the vault unwrap).
fn load_metadata(
    data: &[u8],
    sce: &Sce,
    sceversion: u64,
    keys: &super::keys::KeyStore,
    app_type: u32,
) -> Result<Meta> {
    let meta_off = usize::try_from(sce.meta).unwrap_or(usize::MAX);
    let hsize = usize::try_from(sce.hsize).unwrap_or(0);
    let info_off = meta_off
        .checked_add(0x20)
        .ok_or_else(|| super::ImportError::Bad("SELF metadata offset overflow".into()))?;
    let hdrs_off = meta_off
        .checked_add(0x60)
        .ok_or_else(|| super::ImportError::Bad("SELF metadata offset overflow".into()))?;
    if hdrs_off > hsize || hsize > data.len() || info_off.checked_add(64).is_none_or(|e| e > data.len()) {
        return err("SELF metadata outside file");
    }
    let mut info = data[info_off..info_off + 64].to_vec();
    if sce.flags & FLAG_DEBUG == 0 {
        if app_type == APP_TYPE_NPDRM {
            // Peel one candidate RAP layer, then let the vault oracle decide:
            // the gate in `import_self_with` guarantees a candidate exists.
            let mut opened = None;
            for rap in rap_candidates(keys) {
                let content_key = npdrm_content_key(&rap);
                let mut candidate = info.clone();
                if aes128_cbc_decrypt(&content_key, &NPDRM_ZERO_IV, &mut candidate).is_err() {
                    continue;
                }
                if let Some(unwrapped) = try_vault_unwrap(&candidate, sceversion) {
                    opened = Some(unwrapped);
                    break;
                }
            }
            info = opened.ok_or_else(|| {
                super::ImportError::Bad(
                    "NPDRM SELF metadata did not unwrap with the supplied RAP \
                     (wrong title's license?) — supply the title's .rap via --keys"
                        .into(),
                )
            })?;
        } else if let Some(unwrapped) = try_vault_unwrap(&info, sceversion) {
            info = unwrapped;
        } else {
            return err("SELF is encrypted and no public APP vault key unwrapped its metadata (firmware too new or NPDRM title)");
        }
    }
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&info[0..0x10]);
    iv.copy_from_slice(&info[0x20..0x30]);

    // The metadata headers are CTR-coded with the file's own key/iv from
    // block zero — the same counter convention as mbedtls, which
    // `aes128_ctr` shares (big-endian 128-bit increment from the IV).
    let mut headers = data[hdrs_off..hsize].to_vec();
    aes128_ctr(&key, &iv, &mut headers);
    if headers.len() < 32 {
        return err("SELF metadata headers truncated");
    }
    let rd32 = |o: usize| u32::from_be_bytes([headers[o], headers[o + 1], headers[o + 2], headers[o + 3]]);
    let section_count = rd32(12) as usize;
    let key_count = rd32(16) as usize;
    if section_count > MAX_META_SECTIONS || key_count > MAX_META_KEYS {
        return err("SELF metadata counts implausible");
    }
    let need = 32usize + section_count * 48 + key_count * 16;
    if need > headers.len() {
        return err("SELF metadata headers truncated");
    }
    let mut sections = Vec::with_capacity(section_count);
    for i in 0..section_count {
        let o = 32 + i * 48;
        let rd64 = |p: usize| {
            u64::from_be_bytes([
                headers[o + p],
                headers[o + p + 1],
                headers[o + p + 2],
                headers[o + p + 3],
                headers[o + p + 4],
                headers[o + p + 5],
                headers[o + p + 6],
                headers[o + p + 7],
            ])
        };
        let offset = rd64(0);
        let size = rd64(8);
        bounded(data, offset, usize::try_from(size).unwrap_or(usize::MAX), "section")?;
        sections.push(MetaSection {
            offset,
            size,
            typ: rd32(o + 16),
            prog: rd32(o + 20),
            encrypted: rd32(o + 32),
            key_idx: rd32(o + 36) as usize,
            iv_idx: rd32(o + 40) as usize,
            compressed: rd32(o + 44),
        });
    }
    let keys = headers[32 + section_count * 48..32 + section_count * 48 + key_count * 16].to_vec();
    Ok(Meta { sections, keys })
}

// ---------------------------------------------------------------- rebuild

/// One program header's file placement (`p_offset` is ELF-relative: the
/// output address, per RPCS3 `WriteElf`).
struct Phdr {
    offset: u64,
}

/// The program-header table at the extended header's `phdr` offset
/// (plaintext even in encrypted files: RPCS3 reads it pre-decrypt).
fn read_phdrs(data: &[u8], ext: &Ext, head: &ElfHead) -> Result<(Vec<Phdr>, Vec<u8>)> {
    if head.phnum == 0 || head.phnum > MAX_PHNUM {
        return err("SELF program header count implausible");
    }
    let want = if head.class64 { 56 } else { 32 };
    if head.phentsize < want {
        return err("SELF program header entry too small");
    }
    let at = bounded(data, ext.phdr, head.phnum * head.phentsize, "program headers")?;
    let raw = data[at..at + head.phnum * head.phentsize].to_vec();
    let mut out = Vec::with_capacity(head.phnum);
    for i in 0..head.phnum {
        let o = at + i * head.phentsize;
        let offset = if head.class64 { be64(data, o + 8)? } else { be32(data, o + 4)? as u64 };
        out.push(Phdr { offset });
    }
    Ok((out, raw))
}

/// Writes `bytes` at `offset` in `out`, zero-filling the gap, capped so a
/// corrupt offset cannot balloon the allocation.
fn place(out: &mut Vec<u8>, offset: u64, bytes: &[u8]) -> Result<()> {
    let off = usize::try_from(offset).unwrap_or(MAX_OUT + 1);
    let end = off
        .checked_add(bytes.len())
        .ok_or_else(|| super::ImportError::Bad("SELF payload offset overflow".into()))?;
    if end > MAX_OUT {
        return err("SELF payload address implausible");
    }
    if out.len() < end {
        out.resize(end, 0);
    }
    out[off..end].copy_from_slice(bytes);
    Ok(())
}

/// Reassembles the ELF via the metadata section map: ehdr, then phdrs, then
/// each type-2 section's (decrypted) payload at its program header's
/// `p_offset`, then shdrs (RPCS3 `WriteElf`).
fn rebuild_from_meta(
    data: &[u8],
    ext: &Ext,
    ehdr_off: usize,
    head: &ElfHead,
    meta: &Meta,
) -> Result<Vec<u8>> {
    let (phdrs, table) = read_phdrs(data, ext, head)?;
    let key_count = meta.keys.len() / 16;
    let mut out = Vec::new();
    out.extend_from_slice(&data[ehdr_off..ehdr_off + head.ehsize]);
    out.extend_from_slice(&table);
    for sec in &meta.sections {
        if sec.typ != META_TYPE_PROGRAM {
            continue;
        }
        let prog = sec.prog as usize;
        if prog >= phdrs.len() {
            return err("SELF section names a missing program header");
        }
        let size = usize::try_from(sec.size).unwrap_or(usize::MAX);
        let off = bounded(data, sec.offset, size, "section")?;
        let payload = &data[off..off + size];
        let plain;
        let bytes = if sec.encrypted == META_ENCRYPTED {
            if sec.key_idx >= key_count || sec.iv_idx >= key_count {
                return err("SELF section names a missing vault key");
            }
            let mut key = [0u8; 16];
            let mut iv = [0u8; 16];
            key.copy_from_slice(&meta.keys[sec.key_idx * 16..sec.key_idx * 16 + 16]);
            iv.copy_from_slice(&meta.keys[sec.iv_idx * 16..sec.iv_idx * 16 + 16]);
            let mut buf = payload.to_vec();
            aes128_ctr(&key, &iv, &mut buf);
            plain = buf;
            &plain
        } else {
            payload
        };
        if sec.compressed == META_COMPRESSED_ZLIB {
            return err("SELF section is zlib-compressed — extract the ELF with unself/scetool first");
        }
        place(&mut out, phdrs[prog].offset, bytes)?;
    }
    if ext.shdr != 0 && head.shnum > 0 {
        if head.shnum > MAX_SHNUM {
            return err("SELF section header count implausible");
        }
        let want = if head.class64 { 64 } else { 40 };
        if head.shentsize < want {
            return err("SELF section header entry too small");
        }
        let at = bounded(data, ext.shdr, head.shnum * head.shentsize, "section headers")?;
        place(&mut out, head.shoff, &data[at..at + head.shnum * head.shentsize])?;
    }
    if out.get(0..4) != Some(b"\x7fELF".as_slice()) {
        return err("SELF reassembly lost the ELF header");
    }
    Ok(out)
}

/// Reassembles the ELF via the segment map for files without metadata: the
/// headers-sized prefix is followed by the raw image, copied whole
/// (fail0verflow `read_sections` with no compressed segment degenerates to
/// exactly this single raw section; any zlib segment is refused).
fn rebuild_from_segments(data: &[u8], sce: &Sce, ext: &Ext, head: &ElfHead) -> Result<Vec<u8>> {
    if head.phnum == 0 || head.phnum > MAX_PHNUM {
        return err("SELF program header count implausible");
    }
    let at = bounded(data, ext.seg, head.phnum * 0x20, "segment map")?;
    if sce.flags & FLAG_DEBUG == 0 {
        for i in 0..head.phnum {
            if be32(data, at + i * 0x20 + 0x1c)? != 0 {
                return err("SELF is encrypted and carries no metadata — extract the ELF with unself/scetool first");
            }
        }
    }
    for i in 0..head.phnum {
        if be32(data, at + i * 0x20 + 0x10)? == SEG_COMPRESSED_ZLIB {
            return err("SELF section is zlib-compressed — extract the ELF with unself/scetool first");
        }
    }
    let hsize = usize::try_from(sce.hsize).unwrap_or(usize::MAX);
    let esize = usize::try_from(sce.esize).unwrap_or(0);
    if esize == 0 || esize > MAX_OUT {
        return err("SELF extracted size implausible");
    }
    let end = hsize
        .checked_add(esize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| super::ImportError::Bad("SELF image outside file".into()))?;
    let mut out = data[hsize..end].to_vec();
    if out.get(0..4) != Some(b"\x7fELF".as_slice()) {
        // fail0verflow `check_elf`: the payload lost the headers, so splice
        // the stored copies back in (names intact — unlike unself, nothing
        // here strips them for signing).
        patch_headers(&mut out, data, ext, head)?;
    }
    Ok(out)
}

/// Splices the stored ehdr/phdr/shdr copies over a headerless payload:
/// ehdr (with `e_phoff`/`e_shoff` repointed at the spliced tables), then
/// phdrs, then shdrs.
fn patch_headers(out: &mut Vec<u8>, data: &[u8], ext: &Ext, head: &ElfHead) -> Result<()> {
    let ehdr_off = bounded(data, ext.ehdr, head.ehsize, "ELF header")?;
    let (_, table) = read_phdrs(data, ext, head)?;
    let shdrs = if ext.shdr != 0 && head.shnum > 0 {
        if head.shnum > MAX_SHNUM {
            return err("SELF section header count implausible");
        }
        let want = if head.class64 { 64 } else { 40 };
        if head.shentsize < want {
            return err("SELF section header entry too small");
        }
        let at = bounded(data, ext.shdr, head.shnum * head.shentsize, "section headers")?;
        data[at..at + head.shnum * head.shentsize].to_vec()
    } else {
        Vec::new()
    };
    let mut ehdr = data[ehdr_off..ehdr_off + head.ehsize].to_vec();
    let new_phoff = head.ehsize as u64;
    let new_shoff = new_phoff + table.len() as u64;
    if head.class64 {
        ehdr[0x20..0x28].copy_from_slice(&new_phoff.to_be_bytes());
        ehdr[0x28..0x30].copy_from_slice(&new_shoff.to_be_bytes());
    } else {
        ehdr[0x1c..0x20].copy_from_slice(&(new_phoff as u32).to_be_bytes());
        ehdr[0x20..0x24].copy_from_slice(&(new_shoff as u32).to_be_bytes());
    }
    let mut fixed = ehdr;
    fixed.extend_from_slice(&table);
    fixed.extend_from_slice(&shdrs);
    if fixed.len() > MAX_OUT {
        return err("SELF header splice implausible");
    }
    if out.len() < fixed.len() {
        out.resize(fixed.len(), 0);
    }
    out[..fixed.len()].copy_from_slice(&fixed);
    Ok(())
}

/// The byte extent of the ELF at `base` (headers plus every section and
/// segment it names), for carving embedded images and header-only wrappers.
/// `NOBITS` sections occupy memory, not file, and are skipped.
fn elf_extent(data: &[u8], base: usize) -> Option<usize> {
    let hdr = data.get(base..base + 64)?;
    if hdr[0..4] != *b"\x7fELF" || hdr[6] != 1 {
        return None;
    }
    let class64 = match hdr[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let be = match hdr[5] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let r16 = |o: usize| {
        let s = data.get(base + o..base + o + 2)?;
        Some(if be { u16::from_be_bytes([s[0], s[1]]) } else { u16::from_le_bytes([s[0], s[1]]) } as usize)
    };
    let r32 = |o: usize| {
        let s = data.get(base + o..base + o + 4)?;
        Some(if be { u32::from_be_bytes([s[0], s[1], s[2], s[3]]) } else { u32::from_le_bytes([s[0], s[1], s[2], s[3]]) } as u64)
    };
    let r64 = |o: usize| {
        let s = data.get(base + o..base + o + 8)?;
        Some(if be {
            u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
        } else {
            u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
        })
    };
    let (phoff, phnum, phentsize, shoff, shnum, shentsize, ehsize) = if class64 {
        (r64(0x20)?, r16(0x38)?, r16(0x36)?, r64(0x28)?, r16(0x3c)?, r16(0x3a)?, r16(0x34)?)
    } else {
        (r32(0x1c)?, r16(0x2c)?, r16(0x2a)?, r32(0x20)?, r16(0x30)?, r16(0x2e)?, r16(0x28)?)
    };
    if phnum > MAX_PHNUM || shnum > MAX_SHNUM {
        return None;
    }
    let (ph_min, sh_min) = if class64 { (56, 64) } else { (32, 40) };
    if (phnum > 0 && phentsize < ph_min) || (shnum > 0 && shentsize < sh_min) {
        return None;
    }
    let mut end = ehsize as u64;
    let table_end = |off: u64, n: usize, esz: usize| off.checked_add((n as u64).checked_mul(esz as u64)?);
    if phnum > 0 {
        end = end.max(table_end(phoff, phnum, phentsize)?);
    }
    if shnum > 0 {
        end = end.max(table_end(shoff, shnum, shentsize)?);
    }
    let limit = (data.len() - base) as u64;
    let seg = |off: u64, size: u64| {
        if off > limit || size > limit - off {
            return None;
        }
        Some(off + size)
    };
    for i in 0..phnum {
        let o = base.checked_add(phoff.checked_add((i as u64).checked_mul(phentsize as u64)?)? as usize)?;
        let (off, size) = if class64 {
            (r64_at(data, o + 8, be)?, r64_at(data, o + 32, be)?)
        } else {
            (r32_at(data, o + 4, be)?, r32_at(data, o + 16, be)?)
        };
        end = end.max(seg(off, size)?);
    }
    for i in 0..shnum {
        let o = base.checked_add(shoff.checked_add((i as u64).checked_mul(shentsize as u64)?)? as usize)?;
        let (typ, off, size) = if class64 {
            (r32_at(data, o + 4, be)?, r64_at(data, o + 24, be)?, r64_at(data, o + 32, be)?)
        } else {
            (r32_at(data, o + 4, be)?, r32_at(data, o + 16, be)?, r32_at(data, o + 20, be)?)
        };
        if typ == 8 {
            continue;
        }
        end = end.max(seg(off, size)?);
    }
    if end < ehsize as u64 || end > limit || end > MAX_OUT as u64 {
        return None;
    }
    usize::try_from(end).ok()
}

fn r32_at(data: &[u8], o: usize, be: bool) -> Option<u64> {
    let s = data.get(o..o + 4)?;
    Some(if be { u32::from_be_bytes([s[0], s[1], s[2], s[3]]) } else { u32::from_le_bytes([s[0], s[1], s[2], s[3]]) } as u64)
}

fn r64_at(data: &[u8], o: usize, be: bool) -> Option<u64> {
    let s = data.get(o..o + 8)?;
    Some(if be {
        u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    } else {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

/// Carves embedded SPU ELF32 images out of the reassembled PPU ELF: modules
/// carry their SPU programs as data blobs, and each is its own 128-bit
/// big-endian machine, so each becomes its own program.
fn spu_images(elf: &[u8]) -> Vec<Vec<u8>> {
    let mut images = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut i = 0usize;
    while images.len() < MAX_SPU_IMAGES && i + 64 <= elf.len() {
        if elf[i..i + 4] == *b"\x7fELF" && elf[i + 4] == 1 && elf[i + 5] == 2 && elf[i + 18] == 0 && elf[i + 19] == EM_SPU as u8
        {
            if seen.insert(i) {
                if let Some(end) = elf_extent(elf, i) {
                    images.push(elf[i..i + end].to_vec());
                }
            }
        }
        i += 1;
    }
    images
}

// ---------------------------------------------------------------- import

/// Loads a SELF/SPRX: unwraps (decrypting when needed) the embedded ELF,
/// hands it to the ELF loader, overrides the language, and yields any
/// embedded SPU images beside it. `None` means the magic does not match; a
/// recognized-but-malformed file is `Some(Err(..))`.
#[cfg(test)]
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    import_with(data, &super::keys::KeyStore::empty())
}

/// `import` with a user-supplied key store: NPDRM titles (`app_type` 8)
/// wrap their metadata in an extra layer keyed by their per-title RAP
/// license, so a RAP from `keys` unwraps them where the keyless path
/// reports the key gap.
pub(crate) fn import_with(
    data: &[u8],
    keys: &super::keys::KeyStore,
) -> Option<Result<Vec<(String, NativeImport)>>> {
    if !is_self(data) {
        return None;
    }
    Some(import_self_with(data, keys))
}

fn import_self_with(data: &[u8], keys: &super::keys::KeyStore) -> Result<Vec<(String, NativeImport)>> {
    let (sce, ext) = parse_headers(data)?;
    let (app_type, sceversion) = app_info(data, &ext)?;
    if app_type == APP_TYPE_NPDRM {
        if rap_candidates(keys).is_empty() {
            return err("NPDRM SELF needs its per-title RAP license — re-extract with the license present (supply the title's .rap via --keys)");
        }
    } else if app_type != 0 && app_type != APP_TYPE_APP && sce.flags & FLAG_DEBUG == 0 {
        return err(format!(
            "SELF application type {app_type} is a firmware loader, not an application image"
        ));
    }
    let ehdr_off = bounded(data, ext.ehdr, 64, "ELF header")?;
    let head = elf_head(data, ehdr_off)?;

    // Files that carry metadata are laid out by it (section data is
    // scattered per the metadata offsets); files without it are tool or
    // header-only wrappers handled by the segment map or raw extent.
    let hsize = usize::try_from(sce.hsize).unwrap_or(0);
    let meta_off = usize::try_from(sce.meta).unwrap_or(usize::MAX);
    let meta_present = sce.meta != 0
        && meta_off
            .checked_add(0x60)
            .is_some_and(|end| end <= hsize && hsize <= data.len());
    let elf = if meta_present {
        let meta = load_metadata(data, &sce, sceversion, keys, app_type)?;
        rebuild_from_meta(data, &ext, ehdr_off, &head, &meta)?
    } else if ext.seg != 0 {
        rebuild_from_segments(data, &sce, &ext, &head)?
    } else if let Some(end) = elf_extent(data, ehdr_off) {
        data[ehdr_off..ehdr_off + end].to_vec()
    } else {
        return err("SELF carries no section map and no intact ELF extent");
    };

    let sprx = is_sprx(data);
    let label = if sprx { "SPRX" } else { "SELF" };
    let mut ppu = super::import_elf(&elf)?;
    ppu.format = label.into();
    match head.machine {
        EM_PPC64 => ppu.language = PPU_LANGUAGE.into(),
        EM_SPU => ppu.language = SPU_LANGUAGE.into(),
        _ => {}
    }
    let mut images = vec![("ppu".to_string(), ppu)];
    for (i, spu) in spu_images(&elf).into_iter().enumerate() {
        let Ok(mut imp) = super::import_elf(&spu) else {
            continue;
        };
        imp.format = label.into();
        imp.language = SPU_LANGUAGE.into();
        images.push((format!("spu{i}"), imp));
    }
    Ok(images)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: u64 = 0x1_0000;

    fn be16v(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }
    fn be32v(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }
    fn be64v(v: u64) -> [u8; 8] {
        v.to_be_bytes()
    }

    /// Minimal big-endian PPC64 ELF: ehdr + 1 PT_LOAD + 1 ALLOC|EXEC section
    /// of NOPs. `etype` lets fixtures pose as SPRX (`ET_SCE_PPURELEXEC`).
    fn ppc64_elf(etype: u16) -> Vec<u8> {
        let mut elf = vec![0u8; 184 + 16];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 2;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&be16v(etype));
        elf[18..20].copy_from_slice(&be16v(EM_PPC64));
        elf[20..24].copy_from_slice(&be32v(1));
        elf[24..32].copy_from_slice(&be64v(ENTRY));
        elf[32..40].copy_from_slice(&be64v(0x40)); // e_phoff
        elf[40..48].copy_from_slice(&be64v(0x78)); // e_shoff
        elf[52..54].copy_from_slice(&be16v(64)); // e_ehsize
        elf[54..56].copy_from_slice(&be16v(56)); // e_phentsize
        elf[56..58].copy_from_slice(&be16v(1)); // e_phnum
        elf[58..60].copy_from_slice(&be16v(64)); // e_shentsize
        elf[60..62].copy_from_slice(&be16v(1)); // e_shnum
        // phdr @0x40: PT_LOAD, R+X, file 184, vaddr ENTRY, 16 bytes.
        elf[0x40..0x44].copy_from_slice(&be32v(1));
        elf[0x44..0x48].copy_from_slice(&be32v(5));
        elf[0x48..0x50].copy_from_slice(&be64v(184));
        elf[0x50..0x58].copy_from_slice(&be64v(ENTRY));
        elf[0x58..0x60].copy_from_slice(&be64v(ENTRY));
        elf[0x60..0x68].copy_from_slice(&be64v(16));
        elf[0x68..0x70].copy_from_slice(&be64v(16));
        elf[0x70..0x78].copy_from_slice(&be64v(4));
        // shdr @0x78: PROGBITS, ALLOC|EXEC, vaddr ENTRY, file 184, 16 bytes.
        elf[0x7c..0x80].copy_from_slice(&be32v(1));
        elf[0x80..0x88].copy_from_slice(&be64v(6));
        elf[0x88..0x90].copy_from_slice(&be64v(ENTRY));
        elf[0x90..0x98].copy_from_slice(&be64v(184));
        elf[0x98..0xa0].copy_from_slice(&be64v(16));
        elf[0xa8..0xb0].copy_from_slice(&be64v(4)); // sh_addralign
        // code: four PowerPC NOPs.
        for w in 0..4 {
            elf[184 + w * 4..188 + w * 4].copy_from_slice(&be32v(0x6000_0000));
        }
        elf
    }

    /// SELF with a real metadata block. `encrypt` selects the retail shape
    /// (metadata-info CBC layer under the first public APP vault key plus a
    /// CTR section) versus the DEBUG shape (plaintext metadata, raw
    /// section). Like a real SELF, the ELF headers live as a plaintext copy
    /// in the header area (the extended header points at them) while the
    /// metadata section carries only the segment payload — the 16 code
    /// bytes the program header places at `p_offset` 184. `app_type` stamps
    /// the program-identification header; `npdrm_key` adds the NPDRM title's
    /// outer AES-128-CBC layer (vault first, then the per-title layer — the
    /// reverse of the loader's peel order).
    fn self_with_metadata(etype: u16, encrypt: bool, magic4: u8) -> Vec<u8> {
        self_with_metadata_and_type(etype, encrypt, magic4, APP_TYPE_APP, None)
    }

    fn self_with_metadata_and_type(
        etype: u16,
        encrypt: bool,
        magic4: u8,
        app_type: u32,
        npdrm_key: Option<[u8; 16]>,
    ) -> Vec<u8> {
        let elf = ppc64_elf(etype);
        let (erk, riv) = (
            hex_arr::<32>(APP_KEYS[0].2).unwrap(),
            hex_arr::<16>(APP_KEYS[0].3).unwrap(),
        );
        let sceversion = APP_KEYS[0].0;

        // File's own metadata key/iv and section key/iv (fixed test bytes,
        // real mechanism).
        let mkey = [0x11u8; 16];
        let miv = [0x22u8; 16];
        let skey = [0x33u8; 16];
        let siv = [0x44u8; 16];
        let mut payload = elf[184..200].to_vec();
        let enc_flag = if encrypt {
            aes128_ctr(&skey, &siv, &mut payload);
            META_ENCRYPTED
        } else {
            0
        };

        // Layout, in order: SCE + ext + app info + segment map + stored ELF
        // headers + metadata info + metadata headers + payload.
        let app_off = 0x70usize;
        let seg_off = app_off + 0x20;
        let hc_off = seg_off + 0x20;
        let meta_off = hc_off + 184; // == se_meta + 0x20
        let hdrs_off = meta_off + 64;
        let payload_off = hdrs_off + 32 + 48 + 32;

        let mut data = vec![0u8; payload_off];
        data[0..4].copy_from_slice(&[0x53, 0x43, 0x45, magic4]);
        data[0x04..0x08].copy_from_slice(&be32v(2)); // version
        let flags: u16 = if encrypt { 0x0001 } else { FLAG_DEBUG };
        data[0x08..0x0a].copy_from_slice(&be16v(flags));
        data[0x0a..0x0c].copy_from_slice(&be16v(1)); // SELF type
        data[0x0c..0x10].copy_from_slice(&be32v((meta_off - 0x20) as u32)); // se_meta
        data[0x10..0x18].copy_from_slice(&be64v(payload_off as u64)); // hsize
        data[0x18..0x20].copy_from_slice(&be64v(elf.len() as u64)); // esize
        data[0x20..0x28].copy_from_slice(&be64v(3)); // ext version
        data[0x28..0x30].copy_from_slice(&be64v(app_off as u64));
        data[0x30..0x38].copy_from_slice(&be64v(hc_off as u64));
        data[0x38..0x40].copy_from_slice(&be64v((hc_off + 0x40) as u64));
        data[0x40..0x48].copy_from_slice(&be64v((hc_off + 0x78) as u64));
        data[0x48..0x50].copy_from_slice(&be64v(seg_off as u64));
        // app info: vendor, type APP, version in the vault key's range.
        data[app_off + 8..app_off + 12].copy_from_slice(&be32v(0x0100_0002));
        data[app_off + 12..app_off + 16].copy_from_slice(&be32v(app_type));
        data[app_off + 16..app_off + 24].copy_from_slice(&be64v(sceversion));
        // segment map: one plain entry (a real file carries it; the metadata
        // path does not read it).
        data[seg_off..seg_off + 8].copy_from_slice(&be64v(payload_off as u64));
        data[seg_off + 8..seg_off + 16].copy_from_slice(&be64v(payload.len() as u64));
        data[seg_off + 16..seg_off + 20].copy_from_slice(&be32v(1));
        // Stored plaintext ELF headers: ehdr + phdr + shdr.
        data[hc_off..hc_off + 184].copy_from_slice(&elf[0..184]);

        let mut info = vec![0u8; 64];
        info[0..16].copy_from_slice(&mkey);
        info[32..48].copy_from_slice(&miv);
        if encrypt {
            cbc_encrypt(&erk, &riv, &mut info);
            if let Some(nk) = npdrm_key {
                cbc128_encrypt(&nk, &NPDRM_ZERO_IV, &mut info);
            }
        }
        data[meta_off..meta_off + 64].copy_from_slice(&info);

        let mut headers = vec![0u8; 32 + 48 + 32];
        headers[12..16].copy_from_slice(&be32v(1)); // section_count
        headers[16..20].copy_from_slice(&be32v(2)); // key_count
        headers[32..40].copy_from_slice(&be64v(payload_off as u64));
        headers[40..48].copy_from_slice(&be64v(payload.len() as u64));
        headers[48..52].copy_from_slice(&be32v(META_TYPE_PROGRAM));
        headers[52..56].copy_from_slice(&be32v(0)); // program_idx
        headers[64..68].copy_from_slice(&be32v(enc_flag));
        headers[68..72].copy_from_slice(&be32v(0)); // key_idx
        headers[72..76].copy_from_slice(&be32v(1)); // iv_idx
        headers[80..96].copy_from_slice(&skey);
        headers[96..112].copy_from_slice(&siv);
        aes128_ctr(&mkey, &miv, &mut headers);
        data[hdrs_off..hdrs_off + headers.len()].copy_from_slice(&headers);

        data.extend_from_slice(&payload);
        data
    }

    /// Minimal big-endian SPU ELF32: ehdr + 1 PT_LOAD + 1 ALLOC section.
    fn spu_elf32() -> Vec<u8> {
        let mut elf = vec![0u8; 124 + 16];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 1;
        elf[5] = 2;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&be16v(2));
        elf[18..20].copy_from_slice(&be16v(EM_SPU));
        elf[20..24].copy_from_slice(&be32v(1));
        elf[28..32].copy_from_slice(&be32v(52)); // e_phoff
        elf[32..36].copy_from_slice(&be32v(84)); // e_shoff
        elf[40..42].copy_from_slice(&be16v(52)); // e_ehsize
        elf[42..44].copy_from_slice(&be16v(32)); // e_phentsize
        elf[44..46].copy_from_slice(&be16v(1)); // e_phnum
        elf[46..48].copy_from_slice(&be16v(40)); // e_shentsize
        elf[48..50].copy_from_slice(&be16v(1)); // e_shnum
        // phdr @52: PT_LOAD, file 124, 16 bytes.
        elf[52..56].copy_from_slice(&be32v(1));
        elf[56..60].copy_from_slice(&be32v(124));
        elf[60..64].copy_from_slice(&be32v(0));
        elf[64..68].copy_from_slice(&be32v(0));
        elf[68..72].copy_from_slice(&be32v(16));
        elf[72..76].copy_from_slice(&be32v(16));
        elf[76..80].copy_from_slice(&be32v(6));
        elf[80..84].copy_from_slice(&be32v(4));
        // shdr @84: PROGBITS, ALLOC|WRITE, file 124, 16 bytes.
        elf[88..92].copy_from_slice(&be32v(1));
        elf[92..96].copy_from_slice(&be32v(3));
        elf[100..104].copy_from_slice(&be32v(124));
        elf[104..108].copy_from_slice(&be32v(16));
        elf[116..120].copy_from_slice(&be32v(4));
        elf
    }

    /// Test-only AES-256-CBC encrypt (mirror of the loader's decrypt).
    fn cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
        use aes::cipher::BlockCipherEncrypt;
        let cipher = Aes256::new(key.into());
        let mut prev = *iv;
        for chunk in data.chunks_mut(16) {
            let mut block = [0u8; 16];
            for (i, (b, p)) in chunk.iter().zip(prev.iter()).enumerate() {
                block[i] = b ^ p;
            }
            cipher.encrypt_block((&mut block).into());
            chunk.copy_from_slice(&block);
            prev = block;
        }
    }

    /// Test-only AES-128-CBC encrypt (mirror of the loader's NPDRM layer).
    fn cbc128_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
        use aes::cipher::BlockCipherEncrypt;
        use aes::Aes128;
        let cipher = Aes128::new(key.into());
        let mut prev = *iv;
        for chunk in data.chunks_mut(16) {
            let mut block = [0u8; 16];
            for (i, (b, p)) in chunk.iter().zip(prev.iter()).enumerate() {
                block[i] = b ^ p;
            }
            cipher.encrypt_block((&mut block).into());
            chunk.copy_from_slice(&block);
            prev = block;
        }
    }

    /// SELF without metadata: headers plus one plain segment entry, the raw
    /// image contiguous after the headers (fail0verflow single-section shape).
    fn self_with_segments(etype: u16) -> Vec<u8> {
        let elf = ppc64_elf(etype);
        let app_off = 0x70usize;
        let seg_off = app_off + 0x20;
        let elf_off = seg_off + 0x20;
        let mut data = vec![0u8; elf_off];
        data[0..4].copy_from_slice(b"SCE\x00");
        data[0x04..0x08].copy_from_slice(&be32v(2));
        data[0x08..0x0a].copy_from_slice(&be16v(FLAG_DEBUG));
        data[0x0a..0x0c].copy_from_slice(&be16v(1));
        data[0x0c..0x10].copy_from_slice(&be32v(0)); // no metadata
        data[0x10..0x18].copy_from_slice(&be64v(elf_off as u64));
        data[0x18..0x20].copy_from_slice(&be64v(elf.len() as u64));
        data[0x20..0x28].copy_from_slice(&be64v(3));
        data[0x28..0x30].copy_from_slice(&be64v(app_off as u64));
        data[0x30..0x38].copy_from_slice(&be64v(elf_off as u64));
        data[0x38..0x40].copy_from_slice(&be64v((elf_off + 0x40) as u64));
        data[0x40..0x48].copy_from_slice(&be64v((elf_off + 0x78) as u64));
        data[0x48..0x50].copy_from_slice(&be64v(seg_off as u64));
        data[app_off + 12..app_off + 16].copy_from_slice(&be32v(APP_TYPE_APP));
        data[seg_off..seg_off + 8].copy_from_slice(&be64v(elf_off as u64));
        data[seg_off + 8..seg_off + 16].copy_from_slice(&be64v(elf.len() as u64));
        data[seg_off + 16..seg_off + 20].copy_from_slice(&be32v(1));
        data.extend_from_slice(&elf);
        data
    }

    #[test]
    fn detectors_accept_both_sce_magics() {
        let plain = self_with_metadata(2, false, 0x00);
        let variant = self_with_metadata(2, false, 0x04);
        assert!(is_self(&plain));
        assert!(is_self(&variant));
        assert!(!is_self(b"\x7fELF...."));
        assert!(!is_self(b""));
        assert!(!is_self(b"SCEx"));
        assert!(!is_sprx(&plain));
    }

    #[test]
    fn sprx_detector_reads_inner_etype() {
        let sprx = self_with_metadata(ET_SCE_PPURELEXEC, false, 0x00);
        assert!(is_self(&sprx));
        assert!(is_sprx(&sprx));
        let seg_sprx = self_with_segments(ET_SCE_PPURELEXEC);
        assert!(is_sprx(&seg_sprx));
    }

    #[test]
    fn debug_self_unwraps_to_ppc64() {
        let data = self_with_metadata(2, false, 0x00);
        let images = import(&data).expect("recognized").expect("unwraps");
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, "ppu");
        let imp = &images[0].1;
        assert_eq!(imp.format, "SELF");
        assert_eq!(imp.language, PPU_LANGUAGE);
        assert_eq!(imp.mappings.len(), 1);
        assert_eq!(imp.mappings[0].vaddr, ENTRY);
        assert_eq!(imp.process_entry, Some(ENTRY));
        assert_eq!(imp.mappings[0].bytes[0..4], be32v(0x6000_0000));
    }

    #[test]
    fn harness_magic_variant_unwraps() {
        let data = self_with_metadata(2, false, 0x04);
        let images = import(&data).expect("recognized").expect("unwraps");
        assert_eq!(images[0].1.language, PPU_LANGUAGE);
    }

    #[test]
    fn encrypted_self_decrypts_with_public_vault_key() {
        let data = self_with_metadata(2, true, 0x00);
        let images = import(&data).expect("recognized").expect("decrypts");
        assert_eq!(images.len(), 1);
        let imp = &images[0].1;
        assert_eq!(imp.format, "SELF");
        assert_eq!(imp.language, PPU_LANGUAGE);
        assert_eq!(imp.process_entry, Some(ENTRY));
        assert_eq!(imp.mappings[0].bytes[0..4], be32v(0x6000_0000));
    }

    #[test]
    fn segment_only_self_unwraps_without_metadata() {
        let data = self_with_segments(2);
        let images = import(&data).expect("recognized").expect("unwraps");
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].1.language, PPU_LANGUAGE);
        assert_eq!(images[0].1.process_entry, Some(ENTRY));
    }

    #[test]
    fn sprx_labels_format_and_yields_spu_images() {
        let mut inner = ppc64_elf(ET_SCE_PPURELEXEC);
        // An SPU program stashed past the code, inside the grown PT_LOAD and
        // section so the inner extent stays exact.
        inner.extend_from_slice(&spu_elf32());
        let grown = inner.len() as u64 - 184;
        inner[0x60..0x68].copy_from_slice(&be64v(grown));
        inner[0x68..0x70].copy_from_slice(&be64v(grown));
        inner[0x98..0xa0].copy_from_slice(&be64v(grown));
        // Wrap with segments (the metadata-free shape keeps this small).
        let app_off = 0x70usize;
        let seg_off = app_off + 0x20;
        let elf_off = seg_off + 0x20;
        let mut data = vec![0u8; elf_off];
        data[0..4].copy_from_slice(b"SCE\x00");
        data[0x04..0x08].copy_from_slice(&be32v(2));
        data[0x08..0x0a].copy_from_slice(&be16v(FLAG_DEBUG));
        data[0x0a..0x0c].copy_from_slice(&be16v(1));
        data[0x10..0x18].copy_from_slice(&be64v(elf_off as u64));
        data[0x18..0x20].copy_from_slice(&be64v(inner.len() as u64));
        data[0x20..0x28].copy_from_slice(&be64v(3));
        data[0x28..0x30].copy_from_slice(&be64v(app_off as u64));
        data[0x30..0x38].copy_from_slice(&be64v(elf_off as u64));
        data[0x38..0x40].copy_from_slice(&be64v((elf_off + 0x40) as u64));
        data[0x40..0x48].copy_from_slice(&be64v((elf_off + 0x78) as u64));
        data[0x48..0x50].copy_from_slice(&be64v(seg_off as u64));
        data[app_off + 12..app_off + 16].copy_from_slice(&be32v(APP_TYPE_APP));
        data[seg_off..seg_off + 8].copy_from_slice(&be64v(elf_off as u64));
        data[seg_off + 8..seg_off + 16].copy_from_slice(&be64v(inner.len() as u64));
        data[seg_off + 16..seg_off + 20].copy_from_slice(&be32v(1));
        data.extend_from_slice(&inner);

        let images = import(&data).expect("recognized").expect("unwraps");
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].0, "ppu");
        assert_eq!(images[0].1.format, "SPRX");
        assert_eq!(images[0].1.language, PPU_LANGUAGE);
        assert_eq!(images[1].0, "spu0");
        assert_eq!(images[1].1.format, "SPRX");
        assert_eq!(images[1].1.language, SPU_LANGUAGE);
        assert_eq!(images[1].1.mappings.len(), 1);
    }

    #[test]
    fn truncated_self_is_a_recognized_malformation() {
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(b"SCE\x00");
        assert!(is_self(&data));
        assert!(import(&data).expect("recognized").is_err());
    }

    #[test]
    fn garbage_offsets_are_refused() {
        let mut data = self_with_segments(2);
        data[0x30..0x38].copy_from_slice(&be64v(0xFFFF_FFFF)); // ehdr off the end
        assert!(import(&data).expect("recognized").is_err());
    }

    #[test]
    fn raw_elf_is_not_a_self() {
        assert!(import(&ppc64_elf(2)).is_none());
    }

    #[test]
    fn vault_keys_decode_to_key_sizes() {
        assert!(!APP_KEYS.is_empty());
        for (_, _, erk_hex, riv_hex) in APP_KEYS {
            assert!(hex_arr::<32>(erk_hex).is_some());
            assert!(hex_arr::<16>(riv_hex).is_some());
        }
    }

    #[test]
    fn metadata_cbc_roundtrip() {
        let (erk, riv) = (
            hex_arr::<32>(APP_KEYS[3].2).unwrap(),
            hex_arr::<16>(APP_KEYS[3].3).unwrap(),
        );
        let mut block = vec![0x5Au8; 64];
        let plain = block.clone();
        cbc_encrypt(&erk, &riv, &mut block);
        assert_ne!(block, plain);
        aes256_cbc_decrypt(&erk, &riv, &mut block).expect("decrypts");
        assert_eq!(block, plain);
    }

    #[test]
    fn npdrm_self_imports_with_supplied_rap() {
        use super::super::keys::KeyStore;
        use std::io::Write as _;

        // The title's license: 16 bytes, like a dumped `.rap` file.
        // An NPDRM-type SELF whose metadata wears the RAP-derived outer
        let rap = *b"test-rap-0123456";
        let data = self_with_metadata_and_type(2, true, 0x00, APP_TYPE_NPDRM, Some(npdrm_content_key(&rap)));

        // Without keys the encrypted NPDRM path still reports the key gap.
        let gap = import(&data).expect("recognized").expect_err("NPDRM without RAP must refuse");
        let gap_msg = format!("{gap:?}");
        assert!(
            gap_msg.contains("RAP") && gap_msg.contains("--keys"),
            "key gap names the license: {gap_msg}"
        );

        // Another title's RAP does not unwrap either.
        let mut wrong = KeyStore::empty();
        wrong.parse_text_for_test("rap = 00000000000000000000000000000000");
        assert!(import_with(&data, &wrong).expect("recognized").is_err());
        // The right RAP as a named `rap = hex` line unwraps to the PPU image.
        let mut named = KeyStore::empty();
        named.parse_text_for_test("rap = 746573742d7261702d30313233343536");
        let images = import_with(&data, &named).expect("recognized").expect("RAP unwraps NPDRM");
        assert_eq!(images.len(), 1);
        let imp = &images[0].1;
        assert_eq!(imp.format, "SELF");
        assert_eq!(imp.language, PPU_LANGUAGE);
        assert_eq!(imp.process_entry, Some(ENTRY));
        assert_eq!(imp.mappings[0].bytes[0..4], be32v(0x6000_0000));

        // The same RAP as a raw 16-byte `.rap` file unwraps too.
        let path = std::env::temp_dir().join("ps3-npdrm-test.rap");
        std::fs::File::create(&path).unwrap().write_all(&rap).unwrap();
        let raw = KeyStore::load(&path).unwrap();
        let images = import_with(&data, &raw).expect("recognized").expect("raw .rap unwraps NPDRM");
        assert_eq!(images[0].1.process_entry, Some(ENTRY));
        std::fs::remove_file(&path).ok();
    }
}
