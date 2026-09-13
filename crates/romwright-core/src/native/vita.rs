//! PlayStation Vita SELF containers (`eboot.bin`, `.suprx`, `.skprx`).
//!
//! A Vita SELF is a little-endian `SCE\0` wrapper around an ARM ELF32
//! (`ET_SCE_EXEC`). The layout here is ported from documented format facts
//! only — no code is copied from any implementation:
//!
//! * Header, app-info, and `segment_info` table: vitasdk/vita-toolchain
//!   `src/self.h` (`SCE_header`, `SCE_appinfo`, `segment_info`) and
//!   `src/vita-make-fself/vita-make-fself.c`, which writes the plaintext
//!   form: magic `0x454353` (`SCE\0`), version 3, `header_type` 1, one
//!   32-byte `segment_info` per program header with `offset`/`length` naming
//!   the payload, `compression` 1 = stored raw / 2 = zlib, `encryption`
//!   2 = plain. Segments start at `HEADER_LEN` (0x1000).
//! * The embedded ELF copy (`e_machine` ARM `0x28`, or `0xF00D` for secure-
//!   monitor images — still ARMv7 code) carries `sce_module_info`; that
//!   table is parsed by `super::sce`, which the ELF import already runs.
//! * Encrypted segments: the metadata/key-vault pipeline and every public
//!   key below are Team Molecule's openly published `sceutils` research
//!   (`scetypes.py`/`sceutils.py`: `SceHeader`, `MetadataInfo`, ...), as
//!   embedded by the Vita3K emulator (`vita3k/packages/src/sce_utils.cpp`,
//!   `register_keys` case 0 = retail, crediting Team Molecule). Retail APP
//!   (NPDRM) images additionally need their per-title `klic`, which is not
//!   public, so those are refused with a message naming the gap; USER images
//!   decrypt with public constants only.
//!
//! Wire-up: `import` unwraps the SELF to a plain ELF32 and feeds it to the
//! existing ELF import, then stamps the container's own identity on top
//! (`format = "SELF"`, Ghidra language `ARM:LE:32:v7` for the Cortex-A9).

use super::{NativeImport, Result};
use aes::cipher::{BlockCipherDecrypt, KeyInit};

// ---------------------------------------------------------------- headers

/// `SCE\0` in file bytes (vita-toolchain `src/self.h`: `53434500 = SCE\0`).
const SCE_MAGIC: [u8; 4] = *b"SCE\0";
/// `SCE_header` version for Vita (`SceHeader.version == 3`, sceutils).
const SCE_VERSION: u32 = 3;
/// `SceType::SELF` (`sce_type` u16 @10).
const SCE_TYPE_SELF: u16 = 1;
/// Vita module `e_type` (`ET_SCE_EXEC`, vita-toolchain `sce-elf.h`).
const ET_SCE_EXEC: u16 = 0xfe00;
/// ARM (`e_machine` of a normal Vita payload; vita-make-fself.c).
const EM_ARM: u16 = 0x28;
/// Secure-monitor tag `vita-make-fself.c` writes as `e_machine` for
/// `SCE_SELF_TYPE_SECURITY` images. The code is still ARMv7.
const EM_SECURE: u16 = 0xF00D;

/// `segment_info.compression`: stored raw (vita-make-fself.c).
const COMP_RAW: u64 = 1;
/// `segment_info.compression`: zlib (`compress2`, vita-make-fself.c `-c`).
const COMP_ZLIB: u64 = 2;
/// `segment_info.encryption`: plain (vita-make-fself.c; Vita3K
/// `is_fself_encrypted`: `encryption != 2` means encrypted).
const ENC_PLAIN: u64 = 2;

/// `SelfType` values the app-info header carries (sceutils `SelfType`).
const SELF_TYPE_APP: u32 = 0x08;
const SELF_TYPE_USER: u32 = 0x0D;

/// `MetadataSection.encryption == AES128CTR` (sceutils `EncryptionType`).
const METSEC_AES128CTR: i32 = 3;
/// `MetadataSection.compression == DEFLATE` (sceutils `CompressionType`).
const METSEC_DEFLATE: i32 = 2;
/// `MetadataInfo.Size` (sceutils): the AES-256-CBC unit holding the
/// section key/iv.
const METAINFO_SIZE: usize = 64;
/// `MetadataHeader.Size` (sceutils).
const METAHEADER_SIZE: usize = 32;
/// `MetadataSection.Size` (sceutils).
const METASECTION_SIZE: usize = 48;

// ------------------------------------------------------- public key table

const fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("vita: bad hex in public key constant"),
    }
}

const fn hex16(s: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = hex_val(s[2 * i]) << 4 | hex_val(s[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex32(s: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = hex_val(s[2 * i]) << 4 | hex_val(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// One public retail metadata key (Vita3K `register_keys` case 0, from Team
/// Molecule's published sceutils research): AES-256-CBC-decrypts the
/// metadata blob of a `self_type` image at `keyrev` whose app `sys_version`
/// falls in `[min_sysver, max_sysver]`.
struct MetaKey {
    self_type: u32,
    keyrev: u8,
    min_sysver: u64,
    max_sysver: u64,
    key: [u8; 32],
    iv: [u8; 16],
}

const MAXVER: u64 = 0xffff_ffff_ffff_ffff;

const META_KEYS: &[MetaKey] = &[
    // APP (NPDRM `eboot.bin`) metadata keys.
    MetaKey { self_type: SELF_TYPE_APP, keyrev: 0, min_sysver: 0x0000_0000_0000, max_sysver: 0x1692_0000_0000, key: hex32(b"AAA508FA5E85EAEE597ED2B27804D22287CFADF1DF32EDC7A7C58E8C9AA8BB36"), iv: hex16(b"CD1BD3A59200CC67A3B804808DC2AE73") },
    MetaKey { self_type: SELF_TYPE_APP, keyrev: 0, min_sysver: 0x1800_0000_0000, max_sysver: MAXVER, key: hex32(b"5661E5FB20CFD1D1DFF50C1E59A6EA977D0AA5C5770F53B9CDD4E9451FFF55CB"), iv: hex16(b"23D02FF79BF430E2D123869BF0CACAA0") },
    MetaKey { self_type: SELF_TYPE_APP, keyrev: 1, min_sysver: 0x0000_0000_0000, max_sysver: MAXVER, key: hex32(b"4181B2DF5F5D94D3C80B7D86EACF1928533A49BA58EDE2B43CDEE7E572568BD4"), iv: hex16(b"B1678C0543B6C1997B63A6F4F3C8FD33") },
    MetaKey { self_type: SELF_TYPE_APP, keyrev: 2, min_sysver: 0x1800_0000_0000, max_sysver: MAXVER, key: hex32(b"5282582F17F068F89A260AAFB71C58928F45A8D08C681376B07FF9EAB1114226"), iv: hex16(b"29672DF43E426F41AF46D42E8437D449") },
    MetaKey { self_type: SELF_TYPE_APP, keyrev: 3, min_sysver: 0x1800_0000_0000, max_sysver: MAXVER, key: hex32(b"270CBA370061B87077672ADB5142D18844AAED352A9CCEE63602B0D740594334"), iv: hex16(b"1CF2454FBF47D76221B91AFC3B608C28") },
    MetaKey { self_type: SELF_TYPE_APP, keyrev: 4, min_sysver: 0x3630_0000_0000, max_sysver: MAXVER, key: hex32(b"A782BC5A9EDDFC49A513FF3E592C4677A8C8920F23C9F11F2558FB9D99A43868"), iv: hex16(b"559B5E658559EB65EBF892C274E098A9") },
    MetaKey { self_type: SELF_TYPE_APP, keyrev: 5, min_sysver: 0x3630_0000_0000, max_sysver: MAXVER, key: hex32(b"12D64D0172495226010A687DE245A73DE028B3561E25E69BABC325636F3CAE0A"), iv: hex16(b"F149EED1757E5A915B24309795BFC380") },
    // USER (`.suprx`/`.skprx`) metadata keys.
    MetaKey { self_type: SELF_TYPE_USER, keyrev: 0, min_sysver: 0x1030_0000_0000, max_sysver: 0x1692_0000_0000, key: hex32(b"4769935C3B1CB248C3A88A406B1535D5DC2C0279D5901DE534DC4A11B8F60804"), iv: hex16(b"0CE906F746D40105660456D827CEBD25") },
    MetaKey { self_type: SELF_TYPE_USER, keyrev: 0, min_sysver: 0x1800_0000_0000, max_sysver: MAXVER, key: hex32(b"4769935C3B1CB248C3A88A406B1535D5DC2C0279D5901DE534DC4A11B8F60804"), iv: hex16(b"0CE906F746D40105660456D827CEBD25") },
    MetaKey { self_type: SELF_TYPE_USER, keyrev: 1, min_sysver: 0x1030_0000_0000, max_sysver: MAXVER, key: hex32(b"613AD6EAC63D4E14F51A8C6AF18C66621968323B6F205B5E515C16D77BB06671"), iv: hex16(b"ADBDAA5041B2094CF2B359301DE64171") },
    MetaKey { self_type: SELF_TYPE_USER, keyrev: 2, min_sysver: 0x1800_0000_0000, max_sysver: MAXVER, key: hex32(b"0F2041269B26D6B7EF143E35E83E914629A92F50F3A4CEE14CDFF63AEC641117"), iv: hex16(b"07EF64437F0CB6995E6D785E42796C83") },
    MetaKey { self_type: SELF_TYPE_USER, keyrev: 3, min_sysver: 0x1800_0000_0000, max_sysver: MAXVER, key: hex32(b"3AFADA34660C6515B539EBBBC79C9C0ADA4337C32652CA03C6DD21A1D612D8F4"), iv: hex16(b"7F98A137869B91B1EB9604F81FD74C50") },
    MetaKey { self_type: SELF_TYPE_USER, keyrev: 4, min_sysver: 0x3630_0000_0000, max_sysver: MAXVER, key: hex32(b"8FF491B36713E8AA38DE30B303689657F07AE70A8A8B1D7867441C52DB39C806"), iv: hex16(b"D9CC7E26CE99053E48F9BEF1CB93C184") },
    MetaKey { self_type: SELF_TYPE_USER, keyrev: 5, min_sysver: 0x3630_0000_0000, max_sysver: MAXVER, key: hex32(b"4D71B2FB3D4359FB34445305C88A5E82FA12D34A8308F312AA34B58F6112253A"), iv: hex16(b"04A27133FF0205C96B7F45A60D7D417B") },
];

/// Public retail NPDRM keys (same sources): unwrap the per-title `klic`
/// into the key that decrypts an APP image's metadata head. The `klic`
/// itself lives in the title's license file, so it is never embedded here.
const NPDRM_KEYS: &[(u8, [u8; 16])] = &[
    (0, hex16(b"C10368BF3D2943BC6E5BD05E46A9A7B6")),
    (1, hex16(b"16419DD3BFBE8BDC596929B72CE237CD")),
];
/// NPDRM IVs are zero (both Vita3K and sceutils pass a zero IV).
const ZERO_IV: [u8; 16] = [0u8; 16];

// ---------------------------------------------------------------- readers

fn u16le(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| super::ImportError::Bad("vita: truncated header".into()))
}

fn u32le(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| super::ImportError::Bad("vita: truncated header".into()))
}

fn u64le(data: &[u8], off: usize) -> Result<u64> {
    data.get(off..off + 8)
        .map(|s| {
            u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
        })
        .ok_or_else(|| super::ImportError::Bad("vita: truncated header".into()))
}

fn i32le(data: &[u8], off: usize) -> Result<i32> {
    u32le(data, off).map(|v| v as i32)
}

// ---------------------------------------------------------------- crypto

/// AES-CBC decrypt with no padding (each plaintext block is the
/// ECB-decrypted ciphertext XOR the previous ciphertext block, first XOR
/// the IV) — the same construction `xex.rs` uses for its file key.
fn cbc_decrypt128(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 || data.is_empty() {
        return super::err("vita: metadata blob is not a whole number of blocks");
    }
    let cipher = aes::Aes128::new(key.into());
    let mut prev: [u8; 16] = *iv;
    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks_exact(16) {
        let mut plain: [u8; 16] = block.try_into().expect("exact chunks");
        cipher.decrypt_block((&mut plain).into());
        for (i, b) in plain.iter_mut().enumerate() {
            *b ^= prev[i];
        }
        prev = block.try_into().expect("exact chunks");
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

/// AES-256-CBC decrypt, same construction: the metadata head cipher
/// (sceutils `get_segments` uses AES-256-CBC for `hdr_dec`).
fn cbc_decrypt256(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 || data.is_empty() {
        return super::err("vita: metadata blob is not a whole number of blocks");
    }
    let cipher = aes::Aes256::new(key.into());
    let mut prev: [u8; 16] = *iv;
    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks_exact(16) {
        let mut plain: [u8; 16] = block.try_into().expect("exact chunks");
        cipher.decrypt_block((&mut plain).into());
        for (i, b) in plain.iter_mut().enumerate() {
            *b ^= prev[i];
        }
        prev = block.try_into().expect("exact chunks");
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

// ---------------------------------------------------------------- layout

/// The parsed SELF header: table offsets plus the key-selection fields
/// (`SceHeader` + `SelfHeader` in sceutils, `SCE_header` in self.h).
struct SelfLayout {
    keyrev: u8,
    metadata_offset: usize,
    header_len: usize,
    appinfo_offset: usize,
    elf_offset: usize,
    phdr_offset: usize,
    seginfo_offset: usize,
    phnum: usize,
}

fn parse_layout(data: &[u8]) -> Result<SelfLayout> {
    if data.len() < 128 {
        return super::err("vita: file too small for a SELF header");
    }
    if data[0..4] != SCE_MAGIC {
        return super::err("vita: not a Vita SELF image");
    }
    if u32le(data, 4)? != SCE_VERSION {
        return super::err("vita: unsupported SCE version");
    }
    if u16le(data, 10)? != SCE_TYPE_SELF {
        return super::err("vita: SCE type is not SELF");
    }
    let keyrev = data[9];
    let metadata_offset = u32le(data, 12)? as usize;
    let header_len = u64le(data, 16)? as usize;
    let appinfo_offset = u64le(data, 56)? as usize;
    let elf_offset = u64le(data, 64)? as usize;
    let phdr_offset = u64le(data, 72)? as usize;
    let seginfo_offset = u64le(data, 88)? as usize;
    if header_len < 128 || header_len > data.len() {
        return super::err("vita: SELF header length out of range");
    }
    if metadata_offset >= header_len {
        return super::err("vita: SELF metadata offset out of range");
    }
    let appinfo_end = appinfo_offset.checked_add(32).ok_or_else(|| {
        super::ImportError::Bad("vita: app-info offset overflow".into())
    })?;
    if appinfo_end > data.len() {
        return super::err("vita: SELF app-info outside file");
    }
    let ehdr_end = elf_offset.checked_add(52).ok_or_else(|| {
        super::ImportError::Bad("vita: ELF offset overflow".into())
    })?;
    if ehdr_end > data.len() {
        return super::err("vita: embedded ELF header outside file");
    }
    let ehdr = &data[elf_offset..ehdr_end];
    if ehdr[0..4] != *b"\x7fELF" || ehdr[4] != 1 || ehdr[5] != 1 {
        return super::err("vita: embedded image is not a 32-bit little-endian ELF");
    }
    if u16::from_le_bytes([ehdr[16], ehdr[17]]) != ET_SCE_EXEC {
        return super::err("vita: embedded ELF is not a Vita module (ET_SCE_EXEC)");
    }
    let machine = u16::from_le_bytes([ehdr[18], ehdr[19]]);
    if machine != EM_ARM && machine != EM_SECURE {
        return super::err("vita: embedded ELF is not an ARM image");
    }
    // ELF32 `e_phnum` sits at header offset 44 (16 ident + 2 type + 2
    // machine + 4 version + 4 entry + 4 phoff + 4 shoff + 4 flags + 2
    // ehsize + 2 phentsize).
    let phnum = u16::from_le_bytes([data[elf_offset + 44], data[elf_offset + 45]]) as usize;
    if phnum == 0 || phnum > 32 {
        return super::err("vita: implausible program header count");
    }
    let phdr_end = phdr_offset.checked_add(phnum * 32).ok_or_else(|| {
        super::ImportError::Bad("vita: program header table overflow".into())
    })?;
    let seginfo_end = seginfo_offset.checked_add(phnum * 32).ok_or_else(|| {
        super::ImportError::Bad("vita: segment-info table overflow".into())
    })?;
    if phdr_end > data.len() || seginfo_end > data.len() {
        return super::err("vita: SELF tables outside file");
    }
    Ok(SelfLayout {
        keyrev,
        metadata_offset,
        header_len,
        appinfo_offset,
        elf_offset,
        phdr_offset,
        seginfo_offset,
        phnum,
    })
}

/// One program header's sizes plus its `segment_info` payload locator.
struct Segment {
    filesz: u64,
    memsz: u64,
    payload_off: usize,
    payload_len: usize,
    compression: u64,
    encryption: u64,
}

fn read_segments(data: &[u8], layout: &SelfLayout) -> Result<Vec<Segment>> {
    let mut segments = Vec::with_capacity(layout.phnum);
    for i in 0..layout.phnum {
        let ph = layout.phdr_offset + i * 32;
        // ELF32 program header: u32 p_type @0, p_offset @4, p_vaddr @8,
        // p_paddr @12, p_filesz @16, p_memsz @20, p_flags @24, p_align @28.
        let filesz = u32le(data, ph + 16)? as u64;
        let memsz = u32le(data, ph + 20)? as u64;
        if filesz > memsz {
            return super::err("vita: segment file size exceeds memory size");
        }
        let si = layout.seginfo_offset + i * 32;
        let payload_off = u64le(data, si)? as usize;
        let payload_len = u64le(data, si + 8)? as usize;
        let compression = u64le(data, si + 16)?;
        let encryption = u64le(data, si + 24)?;
        if payload_len > 0x1000_0000 {
            return super::err("vita: segment length implausible");
        }
        let payload_end = payload_off.checked_add(payload_len).ok_or_else(|| {
            super::ImportError::Bad("vita: segment payload overflow".into())
        })?;
        if payload_end > data.len() {
            return super::err("vita: segment payload outside file");
        }
        segments.push(Segment {
            filesz,
            memsz,
            payload_off,
            payload_len,
            compression,
            encryption,
        });
    }
    Ok(segments)
}

// ------------------------------------------------------- metadata key vault

/// One metadata section's AES-128-CTR key material (sceutils `SceSegment`).
struct VaultEntry {
    key: [u8; 16],
    iv: [u8; 16],
    compressed: bool,
}

/// The title's per-title `klic` from the user's key store: a `klic = <hex>`
/// line first, then any raw 16-byte dump (a `.klic` license file *is* the
/// key, so the store selects it by length).
fn klic_from_keys(keys: &super::keys::KeyStore) -> Option<[u8; 16]> {
    if let Some(klic) = keys.get_array::<16>("klic") {
        return Some(klic);
    }
    keys.raw_keys()
        .iter()
        .find_map(|(_, bytes)| <[u8; 16]>::try_from(bytes.as_slice()).ok())
}

/// Recover every encrypted segment's key/iv from the metadata blob
/// (sceutils `get_segments`): the blob at
/// `metadata_offset + 48 .. header_length` opens with a 64-byte
/// AES-256-CBC unit holding the section key/iv (zero pads prove the public
/// key was right), then an AES-128-CBC body of section descriptors plus the
/// key vault. APP images wrap the head in their per-title `klic`, which is
/// not public — without one only the refusal below can run.

fn metadata_vault(
    data: &[u8],
    layout: &SelfLayout,
    self_type: u32,
    sysver: u64,
    klic: Option<&[u8; 16]>,
) -> Result<Vec<Option<VaultEntry>>> {
    let blob_start = layout.metadata_offset.checked_add(48).ok_or_else(|| {
        super::ImportError::Bad("vita: metadata offset overflow".into())
    })?;
    if blob_start >= layout.header_len {
        return super::err("vita: metadata blob outside header");
    }
    let blob = &data[blob_start..layout.header_len];
    if blob.len() < METAINFO_SIZE || blob.len() % 16 != 0 {
        return super::err("vita: metadata blob truncated");
    }
    let meta = META_KEYS
        .iter()
        .find(|k| {
            k.self_type == self_type
                && k.keyrev == layout.keyrev
                && sysver >= k.min_sysver
                && sysver <= k.max_sysver
        })
        .ok_or_else(|| {
            super::ImportError::Bad(format!(
                "vita: no public metadata key for self_type {self_type:#x} keyrev {} sysver {sysver:#x}",
                layout.keyrev
            ))
        })?;
    let head_in = if self_type == SELF_TYPE_APP {
        let klic = klic.ok_or_else(|| {
            super::ImportError::Bad(
                "vita: retail NPDRM APP segments need the title's klic \
                 (a per-title key from its license file, not a public \
                 constant) — import a decrypted image instead; supply it \
                 via --keys (klic = <hex> or a .klic file)"
                    .into(),
            )
        })?;
        let keyrev = if layout.keyrev >= 2 { 1 } else { 0 };
        let np_key = NPDRM_KEYS
            .iter()
            .find(|(rev, _)| *rev == keyrev)
            .map(|(_, key)| key)
            .ok_or_else(|| super::ImportError::Bad("vita: no public NPDRM key".into()))?;
        let predec = cbc_decrypt128(np_key, &ZERO_IV, klic)?;
        let predec: [u8; 16] = predec.try_into().map_err(|_| {
            super::ImportError::Bad("vita: NPDRM unwrap failed".into())
        })?;
        cbc_decrypt128(&predec, &ZERO_IV, &blob[..METAINFO_SIZE])?
    } else {
        blob[..METAINFO_SIZE].to_vec()
    };
    let meta_info = cbc_decrypt256(&meta.key, &meta.iv, &head_in)?;
    if meta_info[16..32] != [0u8; 16] || meta_info[48..64] != [0u8; 16] {
        return super::err(
            "vita: metadata head failed its padding check (wrong public key for this image?)",
        );
    }
    let section_key: [u8; 16] = meta_info[0..16].try_into().expect("sliced");
    let section_iv: [u8; 16] = meta_info[32..48].try_into().expect("sliced");
    let body = cbc_decrypt128(&section_key, &section_iv, &blob[METAINFO_SIZE..])?;
    if body.len() < METAHEADER_SIZE {
        return super::err("vita: metadata body truncated");
    }
    let section_count = u32::from_le_bytes(body[12..16].try_into().expect("sliced")) as usize;
    let key_count = u32::from_le_bytes(body[16..20].try_into().expect("sliced")) as usize;
    if section_count > 64 || key_count > 128 {
        return super::err("vita: metadata counts implausible");
    }
    let sections_end = METAHEADER_SIZE
        .checked_add(section_count * METASECTION_SIZE)
        .ok_or_else(|| super::ImportError::Bad("vita: metadata size overflow".into()))?;
    let vault_end = sections_end.checked_add(key_count * 16).ok_or_else(|| {
        super::ImportError::Bad("vita: metadata vault overflow".into())
    })?;
    if vault_end > body.len() {
        return super::err("vita: metadata vault truncated");
    }
    let mut vault = vec![[0u8; 16]; key_count];
    for (i, slot) in vault.iter_mut().enumerate() {
        *slot = body[sections_end + i * 16..sections_end + (i + 1) * 16]
            .try_into()
            .expect("sliced");
    }
    // Indexed by segment: only AES-128-CTR sections carry keys (sceutils
    // records exactly those in `segs`).
    let mut entries: Vec<Option<VaultEntry>> = Vec::new();
    entries.resize_with(layout.phnum, || None);
    // `MetadataSection` is `<QQIiIiIiiI` (sceutils `scetypes.py`): offset,
    // size, type, seg_idx, hash, hash_idx, encryption, key_idx, iv_idx,
    // compression.
    for i in 0..section_count {
        let off = METAHEADER_SIZE + i * METASECTION_SIZE;
        let seg_idx = i32le(&body, off + 20)? as usize;
        let encryption = i32le(&body, off + 32)?;
        let key_idx = i32le(&body, off + 36)? as usize;
        let iv_idx = i32le(&body, off + 40)? as usize;
        let compression = i32le(&body, off + 44)?;
        if encryption != METSEC_AES128CTR {
            continue;
        }
        if seg_idx >= layout.phnum || key_idx >= key_count || iv_idx >= key_count {
            return super::err("vita: metadata section indexes out of range");
        }
        entries[seg_idx] = Some(VaultEntry {
            key: vault[key_idx],
            iv: vault[iv_idx],
            compressed: compression == METSEC_DEFLATE,
        });
    }
    Ok(entries)
}

// ---------------------------------------------------------------- unwrap

/// Resolve every segment's bytes: plain copies, AES-128-CTR vault decrypts
/// (the vault IV is the CTR counter block, OpenSSL/BE convention — the same
/// counter `super::crypto::aes128_ctr` implements), compressed refusal.
fn resolve_payloads(
    data: &[u8],
    layout: &SelfLayout,
    segments: &[Segment],
    self_type: u32,
    sysver: u64,
    klic: Option<&[u8; 16]>,
) -> Result<Vec<Vec<u8>>> {
    let need_vault = segments.iter().any(|s| {
        s.filesz > 0 && s.encryption != ENC_PLAIN
    });
    let vault = if need_vault {
        Some(metadata_vault(data, layout, self_type, sysver, klic)?)
    } else {
        None
    };
    let mut payloads = Vec::with_capacity(segments.len());
    for (i, seg) in segments.iter().enumerate() {
        if seg.filesz == 0 {
            payloads.push(Vec::new());
            continue;
        }
        if seg.compression != COMP_RAW && seg.compression != COMP_ZLIB {
            return super::err("vita: segment has an unknown compression flag");
        }
        if (seg.payload_len as u64) < seg.filesz {
            return super::err("vita: segment carries fewer bytes than its program header claims");
        }
        let mut bytes = data[seg.payload_off..seg.payload_off + seg.payload_len].to_vec();
        if seg.encryption != ENC_PLAIN {
            let entry = vault
                .as_ref()
                .and_then(|v| v[i].as_ref())
                .ok_or_else(|| {
                    super::ImportError::Bad(format!(
                        "vita: segment {i} is encrypted but the metadata names no key for it"
                    ))
                })?;
            if entry.compressed || seg.compression == COMP_ZLIB {
                return super::err(
                    "vita: segment is zlib-compressed (vita-make-fself -c); \
                     no inflate is available offline — import a decompressed image",
                );
            }
            super::crypto::aes128_ctr(&entry.key, &entry.iv, &mut bytes);
        } else if seg.compression == COMP_ZLIB {
            return super::err(
                "vita: segment is zlib-compressed (vita-make-fself -c); \
                 no inflate is available offline — import a decompressed image",
            );
        }
        payloads.push(bytes);
    }
    Ok(payloads)
}

/// Rebuild the plain ELF32 the SELF wraps: header copy with a fresh program
/// table pointing at the payloads laid out behind it (Vita3K `decrypt_fself`
/// rebuilds the same shape before parsing).
fn rebuild_elf(
    data: &[u8],
    layout: &SelfLayout,
    segments: &[Segment],
    payloads: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut elf = data[layout.elf_offset..layout.elf_offset + 52].to_vec();
    // Fresh program table directly behind the header; section headers were
    // never carried (`shdr_offset` is 0 on toolchain output).
    elf[28..32].copy_from_slice(&(52u32).to_le_bytes());
    elf[32..36].copy_from_slice(&0u32.to_le_bytes());
    let mut cursor = 52 + layout.phnum * 32;
    for (i, seg) in segments.iter().enumerate() {
        let mut phdr = data[layout.phdr_offset + i * 32..layout.phdr_offset + (i + 1) * 32].to_vec();
        if seg.filesz == 0 {
            phdr[4..8].copy_from_slice(&0u32.to_le_bytes());
        } else {
            let off = u32::try_from(cursor).map_err(|_| {
                super::ImportError::Bad("vita: rebuilt image too large".into())
            })?;
            phdr[4..8].copy_from_slice(&off.to_le_bytes());
            cursor = cursor.checked_add(payloads[i].len()).ok_or_else(|| {
                super::ImportError::Bad("vita: rebuilt image too large".into())
            })?;
        }
        elf.extend_from_slice(&phdr);
    }
    for (seg, payload) in segments.iter().zip(payloads.iter()) {
        if seg.filesz > 0 {
            elf.extend_from_slice(payload);
        }
    }
    Ok(elf)
}

// ---------------------------------------------------------------- entry points

/// True for a Vita SELF: `SCE\0` magic, version 3, SELF type, table offsets
/// inside the file, and an ARM `ET_SCE_EXEC` ELF32 where the header says it
/// is. The LE version check is what separates Vita SELFs from PS3 ones (a
/// big-endian PS3 header reads as a huge LE version, never 3).
pub(crate) fn is_self(data: &[u8]) -> bool {
    parse_layout(data).is_ok()
}

/// True for an already-decrypted Vita module ELF: 32-bit LE ARM
/// `ET_SCE_EXEC`. Those import through the plain ELF path (`super::sce`
/// reads their module info); this detector just names them.
pub(crate) fn is_vita_elf(data: &[u8]) -> bool {
    if data.len() < 20 || data[0..4] != *b"\x7fELF" || data[4] != 1 || data[5] != 1 {
        return false;
    }
    let e_type = u16::from_le_bytes([data[16], data[17]]);
    let machine = u16::from_le_bytes([data[18], data[19]]);
    e_type == ET_SCE_EXEC && (machine == EM_ARM || machine == EM_SECURE)
}

fn import_self(data: &[u8], keys: &super::keys::KeyStore) -> Result<Vec<(String, NativeImport)>> {
    let layout = parse_layout(data)?;
    let self_type = u32le(data, layout.appinfo_offset + 12)?;
    let sysver = u64le(data, layout.appinfo_offset + 16)?;
    let segments = read_segments(data, &layout)?;
    // The NPDRM APP head is wrapped in the title's `klic`; a user dump
    // supplies it, otherwise the vault refusal below names the gap.
    let klic = klic_from_keys(keys);
    let payloads = resolve_payloads(data, &layout, &segments, self_type, sysver, klic.as_ref())?;
    let elf = rebuild_elf(data, &layout, &segments, &payloads)?;
    // `import_elf` dispatches ELF32 to the sectionless path, which maps the
    // PT_LOADs and runs `super::sce::collect` over the module info — the
    // NID-named exports/imports arrive through that call.
    let mut imp = super::import_elf(&elf)?;
    imp.format = "SELF".into();
    imp.language = "ARM:LE:32:v7".into();
    Ok(vec![(String::new(), imp)])
}

/// Unwrap a Vita SELF to its ARMv7 image; None when the magic doesn't match.
pub(crate) fn import(data: &[u8]) -> Option<Result<Vec<(String, NativeImport)>>> {
    import_with(data, &super::keys::KeyStore::empty())
}

/// `import` with a user-supplied key store: a `klic = <hex>` line or a raw
/// 16-byte `.klic` dump unwraps a retail NPDRM APP image's metadata head;
/// absent, the klic-gap error is unchanged.
pub(crate) fn import_with(
    data: &[u8],
    keys: &super::keys::KeyStore,
) -> Option<Result<Vec<(String, NativeImport)>>> {
    if !is_self(data) {
        return None;
    }
    Some(import_self(data, keys))
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal Vita module ELF32: one PT_LOAD at 0x81000000 holding
    /// `sce_module_info` plus one export and one import entry (mirrors the
    /// layout `super::sce`'s own fixture proves that parser against).
    fn inner_elf() -> Vec<u8> {
        const BASE: u32 = 0x8100_0000;
        const SEG_OFF: usize = 0x100;
        const INFO: usize = SEG_OFF + 0x40;
        const EXPORT: usize = SEG_OFF + 0xa0;
        const IMPORT: usize = SEG_OFF + 0xc0;
        const NIDTAB: usize = SEG_OFF + 0x100;
        const ENTTAB: usize = SEG_OFF + 0x110;
        const FNID: usize = SEG_OFF + 0x120;
        const FSTUB: usize = SEG_OFF + 0x130;
        const LIBNAME: usize = SEG_OFF + 0x140;
        const START: usize = SEG_OFF + 0x160;
        let mut data = vec![0u8; SEG_OFF + 0x200];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 1;
        data[5] = 1;
        data[6] = 1;
        data[16..18].copy_from_slice(&ET_SCE_EXEC.to_le_bytes());
        data[18..20].copy_from_slice(&EM_ARM.to_le_bytes());
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[24..28].copy_from_slice(&((INFO - SEG_OFF) as u32).to_le_bytes());
        data[28..32].copy_from_slice(&52u32.to_le_bytes());
        data[40..42].copy_from_slice(&52u16.to_le_bytes());
        data[42..44].copy_from_slice(&32u16.to_le_bytes());
        data[44..46].copy_from_slice(&1u16.to_le_bytes());
        let ph = 52;
        data[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        data[ph + 4..ph + 8].copy_from_slice(&(SEG_OFF as u32).to_le_bytes());
        data[ph + 8..ph + 12].copy_from_slice(&BASE.to_le_bytes());
        data[ph + 16..ph + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[ph + 20..ph + 24].copy_from_slice(&0x200u32.to_le_bytes());
        data[ph + 24..ph + 28].copy_from_slice(&5u32.to_le_bytes());
        data[ph + 28..ph + 32].copy_from_slice(&0x1000u32.to_le_bytes());
        data[INFO + 2..INFO + 4].copy_from_slice(&0x0101u16.to_le_bytes());
        data[INFO + 4..INFO + 4 + 9].copy_from_slice(b"TestMod\0\0");
        data[INFO + 31] = 6;
        let put = |off: usize, value: u32, data: &mut [u8]| {
            data[off..off + 4].copy_from_slice(&value.to_le_bytes());
        };
        put(INFO + 36, (EXPORT - SEG_OFF) as u32, &mut data);
        put(INFO + 40, (EXPORT + 0x20 - SEG_OFF) as u32, &mut data);
        put(INFO + 44, (IMPORT - SEG_OFF) as u32, &mut data);
        put(INFO + 48, (IMPORT + 0x34 - SEG_OFF) as u32, &mut data);
        put(INFO + 52, 0x11223344, &mut data);
        put(INFO + 68, (START - SEG_OFF) as u32 | 1, &mut data);
        put(INFO + 72, 0xffff_ffff, &mut data);
        data[EXPORT..EXPORT + 2].copy_from_slice(&0x20u16.to_le_bytes());
        data[EXPORT + 6..EXPORT + 8].copy_from_slice(&1u16.to_le_bytes());
        put(EXPORT + 8, 1, &mut data);
        put(EXPORT + 24, BASE + (NIDTAB - SEG_OFF) as u32, &mut data);
        put(EXPORT + 28, BASE + (ENTTAB - SEG_OFF) as u32, &mut data);
        put(NIDTAB, 0x935c_d196, &mut data);
        put(NIDTAB + 4, 0x6c22_24ba, &mut data);
        put(ENTTAB, BASE + (START - SEG_OFF) as u32 | 1, &mut data);
        put(ENTTAB + 4, BASE + (INFO - SEG_OFF) as u32, &mut data);
        data[IMPORT..IMPORT + 2].copy_from_slice(&0x34u16.to_le_bytes());
        data[IMPORT + 2..IMPORT + 4].copy_from_slice(&1u16.to_le_bytes());
        data[IMPORT + 6..IMPORT + 8].copy_from_slice(&1u16.to_le_bytes());
        put(IMPORT + 20, BASE + (LIBNAME - SEG_OFF) as u32, &mut data);
        put(IMPORT + 28, BASE + (FNID - SEG_OFF) as u32, &mut data);
        put(IMPORT + 32, BASE + (FSTUB - SEG_OFF) as u32, &mut data);
        put(FNID, 0x0056_061b, &mut data);
        put(FSTUB, BASE + (SEG_OFF + 0x180 - SEG_OFF) as u32, &mut data);
        data[LIBNAME..LIBNAME + 8].copy_from_slice(b"SceLibc\0");
        data
    }

    const HEADER_LEN: usize = 0x1000;
    const META_OFF: usize = 0x600;
    const APPINFO_OFF: usize = 0x80;
    const ELF_OFF: usize = 0xB0;
    const PHDR_OFF: usize = 0xF0;
    const SEGINFO_OFF: usize = 0x110;

    #[allow(clippy::too_many_arguments)]
    fn wrap_self(
        inner: &[u8],
        self_type: u32,
        sysver: u64,
        compression: u64,
        encryption: u64,
        mut payload: Option<Vec<u8>>,
        metadata: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let seg_len = payload.as_ref().map(|p| p.len()).unwrap_or(0x200);
        let total = HEADER_LEN + seg_len;
        let mut data = vec![0u8; total];
        data[0..4].copy_from_slice(b"SCE\0");
        data[4..8].copy_from_slice(&3u32.to_le_bytes());
        data[8..10].copy_from_slice(&0xC0u16.to_le_bytes());
        data[10..12].copy_from_slice(&1u16.to_le_bytes());
        data[12..16].copy_from_slice(&(META_OFF as u32).to_le_bytes());
        data[16..24].copy_from_slice(&(HEADER_LEN as u64).to_le_bytes());
        data[24..32].copy_from_slice(&(inner.len() as u64).to_le_bytes());
        data[32..40].copy_from_slice(&(total as u64).to_le_bytes());
        data[48..56].copy_from_slice(&4u64.to_le_bytes());
        data[56..64].copy_from_slice(&(APPINFO_OFF as u64).to_le_bytes());
        data[64..72].copy_from_slice(&(ELF_OFF as u64).to_le_bytes());
        data[72..80].copy_from_slice(&(PHDR_OFF as u64).to_le_bytes());
        data[88..96].copy_from_slice(&(SEGINFO_OFF as u64).to_le_bytes());
        data[96..104].copy_from_slice(&0x130u64.to_le_bytes());
        data[104..112].copy_from_slice(&0x140u64.to_le_bytes());
        // App info: authid, vendor, self_type, sys_version.
        data[APPINFO_OFF..APPINFO_OFF + 8].copy_from_slice(&0x2F00_0000_0000_0001u64.to_le_bytes());
        data[APPINFO_OFF + 12..APPINFO_OFF + 16].copy_from_slice(&self_type.to_le_bytes());
        data[APPINFO_OFF + 16..APPINFO_OFF + 24].copy_from_slice(&sysver.to_le_bytes());
        // ELF header + program header copies (p_offset keeps the inner
        // file's own value — the loader places bytes by segment_info).
        data[ELF_OFF..ELF_OFF + 52].copy_from_slice(&inner[..52]);
        data[PHDR_OFF..PHDR_OFF + 32].copy_from_slice(&inner[52..84]);
        // segment_info: payload at HEADER_LEN, stored length, flags.
        data[SEGINFO_OFF..SEGINFO_OFF + 8].copy_from_slice(&(HEADER_LEN as u64).to_le_bytes());
        data[SEGINFO_OFF + 8..SEGINFO_OFF + 16].copy_from_slice(&(seg_len as u64).to_le_bytes());
        data[SEGINFO_OFF + 16..SEGINFO_OFF + 24].copy_from_slice(&compression.to_le_bytes());
        data[SEGINFO_OFF + 24..SEGINFO_OFF + 32].copy_from_slice(&encryption.to_le_bytes());
        if let Some(blob) = metadata {
            let end = META_OFF + 48 + blob.len();
            data[META_OFF + 48..end].copy_from_slice(&blob);
        }
        let bytes = payload.take().unwrap_or_else(|| inner[0x100..0x300].to_vec());
        data[HEADER_LEN..HEADER_LEN + bytes.len()].copy_from_slice(&bytes);
        data
    }

    fn plain_self() -> Vec<u8> {
        wrap_self(&inner_elf(), SELF_TYPE_APP, 0x0360_0000_0000, COMP_RAW, ENC_PLAIN, None, None)
    }

    fn check_import(images: Vec<(String, NativeImport)>) {
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, "");
        let imp = &images[0].1;
        assert_eq!(imp.format, "SELF");
        assert_eq!(imp.language, "ARM:LE:32:v7");
        assert!(!imp.mappings.is_empty());
        assert!(imp.mappings.iter().any(|m| m.vaddr == 0x8100_0000));
        let names: std::collections::HashMap<u64, &str> = imp
            .functions
            .iter()
            .map(|f| (f.entry, f.name.as_str()))
            .collect();
        assert_eq!(names.get(&0x8100_0160), Some(&"module_start"));
        assert_eq!(
            names.get(&0x8100_0180),
            Some(&"sce_import_SceLibc_0056061b")
        );
        assert_eq!(imp.process_entry, Some(0x8100_0160));
    }

    #[test]
    fn plain_self_unwraps_to_armv7_with_named_exports() {
        let data = plain_self();
        assert!(is_self(&data));
        let images = import(&data).expect("recognized").expect("import");
        check_import(images);
    }

    #[test]
    fn detectors_reject_other_formats() {
        assert!(!is_self(&[]));
        assert!(!is_self(b"\x7fELF....not really"));
        assert!(!is_self(&inner_elf()));
        assert!(import(&inner_elf()).is_none());
        // PS3-style big-endian header bytes never read as LE version 3.
        let mut be = plain_self();
        be[4..8].copy_from_slice(&3u32.to_be_bytes());
        assert!(!is_self(&be));
        // Decrypted Vita ELF detector names the bare module form.
        assert!(is_vita_elf(&inner_elf()));
        assert!(!is_vita_elf(b"\x7fELF\x01\x01\x01garbage"));
    }

    #[test]
    fn truncated_self_is_malformed_not_misdetected() {
        let data = plain_self();
        // Tables cut off: not our format.
        let short = data[..0x120].to_vec();
        assert!(!is_self(&short));
        assert!(import(&short).is_none());
        // Tables parse but the payload pointer leaves the file: recognized
        // as SELF, and the import fails instead of panicking.
        let mut bad_tables = data.clone();
        bad_tables[SEGINFO_OFF..SEGINFO_OFF + 8].copy_from_slice(&0xFFFFu64.to_le_bytes());
        assert!(is_self(&bad_tables));
        assert!(import(&bad_tables).expect("recognized").is_err());
    }

    // ------------------------------------------------ encrypted fixtures

    use aes::cipher::BlockCipherEncrypt;

    fn cbc_encrypt128(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let cipher = aes::Aes128::new(key.into());
        let mut prev: [u8; 16] = *iv;
        let mut out = Vec::with_capacity(data.len());
        for block in data.chunks_exact(16) {
            let mut b: [u8; 16] = block.try_into().unwrap();
            for (i, v) in b.iter_mut().enumerate() {
                *v ^= prev[i];
            }
            cipher.encrypt_block((&mut b).into());
            prev = b;
            out.extend_from_slice(&b);
        }
        out
    }

    fn cbc_encrypt256(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let cipher = aes::Aes256::new(key.into());
        let mut prev: [u8; 16] = *iv;
        let mut out = Vec::with_capacity(data.len());
        for block in data.chunks_exact(16) {
            let mut b: [u8; 16] = block.try_into().unwrap();
            for (i, v) in b.iter_mut().enumerate() {
                *v ^= prev[i];
            }
            cipher.encrypt_block((&mut b).into());
            prev = b;
            out.extend_from_slice(&b);
        }
        out
    }

    /// Build a metadata blob + CTR-encrypted payload using the embedded
    /// public USER keyrev-0 constants, mirroring sceutils `get_segments`
    /// in reverse.
    fn encrypted_user_parts() -> (Vec<u8>, Vec<u8>) {
        let key = &META_KEYS[7];
        assert_eq!((key.self_type, key.keyrev), (SELF_TYPE_USER, 0));
        let seg_key: [u8; 16] = *b"0123456789abcdef";
        let seg_iv: [u8; 16] = *b"fedcba9876543210";
        // MetadataInfo: key @0, zero pad, iv @32, zero pad.
        let mut info = vec![0u8; 64];
        info[..16].copy_from_slice(&seg_key);
        info[32..48].copy_from_slice(&seg_iv);
        let head = cbc_encrypt256(&key.key, &key.iv, &info);
        // MetadataHeader: sig_len, sig_type, 1 section, 2 keys, opt 0, 0, 0.
        let mut body = vec![0u8; 32];
        body[12..16].copy_from_slice(&1u32.to_le_bytes());
        body[16..20].copy_from_slice(&2u32.to_le_bytes());
        // MetadataSection `<QQIiIiIiiI`: offset, size, type 0, seg_idx 0,
        // hash NONE(1), hash_idx 0, encryption AES128CTR(3), key_idx 0,
        // iv_idx 1, compression NONE(1).
        let mut section = vec![0u8; 48];
        section[..8].copy_from_slice(&(HEADER_LEN as u64).to_le_bytes());
        section[8..16].copy_from_slice(&0x200u64.to_le_bytes());
        section[20..24].copy_from_slice(&0i32.to_le_bytes());
        section[24..28].copy_from_slice(&1i32.to_le_bytes());
        section[32..36].copy_from_slice(&3i32.to_le_bytes());
        section[36..40].copy_from_slice(&0i32.to_le_bytes());
        section[40..44].copy_from_slice(&1i32.to_le_bytes());
        section[44..48].copy_from_slice(&1i32.to_le_bytes());
        body.extend_from_slice(&section);
        body.extend_from_slice(&seg_key);
        body.extend_from_slice(&seg_iv);
        let tail = cbc_encrypt128(&seg_key, &seg_iv, &body);
        let mut blob = head;
        blob.extend_from_slice(&tail);
        // Segment payload: CTR-encrypt the inner segment bytes.
        let mut payload = inner_elf()[0x100..0x300].to_vec();
        super::super::crypto::aes128_ctr(&seg_key, &seg_iv, &mut payload);
        (blob, payload)
    }

    #[test]
    fn encrypted_user_self_decrypts_with_public_keys() {
        let (blob, payload) = encrypted_user_parts();
        let data = wrap_self(
            &inner_elf(),
            SELF_TYPE_USER,
            0x3630_0000_0000,
            COMP_RAW,
            1,
            Some(payload),
            Some(blob),
        );
        assert!(is_self(&data));
        let images = import(&data).expect("recognized").expect("import");
        check_import(images);
    }

    #[test]
    fn encrypted_app_self_without_klic_is_refused() {
        let (blob, payload) = encrypted_user_parts();
        let data = wrap_self(
            &inner_elf(),
            SELF_TYPE_APP,
            0x0360_0000_0000,
            COMP_RAW,
            1,
            Some(payload),
            Some(blob),
        );
        assert!(is_self(&data));
        let err = import(&data).expect("recognized").expect_err("needs klic");
        assert!(format!("{err:?}").contains("klic"), "unexpected: {err:?}");
    }

    /// Build an NPDRM APP metadata blob + CTR-encrypted payload wrapped in
    /// the caller's `klic`, mirroring sceutils `get_segments` in reverse:
    /// the AES-256 head carries the same section key/iv as the USER parts,
    /// additionally wrapped in the klic-derived key the loader unwraps.
    fn encrypted_app_parts(klic: &[u8; 16]) -> (Vec<u8>, Vec<u8>) {
        let meta = META_KEYS
            .iter()
            .find(|k| k.self_type == SELF_TYPE_APP && k.keyrev == 0)
            .expect("APP keyrev-0 metadata key");
        let np_key = NPDRM_KEYS
            .iter()
            .find(|(rev, _)| *rev == 0)
            .map(|(_, key)| key)
            .expect("NPDRM rev-0 key");
        let seg_key: [u8; 16] = *b"0123456789abcdef";
        let seg_iv: [u8; 16] = *b"fedcba9876543210";
        // MetadataInfo: key @0, zero pad, iv @32, zero pad.
        let mut info = vec![0u8; 64];
        info[..16].copy_from_slice(&seg_key);
        info[32..48].copy_from_slice(&seg_iv);
        let head_in = cbc_encrypt256(&meta.key, &meta.iv, &info);
        // The loader AES-decrypts the klic with the NPDRM key to obtain the
        // head key, so the fixture wraps it the same way round.
        let predec = cbc_decrypt128(np_key, &ZERO_IV, klic).expect("klic is one block");
        let predec: [u8; 16] = predec.try_into().expect("klic wrap is one block");
        let head = cbc_encrypt128(&predec, &ZERO_IV, &head_in);
        // MetadataHeader: sig_len, sig_type, 1 section, 2 keys, opt 0, 0, 0.
        let mut body = vec![0u8; 32];
        body[12..16].copy_from_slice(&1u32.to_le_bytes());
        body[16..20].copy_from_slice(&2u32.to_le_bytes());
        // MetadataSection `<QQIiIiIiiI`: offset, size, type 0, seg_idx 0,
        // hash NONE(1), hash_idx 0, encryption AES128CTR(3), key_idx 0,
        // iv_idx 1, compression NONE(1).
        let mut section = vec![0u8; 48];
        section[..8].copy_from_slice(&(HEADER_LEN as u64).to_le_bytes());
        section[8..16].copy_from_slice(&0x200u64.to_le_bytes());
        section[20..24].copy_from_slice(&0i32.to_le_bytes());
        section[24..28].copy_from_slice(&1i32.to_le_bytes());
        section[32..36].copy_from_slice(&3i32.to_le_bytes());
        section[36..40].copy_from_slice(&0i32.to_le_bytes());
        section[40..44].copy_from_slice(&1i32.to_le_bytes());
        section[44..48].copy_from_slice(&1i32.to_le_bytes());
        body.extend_from_slice(&section);
        body.extend_from_slice(&seg_key);
        body.extend_from_slice(&seg_iv);
        let tail = cbc_encrypt128(&seg_key, &seg_iv, &body);
        let mut blob = head;
        blob.extend_from_slice(&tail);
        // Segment payload: CTR-encrypt the inner segment bytes.
        let mut payload = inner_elf()[0x100..0x300].to_vec();
        super::super::crypto::aes128_ctr(&seg_key, &seg_iv, &mut payload);
        (blob, payload)
    }

    #[test]
    fn encrypted_app_self_decrypts_with_supplied_klic() {
        let klic: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let (blob, payload) = encrypted_app_parts(&klic);
        let data = wrap_self(
            &inner_elf(),
            SELF_TYPE_APP,
            0x0360_0000_0000,
            COMP_RAW,
            1,
            Some(payload),
            Some(blob),
        );
        assert!(is_self(&data));
        // Without keys the klic gap fires, through both entry points.
        for err in [
            import(&data).expect("recognized").expect_err("needs klic"),
            import_with(&data, &super::super::keys::KeyStore::empty())
                .expect("recognized")
                .expect_err("needs klic"),
        ] {
            assert!(format!("{err:?}").contains("klic"), "unexpected: {err:?}");
        }
        // A `klic = <hex>` line decrypts the image.
        let mut named = super::super::keys::KeyStore::empty();
        let hex: String = klic.iter().map(|b| format!("{b:02x}")).collect();
        named.parse_text_for_test(&format!("klic = {hex}"));
        let images = import_with(&data, &named)
            .expect("recognized")
            .expect("import");
        check_import(images);
        // A raw `.klic` dump decrypts it too.
        let path = std::env::temp_dir().join("vita-test-title.klic");
        std::fs::write(&path, klic).unwrap();
        let raw = super::super::keys::KeyStore::load(&path).unwrap();
        let images = import_with(&data, &raw)
            .expect("recognized")
            .expect("import");
        check_import(images);

        std::fs::remove_file(&path).ok();
    }
    #[test]
    fn compressed_segment_is_refused() {
        let data = wrap_self(
            &inner_elf(),
            SELF_TYPE_APP,
            0x0360_0000_0000,
            COMP_ZLIB,
            ENC_PLAIN,
            None,
            None,
        );
        assert!(is_self(&data));
        let err = import(&data).expect("recognized").expect_err("compressed");
        assert!(format!("{err:?}").contains("zlib"), "unexpected: {err:?}");
    }
}
