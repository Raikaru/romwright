//! KIRK-backed `~PSP` decryption for PSP modules.
//!
//! Facts ported from public references (no code copied from any
//! implementation):
//!
//! - The `~PSP` wrapper is a 0x150-byte `PSP_Header`: an 0x80-byte prefix,
//!   scattered key material at 0x80..0xD0, the 4-byte tag at 0xD0, a SHA-1
//!   slot at 0x12C, an id slot at 0x140, and the AES-CBC payload past 0x150.
//! - `pspDecryptPRX` tries decrypt types 0, 1, 2, 5, 6, 9 in order; the
//!   first whose header check passes wins. Each type looks the tag up in a
//!   public tag table, unscrambles the key/id fields with `kirk7`
//!   (AES-128-CBC decrypt, zero IV, keyed by the 128-entry vault), hashes
//!   the rearranged header with SHA-1, then runs KIRK CMD1: the AES+CMAC
//!   keypair is AES-128-CBC-decrypted with the CMD1 master key and the
//!   payload with that AES key.
//! - Type 0/1 keys arrive pre-expanded (144 bytes used as the XOR buffer,
//!   with one raw exception the hardware would unscramble first); types
//!   2/5/6/9 expand their 16-byte seed into a 0x90-byte XOR buffer by
//!   stamping the block index into each block and running `kirk7` over it.
//! - A module whose header names decrypt_mode 23 (SPRX, arrived in an NPDRM
//!   EDAT) carries a fixed extra XOR on its type-5 key.
//! - The KIRK key vault, the CMD1 master key, and every tag table entry are
//!   long-public constants (PSARDUMPER/JPCSP dumps); they live generated in
//!   `kirk_tables.rs`, not hand-copied here.
//! - Type 6/9 headers verify an ECDSA signature on real hardware; a loader
//!   only needs the bytes, so the signature is not verified here — the
//!   SHA-1 header check still gates every type.
//! - A decrypted payload starting `KL4E`/`KL3E`/`KL2E` is zlib-deflated past
//!   a small header and is inflated before import.
//!
//! What this module does not do: `kirk7` inverses for any path the loader
//! never runs, CMAC bookkeeping (integrity already rides the SHA-1 header
//! check), or ECDSA arithmetic.

use super::crypto::{aes128_cbc_decrypt, sha1};
use super::kirk_tables::{
    KEYVAULT, KIRK1_KEY, TAG_INFO, TAG_INFO2, XOR_91E0A9AD, TagInfo, TagInfo2,
};
use super::{ImportError, err};

/// Internal fallible step: any failure means "try the next decrypt type".
type KirkResult<T> = std::result::Result<T, ()>;

/// Size of the `~PSP` header every decrypt type rearranges.
const PSP_HEADER: usize = 0x150;
/// Size of a KIRK CMD1 (header or ECDSA-header: both are 0x90 bytes).
const KIRK_HEADER: usize = 0x90;
/// Size of the plaintext prefix copied verbatim (`prxHeader`).
const PRX_HEADER: usize = 0x80;
/// Where the reassembled KIRK header sits in the output buffer:
/// `0x150 - 0x90 - 0x80`. The payload then lands exactly at 0x150, over the
/// file's own ciphertext, when `data_offset` is 0x80.
const OUT_OFF: usize = PSP_HEADER - KIRK_HEADER - PRX_HEADER;
/// `decrypt_mode` value marking an NPDRM-EDAT SPRX (extra fixed XOR).
const DECRYPT_MODE_SPRX: u8 = 23;

fn u32le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// `kirk7`: AES-128-CBC decrypt with vault key `code`. False when the key id
/// is out of range (a corrupt tag entry), so the type is skipped.
fn kirk7(data: &mut [u8], code: u8) -> bool {
    let Some(key) = KEYVAULT.get(code as usize) else {
        return false;
    };
    aes128_cbc_decrypt(key, data).is_ok()
}

/// Stamps the 16-byte seed into nine blocks (block index in byte 0), runs
/// `kirk7` over the 0x90-byte buffer, then folds in the bonus seed when one
/// is supplied (only type 5 passes one; the loader always passes none).
pub(crate) fn expand_seed(
    seed: &[u8; 16],
    code: u8,
    bonus: Option<&[u8; 16]>,
) -> Option<[u8; 0x90]> {
    let mut buf = [0u8; 0x90];
    for (i, chunk) in buf.chunks_mut(16).enumerate() {
        chunk.copy_from_slice(seed);
        chunk[0] = i as u8;
    }
    if !kirk7(&mut buf, code) {
        return None;
    }
    if let Some(extra) = bonus {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte ^= extra[i % 16];
        }
    }
    Some(buf)
}

/// The type-2/5/6/9 header pass: XOR with the expanded seed, `kirk7`, XOR
/// with the seed's second half.
fn decrypt_kirk_header(
    out: &mut [u8; 0x40],
    input: &[u8; 0x40],
    xor: &[u8; 0x90],
    code: u8,
) -> bool {
    let mut tmp = [0u8; 0x40];
    for i in 0..0x40 {
        tmp[i] = input[i] ^ xor[0x10 + i];
    }
    if !kirk7(&mut tmp, code) {
        return false;
    }
    for i in 0..0x40 {
        out[i] = tmp[i] ^ xor[0x50 + i];
    }
    true
}

/// The type-0/1 header pass: same shape over 0x70 bytes at seed offsets
/// 0x14 and 0x20.
fn decrypt_kirk_header_type0(
    out: &mut [u8; 0x70],
    input: &[u8],
    xor: &[u8; 0x90],
    code: u8,
) -> bool {
    let mut tmp = [0u8; 0x70];
    for i in 0..0x70 {
        tmp[i] = input[i] ^ xor[0x14 + i];
    }
    if !kirk7(&mut tmp, code) {
        return false;
    }
    for i in 0..0x70 {
        out[i] = tmp[i] ^ xor[0x20 + i];
    }
    true
}

/// Finish a decrypt: the reassembled header sits at `OUT_OFF`, the payload
/// ciphertext follows the 0x80-byte prefix copy. Decrypts the AES keypair
/// with the CMD1 master key, the payload with that AES key, and moves the
/// plaintext to the front of `out`. Returns the payload length.
fn cmd1_payload(out: &mut [u8], header: &[u8; KIRK_HEADER]) -> KirkResult<usize> {
    let data_size = u32le(&header[0x70..0x74]) as usize;
    let data_offset = u32le(&header[0x74..0x78]) as usize;
    let aligned = data_size.next_multiple_of(16);
    let start = OUT_OFF + KIRK_HEADER + data_offset;
    let end = start.checked_add(aligned).ok_or(())?;
    if end > out.len() || start < PSP_HEADER {
        return Err(());
    }
    let mut keys = [0u8; 32];
    keys.copy_from_slice(&header[0..0x20]);
    aes128_cbc_decrypt(&KIRK1_KEY, &mut keys).map_err(|_| ())?;
    let mut aes_key = [0u8; 16];
    aes_key.copy_from_slice(&keys[0..16]);
    aes128_cbc_decrypt(&aes_key, &mut out[start..end]).map_err(|_| ())?;
    out.copy_within(start..start + data_size, 0);
    Ok(data_size)
}

/// The `comp_size` word: how many front bytes the caller keeps. Negative or
/// overlong sizes fail the type instead of panicking downstream.
fn decrypt_size(data: &[u8], out_len: usize) -> KirkResult<usize> {
    let size = i32::from_le_bytes([
        data[0xB0],
        data[0xB1],
        data[0xB2],
        data[0xB3],
    ]);
    if size < 0 || size as usize > out_len {
        return Err(());
    }
    Ok(size as usize)
}

fn lookup_tag(tag: u32) -> Result<&'static TagInfo, ()> {
    // First match wins: the table holds one tag twice (letter case), and
    // the reference's linear search stops at the first.
    TAG_INFO.iter().find(|t| t.tag == tag).ok_or(())
}

fn lookup_tag2(tag: u32) -> Result<&'static TagInfo2, ()> {
    TAG_INFO2.iter().find(|t| t.tag == tag).ok_or(())
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

// ---------------------------------------------------------------- type 0

fn try_type0(data: &[u8], out: &mut [u8]) -> KirkResult<usize> {
    out.copy_from_slice(data);
    let entry = lookup_tag(u32le(&data[0xD0..0xD4]))?;
    let mut xor = [0u8; 0x90];
    xor.copy_from_slice(entry.key);
    if entry.scramble_key && !kirk7(&mut xor, entry.code) {
        return Err(());
    }
    let mut kirk_block = [0u8; 0x90];
    kirk_block[0..0x40].copy_from_slice(&data[0x110..0x150]);
    kirk_block[0x40..0x90].copy_from_slice(&data[0x80..0xD0]);
    if sha1(&[
        &xor[0..0x14],
        &data[0xE8..0x110],
        &kirk_block,
        &data[0..0x80],
    ]) != data[0xD4..0xE8]
    {
        return Err(());
    }
    let mut header = [0u8; KIRK_HEADER];
    header.copy_from_slice(&kirk_block);
    if !decrypt_kirk_header_type0(
        (&mut header[0..0x70]).try_into().map_err(|_| ())?,
        &kirk_block,
        &xor,
        entry.code,
    ) {
        return Err(());
    }
    out[OUT_OFF..OUT_OFF + KIRK_HEADER].copy_from_slice(&header);
    out[OUT_OFF + KIRK_HEADER..OUT_OFF + KIRK_HEADER + PRX_HEADER]
        .copy_from_slice(&data[0..PRX_HEADER]);
    cmd1_payload(out, &header)?;
    decrypt_size(data, out.len())
}

// ---------------------------------------------------------------- type 1

fn try_type1(data: &[u8], out: &mut [u8]) -> KirkResult<usize> {
    out.copy_from_slice(data);
    let entry = lookup_tag(u32le(&data[0xD0..0xD4]))?;
    let mut xor = [0u8; 0x90];
    xor.copy_from_slice(entry.key);
    // Rearranged: tag, sha1, unused, key block, prefix.
    let mut r = [0u8; PSP_HEADER];
    r[0..4].copy_from_slice(&data[0xD0..0xD4]);
    r[4..0x18].copy_from_slice(&data[0xD4..0xE8]);
    r[0x18..0x40].copy_from_slice(&data[0xE8..0x110]);
    r[0x40..0x80].copy_from_slice(&data[0x110..0x150]);
    r[0x80..0xD0].copy_from_slice(&data[0x80..0xD0]);
    r[0xD0..0x150].copy_from_slice(&data[0..0x80]);
    if !kirk7(&mut r[0x10..0xB0], entry.code) {
        return Err(());
    }
    if sha1(&[&xor[0..0x14], &r[0x18..0x40], &r[0x40..0xD0], &r[0xD0..0x150]])
        != r[4..0x18]
    {
        return Err(());
    }
    let mut header = [0u8; KIRK_HEADER];
    header.copy_from_slice(&r[0x40..0xD0]);
    if !decrypt_kirk_header_type0(
        (&mut header[0..0x70]).try_into().map_err(|_| ())?,
        &r[0x40..0xD0],
        &xor,
        entry.code,
    ) {
        return Err(());
    }
    out[OUT_OFF..OUT_OFF + KIRK_HEADER].copy_from_slice(&header);
    out[OUT_OFF + KIRK_HEADER..OUT_OFF + KIRK_HEADER + PRX_HEADER]
        .copy_from_slice(&data[0..PRX_HEADER]);
    cmd1_payload(out, &header)?;
    decrypt_size(data, out.len())
}

// ----------------------------------------- shared type-2/5/6/9 rearrange
//
// Rearranged 0x150-byte form: tag[0..4], zero gap, id at 0x5C, sha1 at
// 0x6C, key header at 0x80, metadata at 0xC0, prefix at 0xD0. Types 2 and 5
// leave a 0x58 gap; types 6 and 9 carry the ECDSA tail at 0x3C..0x5C.

/// Scatter the file's key fields into the rearranged form. `tail_from` is
/// the file offset of the ECDSA tail for type 6, none for 2/5/9 (type 9's
/// signature bytes hash as zero).
fn rearrange(data: &[u8], tail_from: Option<usize>) -> [u8; PSP_HEADER] {
    let mut r = [0u8; PSP_HEADER];
    r[0..4].copy_from_slice(&data[0xD0..0xD4]);
    if let Some(off) = tail_from {
        r[0x3C..0x5C].copy_from_slice(&data[off..off + 0x20]);
    }
    r[0x5C..0x6C].copy_from_slice(&data[0x140..0x150]);
    r[0x6C..0x80].copy_from_slice(&data[0x12C..0x140]);
    r[0x80..0xB0].copy_from_slice(&data[0x80..0xB0]);
    r[0xB0..0xC0].copy_from_slice(&data[0xC0..0xD0]);
    r[0xC0..0xD0].copy_from_slice(&data[0xB0..0xC0]);
    r[0xD0..0x150].copy_from_slice(&data[0..0x80]);
    r
}

/// SHA-1 over the rearranged header: tag, seed head, gap, tail, id, key
/// header, metadata, prefix. The gap covers 0x58 bytes for types 2/5 (tail
/// range included as zeros) and 0x38 + tail for 6/9 — slicing the buffer
/// this way hashes both layouts correctly.
fn header_hash(r: &[u8; PSP_HEADER], xor_head: &[u8], wide_gap: bool) -> [u8; 20] {
    if wide_gap {
        sha1(&[
            &r[0..4],
            xor_head,
            &r[4..0x5C],
            &r[0x5C..0x6C],
            &r[0x80..0xC0],
            &r[0xC0..0xD0],
            &r[0xD0..0x150],
        ])
    } else {
        sha1(&[
            &r[0..4],
            xor_head,
            &r[4..0x3C],
            &r[0x3C..0x5C],
            &r[0x5C..0x6C],
            &r[0x80..0xC0],
            &r[0xC0..0xD0],
            &r[0xD0..0x150],
        ])
    }
}

/// Write the decrypted header and prefix copy into `out`, then run CMD1.
fn finish(
    out: &mut [u8],
    r: &[u8; PSP_HEADER],
    xor: &[u8; 0x90],
    code: u8,
    ecdsa: bool,
) -> KirkResult<()> {
    let mut header = [0u8; KIRK_HEADER];
    header[0x70..0x80].copy_from_slice(&r[0xC0..0xD0]);
    if !decrypt_kirk_header(
        (&mut header[0..0x40]).try_into().map_err(|_| ())?,
        r[0x80..0xC0].try_into().map_err(|_| ())?,
        xor,
        code,
    ) {
        return Err(());
    }
    header[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
    if ecdsa {
        header[0x64] = 1;
    }
    out[OUT_OFF..OUT_OFF + KIRK_HEADER].copy_from_slice(&header);
    out[OUT_OFF + KIRK_HEADER..OUT_OFF + KIRK_HEADER + PRX_HEADER]
        .copy_from_slice(&r[0xD0..0x150]);
    cmd1_payload(out, &header)?;
    Ok(())
}

// ---------------------------------------------------------------- type 2

fn try_type2(data: &[u8], out: &mut [u8]) -> KirkResult<usize> {
    out.copy_from_slice(data);
    let entry = lookup_tag2(u32le(&data[0xD0..0xD4]))?;
    if !all_zero(&data[0xD4..0x12C]) {
        return Err(());
    }
    let xor = expand_seed(entry.key, entry.code, None).ok_or(())?;
    let mut r = rearrange(data, None);
    if !kirk7(&mut r[0x5C..0xBC], entry.code) {
        return Err(());
    }
    if header_hash(&r, &xor[0..0x10], true) != r[0x6C..0x80] {
        return Err(());
    }
    finish(out, &r, &xor, entry.code, false)?;
    decrypt_size(data, out.len())
}

// ---------------------------------------------------------------- type 5

fn try_type5(data: &[u8], out: &mut [u8]) -> KirkResult<usize> {
    out.copy_from_slice(data);
    let entry = lookup_tag2(u32le(&data[0xD0..0xD4]))?;
    if !all_zero(&data[0xD5..0x12C]) {
        return Err(());
    }
    let xor = expand_seed(entry.key, entry.code, None).ok_or(())?;
    // The decrypt_mode XOR wins over the tag table's fallback.
    let xor1: Option<&[u8; 16]> = if data[0x7C] == DECRYPT_MODE_SPRX {
        Some(&XOR_91E0A9AD)
    } else {
        entry.seed
    };
    let mut r = rearrange(data, None);
    // First the key header plus the SHA-1 head, folded with the XOR...
    let mut block = [0u8; 0x50];
    block[0..0x40].copy_from_slice(&r[0x80..0xC0]);
    block[0x40..0x50].copy_from_slice(&r[0x6C..0x7C]);
    if let Some(x) = xor1 {
        for (i, b) in block.iter_mut().enumerate() {
            *b ^= x[i % 16];
        }
    }
    if !kirk7(&mut block, entry.code) {
        return Err(());
    }
    r[0x80..0xC0].copy_from_slice(&block[0..0x40]);
    r[0x6C..0x7C].copy_from_slice(&block[0x40..0x50]);
    // ...then the id run through to the key header.
    if let Some(x) = xor1 {
        for (i, b) in r[0x5C..0xBC].iter_mut().enumerate() {
            *b ^= x[i % 16];
        }
    }
    if !kirk7(&mut r[0x5C..0xBC], entry.code) {
        return Err(());
    }
    if header_hash(&r, &xor[0..0x10], true) != r[0x6C..0x80] {
        return Err(());
    }
    finish(out, &r, &xor, entry.code, false)?;
    decrypt_size(data, out.len())
}

// ---------------------------------------------------------------- type 6

fn try_type6(data: &[u8], out: &mut [u8]) -> KirkResult<usize> {
    out.copy_from_slice(data);
    let entry = lookup_tag2(u32le(&data[0xD0..0xD4]))?;
    if !all_zero(&data[0xD4..0x10C]) {
        return Err(());
    }
    let xor = expand_seed(entry.key, entry.code, None).ok_or(())?;
    let mut r = rearrange(data, Some(0x10C));
    if !kirk7(&mut r[0x5C..0xBC], entry.code) {
        return Err(());
    }
    if header_hash(&r, &xor[0..0x10], false) != r[0x6C..0x80] {
        return Err(());
    }
    // The signature tail rides along in the output header's unused half.
    out[OUT_OFF + 0x40..OUT_OFF + 0x60].copy_from_slice(&r[0x3C..0x5C]);
    finish(out, &r, &xor, entry.code, true)?;
    decrypt_size(data, out.len())
}

// ---------------------------------------------------------------- type 9

fn try_type9(data: &[u8], out: &mut [u8]) -> KirkResult<usize> {
    out.copy_from_slice(data);
    let entry = lookup_tag2(u32le(&data[0xD0..0xD4]))?;
    // Only up to 0x104: past that is the signature, present rather than
    // empty here, and hashed as zero (see `rearrange`).
    if !all_zero(&data[0xD4..0x104]) {
        return Err(());
    }
    let xor = expand_seed(entry.key, entry.code, None).ok_or(())?;
    let mut r = rearrange(data, None);
    if !kirk7(&mut r[0x5C..0xBC], entry.code) {
        return Err(());
    }
    if header_hash(&r, &xor[0..0x10], false) != r[0x6C..0x80] {
        return Err(());
    }
    finish(out, &r, &xor, entry.code, false)?;
    decrypt_size(data, out.len())
}

// ---------------------------------------------------------------- entry

/// True for a KL-compressed payload: the decrypted output starts with the
/// `KL2E`/`KL3E`/`KL4E` magic.
fn is_kl(data: &[u8]) -> bool {
    data.len() >= 4
        && (&data[0..4] == b"KL4E" || &data[0..4] == b"KL3E" || &data[0..4] == b"KL2E")
}

/// Inflate a KL-compressed payload: a small header, then a zlib stream.
fn decompress_kl(payload: &[u8]) -> std::result::Result<Vec<u8>, ImportError> {
    if payload.len() <= 0x10 {
        return err("KL-compressed PSP payload holds only a header");
    }
    miniz_oxide::inflate::decompress_to_vec_zlib(&payload[0x10..]).map_err(|e| {
        super::ImportError::Bad(format!("KL-compressed PSP payload failed to inflate: {e}"))
    })
}

/// Decrypts a `~PSP` image to its payload: tries types 0, 1, 2, 5, 6, 9 in
/// order, first success wins, then inflates KL-compressed payloads. Errors
/// cleanly when no type's header check passes.
pub(crate) fn decrypt_prx(data: &[u8]) -> std::result::Result<Vec<u8>, ImportError> {
    if data.len() < PSP_HEADER {
        return err(format!(
            "encrypted PSP module (~PSP/KIRK) is {} bytes, smaller than the 0x150-byte header",
            data.len()
        ));
    }
    let mut out = data.to_vec();
    let decrypted = try_type0(data, &mut out)
        .or_else(|()| try_type1(data, &mut out))
        .or_else(|()| try_type2(data, &mut out))
        .or_else(|()| try_type5(data, &mut out))
        .or_else(|()| try_type6(data, &mut out))
        .or_else(|()| try_type9(data, &mut out));
    let size = match decrypted {
        Ok(size) => size,
        Err(()) => {
            let tag = u32le(&data[0xD0..0xD4]);
            return err(format!(
                "encrypted PSP module (~PSP/KIRK) with tag 0x{tag:08X} matches no PRX decrypt type \
                 (tried 0,1,2,5,6,9): unknown tag or corrupt header; decrypt first with prxtool, \
                 prxdecrypt or PPSSPP"
            ));
        }
    };
    out.truncate(size);
    if is_kl(&out) {
        let inflated = decompress_kl(&out)?;
        if inflated.is_empty() {
            return err("KL-compressed PSP payload inflated to nothing");
        }
        return Ok(inflated);
    }
    Ok(out)
}
