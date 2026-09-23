//! Xbox 360 XEX2 images (Xenon = PowerPC A2, `PowerPC:BE:64:Xenon-32addr`).
//!
//! A `.xex` is a big-endian container wrapping an encrypted, optionally
//! LZX-compressed PE image. The format is ported from zeroKilo/XEXLoaderWV
//! (Apache-2.0), which is the reference implementation; field offsets and the
//! crypto pipeline are taken from its `XEXHeader`, `XEXLoaderInfo`, and
//! `BaseFileFormat`.
//!
//! Layout (all integers big-endian):
//!   header: magic "XEX2", flags, offsetPE, reserved, offsetSecuInfo,
//!           nOptHeader, then nOptHeader 8-byte {id, value} records.
//!   optional headers: id>>8 selects the kind — 0x3 base file format
//!           (encryption/compression), 0x101 entry point, 0x102 image base,
//!           0x103 import libraries. The low byte of id sizes the payload.
//!   security info at offsetSecuInfo: imageSize @+4, fileKey @+0x11C,
//!           then a section table at +0x180.
//!
//! Crypto: the retail key `20B185A59D28FDC340583FBB0896BF91` (a public
//! constant, the same one xextool embeds — no runtime fetch) AES-CBC-decrypts
//! the fileKey into a sessionKey, which AES-CBC-decrypts the PE payload. Both
//! use a zero IV, so CBC reduces to ECB-decrypt each block then XOR the prior
//! ciphertext block.
//!
//! Compression: 0/3 raw, 1 basic (dataSize/zeroSize runs), 2 normal (the
//! custom block framing over an LZX stream, window_bits 15).

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::Aes128;

use super::{DeclaredRegion, Mapping, NativeFunction, NativeImport, Result};

/// "XEX2".
const MAGIC: u32 = 0x5845_5832;
/// The retail XEX key, a public constant (xextool, XEXLoaderWV).
const RETAIL_KEY: [u8; 16] = [
    0x20, 0xb1, 0x85, 0xa5, 0x9d, 0x28, 0xfd, 0xc3, 0x40, 0x58, 0x3f, 0xbb, 0x08, 0x96, 0xbf, 0x91,
];
/// AES block size.
const BLOCK: usize = 16;

fn be32(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| super::ImportError::Bad("xex: truncated u32".into()))
}
fn be16(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| super::ImportError::Bad("xex: truncated u16".into()))
}

/// AES-CBC decrypt with a zero IV: each plaintext block is the ECB-decrypted
/// ciphertext XOR the previous ciphertext block (the first XORs zero).
fn aes_cbc_decrypt(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());
    let mut out = Vec::with_capacity(data.len());
    let mut prev = [0u8; BLOCK];
    for chunk in data.chunks(BLOCK) {
        let mut block = [0u8; BLOCK];
        let n = chunk.len().min(BLOCK);
        block[..n].copy_from_slice(&chunk[..n]);
        let mut dec = block;
        cipher.decrypt_block((&mut dec).into());
        for i in 0..BLOCK {
            dec[i] ^= prev[i];
        }
        prev = block;
        out.extend_from_slice(&dec[..n]);
    }
    out
}

/// One optional-header record's resolved payload.
struct OptHeader {
    id: u32,
    data: Vec<u8>,
}

/// Reads the optional headers. The low byte of `id` encodes how the payload
/// is located (XEXHeader.ProcessOptionalHeaders).
fn read_opt_headers(data: &[u8], count: usize) -> Result<Vec<OptHeader>> {
    let mut out = Vec::new();
    for i in 0..count {
        let rec = 24 + i * 8;
        let id = be32(data, rec)?;
        let value = be32(data, rec + 4)? as usize;
        let low = id & 0xFF;
        let payload = if low == 0xFF {
            let len = be32(data, value)? as usize;
            data.get(value..value + len)
                .ok_or_else(|| super::ImportError::Bad("xex: opt header payload truncated".into()))?
                .to_vec()
        } else if low < 2 {
            // The value field itself is the payload.
            data.get(rec + 4..rec + 8)
                .ok_or_else(|| super::ImportError::Bad("xex: opt header inline truncated".into()))?
                .to_vec()
        } else {
            let len = (low as usize) * 4;
            data.get(value..value + len)
                .ok_or_else(|| super::ImportError::Bad("xex: opt header sized truncated".into()))?
                .to_vec()
        };
        out.push(OptHeader { id, data: payload });
    }
    Ok(out)
}

/// The decompressed PE image, recovered from the (decrypted) payload per the
/// base file format's compression mode.
fn decompress(
    compression: u16,
    basic: &[(u32, u32)],
    block_size: u32,
    image_size: usize,
    compressed: &[u8],
) -> Result<Vec<u8>> {
    match compression {
        0 | 3 => Ok(compressed.to_vec()),
        1 => {
            // Basic: copy dataSize bytes, then zeroSize bytes of padding.
            let mut out = Vec::with_capacity(image_size);
            let mut pos = 0usize;
            for &(data_size, zero_size) in basic {
                let n = data_size as usize;
                out.extend_from_slice(
                    compressed
                        .get(pos..pos + n)
                        .ok_or_else(|| super::ImportError::Bad("xex: basic compression overruns input".into()))?,
                );
                out.resize(out.len() + zero_size as usize, 0);
                pos += n;
            }
            Ok(out)
        }
        2 => {
            // Normal: a custom block framing over an LZX stream. Each block
            // leads with a nextSize u32, then 20 bytes of header, then
            // length-prefixed chunks whose payloads concatenate into the LZX
            // input (XEXHeader.ReadPEImage case 2).
            let mut lzx_input = Vec::new();
            let mut pos = 0usize;
            let bs = block_size as usize;
            loop {
                let next = be32(compressed, pos)? as usize;
                let block_end = (pos + bs).min(compressed.len());
                let mut i = pos + 24;
                while i + 2 <= block_end {
                    let len = be16(compressed, i)? as usize;
                    if len == 0 {
                        break;
                    }
                    lzx_input.extend_from_slice(
                        compressed
                            .get(i + 2..i + 2 + len)
                            .ok_or_else(|| super::ImportError::Bad("xex: lzx chunk truncated".into()))?,
                    );
                    i += 2 + len;
                }
                if next == 0 {
                    break;
                }
                pos += next;
                if pos >= compressed.len() {
                    break;
                }
            }
            // window_bits 15 -> 32 KB window (LzxDecompression.init(15, ...)).
            let mut lzxd = lzxd::Lzxd::new(lzxd::WindowSize::KB32);
            let mut out = Vec::new();
            let mut chunk = lzx_input.as_slice();
            while !chunk.is_empty() {
                let decoded = lzxd
                    .decompress_next(chunk, image_size - out.len())
                    .map_err(|e| super::ImportError::Bad(format!("xex: lzx: {e}")))?;
                if decoded.is_empty() {
                    break;
                }
                out.extend_from_slice(decoded);
                // decompress_next consumes the whole slice each call.
                break;
            }
            let _ = &mut chunk;
            Ok(out)
        }
        other => super::err(&format!("xex: compression {other} not supported")),
    }
}

/// True when `data` is an XEX2 image.
pub(crate) fn is_xex(data: &[u8]) -> bool {
    data.len() >= 24 && be32(data, 0).ok() == Some(MAGIC)
}

/// Loads an XEX2 image: decrypts and decompresses the embedded PE, maps its
/// sections at `imageBase + VirtualAddress`, and seeds the entry point.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    if !is_xex(data) {
        return super::err("not an XEX2 image");
    }
    let offset_pe = be32(data, 8)? as usize;
    let offset_sec = be32(data, 16)? as usize;
    let n_opt = be32(data, 20)? as usize;
    let headers = read_opt_headers(data, n_opt)?;

    let mut encryption = 0u16;
    let mut compression = 0u16;
    let mut basic: Vec<(u32, u32)> = Vec::new();
    let mut block_size = 0u32;
    let mut entry = 0u32;
    let mut image_base = 0u32;
    for h in &headers {
        match h.id >> 8 {
            0x3 => {
                encryption = be16(&h.data, 4)?;
                compression = be16(&h.data, 6)?;
                match compression {
                    1 => {
                        let count = h.data.len() / 8 - 1;
                        for i in 0..count {
                            basic.push((
                                be32(&h.data, 8 + i * 8)?,
                                be32(&h.data, 0xC + i * 8)?,
                            ));
                        }
                    }
                    2 | 3 => {
                        block_size = be32(&h.data, 0xC)?;
                    }
                    _ => {}
                }
            }
            0x101 => entry = be32(&h.data, 0)?,
            0x102 => image_base = be32(&h.data, 0)?,
            _ => {}
        }
    }

    // Security info: imageSize @+4. The AES file key sits at +0x150 in the
    // XEX2 security info retail and late development images carry, and at
    // +0x11C in the earlier layout; which applies is proven by decryption.
    let image_size = be32(data, offset_sec + 4)? as usize;
    let file_keys: Vec<[u8; 16]> = [0x150usize, 0x11C]
        .iter()
        .filter_map(|&at| data.get(offset_sec + at..offset_sec + at + 16)?.try_into().ok())
        .collect();
    if file_keys.is_empty() {
        return super::err("xex: fileKey truncated");
    }
    // The PE payload runs from offsetPE to EOF.
    let payload = data
        .get(offset_pe..)
        .ok_or_else(|| super::ImportError::Bad("xex: no PE payload".into()))?;
    if encryption != 0 && encryption != 1 {
        return super::err(&format!("xex: encryption {encryption} not supported"));
    }
    // Retail images are keyed by the retail key; development and
    // pre-release builds by the devkit key, which is all zeros. Which one
    // applies is only known by decrypting: the right key yields an `MZ`
    // image (XEXLoaderWV tries them in this order).
    let mut pe_image = Vec::new();
    'keys: for (key, file_key) in [RETAIL_KEY, [0u8; 16]]
        .into_iter()
        .flat_map(|key| file_keys.iter().map(move |file_key| (key, *file_key)))
    {
        let session_key: [u8; 16] = aes_cbc_decrypt(&key, &file_key)
            .try_into()
            .map_err(|_| super::ImportError::Bad("xex: session key".into()))?;
        let plain = if encryption == 1 {
            aes_cbc_decrypt(&session_key, payload)
        } else {
            payload.to_vec()
        };
        match decompress(compression, &basic, block_size, image_size, &plain) {
            Ok(image) if image.starts_with(b"MZ") => {
                pe_image = image;
                break 'keys;
            }
            Ok(image) if pe_image.is_empty() => pe_image = image,
            Ok(_) => {}
            Err(error) if encryption == 0 => return Err(error),
            Err(_) => {}
        }
        if encryption == 0 {
            break;
        }
    }

    // The decompressed image is a memory image: each PE section's bytes sit at
    // its VirtualAddress (RVA), not PointerToRawData (XEXHeader.ProcessPEImage
    // reads peImage[VirtualAddress..]). Map sections at imageBase + RVA.
    let mut mappings = Vec::new();
    let mut names = Vec::new();
    // PE header: e_lfanew @0x3C, then PE sig + COFF + optional header.
    let pe_off = pe_image
        .get(0x3C..0x40)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0) as usize;
    let num_sections = pe_image
        .get(pe_off + 6..pe_off + 8)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0) as usize;
    let opt_size = pe_image
        .get(pe_off + 20..pe_off + 22)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0) as usize;
    let sec_table = pe_off + 24 + opt_size;
    for i in 0..num_sections {
        let o = sec_table + i * 40;
        let name = pe_image
            .get(o..o + 8)
            .map(|s| {
                String::from_utf8_lossy(s)
                    .trim_end_matches('\0')
                    .to_string()
            })
            .unwrap_or_default();
        let vsize = pe_image
            .get(o + 8..o + 12)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            .unwrap_or(0) as usize;
        let vaddr = pe_image
            .get(o + 12..o + 16)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            .unwrap_or(0) as u64;
        let chars = pe_image
            .get(o + 36..o + 40)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            .unwrap_or(0) as u64;
        if vsize == 0 {
            continue;
        }
        // Section bytes live at RVA in the memory image.
        let bytes = pe_image
            .get(vaddr as usize..vaddr as usize + vsize)
            .unwrap_or(&[])
            .to_vec();
        let flags = (u64::from(chars & 0x20000000 != 0) << 2)
            | (u64::from(chars & 0x40000000 != 0) << 1)
            | u64::from(chars & 0x80000000 != 0);
        mappings.push(Mapping {
            vaddr: u64::from(image_base) + vaddr,
            size: vsize as u64,
            file_off: vaddr,
            flags,
            bytes,
        });
        names.push(if name.is_empty() { format!("sec{i}") } else { name });
    }
    if mappings.is_empty() {
        return super::err("xex: PE image has no sections");
    }
    let entry_addr = u64::from(image_base) + u64::from(entry);
    let mut import = NativeImport {
        mappings,
        mapping_names: names,
        format: "xex".into(),
        language: "PowerPC:BE:64:Xenon-32addr".into(),
        process_entry: Some(entry_addr),
        ..Default::default()
    };
    import.functions.push(NativeFunction {
        entry: entry_addr,
        name: "entry".into(),
        size: 1,
    });
    import.declared_regions = Vec::<DeclaredRegion>::new();
    Ok(import)
}
