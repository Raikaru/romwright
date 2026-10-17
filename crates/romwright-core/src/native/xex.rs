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
//! custom block chain whose length-prefixed chunks are the LZX frames of one
//! stream, windowed per the header's `window_size`).

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

/// The LZX window for a `window_size` byte count from the base file format
/// header (a power of two from 32 KiB to 32 MiB).
fn lzx_window(window_size: u32) -> Result<lzxd::WindowSize> {
    use lzxd::WindowSize::*;
    Ok(match window_size {
        0x0000_8000 => KB32,
        0x0001_0000 => KB64,
        0x0002_0000 => KB128,
        0x0004_0000 => KB256,
        0x0008_0000 => KB512,
        0x0010_0000 => MB1,
        0x0020_0000 => MB2,
        0x0040_0000 => MB4,
        0x0080_0000 => MB8,
        0x0100_0000 => MB16,
        0x0200_0000 => MB32,
        other => return super::err(format!("xex: lzx window {other:#x} not supported")),
    })
}

/// Splits the normal-compression payload into LZX frames.
///
/// The payload is a chain of blocks. A block is `nextSize: u32`, a 20-byte
/// hash of the following block, then big-endian `u16` length-prefixed chunks,
/// ended by a zero length or by the block's end. `first_size` (from the base
/// file format header) is the size of the first block; each block's own header
/// gives the size of the block after it, and zero ends the chain. A block
/// therefore starts one *current* block size after the previous block, not one
/// `nextSize` after it. Every chunk is one LZX frame.
fn lzx_frames(compressed: &[u8], first_size: usize) -> Result<Vec<&[u8]>> {
    const BLOCK_HEADER: usize = 4 + 20;
    let mut frames = Vec::new();
    let mut pos = 0usize;
    let mut size = first_size;
    while size != 0 {
        let block_end = pos
            .checked_add(size)
            .filter(|&end| end <= compressed.len() && size >= BLOCK_HEADER)
            .ok_or_else(|| super::ImportError::Bad("xex: lzx block outside payload".into()))?;
        let next = be32(compressed, pos)? as usize;
        let mut i = pos + BLOCK_HEADER;
        while i + 2 <= block_end {
            let len = be16(compressed, i)? as usize;
            if len == 0 {
                break;
            }
            let chunk = compressed
                .get(i + 2..i + 2 + len)
                .filter(|_| i + 2 + len <= block_end)
                .ok_or_else(|| super::ImportError::Bad("xex: lzx chunk overruns its block".into()))?;
            frames.push(chunk);
            i += 2 + len;
        }
        pos = block_end;
        size = next;
    }
    Ok(frames)
}

/// The decompressed PE image, recovered from the (decrypted) payload per the
/// base file format's compression mode.
fn decompress(
    compression: u16,
    basic: &[(u32, u32)],
    block_size: u32,
    window_size: u32,
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
            let frames = lzx_frames(compressed, block_size as usize)?;
            let window = lzx_window(window_size)?;
            let mut lzxd = lzxd::Lzxd::new(window);
            let mut out = Vec::with_capacity(image_size);
            // Each chunk is one LZX frame: it decodes to exactly
            // `MAX_CHUNK_SIZE` bytes (fewer only for the image's last frame)
            // and ends 16-bit aligned, so it is decoded on its own bitstream
            // while the window, trees and repeat offsets carry over.
            for frame in frames {
                let want = lzxd::MAX_CHUNK_SIZE.min(image_size - out.len());
                if want == 0 {
                    break;
                }
                let decoded = lzxd
                    .decompress_next(frame, want)
                    .map_err(|e| super::ImportError::Bad(format!("xex: lzx: {e}")))?;
                out.extend_from_slice(decoded);
            }
            if out.len() != image_size {
                return super::err(format!(
                    "xex: lzx stream decodes to {:#x} of {image_size:#x} image bytes",
                    out.len()
                ));
            }
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
    let mut window_size = 0u32;
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
                        window_size = be32(&h.data, 8)?;
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
        match decompress(compression, &basic, block_size, window_size, image_size, &plain) {
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
    // The entry-point header holds a virtual address, not an image offset
    // (Black Ops 2: 0x827170e8 over base 0x82000000); adding the base put
    // the seed past the 32-bit space and failed every switch worker.
    let entry_addr = u64::from(entry);
    let mut import = NativeImport {
        mappings,
        mapping_names: names,
        format: "xex".into(),
        language: "PowerPC:BE:64:Xenon-32addr".into(),
        process_entry: Some(entry_addr),
        unrelocated_data_pointers: true,
        ..Default::default()
    };
    // The optional header's linker version (`MajorLinkerVersion`,
    // `MinorLinkerVersion`) is the compiler evidence a stripped XEX keeps.
    import.image_facts.pe_linker = pe_image.get(pe_off + 26..pe_off + 28).map(|version| (version[0], version[1]));
    import.functions.push(NativeFunction {
        entry: entry_addr,
        name: "entry".into(),
        size: 1,
    });
    import.declared_regions = Vec::<DeclaredRegion>::new();
    let exception_directory = pe_image
        .get(pe_off + 24 + 96 + 3 * 8..pe_off + 24 + 96 + 4 * 8)
        .map(|s| {
            let word = |at: usize| u32::from_le_bytes([s[at], s[at + 1], s[at + 2], s[at + 3]]);
            (word(0), word(4))
        });
    if let Some((rva, size)) = exception_directory {
        let table = pe_image.get(rva as usize..(rva as usize).saturating_add(size as usize));
        pdata_functions(table.unwrap_or(&[]), u64::from(image_base) + u64::from(rva), &mut import);
    }
    Ok(import)
}

/// Function starts from a PowerPC exception directory (`.pdata`): 8-byte
/// records of `BeginAddress` (a virtual address) and a packed word whose
/// bits 8-29 are the function length in instructions (Microsoft PE format,
/// "The .pdata Section", the 32-bit ARM/PowerPC/SH layout; big-endian on
/// Xenon). The compiler writes one per function body, including the ones
/// only a vtable or script table reaches: Black Ops 2 has 21,393 records,
/// 21,324 of them functions its map names; recall went 0.773 to 0.940.
fn pdata_functions(table: &[u8], table_vaddr: u64, import: &mut NativeImport) {
    let known: std::collections::HashSet<u64> = import.functions.iter().map(|f| f.entry).collect();
    for (index, record) in table.chunks_exact(8).enumerate() {
        let begin = u64::from(u32::from_be_bytes([record[0], record[1], record[2], record[3]]));
        let packed = u32::from_be_bytes([record[4], record[5], record[6], record[7]]);
        let instructions = (packed >> 8) & 0x3f_ffff;
        let executable = import
            .mappings
            .iter()
            .any(|m| m.flags & 4 != 0 && begin >= m.vaddr && begin - m.vaddr < m.size);
        if instructions == 0 || !executable {
            continue;
        }
        if !known.contains(&begin) {
            import.functions.push(NativeFunction {
                entry: begin,
                name: format!("FUN_{begin:08x}"),
                size: 1,
            });
        }
        import.xrefs.push(super::NativeXref::with_provenance(
            table_vaddr + 8 * index as u64,
            begin,
            "DATA",
            "native-import:pe-unwind",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records are big-endian, name virtual addresses, and only a nonzero
    /// length landing in executable bytes seeds a function.
    #[test]
    fn pdata_records_seed_functions_in_code() {
        let code = Mapping { vaddr: 0x8214_0000, size: 0x100, file_off: 0, flags: 5, bytes: vec![0; 0x100] };
        let data = Mapping { vaddr: 0x828a_0000, size: 0x100, file_off: 0, flags: 3, bytes: vec![0; 0x100] };
        let mut import = NativeImport { mappings: vec![code, data], ..Default::default() };
        let record = |begin: u32, instructions: u32| {
            let mut bytes = begin.to_be_bytes().to_vec();
            bytes.extend((instructions << 8 | 0x4000_0003).to_be_bytes());
            bytes
        };
        let table = [record(0x8214_0010, 12), record(0x8214_0040, 0), record(0x828a_0000, 4)].concat();
        pdata_functions(&table, 0x8211_3400, &mut import);
        let entries: Vec<u64> = import.functions.iter().map(|f| f.entry).collect();
        assert_eq!(entries, [0x8214_0010]);
        assert_eq!((import.xrefs.len(), import.xrefs[0].from), (1, 0x8211_3400));
    }

    /// MSB-first bit writer packing 16-bit little-endian words, the LZX
    /// bitstream layout (MS-PATCH 2.2).
    #[derive(Default)]
    struct Bits(Vec<bool>);

    impl Bits {
        fn put(&mut self, value: u32, count: u32) {
            self.0.extend((0..count).rev().map(|bit| value >> bit & 1 == 1));
        }

        /// Pads to a 16-bit boundary and packs the words.
        fn finish(mut self) -> Vec<u8> {
            while !self.0.len().is_multiple_of(16) {
                self.0.push(false);
            }
            self.0
                .chunks(16)
                .flat_map(|word| {
                    let value = word.iter().fold(0u16, |acc, &bit| acc << 1 | bit as u16);
                    value.to_le_bytes()
                })
                .collect()
        }
    }

    /// A verbatim block header whose main tree gives every literal an 8-bit
    /// code (so a literal is its own byte, MSB first) and has no matches.
    /// `delta` is the pretree symbol turning the previous literal path length
    /// into 8: 9 from the initial all-zero tree, 0 when it is already 8.
    fn literal_block_header(bits: &mut Bits, size: u32, delta: u32) {
        bits.put(1, 3);
        bits.put(size, 24);
        // Pretree for the literals: `delta` and the zero-run code 18 get one
        // bit each (codes 0 and 1).
        let pretree = |bits: &mut Bits, first: u32| {
            for symbol in 0..20 {
                bits.put(u32::from(symbol == first || symbol == 18), 4);
            }
        };
        pretree(bits, delta);
        for _ in 0..256 {
            bits.put(0, 1);
        }
        // Zero runs cover the 240 match elements (30 position slots x 8) and
        // the empty 249-element length tree: 51 is the longest run.
        for total in [240u32, 249] {
            pretree(bits, delta);
            let mut left = total;
            while left > 0 {
                let run = left.min(51);
                bits.put(1, 1);
                bits.put(run - 20, 5);
                left -= run;
            }
        }
    }

    /// Chunk-framed XEX payload built from the public structures: the LZX
    /// stream is three frames (the first ends on an odd byte, so it carries
    /// alignment padding that a single concatenated decode would misread as
    /// data), and two blocks of different sizes, the first zero-padded.
    #[test]
    fn lzx_frames_decode_across_blocks_and_alignment() {
        let image: Vec<u8> = (0..2 * 0x8000 + 100u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        // Block A spans frames 1 and 2, block B spans frames 2 and 3.
        let first = 0x8000 + 0x80;
        let mut frames = Vec::new();
        let mut frame = Bits::default();
        frame.put(0, 1); // no E8 translation
        literal_block_header(&mut frame, first as u32, 9);
        for &byte in &image[..0x8000] {
            frame.put(byte.into(), 8);
        }
        // The first frame's bit count is 8 modulo 16, so its end carries a
        // padding byte that is not part of any element.
        assert_eq!(frame.0.len() % 16, 8);
        frames.push(frame.finish());
        let mut frame = Bits::default();
        for &byte in &image[0x8000..first] {
            frame.put(byte.into(), 8);
        }
        literal_block_header(&mut frame, (image.len() - first) as u32, 0);
        for &byte in &image[first..0x10000] {
            frame.put(byte.into(), 8);
        }
        frames.push(frame.finish());
        let mut frame = Bits::default();
        for &byte in &image[0x10000..] {
            frame.put(byte.into(), 8);
        }
        frames.push(frame.finish());

        let block = |next: u32, chunks: &[&Vec<u8>], pad: usize| {
            let mut bytes = next.to_be_bytes().to_vec();
            bytes.extend([0xA5; 20]); // hash of the next block, unchecked
            for chunk in chunks {
                bytes.extend((chunk.len() as u16).to_be_bytes());
                bytes.extend(chunk.iter());
            }
            bytes.extend((0..pad).map(|_| 0));
            bytes
        };
        let rest = block(0, &[&frames[1], &frames[2]], 0);
        let head = block(rest.len() as u32, &[&frames[0]], 6);
        let payload = [head.as_slice(), rest.as_slice()].concat();

        let decoded = decompress(2, &[], head.len() as u32, 0x8000, image.len(), &payload).unwrap();
        assert_eq!(decoded, image);

        // Anything but the right first-block size, or a frame-count mismatch,
        // is an error rather than a short or garbled image.
        assert!(decompress(2, &[], head.len() as u32 + 1, 0x8000, image.len(), &payload).is_err());
        assert!(decompress(2, &[], head.len() as u32, 0x8000, image.len() + 1, &payload).is_err());
        assert!(decompress(2, &[], head.len() as u32, 0x1234, image.len(), &payload).is_err());
    }
}
