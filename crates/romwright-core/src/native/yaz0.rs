//! Yaz0 decompression (`.szs` files: the Nintendo LZ77 wrapper GameCube and
//! Wii games put around RELs, archives and models).
//!
//! Format, as documented by the GC/Wii homebrew community (Yaz0 on the
//! Custom Mario Kart wiki, decomp-toolkit's `yaz0` command): a 16-byte
//! header -- `Yaz0`, the big-endian decompressed size, eight reserved
//! bytes -- then groups of eight chunks, each group led by a flag byte read
//! most-significant bit first. A set bit copies one literal byte. A clear
//! bit is a back-reference of two bytes `NR RR`: the distance back is
//! `(RRR) + 1` (the low nibble of the first byte and the whole second) and
//! the length is `N + 2`; when `N` is zero a third byte holds `length - 0x12`.
//! The copy may overlap its own output, which is how runs are encoded.
//! Independent implementation; no upstream code copied.

use super::{err, Result};

const HEADER: usize = 16;
/// The longest run one chunk encodes: `0xff + 0x12`.
const MAX_RUN: usize = 0x111;

/// True when `data` starts with the Yaz0 magic.
pub(crate) fn is_yaz0(data: &[u8]) -> bool {
    data.len() >= HEADER && &data[0..4] == b"Yaz0"
}

/// Decompresses a Yaz0 stream. The header's size is trusted only as far as
/// the input can produce it: every input byte yields at most `MAX_RUN`
/// output bytes per three bytes, so a larger claim is refused before any
/// allocation rather than after.
pub(crate) fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    if !is_yaz0(data) {
        return err("not a Yaz0 stream");
    }
    let size = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
    let (out, complete) = decode(data, size)?;
    if !complete {
        return err("truncated Yaz0 stream");
    }
    Ok(out)
}

/// The first `want` bytes of a Yaz0 stream's output (fewer when the stream
/// declares fewer), decoded from a prefix of the stream: the second field
/// is false when `data` ended before `want` bytes could be produced, so a
/// caller probing a large file's directory reads more input and asks again.
pub(crate) fn decompress_prefix(data: &[u8], want: usize) -> Result<(Vec<u8>, bool)> {
    if !is_yaz0(data) {
        return err("not a Yaz0 stream");
    }
    let size = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
    decode(data, want.min(size))
}

/// Decodes until `limit` bytes are out or the input ends; the flag says
/// which. A malformed reference is an error either way.
fn decode(data: &[u8], limit: usize) -> Result<(Vec<u8>, bool)> {
    let input = &data[HEADER..];
    if limit > input.len().saturating_mul(MAX_RUN / 2 + 1) {
        // Only a whole stream can prove its claim false: a prefix simply
        // ends early.
        let size = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
        if limit == size {
            return err("Yaz0 declared size exceeds what the stream can hold");
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(limit.min(input.len().saturating_mul(MAX_RUN / 2 + 1)));
    let mut at = 0usize;
    while out.len() < limit {
        let Some(&flags) = input.get(at) else { return Ok((out, false)) };
        at += 1;
        for bit in (0..8).rev() {
            if out.len() >= limit {
                break;
            }
            if flags >> bit & 1 == 1 {
                let Some(&byte) = input.get(at) else { return Ok((out, false)) };
                at += 1;
                out.push(byte);
                continue;
            }
            let Some(pair) = input.get(at..at + 2) else { return Ok((out, false)) };
            at += 2;
            let distance = (usize::from(pair[0] & 0x0f) << 8 | usize::from(pair[1])) + 1;
            let length = match pair[0] >> 4 {
                0 => {
                    let Some(&extra) = input.get(at) else { return Ok((out, false)) };
                    at += 1;
                    usize::from(extra) + 0x12
                }
                nibble => usize::from(nibble) + 2,
            };
            if distance > out.len() {
                return err("Yaz0 back-reference before the start of the output");
            }
            // A run is allowed to read bytes it has just written.
            let from = out.len() - distance;
            for step in 0..length.min(limit - out.len()) {
                out.push(out[from + step]);
            }
        }
    }
    Ok((out, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(size: u32) -> Vec<u8> {
        let mut out = b"Yaz0".to_vec();
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&[0; 8]);
        out
    }

    #[test]
    fn literals_and_overlapping_runs_decode() {
        // 'a','b' literals, then a 2-byte reference (distance 2, length 6)
        // that overlaps its own output: "ab" + "ababab" + "ab".
        let mut stream = header(8);
        stream.extend_from_slice(&[0b1100_0000, b'a', b'b', 0x40, 0x01]);
        assert_eq!(decompress(&stream).unwrap(), b"abababab");
    }

    #[test]
    fn long_run_uses_the_third_byte() {
        // One literal then distance 1 with length 0x12 + 0x20 = 0x32.
        let mut stream = header(0x33);
        stream.extend_from_slice(&[0b1000_0000, 0x5a, 0x00, 0x00, 0x20]);
        assert_eq!(decompress(&stream).unwrap(), vec![0x5a; 0x33]);
    }

    #[test]
    fn a_run_is_clipped_to_the_declared_size() {
        let mut stream = header(4);
        stream.extend_from_slice(&[0b1000_0000, 7, 0x00, 0x00, 0x20]);
        assert_eq!(decompress(&stream).unwrap(), vec![7; 4]);
    }

    #[test]
    fn malformed_streams_are_refused() {
        assert!(decompress(b"Yaz1\0\0\0\0\0\0\0\0\0\0\0\0").is_err());
        // Truncated mid-reference.
        let mut stream = header(8);
        stream.extend_from_slice(&[0b1000_0000, b'a', 0x40]);
        assert!(decompress(&stream).is_err());
        // Reference before the start of the output.
        let mut stream = header(4);
        stream.extend_from_slice(&[0b0000_0000, 0x20, 0x05]);
        assert!(decompress(&stream).is_err());
        // A size no stream this short can reach.
        let mut stream = header(0x7fff_ffff);
        stream.push(0xff);
        assert!(decompress(&stream).is_err());
    }
}
