//! PCSX2 PINE client (P3.11).
//!
//! Port facts (public protocol surface, clean-room implementation — no
//! emulator code is copied):
//!
//! * Transport is TCP on `127.0.0.1:28011` by default (Windows; POSIX
//!   builds listen on a Unix-domain socket instead — this client speaks
//!   TCP). The numeric default is also published as
//!   `DEFAULT_PCSX2_SLOT`.
//! * Every packet is a 4-byte little-endian length counting the bytes
//!   that follow it, then a 1-byte opcode, then the body.
//! * Opcodes `0x00..=0x0F` are the documented command set: `Read8/16/32/64`,
//!   `Write8/16/32/64`, `Version`, `SaveState`, `LoadState`, `Title`,
//!   `ID`, `UUID`, `GameVersion`, `Status` (`0xFF` = unimplemented).
//! * Bodies are protobuf messages: request field 1 is the `u32` address,
//!   write requests add field 2 with the value; read responses carry the
//!   value in field 1; string queries (`Version`, `Title`, `ID`, `UUID`,
//!   `GameVersion`) return a field-1 length-delimited string; `Status`
//!   returns a field-1 varint mapped to [`PineStatus`].
//! * Responses replace the opcode byte with a result byte: `0x00`
//!   success, `0xFF` command failure.
//!
//! The client keeps one persistent connection and performs strict
//! request/response pairing (write then full read) so rapid successive
//! commands — including the 100-cycle race in the test suite — cannot
//! desynchronise. Bulk writes go through [`PineWriteBatch`]: individual
//! writes are queued locally and flushed in order ("write-queued").
//!
//! PINE exposes no register file and no breakpoint primitive, so
//! [`PineClient::registers`] honestly reports [`DebugError::Unsupported`]
//! and the trace hook is poll-based: [`PineClient::watch_memory`] snapshots
//! a window and [`PineClient::poll_watch`] re-reads it, emitting a
//! `write` [`TraceHit`](crate::trace::TraceHit) the first poll that
//! observes a change.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::trace::{TraceHit, TraceKind};
use crate::{DebugError, Result};

/// Default PINE TCP port (also published upstream as the default slot).
pub const DEFAULT_PINE_PORT: u16 = 28011;
/// Largest single block transfer; mirrors the RSP client's 1 MiB ceiling.
pub const MAX_PINE_BLOCK_BYTES: usize = 1024 * 1024;
const HEADER_LEN: usize = 5; // 4-byte length + 1-byte opcode/result.
const MAX_PACKET_BYTES: usize = 4 + 1024 * 1024 + 16;
const RESULT_OK: u8 = 0x00;
const RESULT_FAILED: u8 = 0xFF;

/// Documented PINE opcodes (`0xFF` = unimplemented sentinel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PineOpcode {
    Read8 = 0x00,
    Read16 = 0x01,
    Read32 = 0x02,
    Read64 = 0x03,
    Write8 = 0x04,
    Write16 = 0x05,
    Write32 = 0x06,
    Write64 = 0x07,
    Version = 0x08,
    SaveState = 0x09,
    LoadState = 0x0A,
    Title = 0x0B,
    Id = 0x0C,
    Uuid = 0x0D,
    GameVersion = 0x0E,
    Status = 0x0F,
}

/// Emulator run-state returned by the `Status` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PineStatus {
    Running,
    Paused,
    Shutdown,
    Unknown,
}

impl PineStatus {
    fn decode(value: u64) -> Self {
        match value {
            0 => Self::Running,
            1 => Self::Paused,
            2 => Self::Shutdown,
            _ => Self::Unknown,
        }
    }
}

// --- Minimal protobuf codec (varint + field scan, enough for PINE). ---

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let bits = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(bits);
            return;
        }
        out.push(bits | 0x80);
    }
}

fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, &byte) in buf.iter().enumerate().take(10) {
        let bits = (byte & 0x7F) as u64;
        value |= bits.checked_shl((index * 7) as u32)?;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// Encodes a `uint32` field: tag byte(s) + varint value.
fn pb_u32_field(field: u32, value: u32, out: &mut Vec<u8>) {
    encode_varint(((field as u64) << 3) | 0, out); // wire type 0: varint.
    encode_varint(value as u64, out);
}

/// Encodes a string field: tag + length-delimited bytes.
fn pb_string_field(field: u32, value: &str, out: &mut Vec<u8>) {
    encode_varint(((field as u64) << 3) | 2, out); // wire type 2: LEN.
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value.as_bytes());
}

/// Scans protobuf fields, returning the first varint with `field` number.
fn pb_find_varint(buf: &[u8], field: u32) -> Option<u64> {
    let mut cursor = buf;
    while !cursor.is_empty() {
        let (tag, tag_len) = decode_varint(cursor)?;
        cursor = &cursor[tag_len..];
        let number = (tag >> 3) as u32;
        match (tag & 7) as u8 {
            0 => {
                let (value, value_len) = decode_varint(cursor)?;
                if number == field {
                    return Some(value);
                }
                cursor = &cursor[value_len..];
            }
            2 => {
                let (len, len_len) = decode_varint(cursor)?;
                let len = usize::try_from(len).ok()?;
                cursor = cursor.get(len_len..)?.get(..len).map(|_| &cursor[len_len + len..])?;
            }
            _ => return None, // PINE only uses varint and LEN fields.
        }
    }
    None
}

/// Scans protobuf fields, returning the first length-delimited `field`.
fn pb_find_string(buf: &[u8], field: u32) -> Option<String> {
    let mut cursor = buf;
    while !cursor.is_empty() {
        let (tag, tag_len) = decode_varint(cursor)?;
        cursor = &cursor[tag_len..];
        let number = (tag >> 3) as u32;
        match (tag & 7) as u8 {
            0 => {
                let (_, value_len) = decode_varint(cursor)?;
                cursor = &cursor[value_len..];
            }
            2 => {
                let (len, len_len) = decode_varint(cursor)?;
                let len = usize::try_from(len).ok()?;
                let body = cursor.get(len_len..)?.get(..len)?;
                if number == field {
                    return Some(String::from_utf8_lossy(body).into_owned());
                }
                cursor = &cursor[len_len + len..];
            }
            _ => return None,
        }
    }
    None
}

fn encode_request(opcode: PineOpcode, body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(HEADER_LEN + body.len());
    packet.extend_from_slice(&((1 + body.len()) as u32).to_le_bytes());
    packet.push(opcode as u8);
    packet.extend_from_slice(body);
    packet
}

/// Read-only PINE client over one persistent TCP connection.
#[derive(Debug)]
pub struct PineClient {
    stream: TcpStream,
}

impl PineClient {
    /// Connects to an endpoint such as `127.0.0.1:28011`.
    pub fn connect(endpoint: &str) -> Result<Self> {
        Self::connect_with_timeout(endpoint, Duration::from_secs(5))
    }

    /// Connects with an explicit connect and I/O deadline.
    pub fn connect_with_timeout(endpoint: &str, timeout: Duration) -> Result<Self> {
        let mut addresses = ToSocketAddrs::to_socket_addrs(endpoint).map_err(DebugError::PineConnect)?;
        let address = addresses.next().ok_or_else(|| {
            DebugError::PineProtocol(format!("endpoint has no addresses: {endpoint}"))
        })?;
        Self::connect_addr(address, timeout)
    }

    /// Connects to a resolved socket address.
    pub fn connect_addr(address: SocketAddr, timeout: Duration) -> Result<Self> {
        let stream =
            TcpStream::connect_timeout(&address, timeout).map_err(DebugError::PineConnect)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(DebugError::PineConnect)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(DebugError::PineConnect)?;
        Ok(Self { stream })
    }

    /// Reads one byte from EE memory.
    pub fn read8(&mut self, address: u32) -> Result<u8> {
        let body = self.round_trip(PineOpcode::Read8, &address_body(address, None))?;
        Ok(pb_find_varint(&body, 1).unwrap_or(0) as u8)
    }

    /// Reads two bytes (little-endian) from EE memory.
    pub fn read16(&mut self, address: u32) -> Result<u16> {
        let body = self.round_trip(PineOpcode::Read16, &address_body(address, None))?;
        Ok(pb_find_varint(&body, 1).unwrap_or(0) as u16)
    }

    /// Reads four bytes (little-endian) from EE memory.
    pub fn read32(&mut self, address: u32) -> Result<u32> {
        let body = self.round_trip(PineOpcode::Read32, &address_body(address, None))?;
        Ok(pb_find_varint(&body, 1).unwrap_or(0) as u32)
    }

    /// Reads eight bytes (little-endian) from EE memory.
    pub fn read64(&mut self, address: u32) -> Result<u64> {
        let body = self.round_trip(PineOpcode::Read64, &address_body(address, None))?;
        Ok(pb_find_varint(&body, 1).unwrap_or(0))
    }

    /// Writes one byte to EE memory.
    pub fn write8(&mut self, address: u32, value: u8) -> Result<()> {
        self.round_trip(
            PineOpcode::Write8,
            &address_body(address, Some(value as u64)),
        )?;
        Ok(())
    }

    /// Writes two bytes (little-endian) to EE memory.
    pub fn write16(&mut self, address: u32, value: u16) -> Result<()> {
        self.round_trip(
            PineOpcode::Write16,
            &address_body(address, Some(value as u64)),
        )?;
        Ok(())
    }

    /// Writes four bytes (little-endian) to EE memory.
    pub fn write32(&mut self, address: u32, value: u32) -> Result<()> {
        self.round_trip(
            PineOpcode::Write32,
            &address_body(address, Some(value as u64)),
        )?;
        Ok(())
    }

    /// Writes eight bytes (little-endian) to EE memory.
    pub fn write64(&mut self, address: u32, value: u64) -> Result<()> {
        self.round_trip(PineOpcode::Write64, &address_body(address, Some(value)))?;
        Ok(())
    }

    /// Reads `len` bytes starting at `address` (32-bit chunks + tail).
    pub fn read_memory(&mut self, address: u32, len: usize) -> Result<Vec<u8>> {
        if len == 0 || len > MAX_PINE_BLOCK_BYTES {
            return Err(DebugError::RemoteMemoryCount(len));
        }
        let mut out = Vec::with_capacity(len);
        let mut cursor = address;
        let mut remaining = len;
        while remaining >= 4 {
            out.extend_from_slice(&self.read32(cursor)?.to_le_bytes());
            cursor = cursor.wrapping_add(4);
            remaining -= 4;
        }
        if remaining >= 2 {
            out.extend_from_slice(&self.read16(cursor)?.to_le_bytes());
            cursor = cursor.wrapping_add(2);
            remaining -= 2;
        }
        if remaining == 1 {
            out.push(self.read8(cursor)?);
        }
        Ok(out)
    }

    /// Writes `data` starting at `address` immediately (32-bit chunks + tail).
    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() > MAX_PINE_BLOCK_BYTES {
            return Err(DebugError::RemoteMemoryCount(data.len()));
        }
        let mut cursor = address;
        let mut chunks = data.chunks_exact(4);
        for chunk in &mut chunks {
            let value = u32::from_le_bytes(chunk.try_into().expect("exact 4-byte chunk"));
            self.write32(cursor, value)?;
            cursor = cursor.wrapping_add(4);
        }
        let tail = chunks.remainder();
        if tail.len() >= 2 {
            self.write16(cursor, u16::from_le_bytes([tail[0], tail[1]]))?;
            cursor = cursor.wrapping_add(2);
        }
        if tail.len() % 2 == 1 {
            self.write8(cursor, tail[tail.len() - 1])?;
        }
        Ok(())
    }

    /// PINE exposes no register file; the EE console is inspected through
    /// memory and status. Present so every adapter offers the same surface.
    pub fn registers(&mut self) -> Result<Vec<(String, Vec<u8>)>> {
        Err(DebugError::Unsupported(
            "pine exposes no register file; use read_memory/status".to_string(),
        ))
    }

    /// Takes a snapshot watch over `[address, address+size)` for [`Self::poll_watch`].
    pub fn watch_memory(&mut self, address: u32, size: usize) -> Result<PineWatch> {
        let baseline = self.read_memory(address, size)?;
        Ok(PineWatch {
            address,
            baseline,
        })
    }

    /// Re-reads a watch; on the first observed change returns a `write`
    /// [`TraceHit`] with provenance `emulator:pcsx2` and refreshes the
    /// baseline, otherwise returns `None`.
    pub fn poll_watch(&mut self, watch: &mut PineWatch) -> Result<Option<TraceHit>> {
        let current = self.read_memory(watch.address, watch.baseline.len())?;
        if current == watch.baseline {
            return Ok(None);
        }
        watch.baseline = current;
        Ok(Some(TraceHit::new(
            watch.address as u64,
            TraceKind::Write,
            "pcsx2",
        )))
    }

    /// Queries the PINE protocol version string.
    pub fn version(&mut self) -> Result<String> {
        let body = self.round_trip(PineOpcode::Version, &[])?;
        pb_find_string(&body, 1)
            .ok_or_else(|| DebugError::PineProtocol("version reply has no string field".into()))
    }

    /// Queries the emulator run-state.
    pub fn status(&mut self) -> Result<PineStatus> {
        let body = self.round_trip(PineOpcode::Status, &[])?;
        pb_find_varint(&body, 1)
            .map(PineStatus::decode)
            .ok_or_else(|| DebugError::PineProtocol("status reply has no varint field".into()))
    }

    /// Queries the running game's title.
    pub fn title(&mut self) -> Result<String> {
        let body = self.round_trip(PineOpcode::Title, &[])?;
        pb_find_string(&body, 1)
            .ok_or_else(|| DebugError::PineProtocol("title reply has no string field".into()))
    }

    /// Queries the running game's serial/ID.
    pub fn game_id(&mut self) -> Result<String> {
        let body = self.round_trip(PineOpcode::Id, &[])?;
        pb_find_string(&body, 1)
            .ok_or_else(|| DebugError::PineProtocol("id reply has no string field".into()))
    }

    /// Saves to the emulator's savestate slot.
    pub fn save_state(&mut self, slot: u8) -> Result<()> {
        let mut body = Vec::new();
        pb_u32_field(1, slot as u32, &mut body);
        self.round_trip(PineOpcode::SaveState, &body)?;
        Ok(())
    }

    /// Loads the emulator's savestate slot.
    pub fn load_state(&mut self, slot: u8) -> Result<()> {
        let mut body = Vec::new();
        pb_u32_field(1, slot as u32, &mut body);
        self.round_trip(PineOpcode::LoadState, &body)?;
        Ok(())
    }

    fn round_trip(&mut self, opcode: PineOpcode, body: &[u8]) -> Result<Vec<u8>> {
        let packet = encode_request(opcode, body);
        if packet.len() > MAX_PACKET_BYTES {
            return Err(DebugError::PineProtocol(format!(
                "request of {} bytes exceeds the packet ceiling",
                packet.len()
            )));
        }
        self.stream
            .write_all(&packet)
            .map_err(DebugError::PineIo)?;
        self.stream.flush().map_err(DebugError::PineIo)?;
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(DebugError::PineIo)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_PACKET_BYTES - 4 {
            return Err(DebugError::PineProtocol(format!(
                "response length {len} is out of range"
            )));
        }
        let mut rest = vec![0u8; len];
        self.stream.read_exact(&mut rest).map_err(DebugError::PineIo)?;
        match rest[0] {
            RESULT_OK => Ok(rest[1..].to_vec()),
            RESULT_FAILED => Err(DebugError::PineTarget(format!(
                "command {:?} failed",
                opcode
            ))),
            other => Err(DebugError::PineProtocol(format!(
                "response result byte 0x{other:02x} is not 0x00 or 0xFF"
            ))),
        }
    }
}

fn address_body(address: u32, value: Option<u64>) -> Vec<u8> {
    let mut body = Vec::new();
    pb_u32_field(1, address, &mut body);
    if let Some(value) = value {
        encode_varint((2 << 3) | 0, &mut body);
        encode_varint(value, &mut body);
    }
    body
}

/// A snapshot watch over a PINE memory window (see [`PineClient::poll_watch`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PineWatch {
    address: u32,
    baseline: Vec<u8>,
}

impl PineWatch {
    /// The watched base address.
    pub fn address(&self) -> u32 {
        self.address
    }

    /// The watched window length in bytes.
    pub fn len(&self) -> usize {
        self.baseline.len()
    }

    /// Whether the window is empty (never constructed empty via the client).
    pub fn is_empty(&self) -> bool {
        self.baseline.is_empty()
    }
}

/// One queued PINE write; flushed in order by [`PineWriteBatch::flush`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PineWriteOp {
    W8(u32, u8),
    W16(u32, u16),
    W32(u32, u32),
    W64(u32, u64),
}

/// Write queue: collects PINE writes locally, then sends them in FIFO
/// order on one connection ("write-queued" from the plan).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PineWriteBatch {
    ops: Vec<PineWriteOp>,
}

impl PineWriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn queue_write8(&mut self, address: u32, value: u8) {
        self.ops.push(PineWriteOp::W8(address, value));
    }

    pub fn queue_write16(&mut self, address: u32, value: u16) {
        self.ops.push(PineWriteOp::W16(address, value));
    }

    pub fn queue_write32(&mut self, address: u32, value: u32) {
        self.ops.push(PineWriteOp::W32(address, value));
    }

    pub fn queue_write64(&mut self, address: u32, value: u64) {
        self.ops.push(PineWriteOp::W64(address, value));
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn ops(&self) -> &[PineWriteOp] {
        &self.ops
    }

    /// Sends every queued write in order and drains the queue.
    pub fn flush(&mut self, client: &mut PineClient) -> Result<()> {
        for op in self.ops.drain(..).collect::<Vec<_>>() {
            match op {
                PineWriteOp::W8(address, value) => client.write8(address, value)?,
                PineWriteOp::W16(address, value) => client.write16(address, value)?,
                PineWriteOp::W32(address, value) => client.write32(address, value)?,
                PineWriteOp::W64(address, value) => client.write64(address, value)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::thread;

    /// In-test PINE mock: a byte-addressed RAM plus savestate slots,
    /// speaking the same framing and protobuf bodies as the client.
    /// The server thread owns its state outright and returns it on
    /// disconnect, so no lock primitives are involved.
    struct MockState {
        ram: Vec<u8>,
        slots: HashMap<u8, Vec<u8>>,
        op_log: Vec<u8>,
    }

    fn spawn_mock(ram_size: usize) -> (SocketAddr, thread::JoinHandle<MockState>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut state = MockState {
                ram: vec![0u8; ram_size],
                slots: HashMap::new(),
                op_log: Vec::new(),
            };
            loop {
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).is_err() {
                    return state;
                }
                let len = u32::from_le_bytes(len_buf) as usize;
                if len == 0 || len > MAX_PACKET_BYTES {
                    return state;
                }
                let mut rest = vec![0u8; len];
                if stream.read_exact(&mut rest).is_err() {
                    return state;
                }
                let reply = handle_command(&mut state, rest[0], &rest[1..].to_vec());
                if stream.write_all(&reply).is_err() {
                    return state;
                }
                if stream.flush().is_err() {
                    return state;
                }
            }
        });
        (address, handle)
    }

    fn ok_response(body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&((1 + body.len()) as u32).to_le_bytes());
        packet.push(RESULT_OK);
        packet.extend_from_slice(body);
        packet
    }

    fn fail_response() -> Vec<u8> {
        1u32.to_le_bytes().iter().copied().chain([RESULT_FAILED]).collect()
    }

    fn string_body(value: &str) -> Vec<u8> {
        let mut body = Vec::new();
        pb_string_field(1, value, &mut body);
        body
    }

    fn value_body(value: u64) -> Vec<u8> {
        let mut body = Vec::new();
        encode_varint((1 << 3) | 0, &mut body);
        encode_varint(value, &mut body);
        body
    }

    fn handle_command(state: &mut MockState, opcode: u8, body: &[u8]) -> Vec<u8> {
        state.op_log.push(opcode);
        match opcode {
            0x00..=0x03 => {
                let width = 1usize << (opcode - 0x00);
                let Some(address) = pb_find_varint(body, 1) else {
                    return fail_response();
                };
                match read_mem(state, address as u32, width) {
                    Some(value) => ok_response(&value_body(value)),
                    None => fail_response(),
                }
            }
            0x04..=0x07 => {
                let width = 1usize << (opcode - 0x04);
                let (Some(address), Some(value)) =
                    (pb_find_varint(body, 1), pb_find_varint(body, 2))
                else {
                    return fail_response();
                };
                if write_mem(state, address as u32, width, value) {
                    ok_response(&[])
                } else {
                    fail_response()
                }
            }
            0x08 => ok_response(&string_body("PINE/1-test")),
            0x09 => {
                let Some(slot) = pb_find_varint(body, 1) else {
                    return fail_response();
                };
                state.slots.insert(slot as u8, state.ram.clone());
                ok_response(&[])
            }
            0x0A => {
                let Some(slot) = pb_find_varint(body, 1) else {
                    return fail_response();
                };
                match state.slots.get(&(slot as u8)).cloned() {
                    Some(snapshot) => {
                        state.ram = snapshot;
                        ok_response(&[])
                    }
                    None => fail_response(),
                }
            }
            0x0B => ok_response(&string_body("Test Game")),
            0x0C => ok_response(&string_body("TEST-00001")),
            0x0D => ok_response(&string_body("uuid-test")),
            0x0E => ok_response(&string_body("1.00")),
            0x0F => {
                let mut body = Vec::new();
                pb_u32_field(1, 0, &mut body); // Running.
                ok_response(&body)
            }
            _ => fail_response(),
        }
    }

    fn read_mem(state: &MockState, address: u32, width: usize) -> Option<u64> {
        let bytes = state.ram.get(address as usize..address as usize + width)?;
        let mut value = 0u64;
        for (index, &byte) in bytes.iter().enumerate() {
            value |= (byte as u64) << (index * 8);
        }
        Some(value)
    }

    fn write_mem(state: &mut MockState, address: u32, width: usize, value: u64) -> bool {
        let Some(slot) = state.ram.get_mut(address as usize..address as usize + width) else {
            return false;
        };
        for (index, byte) in slot.iter_mut().enumerate() {
            *byte = ((value >> (index * 8)) & 0xFF) as u8;
        }
        true
    }

    fn client(address: SocketAddr) -> PineClient {
        PineClient::connect_addr(address, Duration::from_secs(2)).unwrap()
    }

    #[test]
    fn scalar_and_block_memory_round_trip() {
        let (address, server) = spawn_mock(0x2000);
        let mut client = client(address);
        client.write8(0x100, 0xAB).unwrap();
        client.write16(0x110, 0xCDEF).unwrap();
        client.write32(0x120, 0x1234_5678).unwrap();
        client.write64(0x130, 0x0102_0304_0506_0708).unwrap();
        assert_eq!(client.read8(0x100).unwrap(), 0xAB);
        assert_eq!(client.read16(0x110).unwrap(), 0xCDEF);
        assert_eq!(client.read32(0x120).unwrap(), 0x1234_5678);
        assert_eq!(client.read64(0x130).unwrap(), 0x0102_0304_0506_0708);

        let pattern: Vec<u8> = (0..64u8).collect();
        client.write_memory(0x400, &pattern).unwrap();
        assert_eq!(client.read_memory(0x400, 64).unwrap(), pattern);
        // Odd-length tail exercises the 16+8 remainder path.
        let odd: Vec<u8> = (0..7u8).collect();
        client.write_memory(0x500, &odd).unwrap();
        assert_eq!(client.read_memory(0x500, 7).unwrap(), odd);

        assert!(matches!(
            client.read_memory(0x0, 0),
            Err(DebugError::RemoteMemoryCount(0))
        ));
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn metadata_and_slots_round_trip() {
        let (address, server) = spawn_mock(0x1000);
        let mut client = client(address);
        assert_eq!(client.version().unwrap(), "PINE/1-test");
        assert_eq!(client.status().unwrap(), PineStatus::Running);
        assert_eq!(client.title().unwrap(), "Test Game");
        assert_eq!(client.game_id().unwrap(), "TEST-00001");
        client.write32(0x10, 0xDEAD_BEEF).unwrap();
        client.save_state(3).unwrap();
        client.write32(0x10, 0).unwrap();
        client.load_state(3).unwrap();
        assert_eq!(client.read32(0x10).unwrap(), 0xDEAD_BEEF);
        assert!(matches!(
            client.load_state(9),
            Err(DebugError::PineTarget(_))
        ));
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn write_batch_flushes_in_fifo_order() {
        let (address, server) = spawn_mock(0x1000);
        let mut client = client(address);
        let mut batch = PineWriteBatch::new();
        assert!(batch.is_empty());
        batch.queue_write32(0x20, 0x1111_1111);
        batch.queue_write8(0x20, 0xFF);
        batch.queue_write16(0x22, 0xBEEF);
        batch.queue_write64(0x30, 0x0102_0304_0506_0708);
        assert_eq!(batch.len(), 4);
        batch.flush(&mut client).unwrap();
        assert!(batch.is_empty());
        assert_eq!(client.read32(0x20).unwrap(), 0xBEEF_11FF);
        assert_eq!(client.read64(0x30).unwrap(), 0x0102_0304_0506_0708);
        drop(client);
        // FIFO: the earlier 32-bit write lands before the overlapping 8/16-bit fixes.
        let final_state = server.join().unwrap();
        assert_eq!(final_state.op_log, vec![0x06, 0x04, 0x05, 0x07, 0x02, 0x03]);
    }

    #[test]
    fn watch_poll_emits_import_trace_write_on_change() {
        let (address, server) = spawn_mock(0x1000);
        let mut client = client(address);
        let mut watch = client.watch_memory(0x40, 4).unwrap();
        assert_eq!(client.poll_watch(&mut watch).unwrap(), None);
        client.write32(0x40, 0xA5A5_A5A5).unwrap();
        let hit = client.poll_watch(&mut watch).unwrap().expect("change observed");
        assert_eq!(hit.address, 0x40);
        assert_eq!(hit.kind, TraceKind::Write);
        assert_eq!(hit.provenance, "emulator:pcsx2");
        assert_eq!(hit.to_csv_row(), "40,write");
        // Baseline refreshed: a quiet poll reports nothing.
        assert_eq!(client.poll_watch(&mut watch).unwrap(), None);
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn hundred_cycle_read_modify_write_race_stays_paired() {
        let (address, server) = spawn_mock(0x1000);
        let mut client = client(address);
        client.write32(0x80, 0).unwrap();
        for _ in 0..100 {
            let value = client.read32(0x80).unwrap();
            client.write32(0x80, value.wrapping_add(1)).unwrap();
        }
        assert_eq!(client.read32(0x80).unwrap(), 100);
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn registers_are_honestly_unsupported() {
        let (address, server) = spawn_mock(0x100);
        let mut client = client(address);
        assert!(matches!(
            client.registers(),
            Err(DebugError::Unsupported(_))
        ));
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn protobuf_codec_round_trips() {
        let mut buf = Vec::new();
        encode_varint(0, &mut buf);
        encode_varint(300, &mut buf);
        encode_varint(u64::from(u32::MAX) + 1, &mut buf);
        let (first, first_len) = decode_varint(&buf).unwrap();
        let (second, second_len) = decode_varint(&buf[first_len..]).unwrap();
        let (third, _) = decode_varint(&buf[first_len + second_len..]).unwrap();
        assert_eq!((first, second, third), (0, 300, u64::from(u32::MAX) + 1));

        let mut fields = Vec::new();
        pb_u32_field(1, 0x1FF0, &mut fields);
        pb_string_field(2, "hi", &mut fields);
        assert_eq!(pb_find_varint(&fields, 1), Some(0x1FF0));
        assert_eq!(pb_find_string(&fields, 2).as_deref(), Some("hi"));
        assert_eq!(pb_find_varint(&fields, 2), None);
    }
}
