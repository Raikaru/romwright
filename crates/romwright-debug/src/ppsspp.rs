//! PPSSPP WebSocket debugger client (P3.11).
//!
//! Port facts (public protocol surface, clean-room implementation — no
//! emulator code is copied; event/parameter shapes are documented in
//! PPSSPP's `docs/WebSocketDebugger.md` and the per-subscriber handler
//! comments):
//!
//! * Transport is a WebSocket on the Remote-ISO HTTP server, path
//!   `/debugger`, subprotocol `debugger.ppsspp.org` (mandatory — a plain
//!   GET without upgrade serves the web UI instead).
//! * Every message is JSON shaped as `{"event": NAME, ...}`. Requests
//!   may carry a `ticket` echoed back verbatim; responses reuse the
//!   request's event name, so the ticket is the correlation key.
//! * Memory: `memory.read {address, size} -> {base64}`,
//!   `memory.read_u8/u16/u32 {address} -> {value, uintValue}`,
//!   `memory.write_u8/u16/u32 {address, value} -> {value, uintValue}`,
//!   `memory.write {address, base64} -> {}`. Errors arrive as
//!   `{"event": "error", "message", "level", "ticket"?}`.
//! * Registers: `cpu.getAllRegs {thread?} -> {categories: [{id, name,
//!   registerNames[], uintValues[], floatValues[]}]}`; category 0 (GPR)
//!   appends `pc`/`hi`/`lo` to both name and value arrays.
//! * Status: `cpu.status {} -> {stepping, paused, pc, ticks, us, clockHz}`.
//! * Breakpoints: `cpu.breakpoint.add {address, enabled?, log?,
//!   condition?, logFormat?} -> {}`; log-only means `log: true` with
//!   `enabled: false` — the CPU never stops. Every trip where the
//!   breakpoint has an action broadcasts `cpu.breakpoint.hit {sequence,
//!   hit: {kind: exec|memory|register, pc, address, hits, logged, paused,
//!   ...}}`; the same `hit` object rides `cpu.stepping` when a breakpoint
//!   is what stopped the CPU.
//!
//! The trace hook is [`PpssppClient::poll_hit`]: it converts those hit
//! broadcasts into [`TraceHit`](crate::trace::TraceHit)s with provenance
//! `emulator:ppsspp`, which serialize to `import-trace` CSV rows.
//!
//! The WebSocket framing and HTTP upgrade are implemented on plain
//! [`std::net::TcpStream`] (masked client frames, fragmented server
//! frames, ping/pong) so this crate gains no async runtime dependency.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::trace::{TraceHit, TraceKind};
use crate::{DebugError, Result};

/// WebSocket path serving the debugger.
pub const DEBUGGER_PATH: &str = "/debugger";
/// Mandatory WebSocket subprotocol.
pub const DEBUGGER_SUBPROTOCOL: &str = "debugger.ppsspp.org";
/// Largest single block transfer; mirrors the RSP client's 1 MiB ceiling.
pub const MAX_PPSSPP_BLOCK_BYTES: usize = 1024 * 1024;
/// RFC 6455 example key; the mock tests pin this so the accept header is
/// the famous `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.
#[cfg(test)]
const TEST_WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// --- SHA-1 (FIPS 180-4, public-domain algorithm constants). ---

fn sha1(message: &[u8]) -> [u8; 20] {
    let mut h = [
        0x6745_2301u32,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut padded = message.to_vec();
    let bit_len = (message.len() as u64).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().expect("exact word"));
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn ws_accept(key: &str) -> String {
    STANDARD.encode(sha1(format!("{key}{WS_GUID}").as_bytes()))
}

fn ws_key() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0x9E37_79B9);
    let counter = COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0x1234_5678);
    let pid = std::process::id() as u64;
    // Xorshift diffusion; uniqueness (not secrecy) is all a nonce needs.
    let mut state = counter ^ nanos.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ pid.wrapping_mul(0x94D0_49BB_1331_11EB);
    let mut raw = [0u8; 16];
    for byte in &mut raw {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state >> 56) as u8;
    }
    STANDARD.encode(raw)
}

// --- Minimal synchronous WebSocket framing over TcpStream. ---

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

#[derive(Debug)]
struct WsConn {
    stream: TcpStream,
}

impl WsConn {
    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut header = vec![0x80 | (opcode & 0x0F)];
        if payload.len() < 126 {
            header.push(0x80 | payload.len() as u8);
        } else if payload.len() < 65536 {
            header.push(0x80 | 126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            header.push(0x80 | 127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        // Client frames are masked; derive the mask from the same nonce
        // stream as keys (uniqueness, not secrecy, is what matters).
        let mask = ws_key_mask();
        header.extend_from_slice(&mask);
        self.stream.write_all(&header).map_err(DebugError::PpssppIo)?;
        let masked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask[i % 4])
            .collect();
        self.stream.write_all(&masked).map_err(DebugError::PpssppIo)?;
        self.stream.flush().map_err(DebugError::PpssppIo)?;
        Ok(())
    }

    fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_frame(OP_TEXT, text.as_bytes())
    }

    /// Reads one complete text message, answering pings on the way.
    fn recv_text(&mut self) -> Result<String> {
        let mut message = Vec::new();
        loop {
            let mut head = [0u8; 2];
            self.stream.read_exact(&mut head).map_err(DebugError::PpssppIo)?;
            let fin = head[0] & 0x80 != 0;
            let opcode = head[0] & 0x0F;
            let masked = head[1] & 0x80 != 0;
            let mut len = (head[1] & 0x7F) as u64;
            if len == 126 {
                let mut ext = [0u8; 2];
                self.stream.read_exact(&mut ext).map_err(DebugError::PpssppIo)?;
                len = u16::from_be_bytes(ext) as u64;
            } else if len == 127 {
                let mut ext = [0u8; 8];
                self.stream.read_exact(&mut ext).map_err(DebugError::PpssppIo)?;
                len = u64::from_be_bytes(ext);
            }
            if len > 64 * 1024 * 1024 {
                return Err(DebugError::PpssppProtocol(format!(
                    "websocket frame of {len} bytes exceeds the ceiling"
                )));
            }
            let mask = if masked {
                let mut key = [0u8; 4];
                self.stream.read_exact(&mut key).map_err(DebugError::PpssppIo)?;
                Some(key)
            } else {
                None
            };
            let mut payload = vec![0u8; len as usize];
            self.stream.read_exact(&mut payload).map_err(DebugError::PpssppIo)?;
            if let Some(key) = mask {
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= key[i % 4];
                }
            }
            match opcode {
                OP_TEXT | OP_CONT => {
                    message.extend_from_slice(&payload);
                    if fin {
                        return String::from_utf8(message).map_err(|_| {
                            DebugError::PpssppProtocol("text frame is not valid UTF-8".into())
                        });
                    }
                }
                OP_BINARY => {
                    return Err(DebugError::PpssppProtocol(
                        "binary frames are not part of the debugger protocol".into(),
                    ));
                }
                OP_PING => self.send_frame(OP_PONG, &payload)?,
                OP_PONG => {}
                OP_CLOSE => {
                    let _ = self.send_frame(OP_CLOSE, &[]);
                    return Err(DebugError::PpssppProtocol("server closed the connection".into()));
                }
                other => {
                    return Err(DebugError::PpssppProtocol(format!(
                        "unknown websocket opcode 0x{other:x}"
                    )));
                }
            }
        }
    }
}

fn ws_key_mask() -> [u8; 4] {
    static COUNTER: AtomicU64 = AtomicU64::new(0x2545_F491);
    let mut state = COUNTER.fetch_add(1, Ordering::Relaxed);
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state.to_le_bytes()[..4].try_into().expect("4-byte mask")
}

/// `version`-handshake answer: which emulator instance we attached to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PpssppVersion {
    pub name: String,
    pub version: String,
    pub pid: Option<u64>,
    pub path: Option<String>,
}

/// Cheap status poll (`cpu.status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpssppStatus {
    pub stepping: bool,
    pub paused: bool,
    pub pc: u32,
}

/// PPSSPP WebSocket debugger client.
#[derive(Debug)]
pub struct PpssppClient {
    conn: WsConn,
    timeout: Duration,
    next_ticket: u64,
    /// Broadcasts that arrived while awaiting a ticketed response.
    pending: VecDeque<serde_json::Value>,
}

impl PpssppClient {
    /// Connects to an endpoint such as `127.0.0.1:2345` (whatever port the
    /// Remote-ISO server bound) and completes the debugger upgrade.
    pub fn connect(endpoint: &str) -> Result<Self> {
        Self::connect_with_timeout(endpoint, Duration::from_secs(5))
    }

    /// Connects with an explicit connect and I/O deadline.
    pub fn connect_with_timeout(endpoint: &str, timeout: Duration) -> Result<Self> {
        Self::connect_with_key_impl(endpoint, timeout, &ws_key())
    }

    fn connect_with_key_impl(endpoint: &str, timeout: Duration, key: &str) -> Result<Self> {
        let mut addresses = ToSocketAddrs::to_socket_addrs(endpoint).map_err(DebugError::PpssppConnect)?;
        let address: SocketAddr = addresses.next().ok_or_else(|| {
            DebugError::PpssppProtocol(format!("endpoint has no addresses: {endpoint}"))
        })?;
        let stream =
            TcpStream::connect_timeout(&address, timeout).map_err(DebugError::PpssppConnect)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(DebugError::PpssppConnect)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(DebugError::PpssppConnect)?;
        let request = format!(
            "GET {DEBUGGER_PATH} HTTP/1.1\r\n\
             Host: {endpoint}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: {DEBUGGER_SUBPROTOCOL}\r\n\
             \r\n"
        );
        let mut conn = WsConn { stream };
        conn.stream.write_all(request.as_bytes()).map_err(DebugError::PpssppIo)?;
        conn.stream.flush().map_err(DebugError::PpssppIo)?;
        let head = read_http_head(&mut conn.stream)?;
        verify_upgrade(&head, key)?;
        Ok(Self {
            conn,
            timeout,
            next_ticket: 1,
            pending: VecDeque::new(),
        })
    }

    /// Identifies this tool (`version` event) and learns the emulator's
    /// identity in return — confirms we attached to the intended instance.
    pub fn hello(&mut self, tool: &str, tool_version: &str) -> Result<PpssppVersion> {
        let mut params = serde_json::Map::new();
        params.insert("name".into(), tool.into());
        params.insert("version".into(), tool_version.into());
        let reply = self.request("version", serde_json::Value::Object(params))?;
        Ok(PpssppVersion {
            name: reply.get("name").and_then(|v| v.as_str()).unwrap_or("").into(),
            version: reply.get("version").and_then(|v| v.as_str()).unwrap_or("").into(),
            pid: reply.get("pid").and_then(serde_json::Value::as_u64),
            path: reply.get("path").and_then(|v| v.as_str()).map(str::to_owned),
        })
    }

    /// Sends one ticketed request and returns the matching response object.
    /// Broadcasts that arrive first are buffered into [`Self::poll_hit`]'s queue.
    pub fn request(&mut self, event: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.wrapping_add(1).max(1);
        let mut message = match params {
            serde_json::Value::Object(map) => map,
            _ => {
                return Err(DebugError::PpssppProtocol(
                    "request params must be a JSON object".into(),
                ));
            }
        };
        message.insert("event".into(), event.into());
        message.insert("ticket".into(), ticket.into());
        self.conn.send_text(&serde_json::Value::Object(message).to_string())?;
        loop {
            let text = self.conn.recv_text()?;
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|error| DebugError::PpssppProtocol(format!("invalid JSON: {error}")))?;
            if value.get("ticket").and_then(serde_json::Value::as_u64) == Some(ticket) {
                if value.get("event").and_then(|v| v.as_str()) == Some("error") {
                    let detail = value
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("request failed");
                    return Err(DebugError::PpssppTarget(detail.into()));
                }
                return Ok(value);
            }
            self.pending.push_back(value);
        }
    }

    /// Reads `size` bytes at `address` via `memory.read`.
    pub fn read_memory(&mut self, address: u32, size: usize) -> Result<Vec<u8>> {
        if size == 0 || size > MAX_PPSSPP_BLOCK_BYTES {
            return Err(DebugError::RemoteMemoryCount(size));
        }
        let reply = self.request(
            "memory.read",
            serde_json::json!({ "address": address, "size": size as u64 }),
        )?;
        let encoded = reply.get("base64").and_then(|v| v.as_str()).ok_or_else(|| {
            DebugError::PpssppProtocol("memory.read reply has no base64 field".into())
        })?;
        let bytes = STANDARD.decode(encoded).map_err(|error| {
            DebugError::PpssppProtocol(format!("memory.read base64 is invalid: {error}"))
        })?;
        if bytes.len() != size {
            return Err(DebugError::PpssppProtocol(format!(
                "memory.read returned {} bytes, expected {size}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Reads one byte via `memory.read_u8`.
    pub fn read_u8(&mut self, address: u32) -> Result<u8> {
        Ok(self.read_scalar("memory.read_u8", address)? as u8)
    }

    /// Reads two bytes via `memory.read_u16`.
    pub fn read_u16(&mut self, address: u32) -> Result<u16> {
        Ok(self.read_scalar("memory.read_u16", address)? as u16)
    }

    /// Reads four bytes via `memory.read_u32`.
    pub fn read_u32(&mut self, address: u32) -> Result<u32> {
        self.read_scalar("memory.read_u32", address)
    }

    /// Writes one byte via `memory.write_u8`.
    pub fn write_u8(&mut self, address: u32, value: u8) -> Result<()> {
        self.write_scalar("memory.write_u8", address, value as u32)
    }

    /// Writes two bytes via `memory.write_u16`.
    pub fn write_u16(&mut self, address: u32, value: u16) -> Result<()> {
        self.write_scalar("memory.write_u16", address, value as u32)
    }

    /// Writes four bytes via `memory.write_u32`.
    pub fn write_u32(&mut self, address: u32, value: u32) -> Result<()> {
        self.write_scalar("memory.write_u32", address, value)
    }

    /// Writes `data` at `address` via `memory.write`.
    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() > MAX_PPSSPP_BLOCK_BYTES {
            return Err(DebugError::RemoteMemoryCount(data.len()));
        }
        self.request(
            "memory.write",
            serde_json::json!({ "address": address, "base64": STANDARD.encode(data) }),
        )?;
        Ok(())
    }

    /// Reads every register via `cpu.getAllRegs`, flattened to
    /// `(name, value)` pairs. Category-0 (GPR + `pc`/`hi`/`lo`) names are
    /// verbatim; other categories are prefixed (`fpr.<name>`).
    pub fn registers(&mut self) -> Result<Vec<(String, u64)>> {
        let reply = self.request("cpu.getAllRegs", serde_json::json!({}))?;
        let categories = reply.get("categories").and_then(|v| v.as_array()).ok_or_else(|| {
            DebugError::PpssppProtocol("cpu.getAllRegs reply has no categories array".into())
        })?;
        let mut out = Vec::new();
        for category in categories {
            let name = category.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let names = category
                .get("registerNames")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    DebugError::PpssppProtocol("register category has no registerNames".into())
                })?;
            let values = category
                .get("uintValues")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    DebugError::PpssppProtocol("register category has no uintValues".into())
                })?;
            if names.len() != values.len() {
                return Err(DebugError::PpssppProtocol(format!(
                    "category {name}: {} names but {} values",
                    names.len(),
                    values.len()
                )));
            }
            let prefix = if category.get("id").and_then(|v| v.as_u64()) == Some(0) {
                String::new()
            } else {
                format!("{}.", name.to_ascii_lowercase())
            };
            for (reg, value) in names.iter().zip(values.iter()) {
                let reg = reg.as_str().ok_or_else(|| {
                    DebugError::PpssppProtocol("register name is not a string".into())
                })?;
                let value = value.as_u64().ok_or_else(|| {
                    DebugError::PpssppProtocol("register value is not a uint".into())
                })?;
                out.push((format!("{prefix}{reg}"), value));
            }
        }
        Ok(out)
    }

    /// Cheap run-state poll via `cpu.status`.
    pub fn status(&mut self) -> Result<PpssppStatus> {
        let reply = self.request("cpu.status", serde_json::json!({}))?;
        Ok(PpssppStatus {
            stepping: reply.get("stepping").and_then(|v| v.as_bool()).unwrap_or(false),
            paused: reply.get("paused").and_then(|v| v.as_bool()).unwrap_or(false),
            pc: reply.get("pc").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        })
    }

    /// Adds an exec breakpoint that only logs (`log: true`,
    /// `enabled: false`) — the CPU never stops, hits arrive as
    /// `cpu.breakpoint.hit` broadcasts for [`Self::poll_hit`].
    pub fn add_breakpoint_log_only(&mut self, address: u32) -> Result<()> {
        self.request(
            "cpu.breakpoint.add",
            serde_json::json!({ "address": address, "log": true, "enabled": false }),
        )?;
        Ok(())
    }

    /// Removes an exec breakpoint.
    pub fn remove_breakpoint(&mut self, address: u32) -> Result<()> {
        self.request("cpu.breakpoint.remove", serde_json::json!({ "address": address }))?;
        Ok(())
    }

    /// Lists exec breakpoints (tolerates the documented
    /// `{breakpoints: [{address...}]}` shape and bare address arrays).
    pub fn list_breakpoints(&mut self) -> Result<Vec<u32>> {
        let reply = self.request("cpu.breakpoint.list", serde_json::json!({}))?;
        let entries = reply
            .get("breakpoints")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                DebugError::PpssppProtocol("cpu.breakpoint.list reply has no breakpoints".into())
            })?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(address) = entry.as_u64() {
                out.push(address as u32);
            } else if let Some(address) = entry.get("address").and_then(|v| v.as_u64()) {
                out.push(address as u32);
            } else if let Some(start) = entry.get("start").and_then(|v| v.as_u64()) {
                out.push(start as u32);
            } else {
                return Err(DebugError::PpssppProtocol(
                    "breakpoint entry carries no address".into(),
                ));
            }
        }
        Ok(out)
    }

    /// Waits up to `timeout` for the next breakpoint-hit broadcast and
    /// converts it to a [`TraceHit`] (`emulator:ppsspp`) for the
    /// `import-trace` feed. Returns `None` on timeout. Broadcasts seen
    /// while awaiting ticketed responses are queued, so this first drains
    /// that queue before touching the socket.
    pub fn poll_hit(&mut self, timeout: Duration) -> Result<Option<TraceHit>> {
        let mut index = 0;
        while index < self.pending.len() {
            if let Some(hit) = trace_hit_from_broadcast(&self.pending[index]) {
                self.pending.remove(index);
                return Ok(Some(hit));
            }
            index += 1;
        }
        self.conn
            .stream
            .set_read_timeout(Some(timeout))
            .map_err(DebugError::PpssppIo)?;
        let result = loop {
            let text = match self.conn.recv_text() {
                Ok(text) => text,
                Err(DebugError::PpssppIo(error))
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break Ok(None);
                }
                Err(error) => break Err(error),
            };
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|error| DebugError::PpssppProtocol(format!("invalid JSON: {error}")))?;
            if let Some(hit) = trace_hit_from_broadcast(&value) {
                break Ok(Some(hit));
            }
            self.pending.push_back(value);
        };
        self.conn
            .stream
            .set_read_timeout(Some(self.timeout))
            .map_err(DebugError::PpssppIo)?;
        result
    }

    fn read_scalar(&mut self, event: &str, address: u32) -> Result<u32> {
        let reply = self.request(event, serde_json::json!({ "address": address }))?;
        reply
            .get("value")
            .or_else(|| reply.get("uintValue"))
            .and_then(serde_json::Value::as_u64)
            .map(|value| value as u32)
            .ok_or_else(|| DebugError::PpssppProtocol(format!("{event} reply has no value")))
    }

    fn write_scalar(&mut self, event: &str, address: u32, value: u32) -> Result<()> {
        self.request(event, serde_json::json!({ "address": address, "value": value }))?;
        Ok(())
    }
}

/// Converts a `cpu.breakpoint.hit` (or a `cpu.stepping` carrying the same
/// `hit` object) into an `import-trace` hit: `exec` stays `exec`, memory
/// maps by access to `read`/`write`, register watchpoints map to `bp`.
/// Returns `None` for unrelated broadcasts.
pub fn trace_hit_from_broadcast(value: &serde_json::Value) -> Option<TraceHit> {
    let event = value.get("event").and_then(|v| v.as_str())?;
    let hit = match event {
        "cpu.breakpoint.hit" | "cpu.stepping" => value.get("hit")?,
        _ => return None,
    };
    if !hit.is_object() {
        return None;
    }
    let address = hit.get("address").and_then(serde_json::Value::as_u64)?;
    let kind = match hit.get("kind").and_then(|v| v.as_str())? {
        "exec" => TraceKind::Exec,
        "memory" => match hit.get("access").and_then(|v| v.as_str()) {
            Some("write") => TraceKind::Write,
            _ => TraceKind::Read,
        },
        "register" => TraceKind::Bp,
        _ => return None,
    };
    Some(TraceHit::new(address, kind, "ppsspp"))
}

fn read_http_head(stream: &mut TcpStream) -> Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while head.len() < 16 * 1024 {
        stream.read_exact(&mut byte).map_err(DebugError::PpssppIo)?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return String::from_utf8(head)
                .map_err(|_| DebugError::PpssppProtocol("handshake head is not UTF-8".into()));
        }
    }
    Err(DebugError::PpssppProtocol("handshake head exceeds 16 KiB".into()))
}

fn verify_upgrade(head: &str, key: &str) -> Result<()> {
    let mut lines = head.lines();
    let status = lines.next().unwrap_or("");
    if !status.contains("101") {
        return Err(DebugError::PpssppProtocol(format!(
            "websocket upgrade rejected: {status}"
        )));
    }
    let mut accept_ok = false;
    let mut protocol_ok = false;
    for line in lines {
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        if name.eq_ignore_ascii_case("sec-websocket-accept") {
            accept_ok = value.trim() == ws_accept(key);
        }
        if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            protocol_ok = value.split(',').any(|entry| entry.trim() == DEBUGGER_SUBPROTOCOL);
        }
    }
    if !accept_ok {
        return Err(DebugError::PpssppProtocol("websocket accept key mismatch".into()));
    }
    if !protocol_ok {
        return Err(DebugError::PpssppProtocol(
            "server did not negotiate debugger.ppsspp.org".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// In-test PPSSPP mock: HTTP upgrade, unmasked server frames, masked
    /// client frames, and the documented JSON event shapes. Owns its RAM
    /// and returns it on disconnect (no lock primitives involved).
    struct MockScript {
        ram: Vec<u8>,
        /// When a `memory.read` targets this address, emit a hit broadcast
        /// *before* the response (ticket-correlation probe).
        broadcast_before_read: Option<u32>,
        hit_address: u32,
    }

    fn spawn_mock(script: MockScript) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let head = read_head(&mut stream);
            assert!(head.contains(DEBUGGER_SUBPROTOCOL), "client offers subprotocol");
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\
                 Sec-WebSocket-Protocol: {DEBUGGER_SUBPROTOCOL}\r\n\
                 \r\n",
                ws_accept(TEST_WS_KEY)
            );
            stream.write_all(response.as_bytes()).unwrap();
            let mut state = script;
            loop {
                let Some(text) = read_client_text(&mut stream) else {
                    return state.ram;
                };
                let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                let event = request.get("event").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                let ticket = request.get("ticket").cloned().unwrap_or(serde_json::Value::Null);
                let mut reply = serde_json::Map::new();
                reply.insert("event".into(), event.clone().into());
                reply.insert("ticket".into(), ticket);
                match event.as_str() {
                    "version" => {
                        reply.insert("name".into(), "mock-ppsspp".into());
                        reply.insert("version".into(), "1.0-test".into());
                        reply.insert("pid".into(), 1234.into());
                        reply.insert("path".into(), serde_json::Value::Null);
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                    }
                    "memory.read" => {
                        let address = request.get("address").and_then(|v| v.as_u64()).unwrap() as usize;
                        let size = request.get("size").and_then(|v| v.as_u64()).unwrap() as usize;
                        if Some(address as u32) == state.broadcast_before_read {
                            write_server_text(&mut stream, &hit_broadcast(state.hit_address, "exec", None));
                        }
                        let bytes = state.ram[address..address + size].to_vec();
                        reply.insert("base64".into(), STANDARD.encode(&bytes).into());
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                    }
                    "memory.read_u8" | "memory.read_u16" | "memory.read_u32" => {
                        let address = request.get("address").and_then(|v| v.as_u64()).unwrap() as usize;
                        let width = match event.as_str() {
                            "memory.read_u8" => 1,
                            "memory.read_u16" => 2,
                            _ => 4,
                        };
                        let mut value = 0u64;
                        for (i, &byte) in state.ram[address..address + width].iter().enumerate() {
                            value |= (byte as u64) << (i * 8);
                        }
                        reply.insert("value".into(), value.into());
                        reply.insert("uintValue".into(), value.into());
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                    }
                    "memory.write_u8" | "memory.write_u16" | "memory.write_u32" => {
                        let address = request.get("address").and_then(|v| v.as_u64()).unwrap() as usize;
                        let value = request.get("value").and_then(|v| v.as_u64()).unwrap();
                        let width = match event.as_str() {
                            "memory.write_u8" => 1,
                            "memory.write_u16" => 2,
                            _ => 4,
                        };
                        for i in 0..width {
                            state.ram[address + i] = ((value >> (i * 8)) & 0xFF) as u8;
                        }
                        reply.insert("value".into(), value.into());
                        reply.insert("uintValue".into(), value.into());
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                    }
                    "memory.write" => {
                        let address = request.get("address").and_then(|v| v.as_u64()).unwrap() as usize;
                        let encoded = request.get("base64").and_then(|v| v.as_str()).unwrap();
                        let bytes = STANDARD.decode(encoded).unwrap();
                        state.ram[address..address + bytes.len()].copy_from_slice(&bytes);
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                    }
                    "cpu.getAllRegs" => {
                        reply.insert(
                            "categories".into(),
                            serde_json::json!([
                                {
                                    "id": 0, "name": "GPR",
                                    "registerNames": ["zero", "at", "v0", "pc", "hi", "lo"],
                                    "uintValues": [0, 1, 2, 0x0880_4010u64, 0, 0],
                                    "floatValues": ["0", "1", "2", "0", "0", "0"],
                                },
                                {
                                    "id": 1, "name": "FPR",
                                    "registerNames": ["f0"],
                                    "uintValues": [1065353216u64],
                                    "floatValues": ["1.000000"],
                                },
                            ]),
                        );
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                    }
                    "cpu.status" => {
                        reply.insert("stepping".into(), false.into());
                        reply.insert("paused".into(), false.into());
                        reply.insert("pc".into(), 0x0880_4010u64.into());
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                    }
                    "cpu.breakpoint.add" => {
                        let address = request.get("address").and_then(|v| v.as_u64()).unwrap();
                        assert_eq!(request.get("log").and_then(|v| v.as_bool()), Some(true));
                        assert_eq!(request.get("enabled").and_then(|v| v.as_bool()), Some(false));
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                        // Log-only trip arrives as a broadcast without stopping.
                        write_server_text(&mut stream, &hit_broadcast(address as u32, "exec", None));
                    }
                    "cpu.breakpoint.remove" => {
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                    }
                    "cpu.breakpoint.list" => {
                        reply.insert("breakpoints".into(), serde_json::json!([{"address": 142876568u64}]));
                        write_server_text(&mut stream, &serde_json::Value::Object(reply));
                    }
                    _ => {
                        let mut error = serde_json::Map::new();
                        error.insert("event".into(), "error".into());
                        error.insert("ticket".into(), request.get("ticket").cloned().unwrap_or_default());
                        error.insert("message".into(), "unknown event".into());
                        error.insert("level".into(), 2.into());
                        write_server_text(&mut stream, &serde_json::Value::Object(error));
                    }
                }
            }
        });
        (address, handle)
    }

    fn hit_broadcast(address: u32, kind: &str, access: Option<&str>) -> serde_json::Value {
        let mut hit = serde_json::json!({
            "kind": kind,
            "pc": address,
            "address": address,
            "hits": 1,
            "logged": true,
            "paused": false,
            "condition": null,
            "breakpoint": { "start": address, "end": address },
        });
        if let Some(access) = access {
            hit["size"] = 4.into();
            hit["access"] = access.into();
        }
        serde_json::json!({ "event": "cpu.breakpoint.hit", "sequence": 1, "hit": hit })
    }

    fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    fn read_client_text(stream: &mut TcpStream) -> Option<String> {
        let mut head = [0u8; 2];
        if stream.read_exact(&mut head).is_err() {
            return None;
        }
        let mut len = (head[1] & 0x7F) as usize;
        assert!(head[1] & 0x80 != 0, "client frames are masked");
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).unwrap();
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).unwrap();
            len = u64::from_be_bytes(ext) as usize;
        }
        let mut mask = [0u8; 4];
        stream.read_exact(&mut mask).unwrap();
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).unwrap();
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        Some(String::from_utf8(payload).unwrap())
    }

    fn write_server_text(stream: &mut TcpStream, value: &serde_json::Value) {
        let text = value.to_string();
        let bytes = text.as_bytes();
        let mut frame = vec![0x81];
        if bytes.len() < 126 {
            frame.push(bytes.len() as u8);
        } else {
            frame.push(126);
            frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(bytes);
        stream.write_all(&frame).unwrap();
        stream.flush().unwrap();
    }

    fn script() -> MockScript {
        MockScript {
            ram: (0..256u32).map(|value| (value & 0xFF) as u8).collect(),
            broadcast_before_read: None,
            hit_address: 0,
        }
    }

    fn client(address: SocketAddr) -> PpssppClient {
        PpssppClient::connect_with_key_impl(address.to_string().as_str(), Duration::from_secs(2), TEST_WS_KEY)
            .unwrap()
    }

    #[test]
    fn sha1_matches_fips_vector() {
        // FIPS 180-4 "abc" digest; guards the handshake accept computation.
        let digest = sha1(b"abc");
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(ws_accept(TEST_WS_KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn hello_memory_and_registers_round_trip() {
        let (address, server) = spawn_mock(script());
        let mut client = client(address);
        let version = client.hello("romwright-test", "0.0").unwrap();
        assert_eq!(version.name, "mock-ppsspp");
        assert_eq!(version.pid, Some(1234));

        assert_eq!(client.read_u8(0x01).unwrap(), 1);
        assert_eq!(client.read_u16(0x02).unwrap(), 0x0302);
        assert_eq!(client.read_u32(0x04).unwrap(), 0x0706_0504);
        assert_eq!(client.read_memory(0x10, 8).unwrap(), vec![16, 17, 18, 19, 20, 21, 22, 23]);

        client.write_u8(0x20, 0xAA).unwrap();
        client.write_u16(0x21, 0xBBCC).unwrap();
        client.write_u32(0x24, 0xDDEE_FF00).unwrap();
        client.write_memory(0x30, &[9, 8, 7]).unwrap();

        let registers = client.registers().unwrap();
        assert!(registers.contains(&("v0".to_owned(), 2)));
        assert!(registers.contains(&("pc".to_owned(), 0x0880_4010)));
        assert!(registers.contains(&("fpr.f0".to_owned(), 1065353216)));

        let status = client.status().unwrap();
        assert_eq!(status.pc, 0x0880_4010);
        assert!(!status.stepping);

        drop(client);
        let ram = server.join().unwrap();
        assert_eq!(ram[0x20], 0xAA);
        assert_eq!(&ram[0x21..0x23], &[0xCC, 0xBB]);
        assert_eq!(&ram[0x24..0x28], &[0x00, 0xFF, 0xEE, 0xDD]);
        assert_eq!(&ram[0x30..0x33], &[9, 8, 7]);
    }

    #[test]
    fn log_only_breakpoint_feeds_import_trace() {
        let (address, server) = spawn_mock(script());
        let mut client = client(address);
        client.add_breakpoint_log_only(0x0880_4010).unwrap();
        // The trip broadcast arrived while awaiting the add response, so
        // poll_hit serves it from the pending queue without I/O.
        let hit = client
            .poll_hit(Duration::from_millis(50))
            .unwrap()
            .expect("log-only trip observed");
        assert_eq!(hit.address, 0x0880_4010);
        assert_eq!(hit.kind, TraceKind::Exec);
        assert_eq!(hit.provenance, "emulator:ppsspp");
        assert_eq!(hit.to_csv_row(), "8804010,exec");
        assert_eq!(client.list_breakpoints().unwrap(), vec![142876568]);
        client.remove_breakpoint(0x0880_4010).unwrap();
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn ticket_correlation_survives_interleaved_broadcast() {
        let probe = 0x40;
        let mut fixture = script();
        fixture.broadcast_before_read = Some(probe);
        fixture.hit_address = 0x0880_5000;
        let (address, server) = spawn_mock(fixture);
        let mut client = client(address);
        // The server emits a hit broadcast before the read response; the
        // ticket matcher must skip it, buffer it, and still resolve.
        let bytes = client.read_memory(probe, 4).unwrap();
        assert_eq!(bytes, vec![64, 65, 66, 67]);
        let hit = client
            .poll_hit(Duration::from_millis(50))
            .unwrap()
            .expect("buffered broadcast recovered");
        assert_eq!(hit.to_csv_row(), "8805000,exec");
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn hit_mapping_covers_memory_and_register_kinds() {
        let read = hit_broadcast(0x1000, "memory", Some("read"));
        assert_eq!(trace_hit_from_broadcast(&read).unwrap().kind, TraceKind::Read);
        let write = hit_broadcast(0x1000, "memory", Some("write"));
        assert_eq!(trace_hit_from_broadcast(&write).unwrap().kind, TraceKind::Write);
        let reg = serde_json::json!({
            "event": "cpu.breakpoint.hit",
            "hit": { "kind": "register", "pc": 8, "address": 8, "register": 4, "registerName": "a0" },
        });
        assert_eq!(trace_hit_from_broadcast(&reg).unwrap().kind, TraceKind::Bp);
        let stepping = serde_json::json!({
            "event": "cpu.stepping",
            "hit": { "kind": "exec", "pc": 16, "address": 16 },
        });
        assert_eq!(trace_hit_from_broadcast(&stepping).unwrap().address, 16);
        assert_eq!(trace_hit_from_broadcast(&serde_json::json!({"event": "game.pause"})), None);
    }

    #[test]
    fn error_event_surfaces_target_failure() {
        let (address, server) = spawn_mock(script());
        let mut client = client(address);
        let error = client.request("no.such.event", serde_json::json!({})).unwrap_err();
        assert!(matches!(error, DebugError::PpssppTarget(message) if message == "unknown event"));
        assert!(matches!(
            client.read_memory(0x10, 0),
            Err(DebugError::RemoteMemoryCount(0))
        ));
        drop(client);
        server.join().unwrap();
    }
}
