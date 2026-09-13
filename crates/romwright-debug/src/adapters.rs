//! Emulator adapters (P2.9): the per-emulator glue that maps the generic
//! GDB-RSP client to each emulator's register layout and memory model.
//!
//! Every emulator that speaks RSP answers the same packets (`g` for all
//! registers, `m` for memory) but the register order and the address
//! space differ. An adapter names the emulator, declares its register
//! order for the `g` reply, and translates the emulator's address space
//! into the tool's flat addresses.

use std::time::Duration;

use crate::{DebugError, Result};

/// One emulator's RSP register layout: the order the `g` packet returns
/// registers in, as (name, byte-width) pairs. The reply is a flat hex
/// string; the adapter slices it by these widths.
pub struct RegisterMap {
    /// The emulator this map describes.
    pub emulator: &'static str,
    /// (name, byte width) in `g`-packet order.
    pub registers: &'static [(&'static str, usize)],
}

/// Dolphin (GameCube/Wii): 32 GPRs + PC + the PPC specials, all 4 bytes.
pub const DOLPHIN_REGISTERS: RegisterMap = RegisterMap {
    emulator: "dolphin",
    registers: &[
        ("r0", 4), ("r1", 4), ("r2", 4), ("r3", 4), ("r4", 4), ("r5", 4),
        ("r6", 4), ("r7", 4), ("r8", 4), ("r9", 4), ("r10", 4), ("r11", 4),
        ("r12", 4), ("r13", 4), ("r14", 4), ("r15", 4), ("r16", 4), ("r17", 4),
        ("r18", 4), ("r19", 4), ("r20", 4), ("r21", 4), ("r22", 4), ("r23", 4),
        ("r24", 4), ("r25", 4), ("r26", 4), ("r27", 4), ("r28", 4), ("r29", 4),
        ("r30", 4), ("r31", 4),
        ("pc", 4), ("lr", 4), ("ctr", 4), ("cr", 4), ("xer", 4),
        ("msr", 4), ("srr0", 4), ("srr1", 4),
    ],
};

/// PCSX2 (PS2): 32 GPRs + HI/LO + PC, all 16 bytes (128-bit MIPS).
pub const PCSX2_REGISTERS: RegisterMap = RegisterMap {
    emulator: "pcsx2",
    registers: &[
        ("zero", 16), ("at", 16), ("v0", 16), ("v1", 16),
        ("a0", 16), ("a1", 16), ("a2", 16), ("a3", 16),
        ("t0", 16), ("t1", 16), ("t2", 16), ("t3", 16),
        ("t4", 16), ("t5", 16), ("t6", 16), ("t7", 16),
        ("s0", 16), ("s1", 16), ("s2", 16), ("s3", 16),
        ("s4", 16), ("s5", 16), ("s6", 16), ("s7", 16),
        ("t8", 16), ("t9", 16), ("k0", 16), ("k1", 16),
        ("gp", 16), ("sp", 16), ("fp", 16), ("ra", 16),
        ("hi", 16), ("lo", 16), ("pc", 16),
    ],
};

/// mGBA (GBA): 16 ARM GPRs + CPSR, all 4 bytes.
pub const MGBA_REGISTERS: RegisterMap = RegisterMap {
    emulator: "mgba",
    registers: &[
        ("r0", 4), ("r1", 4), ("r2", 4), ("r3", 4), ("r4", 4), ("r5", 4),
        ("r6", 4), ("r7", 4), ("r8", 4), ("r9", 4), ("r10", 4), ("r11", 4),
        ("r12", 4), ("sp", 4), ("lr", 4), ("pc", 4), ("cpsr", 4),
    ],
};

/// RPCS3 (PS3): 32 PPU GPRs + PC + the PPC64 specials, all 8 bytes.
pub const RPCS3_REGISTERS: RegisterMap = RegisterMap {
    emulator: "rpcs3",
    registers: &[
        ("r0", 8), ("r1", 8), ("r2", 8), ("r3", 8), ("r4", 8), ("r5", 8),
        ("r6", 8), ("r7", 8), ("r8", 8), ("r9", 8), ("r10", 8), ("r11", 8),
        ("r12", 8), ("r13", 8), ("r14", 8), ("r15", 8), ("r16", 8), ("r17", 8),
        ("r18", 8), ("r19", 8), ("r20", 8), ("r21", 8), ("r22", 8), ("r23", 8),
        ("r24", 8), ("r25", 8), ("r26", 8), ("r27", 8), ("r28", 8), ("r29", 8),
        ("r30", 8), ("r31", 8),
        ("pc", 8), ("lr", 8), ("ctr", 8), ("cr", 8), ("xer", 8),
    ],
};

/// Vita3K (Vita): 16 ARM GPRs + CPSR, all 4 bytes (ARMv7).
pub const VITA3K_REGISTERS: RegisterMap = RegisterMap {
    emulator: "vita3k",
    registers: &[
        ("r0", 4), ("r1", 4), ("r2", 4), ("r3", 4), ("r4", 4), ("r5", 4),
        ("r6", 4), ("r7", 4), ("r8", 4), ("r9", 4), ("r10", 4), ("r11", 4),
        ("r12", 4), ("sp", 4), ("lr", 4), ("pc", 4), ("cpsr", 4),
    ],
};

/// Citra (3DS): 16 ARM GPRs + CPSR, all 4 bytes (ARM11).
pub const CITRA_REGISTERS: RegisterMap = RegisterMap {
    emulator: "citra",
    registers: &[
        ("r0", 4), ("r1", 4), ("r2", 4), ("r3", 4), ("r4", 4), ("r5", 4),
        ("r6", 4), ("r7", 4), ("r8", 4), ("r9", 4), ("r10", 4), ("r11", 4),
        ("r12", 4), ("sp", 4), ("lr", 4), ("pc", 4), ("cpsr", 4),
    ],
};

/// Xenia (Xbox 360): 32 PPC64 GPRs + PC + specials, all 8 bytes.
pub const XENIA_REGISTERS: RegisterMap = RegisterMap {
    emulator: "xenia",
    registers: &[
        ("r0", 8), ("r1", 8), ("r2", 8), ("r3", 8), ("r4", 8), ("r5", 8),
        ("r6", 8), ("r7", 8), ("r8", 8), ("r9", 8), ("r10", 8), ("r11", 8),
        ("r12", 8), ("r13", 8), ("r14", 8), ("r15", 8), ("r16", 8), ("r17", 8),
        ("r18", 8), ("r19", 8), ("r20", 8), ("r21", 8), ("r22", 8), ("r23", 8),
        ("r24", 8), ("r25", 8), ("r26", 8), ("r27", 8), ("r28", 8), ("r29", 8),
        ("r30", 8), ("r31", 8),
        ("pc", 8), ("lr", 8), ("ctr", 8), ("cr", 8), ("xer", 8),
    ],
};

/// melonDS (DS): 16 ARM GPRs + CPSR, all 4 bytes (ARM9/ARM7).
pub const MELONDS_REGISTERS: RegisterMap = RegisterMap {
    emulator: "melonds",
    registers: &[
        ("r0", 4), ("r1", 4), ("r2", 4), ("r3", 4), ("r4", 4), ("r5", 4),
        ("r6", 4), ("r7", 4), ("r8", 4), ("r9", 4), ("r10", 4), ("r11", 4),
        ("r12", 4), ("sp", 4), ("lr", 4), ("pc", 4), ("cpsr", 4),
    ],
};

/// Every adapter this crate ships, for enumeration.
pub const ALL_ADAPTERS: &[&RegisterMap] = &[
    &DOLPHIN_REGISTERS,
    &PCSX2_REGISTERS,
    &MGBA_REGISTERS,
    &RPCS3_REGISTERS,
    &VITA3K_REGISTERS,
    &CITRA_REGISTERS,
    &XENIA_REGISTERS,
    &MELONDS_REGISTERS,
];

/// A live emulator session: an RSP client plus the register map that
/// decodes its `g` reply.
pub struct EmulatorSession {
    client: crate::DolphinGdb,
    map: &'static RegisterMap,
}

impl EmulatorSession {
    /// Connects to an emulator's RSP endpoint with its register map.
    pub fn connect(endpoint: &str, map: &'static RegisterMap) -> Result<Self> {
        let client = crate::DolphinGdb::connect_with_timeout(
            endpoint,
            Duration::from_secs(5),
        )?;
        Ok(Self { client, map })
    }

    /// Reads `count` bytes from the emulator's address space.
    pub fn read_memory(&mut self, address: u64, count: usize) -> Result<Vec<u8>> {
        self.client.read_memory(address, count)
    }

    /// Reads all registers via the `g` packet, decoded by the map into
    /// (name, value) pairs. Values are the register's bytes, big-endian
    /// as the packet carries them.
    pub fn registers(&mut self) -> Result<Vec<(String, Vec<u8>)>> {
        let response = self.client.raw_request(b"g")?;
        if response.first() == Some(&b'E') {
            return Err(DebugError::RemoteTarget(
                String::from_utf8_lossy(&response).into_owned(),
            ));
        }
        let mut out = Vec::with_capacity(self.map.registers.len());
        let mut cursor = 0usize;
        for (name, width) in self.map.registers {
            let hex_len = width * 2;
            if cursor + hex_len > response.len() {
                return Err(DebugError::RemoteProtocol(format!(
                    "g packet too short for register {name}: need {hex_len} hex at {cursor}, have {}",
                    response.len()
                )));
            }
            let mut bytes = Vec::with_capacity(*width);
            for pair in response[cursor..cursor + hex_len].chunks_exact(2) {
                let high = crate::hex_digit(pair[0]).ok_or_else(|| {
                    DebugError::RemoteProtocol("register data is not hex".into())
                })?;
                let low = crate::hex_digit(pair[1]).ok_or_else(|| {
                    DebugError::RemoteProtocol("register data is not hex".into())
                })?;
                bytes.push((high << 4) | low);
            }
            out.push((name.to_string(), bytes));
            cursor += hex_len;
        }
        Ok(out)
    }

    /// The emulator this session speaks to.
    pub fn emulator(&self) -> &'static str {
        self.map.emulator
    }
}
