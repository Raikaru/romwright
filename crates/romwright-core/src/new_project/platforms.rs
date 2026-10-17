//! What `new-project` can do per platform, and exactly what the rest need.
//!
//! The matrix is data so the CLI (`new-project --list-platforms`) and
//! `docs/new-project.md` say the same thing. `needs` lists concrete next
//! steps, not aspirations: each names the tool, its license where it was
//! checked, and the romwright piece that is missing.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// `new-project` produces a building, checksum-verified repo today.
    Implemented,
    /// A byte-matching ecosystem exists; a plugin has to be written for it.
    Planned,
    /// No byte-matching ecosystem: `new-project` writes a non-matching scaffold
    /// (decompiled C that is only compile-checked; objdiff where it has a backend).
    Scaffold,
}

#[derive(Debug, Clone, Serialize)]
pub struct Platform {
    pub id: &'static str,
    pub name: &'static str,
    pub status: Status,
    /// The decompilation toolchain the generated repo drives.
    pub toolkit: &'static str,
    /// Concrete next steps (planned/scaffold) or what the output holds (implemented).
    pub needs: &'static [&'static str],
}

pub const PLATFORMS: &[Platform] = &[
    Platform {
        id: "pe",
        name: "Windows PE (x86)",
        status: Status::Scaffold,
        toolkit: "reccmp-style per-function units: romwright's decompiled C + the era's Visual C++ (msvc4.2 / 6.0 / 7.0 / 7.1 / 8.0, proprietary, run through wibo) + objdiff; i386 COFF target objects of the retail bytes; no whole-executable rebuild",
        needs: &[
            "a 32-bit PE (EXE or DLL); the compiler era comes from the linker version in the image (`msvc-12` = Visual C++ 6.0 ...) or `--compiler`; a MinGW or unidentified PE gets a clang compile check only",
            "python3; wibo, the compiler and objdiff-cli are fetched from the pinned manifest by the generated `configure.py`; `build.py report` writes a per-function match status (there is no whole-image sha1 for PC: the linker, the C runtime and the object order are not recovered)",
            "not done: PE32+ (x86-64), a pinned MinGW GCC; a `__thiscall` function is written as a `__fastcall` with an unused `edx` (Visual C's C has no `__thiscall`), its callers are not",
        ],
    },
    Platform {
        id: "ps2",
        name: "PlayStation 2",
        status: Status::Implemented,
        toolkit: "splat 0.39.1 (MIT) + decompals MIPS PS2 binutils + ninja; MWCC PS2 / ee-gcc compilers",
        needs: &[
            "boot ELF (or an ISO9660 image whose SYSTEM.CNF names it)",
            "splat64 (pip), ninja, python3; build tools are fetched from the pinned manifest or taken from a toolchain profile",
        ],
    },
    Platform {
        id: "gc",
        name: "GameCube",
        status: Status::Implemented,
        toolkit: "decomp-toolkit v1.8.4 (MIT OR Apache-2.0) + dtk-template layout (CC0-1.0) + ninja; MWCC GC/1.0 .. GC/3.0a5.2 (proprietary, run through wibo) + objdiff",
        needs: &[
            "a DOL, or a disc image (ISO, CISO, RVZ, WIA, WBFS) whose boot DOL and RELs are extracted into orig/<game id>/",
            "python3 and ninja; dtk, wibo, sjiswrap, objdiff-cli and the compilers are fetched from the pinned manifest (or a toolchain profile); the all-assembly build rebuilds the retail DOL byte for byte (`dtk shasum`)",
        ],
    },
    Platform {
        id: "wii",
        name: "Wii",
        status: Status::Implemented,
        toolkit: "decomp-toolkit v1.8.4 (MIT OR Apache-2.0) + dtk-template layout (CC0-1.0) + ninja; MWCC GC/3.0a5.x and Wii/1.0 .. Wii/1.7 (proprietary, run through wibo) + objdiff",
        needs: &[
            "the same plugin as GameCube (same DOL/REL formats and dtk flow); a Wii disc (RVZ, WIA, WBFS, ISO) is read through its decrypted data partition and its boot DOL and RELs are written to orig/",
            "python3 and ninja; tools from the pinned manifest as for GameCube",
        ],
    },
    Platform {
        id: "n64",
        name: "Nintendo 64",
        status: Status::Implemented,
        toolkit: "splat 0.39.1 (MIT) + decompals MIPS binutils (GPL) + ninja; IDO 5.3/7.1 (ido-static-recomp) or GCC 2.7.2 (KMC-style) / 2.8.1 (pmret)",
        needs: &[
            "a cartridge ROM in any dump byte order (z64, v64, n64); it is normalised to big-endian .z64 in orig/ and the header CRC1/CRC2 are recomputed after linking for the known CICs (6101, 6102, 6103, 6105, 6106) when the retail header is consistent",
            "the layout is romwright's own (catalog or discovery): header and IPL3 segments, then every executable range that is raw MIPS in the ROM as a code segment; compressed segments and overlays stay binary pieces, so the all-assembly build rebuilds the ROM byte for byte",
            "python3 and ninja; binutils, the compilers (IDO vs GCC by the `move` spelling) and objdiff-cli come from the pinned manifest or a toolchain profile",
        ],
    },
    Platform {
        id: "psx",
        name: "PlayStation",
        status: Status::Implemented,
        toolkit: "splat 0.39.1 (MIT) + maspsx (MIT) + decompals MIPS binutils (GPL) + ninja; PSY-Q 3.3 - 4.6 CC1PSX (proprietary, run through wibo)",
        needs: &[
            "a PS-X EXE (the boot executable of the disc, extracted); the 0x800-byte header is a leading segment and `t_addr`/`t_size`/`gp0` come from it",
            "python3 and ninja; wibo, maspsx, the PSY-Q set and objdiff-cli come from the pinned manifest or a toolchain profile; the PSY-Q generation is a default chosen from the libsys `$Id` stamp",
        ],
    },
    Platform {
        id: "psp",
        name: "PlayStation Portable",
        status: Status::Implemented,
        toolkit: "splat 0.39.1 (MIT, psp platform) + decompals MIPS binutils (GPL) + ninja; psp-gcc 1.7.1 (GPL, i386) or Metrowerks CodeWarrior for PSP (proprietary, wibo)",
        needs: &[
            "a decrypted PSP ELF: an EBOOT/PRX (ET_PRX) or an ET_EXEC image; the retail relocation tables are file bytes the rebuild carries verbatim, so the all-assembly build is byte-identical (a C unit that moves code would need the PRX tables re-emitted, which is not implemented)",
            "python3 and ninja; psp-gcc needs a 32-bit loader (/lib/ld-linux.so.2); Allegrex-only instructions (VFPU, max/min) are assembled as raw words per unit",
        ],
    },
    Platform {
        id: "gba",
        name: "Game Boy Advance",
        status: Status::Implemented,
        toolkit: "romwright's own ARM/Thumb assembly emitter (splat has no ARM): Arm GNU Toolchain 13.3.rel1 as/ld/objcopy/cpp (GPL), agbcc (pret/agbcc release binary, GCC 2.95-derived), ninja",
        needs: &[
            "none for ROMs with ARM/Thumb code in the cartridge image; code a game copies to RAM or unpacks (Golden Sun's overlays, NASCAR's module) stays bytes in the ROM",
            "output: `config/units.json` covers the ROM (header unit with the computed complement check, one `.s` per function, `.incbin` data units); `tools/asm.py` keeps a line as a raw word when `as` encodes it differently; `swap` + `tools/cc.py` (cpp | agbcc | as)",
            "a game built with old_agbcc, agbcc_arm or another compiler needs `--cflags` or a toolchain profile; the detector separates the agbcc lineage from GCC 4+ only",
        ],
    },
    Platform {
        id: "nds",
        name: "Nintendo DS",
        status: Status::Implemented,
        toolkit: "ds-decomp / dsd v0.12.1 (AetiasHax, MIT) with ds-rom v0.8.0 (MIT) for extract/delink/rebuild + mwccarm/mwldarm (proprietary, decomp.me archive) through wibo + objdiff; romwright's symbols merged into dsd's config",
        needs: &[
            "none for decrypted dumps: twewy and KH 358/2 Days (DS Protect ranges included) rebuild to the retail sha1 (the secure-area CRC and header CRC are restored by tools/romfix.py)",
            "an encrypted retail dump needs the ARM7 BIOS (`--arm7-bios`, never stored); the corpus HeartGold (pret's own build, DS Protect ranges unencrypted) does not relink to its own bytes with dsd 0.12.1; the ARM7 program stays a binary",
            "the mwccarm build is a default for the evidence class (NitroSDK banner), not a proven one",
        ],
    },
    Platform {
        id: "3ds",
        name: "Nintendo 3DS",
        status: Status::Scaffold,
        toolkit: "Non-matching scaffold (no public toolchain reproduces Nintendo's RVCT/armcc output): pinned clang 22.1.8 compile check, objdiff-cli for ARMv6K target objects",
        needs: &[
            "writes config/symbols.txt (mode:arm|thumb per function), config/modules.json (sections, load addresses, mapped-image sha256), include/, src/<module>/<shard>/<function>.c marked NON_MATCHING, orig/target/*.o and objdiff.json; `build.py` only proves the C compiles",
            "input: an NCCH/NCSD/CIA (cleartext or zero fixed key; other keys via --keys), or a flat ExeFS .code with `--raw 0x100000 --language ARM:LE:32:v6 [--map symbols.map]`; a raw .code has no section table (one region) and the decompiler refuses functions that read the missing .bss",
            "retail-encrypted titles need the user's keys; none are stored",
        ],
    },
    Platform {
        id: "switch",
        name: "Nintendo Switch",
        status: Status::Scaffold,
        toolkit: "Non-matching scaffold (retail NSOs are Nintendo-clang + LTO builds nothing public reproduces): pinned clang 22.1.8 compile check, objdiff-cli for AArch64 target objects",
        needs: &[
            "writes one symbol file and section map per NSO module (`config/<module>/symbols.txt`, load address, mapped-image sha256, build id of a bare NSO), include/, src/ marked NON_MATCHING, orig/target/*.o and objdiff.json",
            "input: a bare NSO, or NCA/XCI/ExeFS with `--keys prod.keys`; the build id is read only from a bare NSO",
        ],
    },
    Platform {
        id: "ps3",
        name: "PlayStation 3",
        status: Status::Scaffold,
        toolkit: "Non-matching scaffold (SNC/GCC PPU output, SELF container with per-console keys): pinned clang 22.1.8 compile check (32-bit PowerPC target); no objdiff.json (no PowerPC64 backend)",
        needs: &[
            "writes the same tree without objdiff.json; orig/target/*.o (PowerPC relocations) feed `romwright-cli export-scratch --target-object` and the matching workspaces",
            "blocked on the only PS3 image on the hosts: Persona 5's SW.BIN is an encrypted retail SELF and stops at `SELF metadata counts implausible` without the user's keys (--keys RAP/klic); the scaffold was verified on a synthetic decrypted PowerPC64 ELF only",
            "SPU images of a container keep config only (no C)",
        ],
    },
    Platform {
        id: "ps4",
        name: "PlayStation 4",
        status: Status::Scaffold,
        toolkit: "Non-matching scaffold (clang x86-64 output in SELF containers): pinned clang 22.1.8 compile check, objdiff-cli for x86-64 target objects",
        needs: &[
            "writes config/symbols.txt, section map, include/, src/ marked NON_MATCHING, orig/target/*.o (call/jmp rel32 become R_X86_64_PLT32) and objdiff.json; RIP-relative data operands stay retail bytes and differ in objdiff",
            "input: the decrypted ELF (OS ABI 9); unpacking a SELF needs the console's keys, which romwright neither uses nor stores",
        ],
    },
    Platform {
        id: "vita",
        name: "PlayStation Vita",
        status: Status::Scaffold,
        toolkit: "Non-matching scaffold (SNC/GCC/clang output against Sony's SDK): pinned clang 22.1.8 compile check (per-unit -marm/-mthumb); no objdiff.json: objdiff-cli 3.6.1 rejects ARMv7 objects (`ARM arch ARMv7 not supported`)",
        needs: &[
            "writes config/symbols.txt with NID-resolved import names (`type:import`), mode:arm|thumb per function, section map, include/, src/ marked NON_MATCHING and orig/target/*.o for export-scratch/matching workspaces",
            "input: the decrypted ELF or a SELF (NPDRM titles need the klic via --keys); a BINMAP with --map names the rest",
        ],
    },
    Platform {
        id: "x360",
        name: "Xbox 360",
        status: Status::Scaffold,
        toolkit: "Non-matching scaffold (MSVC PowerPC output in XEX2 containers): pinned clang 22.1.8 compile check (32-bit PowerPC target); no objdiff.json (no PowerPC64 backend)",
        needs: &[
            "writes config/symbols.txt, the PE section map, include/, src/ marked NON_MATCHING and orig/target/*.o for export-scratch/matching workspaces; VMX128 code stays `irregular` in the C (no intrinsics)",
            "input: a XEX2 or a PE; encrypted XEX2 needs the user's keys (--keys); a linker map with --map names functions",
        ],
    },
];

pub fn platform(id: &str) -> Option<&'static Platform> {
    PLATFORMS.iter().find(|p| p.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_platform_romwright_imports_has_a_row_and_the_implemented_ones_are_listed() {
        for id in ["ps2", "gc", "wii", "n64", "psx", "psp", "gba", "nds", "3ds", "switch", "ps3", "ps4", "vita", "x360", "pe"] {
            assert!(platform(id).is_some(), "{id}");
        }
        let implemented: Vec<_> = PLATFORMS.iter().filter(|p| p.status == Status::Implemented).map(|p| p.id).collect();
        for id in ["ps2", "gc", "wii", "n64", "psx", "psp", "gba", "nds"] {
            assert!(implemented.contains(&id), "{id}");
        }
        assert!(PLATFORMS.iter().all(|p| !p.needs.is_empty()));
    }
}
