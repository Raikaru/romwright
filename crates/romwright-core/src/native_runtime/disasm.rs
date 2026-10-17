//! In-process disassembly listing: `disasm` and the listing window.
//!
//! The text is what the SLEIGH console's `disassemble` printed
//! (`IfcPrintdisasm` and `IfaceAssemblyEmit`, pinned Ghidra 12.1.3,
//! Apache-2.0): `<address>: <mnemonic padded to 10> <operands>` from
//! `Translate::printAssembly` (Kuna's `Sleigh::print_assembly_into`),
//! `Block <address>` before the first instruction of a basic block, and
//! `Bytes <address>: <hex>` after each instruction.
//!
//! One contract differs from the console and is deliberate. The console ran
//! the decompiler's flow analysis on a function mapped at the requested
//! address and listed the bytes of that function's extent, so a request for
//! more instructions than the function holds stopped at its end, and the
//! blocks were the decompiler's (jump tables included). The listing here is
//! the `count` instructions the caller asked for, from the address asked
//! for, whatever function they belong to; the extent of a function is the
//! store's (`functions`), not a guess made per request. Block starts are
//! derived from the direct flow of the listed instructions alone: the first
//! instruction, each direct branch target inside the listing, and the
//! instruction after any branch, conditional branch, indirect branch or
//! return. A jump-table target nothing in the listing branches to directly is
//! not marked.
use super::{NativeRuntimeError, PcodeOp, Result, SleighLifter, err};
use crate::session::RuntimeConfig;
use kuna_base::address::Address;
use std::collections::BTreeSet;
use std::path::Path;

/// The mnemonic column the console padded to (`IfaceAssemblyEmit(…, 10)`).
const MNEMONIC_PAD: usize = 10;

/// One listed instruction.
struct Row {
    address: u64,
    text: String,
    bytes: Vec<u8>,
    ops: Vec<PcodeOp>,
}

fn parse_address(address: &str) -> Result<u64> {
    let digits = address.trim().trim_start_matches("0x");
    u64::from_str_radix(digits, 16)
        .map_err(|_| NativeRuntimeError(format!("bad address `{address}`: expected hex")))
}

fn raw(address: &Address) -> String {
    let mut text = String::new();
    let _ = address.print_raw(&mut text);
    text
}

/// Where each block after the first begins, from the direct flow of the
/// listed instructions: see the module documentation.
fn block_starts(rows: &[Row]) -> BTreeSet<u64> {
    let mut starts = BTreeSet::new();
    let listed: BTreeSet<u64> = rows.iter().map(|row| row.address).collect();
    for (index, row) in rows.iter().enumerate() {
        let mut transfers = false;
        for op in &row.ops {
            match op.opcode.as_str() {
                "BRANCH" | "CBRANCH" => {
                    transfers = true;
                    if let Some(target) = op.inputs.first().filter(|input| !input.is_const())
                        && listed.contains(&target.offset) {
                            starts.insert(target.offset);
                        }
                }
                "BRANCHIND" | "RETURN" => transfers = true,
                _ => {}
            }
        }
        if transfers
            && let Some(next) = rows.get(index + 1) {
                starts.insert(next.address);
            }
    }
    starts
}

/// `count` instructions from `address` in `binary`, as listing lines;
/// `with_structure` adds the block and byte lines.
fn listing(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    count: u32,
    with_structure: bool,
) -> Result<String> {
    let start = parse_address(address)?;
    let mut lifter = SleighLifter::file(cfg, binary, 0)?;
    let mut rows: Vec<Row> = Vec::new();
    let mut next = start;
    let (mut mnemonic, mut body) = (String::new(), String::new());
    while rows.len() < count as usize {
        let at = lifter.address(next);
        // The instruction's flow runs before its text is printed, as the
        // console's flow analysis ran before `disassemble`: the lift commits
        // the context changes the instruction makes.
        let ops = lifter.lift(&[next]).pop().map(|lifted| lifted.ops).unwrap_or_default();
        let Ok(length) = lifter.sleigh.print_assembly_into(&at, &mut mnemonic, &mut body) else {
            break;
        };
        let Some(length) = usize::try_from(length).ok().filter(|length| *length > 0) else {
            break;
        };
        let mut text = String::with_capacity(MNEMONIC_PAD + body.len());
        text.push_str(&mnemonic);
        text.push_str(&" ".repeat(MNEMONIC_PAD.saturating_sub(mnemonic.len())));
        text.push_str(&body);
        let mut bytes = vec![0u8; length];
        if with_structure
            && lifter.sleigh.loader_rc().borrow_mut().load_fill(&mut bytes, &at).is_err()
        {
            break;
        }
        rows.push(Row { address: next, text, bytes, ops });
        next = next.wrapping_add(length as u64);
    }
    if rows.is_empty() {
        return err("no instruction decodes at that address");
    }
    let blocks = if with_structure { block_starts(&rows) } else { BTreeSet::new() };
    let mut out = String::new();
    for (index, row) in rows.iter().enumerate() {
        let at = lifter.address(row.address);
        let shown = raw(&at);
        if with_structure && (index == 0 || blocks.contains(&row.address)) {
            out.push_str(&format!("Block {shown}\n"));
        }
        out.push_str(&format!("{shown}: {}\n", row.text));
        if with_structure {
            out.push_str(&format!("Bytes {shown}: "));
            for byte in &row.bytes {
                out.push_str(&format!("{byte:02x}"));
            }
            out.push('\n');
        }
    }
    out.pop();
    Ok(out)
}

/// Performs `disasm`: `count` instructions from `address`, address-prefixed
/// instruction lines only.
pub fn disasm_native(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    count: u32,
) -> Result<String> {
    listing(cfg, binary, address, count, false)
}

/// The same instructions with the structural marker lines the Core listing
/// parser reads (`Block`, `Bytes`).
pub fn listing_native(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    count: u32,
) -> Result<String> {
    listing(cfg, binary, address, count, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_runtime::PcodeVarnode;

    fn tiny_bin() -> Option<(RuntimeConfig, std::path::PathBuf)> {
        let cfg = RuntimeConfig::from_env();
        let binary = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures-src/tiny_bin");
        if !cfg.ghidra_install.join("Ghidra").is_dir() || !binary.is_file() {
            eprintln!("SKIP: no Ghidra install or no tiny_bin fixture");
            return None;
        }
        Some((cfg, binary))
    }

    #[test]
    fn disasm_lists_the_requested_instructions_in_the_consoles_format() {
        let Some((cfg, binary)) = tiny_bin() else { return };
        let text = disasm_native(&cfg, &binary, "00400466", 4).unwrap();
        assert_eq!(
            text,
            "0x00400466: PUSH      RBP\n\
             0x00400467: MOV       RBP,RSP\n\
             0x0040046a: MOV       dword ptr [RBP + -0x4],EDI\n\
             0x0040046d: MOV       dword ptr [RBP + -0x8],ESI"
        );
        // `0x`-prefixed addresses and a count past the function's end are
        // the caller's to ask for.
        let more = disasm_native(&cfg, &binary, "0x400466", 40).unwrap();
        assert_eq!(more.lines().count(), 40);
        assert!(more.starts_with(&text));
    }

    #[test]
    fn listing_adds_blocks_and_bytes_and_an_undecodable_start_is_an_error() {
        let Some((cfg, binary)) = tiny_bin() else { return };
        let text = listing_native(&cfg, &binary, "400466", 2).unwrap();
        assert_eq!(
            text,
            "Block 0x00400466\n\
             0x00400466: PUSH      RBP\n\
             Bytes 0x00400466: 55\n\
             0x00400467: MOV       RBP,RSP\n\
             Bytes 0x00400467: 4889e5"
        );
        assert!(disasm_native(&cfg, &binary, "zz", 1).is_err());
        assert!(disasm_native(&cfg, &binary, "10", 1).is_err(), "no byte is mapped there");
    }

    fn row(address: u64, ops: &[(&str, Option<(&str, u64)>)]) -> Row {
        let varnode = |(space, offset): (&str, u64)| PcodeVarnode { space: space.into(), offset, size: 8 };
        Row {
            address,
            text: String::new(),
            bytes: vec![0],
            ops: ops
                .iter()
                .map(|(opcode, input)| PcodeOp {
                    opcode: (*opcode).into(),
                    output: None,
                    inputs: input.iter().copied().map(varnode).collect(),
                })
                .collect(),
        }
    }

    #[test]
    fn blocks_start_after_transfers_and_at_listed_direct_targets() {
        let rows = [
            row(0x10, &[("COPY", None)]),
            // A conditional branch to a listed address: both arms start blocks.
            row(0x11, &[("CBRANCH", Some(("ram", 0x15)))]),
            row(0x12, &[("COPY", None)]),
            // An unconditional branch out of the listing, and a relative
            // (instruction-local) branch, which is no machine flow.
            row(0x13, &[("BRANCH", Some(("ram", 0x99)))]),
            row(0x14, &[("CBRANCH", Some(("const", 1)))]),
            row(0x15, &[("RETURN", Some(("register", 0x20)))]),
            row(0x16, &[("COPY", None)]),
        ];
        assert_eq!(
            block_starts(&rows).into_iter().collect::<Vec<_>>(),
            // After 0x11, after 0x13, the target 0x15, after 0x15; the
            // constant-space branch at 0x14 splits nothing but its own
            // successor (a CBRANCH is a transfer), which is 0x15 again.
            [0x12, 0x14, 0x15, 0x16]
        );
    }
}
