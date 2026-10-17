//! Function starts behind a function's fill on an i386 PE.
//!
//! Compilers and linkers lay functions out one behind another and pad each to its alignment with `int3` (Microsoft) or
//! `nop` forms (GCC). Where a walked function's proven body ends and fill follows, the first byte after the fill, on a
//! 4-byte boundary, that no function already covers is where the next function starts: an unreferenced function, a
//! callback no table names, a dead one, found from its neighbour. A body that ends in a jump table (data, not fill,
//! right behind the last instruction) puts no fill there, so nothing is proposed behind it. A function that ends in a
//! return on a 16-byte boundary needs no fill: the next one starts right there. An address a relocated word or
//! a switch table names is left alone: the case labels of a table nothing resolved are blocks of a function that start
//! on loop-alignment fill (GCC), which this rule would otherwise make functions of (two MinGW images fell to 0.76 / 0.78
//! precision before that exclusion). Nor is anything proposed behind a function holding an indirect jump no switch table
//! was recovered for: the blocks after its proven end are likely its own.
//!
//! Measured before the rule on four fixtures, over every walked function whose body ended before fill: the 4-byte
//! aligned start behind it was a truth function in 71 of 73 cases on a MinGW image and in 80 of 82 and 49 of 54 on Visual
//! C++ 8.0 ones; on Visual C++ 4.2 (GLQuake) 10 of 20, the rest tables behind functions, which the checks below now exclude.

use std::collections::HashSet;

use crate::native::NativeImport;
use crate::native_runtime::FlowKind;

/// The length of the no-op instruction at the start of `bytes`, 0 when it is not one: `int3`, `nop` (with its
/// operand-size prefixes), the multi-byte `nop r/m` (`0f 1f /0`) and the `lea reg, [reg+0]` forms GCC pads loops
/// and functions with (`8d 74 26 00`, `2e 8d b4 26 00 00 00 00`, `8d 49 00`: the register is its own base and the
/// displacement is zero).
fn nop_length(bytes: &[u8]) -> usize {
    let mut at = 0;
    while matches!(bytes.get(at), Some(0x66 | 0x2e | 0x3e)) {
        at += 1;
    }
    let sib_displaced = |modrm_at: usize| -> Option<usize> {
        // the length of ModRM, SIB and displacement from `modrm_at`, for a memory operand with no immediate
        let modrm = *bytes.get(modrm_at)?;
        let (mode, rm) = (modrm >> 6, modrm & 7);
        let sib = usize::from(mode != 3 && rm == 4);
        let disp = match mode {
            0 if rm == 5 => 4,
            0 => 0,
            1 => 1,
            2 => 4,
            _ => return None,
        };
        Some(1 + sib + disp)
    };
    match bytes.get(at).copied() {
        Some(0x90) => at + 1,
        Some(0xcc) if at == 0 => 1,
        Some(0x0f) if bytes.get(at + 1) == Some(&0x1f) => sib_displaced(at + 2).map_or(0, |length| at + 2 + length),
        Some(0x8d) => {
            let (Some(&modrm), length) = (bytes.get(at + 1), sib_displaced(at + 1)) else { return 0 };
            let (mode, reg, rm) = (modrm >> 6, (modrm >> 3) & 7, modrm & 7);
            let Some(length) = length else { return 0 };
            let zero_displacement = bytes.get(at + 1 + length - match mode { 1 => 1, 2 => 4, _ => 0 }..at + 1 + length);
            let base = if rm == 4 { bytes.get(at + 2).map(|sib| (sib & 7, (sib >> 3) & 7)) } else { Some((rm, 4)) };
            match (mode, base, zero_displacement) {
                (1 | 2, Some((base, 4)), Some(displacement)) if base == reg && displacement.iter().all(|&byte| byte == 0) => at + 1 + length,
                (0, Some((base, 4)), _) if rm != 4 && rm != 5 && base == reg => at + 2,
                _ => 0,
            }
        }
        _ => 0,
    }
}

fn bytes_at(imp: &NativeImport, address: u64, len: usize) -> Option<&[u8]> {
    let mapping = imp
        .mappings
        .iter()
        .find(|mapping| mapping.flags & 4 != 0 && address >= mapping.vaddr && address - mapping.vaddr < mapping.size)?;
    let offset = (address - mapping.vaddr) as usize;
    mapping.bytes.get(offset..(offset + len).min(mapping.bytes.len()))
}

/// How many bytes of fill (no-op instructions) start at `address`.
fn fill_length(imp: &NativeImport, address: u64) -> u64 {
    let mut length = 0;
    loop {
        let Some(bytes) = bytes_at(imp, address + length, 12) else { return length };
        match nop_length(bytes) {
            0 => return length,
            step => length += step as u64,
        }
        if length > 64 {
            return length;
        }
    }
}

/// The most passes of the fill-start rule one discovery runs: a run of this many unreferenced functions in a row
/// is found whole, a longer one over the rounds that follow.
pub(in crate::native) const PASSES: usize = 32;

/// The function starts the rule proposes for `imp` as it stands (sorted, none already an entry).
pub(in crate::native) fn starts(imp: &NativeImport) -> Vec<u64> {
    if imp.format != "PE"
        || imp.language != "x86:LE:32:default"
        || !crate::compiler::rules::applies("pe-x86-fill-starts", &crate::compiler::ctx_of(imp))
    {
        return Vec::new();
    }
    let mut extents: Vec<(u64, u64)> = imp.functions.iter().map(|f| (f.entry, f.entry + f.size.max(1))).collect();
    extents.sort_unstable();
    let entries: HashSet<u64> = extents.iter().map(|&(entry, _)| entry).collect();
    // An address a relocated word or a recovered switch table names was judged already: it is a case label (a jump
    // table's targets are what no walk reaches directly), or it was accepted as an entry. Not a start nobody names.
    let named: HashSet<u64> = imp
        .reloc_candidates
        .iter()
        .chain(&imp.pointer_candidates)
        .copied()
        .chain(imp.switch_tables.values().flatten().copied())
        .collect();
    let covered = |address: u64| {
        let index = extents.partition_point(|&(entry, _)| entry <= address);
        // the nearest preceding extent is not enough: an earlier, longer one may reach over it
        extents[..index].iter().rev().take(8).any(|&(entry, end)| entry <= address && address < end)
    };
    // Direct branches: a conditional branch targets a block of its own function, and an unconditional one from inside
    // the function before the fill is that function's own (an `else` arm placed after the loop-alignment fill).
    let mut conditional: HashSet<u64> = HashSet::new();
    let mut unconditional: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
    for shape in &imp.flow_shapes {
        match (shape.kind, shape.target) {
            (FlowKind::CBranch, Some(target)) => {
                conditional.insert(target);
            }
            (FlowKind::Branch, Some(target)) => unconditional.entry(target).or_default().push(shape.address),
            _ => {}
        }
    }
    // How each body ends: a function that returns and stops on a 16-byte boundary has the next one start there, with
    // no fill between (a 16- or 32-byte function: every one of them in the Quake 2 image that nothing calls).
    let mut last: Vec<(u64, FlowKind)> = imp.flow_shapes.iter().map(|shape| (shape.address, shape.kind)).collect();
    last.sort_unstable_by_key(|&(address, _)| address);
    let returns_at = |end: u64| {
        let index = last.partition_point(|&(address, _)| address < end);
        index.checked_sub(1).is_some_and(|before| last[before].1 == FlowKind::Return)
    };
    // A function that holds an indirect jump no switch table was recovered for has blocks no walk reached (its case
    // labels): bytes behind it are as likely its own last blocks as a function.
    let mut unresolved: Vec<u64> = imp
        .indirect_jumps
        .iter()
        .copied()
        .filter(|jump| !imp.switch_tables.contains_key(jump))
        .collect();
    unresolved.sort_unstable();
    let has_unresolved_jump = |entry: u64, end: u64| {
        let index = unresolved.partition_point(|&jump| jump < entry);
        unresolved.get(index).is_some_and(|&jump| jump < end)
    };
    let mut found: Vec<u64> = extents
        .iter()
        .filter(|&&(entry, end)| end - entry > 1 && !entries.is_empty() && entry != end)
        .filter_map(|&(entry, end)| {
            let fill = fill_length(imp, end);
            let start = end + fill;
            let first = bytes_at(imp, start, 4)?;
            let own_block = conditional.contains(&start)
                || unconditional.get(&start).is_some_and(|from| from.iter().any(|&site| site >= entry && site < end));
            ((fill > 0 || start.is_multiple_of(16) && returns_at(end))
                && !own_block
                && !has_unresolved_jump(entry, end)
                && start.is_multiple_of(4)
                && !entries.contains(&start)
                && !named.contains(&start)
                && !covered(start)
                && !matches!(first[0], 0x00 | 0xcc | 0x90)
                && first != [0, 0, 0, 0])
            .then_some(start)
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{Mapping, NativeFunction};

    fn image(code: Vec<u8>, functions: &[(u64, u64)]) -> NativeImport {
        let mut imp = NativeImport {
            format: "PE".into(),
            language: "x86:LE:32:default".into(),
            mappings: vec![Mapping { vaddr: 0x401000, size: code.len() as u64, file_off: 0, flags: 5, bytes: code }],
            ..Default::default()
        };
        imp.functions = functions
            .iter()
            .map(|&(entry, size)| NativeFunction { entry, name: format!("FUN_{entry:08x}"), size })
            .collect();
        imp
    }

    #[test]
    fn the_first_byte_after_a_functions_fill_is_the_next_start() {
        // 0x401000: 8 bytes of body then int3 fill to 0x401010; a function at 0x401010 nothing names; fill; zeros
        let mut code = vec![0x90; 0x40];
        code[..8].copy_from_slice(&[0x55, 0x8b, 0xec, 0x5d, 0xc3, 0x8b, 0xff, 0xc3]);
        for byte in &mut code[8..0x10] {
            *byte = 0xcc;
        }
        code[0x10..0x18].copy_from_slice(&[0x55, 0x8b, 0xec, 0x33, 0xc0, 0x5d, 0xc3, 0xcc]);
        for byte in &mut code[0x18..0x20] {
            *byte = 0xcc;
        }
        let imp = image(code, &[(0x401000, 8)]);
        assert_eq!(starts(&imp), [0x401010]);
        // already an entry, or covered by a function's body: nothing proposed
        assert!(starts(&image(imp.mappings[0].bytes.clone(), &[(0x401000, 8), (0x401010, 8)])).iter().all(|&a| a != 0x401010));
        assert!(starts(&image(imp.mappings[0].bytes.clone(), &[(0x401000, 8), (0x401008, 0x10)])).is_empty());
    }

    #[test]
    fn the_padding_forms_of_both_compilers_are_fill() {
        assert_eq!(nop_length(&[0xcc, 0x55]), 1);
        assert_eq!(nop_length(&[0x66, 0x90]), 2);
        assert_eq!(nop_length(&[0x0f, 0x1f, 0x44, 0x00, 0x00]), 5);
        assert_eq!(nop_length(&[0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]), 8);
        assert_eq!(nop_length(&[0x8d, 0x74, 0x26, 0x00]), 4); // lea esi, [esi+eiz+0]
        assert_eq!(nop_length(&[0x2e, 0x8d, 0xb4, 0x26, 0, 0, 0, 0]), 8); // lea esi, cs:[esi+eiz+0]
        assert_eq!(nop_length(&[0x8d, 0x49, 0x00]), 3); // lea ecx, [ecx+0]
        assert_eq!(nop_length(&[0x8d, 0xb6, 0, 0, 0, 0]), 6); // lea esi, [esi+0]
        assert_eq!(nop_length(&[0x8d, 0x46, 0x00]), 0, "lea eax, [esi+0] is a copy, not a no-op");
        assert_eq!(nop_length(&[0x8d, 0x74, 0x26, 0x01]), 0, "a displacement of one is not a no-op");
        assert_eq!(nop_length(&[0x55, 0x8b, 0xec]), 0);
    }

    #[test]
    fn a_function_that_returns_on_a_16_byte_boundary_has_the_next_one_start_there() {
        let mut code = vec![0x8b; 0x40];
        code[0xf] = 0xc3;
        code[0x10..0x13].copy_from_slice(&[0x55, 0x8b, 0xec]);
        let mut imp = image(code, &[(0x401000, 0x10)]);
        // the body's last instruction is a return
        imp.flow_shapes.push(crate::native::FlowShape { address: 0x40100f, length: 1, kind: FlowKind::Return, conditional: false, target: None });
        assert_eq!(starts(&imp), [0x401010]);
        // an indirect jump ends the body instead (a table follows): nothing
        imp.flow_shapes[0].kind = FlowKind::BranchInd;
        assert!(starts(&imp).is_empty());
    }

    #[test]
    fn a_body_with_no_fill_behind_it_proposes_nothing() {
        // the body ends in a jump table (data), then the next function: no fill at the end of the body
        let mut code = vec![0x55; 0x40];
        code[0x10..0x14].copy_from_slice(&[0x20, 0x10, 0x40, 0x00]);
        assert!(starts(&image(code, &[(0x401000, 0x10)])).is_empty());
    }
}
