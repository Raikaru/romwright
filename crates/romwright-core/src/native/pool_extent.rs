//! Literal-pool extents (`literal-pool-extent` compiler rule).
//!
//! ARM compilers that load a constant with a PC-relative `ldr` put the
//! constants in a literal pool right after the function that loads them, and
//! the symbol size they emit covers the pool: agbcc's `.size` runs to the
//! next function, and so do CodeWarrior's. The flow walk proves a body ends at
//! its last return, so a stored size stops at the pool and reads short -- on
//! the corpus 0.43-0.83 of the GBA and NDS functions that truth sizes
//! (`size_short` of the wave's discovery metric), against 0.00-0.03 on the
//! PowerPC and MIPS games.
//!
//! The pool is read off the function's own bytes: every PC-relative word load
//! in the body whose target lies past the body names a pool word, and the
//! function runs to the end of the highest one. Only instructions the walk
//! decoded count (`flow_shapes`): a pool in the middle of a large function, or
//! the data a body runs into, holds halfwords that look like loads and would
//! stretch the extent over its neighbour. The extent never reaches the next
//! entry, never over an instruction the walk decoded (that is code, not pool),
//! never over more words than the function's own loads can name (one per load,
//! and a word of alignment: a pool shared with a function the walk missed, as
//! hand-written assembly shares one, is not this function's), and never
//! touches a function whose size the image's own symbol table declared.

use super::{Mapping, NativeFunction, NativeImport};
use std::collections::{HashMap, HashSet};

/// Thumb `ldr Rd,[pc,#imm8*4]`: `01001 Rd imm8`. The end of the highest pool
/// word named, and how many loads named a word at or past `body_end`.
fn thumb_pool_end(code: &[u8], entry: u64, body_end: u64, decoded: &HashSet<u64>) -> (u64, u64) {
    let (mut end, mut loads) = (0, 0);
    for (index, pair) in code.as_chunks::<2>().0.iter().enumerate() {
        let half = u16::from_le_bytes([pair[0], pair[1]]);
        let at = entry + 2 * index as u64;
        if half & 0xf800 == 0x4800 && decoded.contains(&at) {
            let target = ((at + 4) & !3) + u64::from(half & 0xff) * 4;
            if target >= body_end {
                loads += 1;
                end = end.max(target + 4);
            }
        }
    }
    (end, loads)
}

/// ARM `ldr Rd,[pc,#+-imm12]` (word, offset addressing, any condition but `1111`).
fn arm_pool_end(code: &[u8], entry: u64, body_end: u64, decoded: &HashSet<u64>) -> (u64, u64) {
    let (mut end, mut loads) = (0, 0);
    for (index, chunk) in code.as_chunks::<4>().0.iter().enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let at = entry + 4 * index as u64;
        if word & 0x0f7f_0000 == 0x051f_0000 && word >> 28 != 0xf && decoded.contains(&at) {
            let offset = u64::from(word & 0xfff);
            let target = if word & 0x0080_0000 != 0 { at + 8 + offset } else { (at + 8).saturating_sub(offset) };
            if target >= body_end {
                loads += 1;
                end = end.max(target + 4);
            }
        }
    }
    (end, loads)
}

fn mapping_of(mappings: &[Mapping], address: u64) -> Option<&Mapping> {
    mappings.iter().find(|m| m.vaddr <= address && address < m.vaddr + m.bytes.len() as u64)
}

/// Grows the size of every function of `functions` (sorted by entry) that is
/// followed by the literal pool its own loads name. Returns how many grew.
pub(super) fn extend(imp: &NativeImport, functions: &mut [NativeFunction], thumb: bool, arm: bool) -> usize {
    let modes: HashMap<u64, u64> = imp
        .contexts
        .iter()
        .filter(|context| context.name == "LowBitCodeMode")
        .map(|context| (context.address, context.value))
        .collect();
    let declared = |entry: u64| {
        let index = imp.symbol_extents.partition_point(|&(start, _)| start < entry);
        imp.symbol_extents.get(index).is_some_and(|&(start, _)| start == entry)
    };
    let decoded: HashSet<u64> = imp.flow_shapes.iter().map(|shape| shape.address).collect();
    let mut starts: Vec<u64> = decoded.iter().copied().collect();
    starts.sort_unstable();
    let next_entries: Vec<u64> = functions.iter().map(|f| f.entry).collect();
    let mut grown = 0;
    for (index, function) in functions.iter_mut().enumerate() {
        if function.size <= 1 || declared(function.entry) {
            continue;
        }
        let is_thumb = modes.get(&function.entry) == Some(&1);
        if (is_thumb && !thumb) || (!is_thumb && !arm) {
            continue;
        }
        let end = function.entry + function.size;
        let next = next_entries.get(index + 1).copied().unwrap_or(u64::MAX);
        let Some(mapping) = mapping_of(&imp.mappings, function.entry) else { continue };
        let mapping_end = mapping.vaddr + mapping.bytes.len() as u64;
        if end >= next || end > mapping_end {
            continue;
        }
        let start = (function.entry - mapping.vaddr) as usize;
        let code = &mapping.bytes[start..(end - mapping.vaddr) as usize];
        let (pool_end, loads) = if is_thumb {
            thumb_pool_end(code, function.entry, end, &decoded)
        } else {
            arm_pool_end(code, function.entry, end, &decoded)
        };
        // The extent must hold no decoded instruction: past the body that is the next code, not a pool.
        let code_inside = starts.get(starts.partition_point(|&at| at < end)).is_some_and(|&at| at < pool_end);
        let named_words = pool_end.saturating_sub(end) <= 4 * loads + 4;
        if pool_end > end && pool_end <= next && pool_end <= mapping_end && !code_inside && named_words {
            function.size = pool_end - function.entry;
            grown += 1;
        }
    }
    grown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{FlowShape, NativeContext};
    use crate::native_runtime::FlowKind;

    /// An image whose halfwords (`step` 2) or words (`step` 4) from 0x1000 up to `decoded_to` bytes in are
    /// decoded instructions, with `thumb_entries` recorded as Thumb entries.
    fn image(bytes: Vec<u8>, thumb_entries: &[u64], step: u64, decoded_to: u64) -> NativeImport {
        NativeImport {
            flow_shapes: (0..decoded_to)
                .step_by(step as usize)
                .map(|offset| FlowShape {
                    address: 0x1000 + offset,
                    length: step as u8,
                    kind: FlowKind::Fallthrough,
                    conditional: false,
                    target: None,
                })
                .collect(),
            language: "ARM:LE:32:v4t".into(),
            mappings: vec![Mapping { vaddr: 0x1000, size: bytes.len() as u64, file_off: 0, flags: 6, bytes }],
            contexts: thumb_entries
                .iter()
                .map(|&address| NativeContext { name: "LowBitCodeMode".into(), address, value: 1 })
                .collect(),
            ..Default::default()
        }
    }

    fn function(entry: u64, size: u64) -> NativeFunction {
        NativeFunction { entry, size, name: format!("FUN_{entry:08x}") }
    }

    fn thumb_bytes(halves: &[u16]) -> Vec<u8> {
        let mut bytes: Vec<u8> = halves.iter().flat_map(|half| half.to_le_bytes()).collect();
        bytes.resize(0x20, 0);
        bytes
    }

    #[test]
    fn a_thumb_function_runs_through_the_pool_its_loads_name() {
        // 0x1000: ldr r0,[pc,#4] (-> 0x1008); ldr r1,[pc,#8] (-> 0x100c); bx lr
        // 0x1006: padding, 0x1008/0x100c: pool, 0x1010: next function
        let imp = image(thumb_bytes(&[0x4801, 0x4902, 0x4770, 0, 0, 0, 0, 0]), &[0x1000, 0x1010], 2, 6);
        let mut functions = [function(0x1000, 6), function(0x1010, 4)];
        assert_eq!(extend(&imp, &mut functions, true, true), 1);
        assert_eq!(functions[0].size, 0x10, "through the second pool word, 0x100c + 4");
        assert_eq!(functions[1].size, 4, "no loads, no pool");
    }

    #[test]
    fn a_pool_that_would_reach_the_next_entry_or_a_declared_size_is_left_alone() {
        let bytes = thumb_bytes(&[0x4803, 0x4770, 0, 0, 0, 0, 0, 0]);
        // The load targets 0x1010 (+4 = 0x1014), past the next entry at 0x1008.
        let imp = image(bytes.clone(), &[0x1000, 0x1008], 2, 4);
        let mut functions = [function(0x1000, 4), function(0x1008, 8)];
        assert_eq!(extend(&imp, &mut functions, true, true), 0);
        assert_eq!(functions[0].size, 4);
        // The image's own symbol table declared the size: it is the image's word.
        let mut declared = image(bytes, &[0x1000], 2, 4);
        declared.symbol_extents = vec![(0x1000, 0x1004)];
        let mut functions = [function(0x1000, 4)];
        assert_eq!(extend(&declared, &mut functions, true, true), 0);
    }

    #[test]
    fn a_halfword_the_walk_never_decoded_is_data_and_stretches_nothing() {
        // 0x1000: bx lr; 0x1002: the halfword 0x48ff, a pool word in the middle of the body that
        // reads as `ldr r0,[pc,#1020]`. Only 0x1000 is a decoded instruction.
        let imp = image(thumb_bytes(&[0x4770, 0x48ff, 0x4770, 0]), &[0x1000], 2, 2);
        let mut functions = [function(0x1000, 6)];
        assert_eq!(extend(&imp, &mut functions, true, true), 0);
        assert_eq!(functions[0].size, 6);
    }

    #[test]
    fn an_extent_over_decoded_code_is_not_a_pool() {
        // The load names 0x1010, but 0x1008 is a decoded instruction: code of a function nobody found.
        let mut imp = image(thumb_bytes(&[0x4803, 0x4770, 0, 0, 0, 0, 0, 0]), &[0x1000], 2, 4);
        imp.flow_shapes.push(FlowShape {
            address: 0x1008,
            length: 2,
            kind: FlowKind::Fallthrough,
            conditional: false,
            target: None,
        });
        let mut functions = [function(0x1000, 4)];
        assert_eq!(extend(&imp, &mut functions, true, true), 0);
        assert_eq!(functions[0].size, 4);
    }

    #[test]
    fn a_pool_shared_with_a_function_nobody_found_is_not_this_functions() {
        // One load names a word 0x40 past the body: sixteen words of "pool" for one load. Nothing in
        // between is decoded (the function there was missed), but nothing in this function loads it.
        let mut bytes = thumb_bytes(&[0x4810, 0x4770]);
        bytes.resize(0x60, 0);
        let imp = image(bytes, &[0x1000], 2, 4);
        let mut functions = [function(0x1000, 4)];
        assert_eq!(extend(&imp, &mut functions, true, true), 0);
        assert_eq!(functions[0].size, 4);
    }

    #[test]
    fn an_arm_function_reads_its_pc_relative_loads_and_the_isa_can_be_switched_off() {
        // 0x1000: ldr r0,[pc,#4] (e59f0004: -> 0x1000 + 8 + 4 = 0x100c); bx lr; nop; .word
        let words = [0xe59f_0004u32, 0xe12f_ff1e, 0xe1a0_0000, 0xdead_beef, 0];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let imp = image(bytes, &[], 4, 8);
        let mut functions = [function(0x1000, 8)];
        assert_eq!(extend(&imp, &mut functions, true, true), 1);
        assert_eq!(functions[0].size, 0x10);
        let mut again = [function(0x1000, 8)];
        assert_eq!(extend(&imp, &mut again, true, false), 0, "the rule can name Thumb only");
    }
}
