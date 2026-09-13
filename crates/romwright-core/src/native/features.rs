//! Structural features of a recovered function: the facts a whole-program
//! diff matches on (`romwright_model::FunctionFeatureRow`).
//!
//! Everything here is counted from what the walk already decoded, so no pass
//! re-reads the image and nothing needs the decompiler. Blocks and edges
//! follow Ghidra's basic-block model: `BasicBlockModel.hasEndOfBlockFlow`
//! (:64-78) ends a block at a jump or a terminal instruction and not at a
//! call, and `SimpleBlockModel` starts one at a branch target
//! (`SimpleBlockModel.getBasicBlockAt`, :168 -- a block runs while the
//! instruction falls through and has no end-of-block flow).

use std::collections::{HashMap, HashSet};

use romwright_model::FunctionFeatureRow;

use super::{FlowShape, NativeImport};
use crate::native_runtime::FlowKind;

/// True when this instruction ends a basic block: a jump (conditional or
/// not, direct or indirect) or a terminal. A call does not.
fn ends_block(kind: FlowKind) -> bool {
    matches!(
        kind,
        FlowKind::Branch | FlowKind::CBranch | FlowKind::BranchInd | FlowKind::Return
    )
}

/// True when flow can continue at the following address.
fn falls_through(shape: &FlowShape) -> bool {
    match shape.kind {
        FlowKind::Branch | FlowKind::BranchInd | FlowKind::Return => false,
        FlowKind::CBranch => true,
        _ => true,
    }
}

/// Measures every function the import recovered.
///
/// A function whose body was never decoded (size 0, no instructions) gets no
/// row: a measurement nobody took is not a fact, and a zeroed row would make
/// two unrelated undecoded functions look identical to a matcher.
pub(crate) fn measure(imp: &NativeImport) -> Vec<FunctionFeatureRow> {
    if imp.flow_shapes.is_empty() || imp.functions.is_empty() {
        return Vec::new();
    }
    let mut shapes: Vec<FlowShape> = imp.flow_shapes.clone();
    shapes.sort_by_key(|shape| shape.address);
    shapes.dedup_by_key(|shape| shape.address);
    let addresses: Vec<u64> = shapes.iter().map(|shape| shape.address).collect();

    // A switch jump's targets are the recovered table, not part of the
    // decoded shape; they are edges all the same.
    let mut table_targets: HashMap<u64, &Vec<u64>> = HashMap::new();
    for (address, targets) in &imp.switch_tables {
        table_targets.insert(*address, targets);
    }

    let mut rows = Vec::with_capacity(imp.functions.len());
    let entries: Vec<u64> = imp.functions.iter().map(|f| f.entry).collect();
    for (index, function) in imp.functions.iter().enumerate() {
        let start = function.entry;
        // The body runs to its proven size, or to the next entry when the
        // size says nothing was proven, exactly as the store fills it.
        let end = match function.size {
            0 => entries.get(index + 1).copied().unwrap_or(u64::MAX),
            size => start.saturating_add(size),
        };
        let first = addresses.partition_point(|address| *address < start);
        let last = addresses.partition_point(|address| *address < end);
        if first == last {
            continue;
        }
        let body = &shapes[first..last];
        let inside = |address: u64| address >= start && address < end;

        // Leaders: the entry, every in-body branch target, and the address
        // after an instruction that ends a block.
        let mut leaders: HashSet<u64> = HashSet::with_capacity(body.len() / 4 + 1);
        leaders.insert(start);
        let mut edges = 0u32;
        let mut loops = 0u32;
        for shape in body {
            let next = shape.address.saturating_add(u64::from(shape.length));
            let mut targets: Vec<u64> = Vec::new();
            if let Some(target) = shape.target {
                targets.push(target);
            }
            if shape.kind == FlowKind::BranchInd {
                if let Some(table) = table_targets.get(&shape.address) {
                    targets.extend(table.iter().copied());
                }
            }
            for target in targets {
                if inside(target) {
                    leaders.insert(target);
                    edges += 1;
                    // A branch to itself or backwards closes a loop.
                    if target <= shape.address {
                        loops += 1;
                    }
                }
            }
            if ends_block(shape.kind) {
                if falls_through(shape) && inside(next) {
                    leaders.insert(next);
                    edges += 1;
                }
            }
        }
        // Only leaders an instruction actually starts at count as blocks: a
        // target into the middle of an instruction is not a block.
        let blocks = leaders
            .iter()
            .filter(|leader| addresses[first..last].binary_search(leader).is_ok())
            .count() as u32;
        // The largest block, in instructions: the leaders are the block
        // starts, so the gaps between them in the instruction sequence are
        // the block lengths.
        let mut starts: Vec<usize> = (first..last)
            .filter(|index| leaders.contains(&addresses[*index]))
            .collect();
        starts.sort_unstable();
        let mut max_block = 0u32;
        for (index, &position) in starts.iter().enumerate() {
            let end_position = starts.get(index + 1).copied().unwrap_or(last);
            max_block = max_block.max((end_position - position) as u32);
        }
        rows.push(FunctionFeatureRow {
            function: romwright_model::Address::ram(start),
            instructions: body.len() as u32,
            blocks: blocks.max(1),
            edges,
            loops,
            max_block: max_block.max(1),
            body_digest: body_digest(imp, start, end),
            shape_digest: shape_digest(body),
        });
    }
    rows
}

/// Digest of the body bytes as the image holds them. Two functions with the
/// same digest are the same bytes at the same address -- the strongest
/// evidence a diff can have, and the reason a stripped image and its
/// unstripped twin match outright.
fn body_digest(imp: &NativeImport, start: u64, end: u64) -> String {
    let mut hasher = Digest::new();
    hasher.write(&start.to_le_bytes());
    for mapping in &imp.mappings {
        let mapping_end = mapping.vaddr.saturating_add(mapping.size);
        if start >= mapping_end || end <= mapping.vaddr {
            continue;
        }
        let from = start.max(mapping.vaddr) - mapping.vaddr;
        let to = end.min(mapping_end) - mapping.vaddr;
        let from = usize::try_from(from).unwrap_or(usize::MAX);
        let to = usize::try_from(to).unwrap_or(usize::MAX).min(mapping.bytes.len());
        if from < to {
            hasher.write(&mapping.bytes[from..to]);
        }
    }
    hasher.finish()
}

/// Digest of the decoded shape: instruction lengths and flow kinds in order,
/// with no address in it. Two functions with the same digest are the same
/// code however it was loaded or relocated.
fn shape_digest(body: &[FlowShape]) -> String {
    let mut hasher = Digest::new();
    for shape in body {
        hasher.write(&[
            shape.length,
            kind_code(shape.kind),
            u8::from(shape.conditional),
        ]);
    }
    hasher.finish()
}

fn kind_code(kind: FlowKind) -> u8 {
    match kind {
        FlowKind::Branch => 1,
        FlowKind::CBranch => 2,
        FlowKind::BranchInd => 3,
        FlowKind::Call => 4,
        FlowKind::CallInd => 5,
        FlowKind::Return => 6,
        FlowKind::Fallthrough => 7,
        FlowKind::Bad => 8,
        FlowKind::Unimpl => 9,
    }
}

/// A 128-bit FNV-1a digest, hex-encoded.
///
/// A digest here answers "are these the same bytes", never "prove these are
/// the same bytes to an adversary", so a keyed cryptographic hash would only
/// cost import time. 128 bits keeps accidental collisions out of the way of
/// the anchor rule that requires a digest to be unique on both sides.
struct Digest {
    state: u128,
}

impl Digest {
    const OFFSET: u128 = 0x6c62272e07bb0142_62b821756295c58d;
    const PRIME: u128 = 0x0000000001000000_000000000000013B;

    fn new() -> Self {
        Self {
            state: Self::OFFSET,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.state ^= u128::from(*byte);
            self.state = self.state.wrapping_mul(Self::PRIME);
        }
    }

    fn finish(self) -> String {
        format!("{:032x}", self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{Mapping, NativeFunction};

    fn shape(address: u64, length: u8, kind: FlowKind, target: Option<u64>) -> FlowShape {
        FlowShape {
            address,
            length,
            kind,
            conditional: kind == FlowKind::CBranch,
            target,
        }
    }

    fn import(functions: Vec<NativeFunction>, shapes: Vec<FlowShape>, bytes: Vec<u8>) -> NativeImport {
        NativeImport {
            functions,
            flow_shapes: shapes,
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: bytes.len() as u64,
                file_off: 0,
                flags: 5,
                bytes,
            }],
            ..Default::default()
        }
    }

    fn function(entry: u64, size: u64) -> NativeFunction {
        NativeFunction {
            entry,
            name: format!("FUN_{entry:08x}"),
            size,
        }
    }

    #[test]
    fn a_conditional_branch_splits_the_body_into_three_blocks() {
        // 0x1000 cbranch -> 0x1008; 0x1004 fallthrough; 0x1008 return.
        // Leaders: 0x1000 (entry), 0x1008 (target), 0x1004 (fallthrough of
        // the branch) -- three blocks, and four edges: branch taken, branch
        // fallthrough, and nothing from the plain instruction or the return.
        let imp = import(
            vec![function(0x1000, 12)],
            vec![
                shape(0x1000, 4, FlowKind::CBranch, Some(0x1008)),
                shape(0x1004, 4, FlowKind::Fallthrough, None),
                shape(0x1008, 4, FlowKind::Return, None),
            ],
            vec![0u8; 12],
        );
        let rows = measure(&imp);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].instructions, 3);
        assert_eq!(rows[0].blocks, 3);
        assert_eq!(rows[0].edges, 2);
        assert_eq!(rows[0].loops, 0, "a forward branch is not a loop");
        assert_eq!(rows[0].max_block, 1);
    }

    #[test]
    fn a_call_does_not_end_a_block() {
        // Ghidra's BasicBlockModel excludes calls; a body of call,
        // fallthrough, return is one block.
        let imp = import(
            vec![function(0x1000, 12)],
            vec![
                shape(0x1000, 4, FlowKind::Call, None),
                shape(0x1004, 4, FlowKind::Fallthrough, None),
                shape(0x1008, 4, FlowKind::Return, None),
            ],
            vec![0u8; 12],
        );
        let rows = measure(&imp);
        assert_eq!(rows[0].blocks, 1, "call must not split the block");
        assert_eq!(rows[0].edges, 0);
        assert_eq!(rows[0].max_block, 3, "all three instructions are one block");
    }

    #[test]
    fn a_backward_branch_counts_as_a_loop() {
        // 0x1000 falls through; 0x1004 branches back to 0x1000.
        let imp = import(
            vec![function(0x1000, 8)],
            vec![
                shape(0x1000, 4, FlowKind::Fallthrough, None),
                shape(0x1004, 4, FlowKind::CBranch, Some(0x1000)),
            ],
            vec![0u8; 8],
        );
        let rows = measure(&imp);
        assert_eq!(rows[0].loops, 1);
        assert_eq!(rows[0].blocks, 1, "the target is the entry, already a leader");
    }

    #[test]
    fn the_shape_digest_ignores_addresses_and_the_body_digest_does_not() {
        let left = import(
            vec![function(0x1000, 8)],
            vec![
                shape(0x1000, 4, FlowKind::Fallthrough, None),
                shape(0x1004, 4, FlowKind::Return, None),
            ],
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );
        let mut right = import(
            vec![function(0x1000, 8)],
            vec![
                shape(0x1000, 4, FlowKind::Fallthrough, None),
                shape(0x1004, 4, FlowKind::Return, None),
            ],
            // Same shape, different bytes: a relocated immediate.
            vec![1, 2, 3, 9, 5, 6, 7, 8],
        );
        let left_rows = measure(&left);
        let right_rows = measure(&right);
        assert_eq!(left_rows[0].shape_digest, right_rows[0].shape_digest);
        assert_ne!(left_rows[0].body_digest, right_rows[0].body_digest);
        // And a body at a different address is a different body digest even
        // with identical bytes.
        right.functions = vec![function(0x1008, 8)];
        right.flow_shapes = vec![
            shape(0x1008, 4, FlowKind::Fallthrough, None),
            shape(0x100c, 4, FlowKind::Return, None),
        ];
        right.mappings[0].bytes = vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        right.mappings[0].size = 16;
        let moved = measure(&right);
        assert_eq!(moved[0].shape_digest, left_rows[0].shape_digest);
        assert_ne!(moved[0].body_digest, left_rows[0].body_digest);
    }

    #[test]
    fn an_undecoded_function_gets_no_row() {
        let imp = import(
            vec![function(0x1000, 4), function(0x2000, 4)],
            vec![shape(0x1000, 4, FlowKind::Return, None)],
            vec![0u8; 8],
        );
        let rows = measure(&imp);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].function.offset, 0x1000);
    }
}
