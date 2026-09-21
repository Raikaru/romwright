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
            masked_digest: masked_digest(imp, start, end, body),
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
/// Digest of the body bytes with relocations and image addresses masked:
/// loader-written bytes read zero, and -- on x86-64 only -- a pc-relative
/// field (a branch displacement, a RIP-relative disp32) reads zero when
/// it names an image address. The operand masking is x86-64-only because
/// the span decoder assumes 64-bit addressing: in 32-bit mode ModRM
/// `mod=00, r/m=101` is an absolute disp32, not RIP-relative, and masking
/// it would zero ordinary absolute operands into false anchors.
/// Relocation masking is universal (loader facts, not decode). Small
/// constants stay: `add eax, 5` and `add eax, 6` are different code. The
/// walk's own lengths bound each instruction, so a decoder disagreement
/// cannot run the masking into the next instruction.
fn masked_digest(imp: &NativeImport, start: u64, end: u64, body: &[FlowShape]) -> String {
    // Ghidra language ids name machine and width (`x86:LE:64:default`).
    // Anything else -- including x86-32 and empty (unfilled) -- gets
    // relocation masking only: without the 64-bit addressing the spans
    // assume, they prove nothing, so only relocations mask.
    let x86_64 = imp.language.split(':').nth(2).is_some_and(|bits| bits == "64")
        && imp.language.starts_with("x86:");
    let mut relocs: Vec<(u64, u64)> = imp.relocations.iter()
        .map(|rel| (rel.address, rel.address.saturating_add(rel.width as u64)))
        .collect();
    relocs.sort_unstable();
    let relocated = |address: u64| relocs.iter()
        .any(|&(from, to)| address >= from && address < to);
    let in_image = |address: u64| imp.mappings.iter().any(|mapping| {
        address >= mapping.vaddr && address < mapping.vaddr.saturating_add(mapping.size)
    });
    let byte_at = |address: u64| {
        for mapping in &imp.mappings {
            if address >= mapping.vaddr && address < mapping.vaddr.saturating_add(mapping.size) {
                if let Ok(index) = usize::try_from(address - mapping.vaddr) {
                    return mapping.bytes.get(index).copied().unwrap_or(0);
                }
            }
        }
        0
    };
    let mut hasher = Digest::new();
    for shape in body {
        let length = usize::from(shape.length);
        if shape.address < start || shape.address.saturating_add(length as u64) > end || length == 0 {
            continue;
        }
        let mut bytes: Vec<u8> = (0..length)
            .map(|offset| byte_at(shape.address.saturating_add(offset as u64)))
            .collect();
        let info = crate::disasm::decode(&bytes, shape.address);
        // Mask the relative field only on x86-64 and only when it names
        // an image address or the loader wrote it: a relative field that
        // names nothing in the image is a (weird) constant, and constants
        // stay. Elsewhere the spans are decoder garbage, so only the
        // relocation sweep below masks.
        if x86_64 && let Some((off, span)) = info.rel {
            let (off, span) = (off as usize, span as usize);
            if off + span <= bytes.len() && (span == 1 || span == 4) {
                let value: i64 = if span == 1 {
                    i8::from_le_bytes([bytes[off]]) as i64
                } else {
                    i32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]) as i64
                };
                let target = u64::from(info.len).saturating_add(shape.address).wrapping_add(value as u64);
                let field = shape.address.saturating_add(off as u64);
                let field_relocated = (0..span as u64).any(|delta| relocated(field.saturating_add(delta)));
                if in_image(target) || field_relocated {
                    for byte in &mut bytes[off..off + span] {
                        *byte = 0;
                    }
                }
            }
        }
        // Mask every loader-written byte wherever it sits: an absolute
        // address immediate has no decoder span, but the relocation names
        // it exactly.
        for (offset, byte) in bytes.iter_mut().enumerate() {
            if relocated(shape.address.saturating_add(offset as u64)) {
                *byte = 0;
            }
        }
        hasher.write(&bytes);
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
    fn the_masked_digest_masks_in_image_displacements_only() {
        // `call` + `ret`, 16 bytes mapped so 0x1008/0x100b are in-image
        // and 0x1105 is not. x86-64: the span decoder's addressing holds.
        let body = |language: &str, disp: [u8; 4]| {
            let mut bytes = vec![0xe8];
            bytes.extend(disp);
            bytes.push(0xc3);
            bytes.extend([0x90; 10]);
            let mut imp = import(
                vec![function(0x1000, 6)],
                vec![
                    shape(0x1000, 5, FlowKind::Call, None),
                    shape(0x1005, 1, FlowKind::Return, None),
                ],
                bytes,
            );
            imp.language = language.into();
            imp
        };
        let x86_64 = "x86:LE:64:default";
        let left = measure(&body(x86_64, [3, 0, 0, 0]));
        let right = measure(&body(x86_64, [6, 0, 0, 0]));
        // Both displacements name the mapped image: masked equal, raw
        // different.
        assert_eq!(left[0].masked_digest, right[0].masked_digest);
        assert_ne!(left[0].body_digest, right[0].body_digest);
        // A displacement naming nothing in the image is a constant, and
        // constants stay: masked differs.
        let outside = measure(&body(x86_64, [0, 1, 0, 0]));
        assert_ne!(left[0].masked_digest, outside[0].masked_digest);
    }

    #[test]
    fn the_masked_digest_masks_no_spans_off_x86_64() {
        // Same bodies under 32-bit and foreign languages: the span decoder
        // assumes 64-bit addressing (in 32-bit mode `mod=00, r/m=101` is
        // an absolute disp32), so spans must not mask there -- not even
        // when the displacement names the mapped image.
        let body = |language: &str, disp: [u8; 4]| {
            let mut bytes = vec![0xe8];
            bytes.extend(disp);
            bytes.push(0xc3);
            bytes.extend([0x90; 10]);
            let mut imp = import(
                vec![function(0x1000, 6)],
                vec![
                    shape(0x1000, 5, FlowKind::Call, None),
                    shape(0x1005, 1, FlowKind::Return, None),
                ],
                bytes,
            );
            imp.language = language.into();
            imp
        };
        for language in ["x86:LE:32:default", "ppc:BE:32:default", ""] {
            let left = measure(&body(language, [3, 0, 0, 0]));
            let right = measure(&body(language, [6, 0, 0, 0]));
            assert_ne!(
                left[0].masked_digest, right[0].masked_digest,
                "spans masked under {language}"
            );
        }
    }

    #[test]
    fn the_masked_digest_masks_relocations_everywhere() {
        // Relocation masking is loader fact, not decode: it holds on every
        // language, including off-x86-64 where spans never mask.
        let body = |language: &str, disp: [u8; 4]| {
            let mut bytes = vec![0xe8];
            bytes.extend(disp);
            bytes.push(0xc3);
            bytes.extend([0x90; 10]);
            let mut imp = import(
                vec![function(0x1000, 6)],
                vec![
                    shape(0x1000, 5, FlowKind::Call, None),
                    shape(0x1005, 1, FlowKind::Return, None),
                ],
                bytes,
            );
            imp.language = language.into();
            imp.relocations = vec![crate::native::MemoryRelocation {
                address: 0x1001,
                bytes: [0; 8],
                width: 4,
            }];
            imp
        };
        for language in ["x86:LE:64:default", "x86:LE:32:default", "ppc:BE:32:default"] {
            let left = measure(&body(language, [3, 0, 0, 0]));
            let right = measure(&body(language, [6, 0, 0, 0]));
            assert_eq!(
                left[0].masked_digest, right[0].masked_digest,
                "relocations not masked under {language}"
            );
        }
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
