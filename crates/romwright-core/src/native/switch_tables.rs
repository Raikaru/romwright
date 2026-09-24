use super::*;

/// Ghidra's `DecompilerSwitchAnalyzer` runs the decompiler on every function
/// holding an indirect jump, lays a reference from the jump to each table
/// entry it recovers, and disassembles them; the case bodies then reach the
/// calls the walk stopped short of. The decompile worker reads the program
/// from a store, so the image is stored to a scratch project first. Returns
/// the number of tables this round added; a branch already holding one is
/// not asked again.
/// A process-unique scratch directory removed on drop.
pub(super) struct ScratchDir {
    pub(super) path: std::path::PathBuf,
}

pub(crate) fn scratch_root() -> std::io::Result<std::path::PathBuf> {
    let root = std::env::var_os("ROMWRIGHT_SCRATCH")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cache/romwright/scratch")))
        .ok_or_else(|| std::io::Error::other("set ROMWRIGHT_SCRATCH or HOME for native scratch storage"))?;
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

impl ScratchDir {
    pub(super) fn new(prefix: &str) -> Option<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let path = scratch_root().ok()?.join(format!("{prefix}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).ok()?;
        Some(Self { path })
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The image, as the value-set analysis reads it.
struct ImageView<'a> {
    imp: &'a NativeImport,
    big_endian: bool,
}

impl vsa::Image for ImageView<'_> {
    fn read(&self, address: u64, size: u32) -> Option<u64> {
        if size == 0 || size > 8 {
            return None;
        }
        // The emulator asks about any address the code computes, including
        // ones near the top of the space: a read that would overflow the
        // address arithmetic is simply not mapped.
        let last = address.checked_add(u64::from(size) - 1)?;
        let mapping = self.imp.mappings.iter().find(|mapping| {
            let end = mapping.vaddr.saturating_add(mapping.size);
            address >= mapping.vaddr && last < end
        })?;
        let offset = usize::try_from(address - mapping.vaddr).ok()?;
        let bytes = mapping.bytes.get(offset..offset + size as usize)?;
        let mut value = 0u64;
        if self.big_endian {
            for byte in bytes {
                value = (value << 8) | u64::from(*byte);
            }
        } else {
            for (index, byte) in bytes.iter().enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
        }
        Some(value)
    }

    fn executable(&self, address: u64) -> bool {
        self.imp.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0
                && address >= mapping.vaddr
                && address < mapping.vaddr + mapping.size
        })
    }

    fn owner(&self, address: u64) -> Option<(u64, u64)> {
        // Single-instruction entries carry no body, so they claim nothing;
        // `switch_candidates` sizes extents the same way.
        self.imp
            .functions
            .iter()
            .filter(|function| function.size > 1)
            .map(|function| (function.entry, function.entry.saturating_add(function.size)))
            .find(|&(start, end)| address >= start && address < end)
    }
}

/// Address index shared by every switch candidate in a discovery round.
/// Discovery appends unsorted rounds; keep equal-address evidence in its
/// original order without copying or reordering the underlying flow records.
pub(super) struct FlowShapeIndex<'a> {
    by_address: Vec<&'a FlowShape>,
}

impl<'a> FlowShapeIndex<'a> {
    pub(super) fn new(shapes: &'a [FlowShape]) -> Self {
        let mut by_address: Vec<_> = shapes.iter().collect();
        by_address.sort_by_key(|shape| shape.address);
        Self { by_address }
    }

    pub(super) fn range(&self, entry: u64, end: u64) -> &[&'a FlowShape] {
        let start = self.by_address.partition_point(|shape| shape.address < entry);
        let remaining = &self.by_address[start..];
        &remaining[..remaining.partition_point(|shape| shape.address < end)]
    }
}

/// The straight-line window ending at `branch`, and the blocks that can
/// reach it, which is where a guard lives.
///
/// Ghidra takes the path out of the SSA form it has already built
/// (`JumpBasic::findDeterminingVarnodes`) and the range out of the blocks
/// that dominate the dispatch (`JumpBasic::analyzeGuards`). There is no SSA
/// here, so the window is the branch's own basic block -- Ghidra's own
/// definition, a run of instructions nothing jumps into
/// (`BasicBlockModel.hasEndOfBlockFlow`) -- and the guard region is the
/// blocks that actually branch or fall into it. Taking the two positionally
/// preceding blocks instead found a guard for 15 of 132 dispatches on libc:
/// a dispatch block is usually jumped to, not fallen into.
/// The function's basic blocks, as the abstract interpreter consumes them:
/// instruction addresses per block and successor indices, with a
/// conditional branch's *taken* edge first so an edge refinement lands on
/// the side that assumes the test.
pub(super) fn function_blocks(
    shapes: &[&FlowShape],
    entry: u64,
    end: u64,
) -> Vec<(u64, Vec<u64>, Vec<usize>)> {
    use crate::native_runtime::FlowKind;
    // The index preserves discovery order at equal addresses; retain the
    // first shape, as the previous stable sort and deduplication did.
    let unique_shapes = || {
        shapes
            .chunk_by(|left, right| left.address == right.address)
            .map(|same_address| same_address[0])
    };
    if shapes.is_empty() {
        return Vec::new();
    }
    let inside = |address: u64| address >= entry && address < end;
    let ends_block = |kind: FlowKind| {
        matches!(
            kind,
            FlowKind::Branch | FlowKind::CBranch | FlowKind::BranchInd | FlowKind::Return
        )
    };
    let mut leaders: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    leaders.insert(shapes[0].address);
    for shape in unique_shapes() {
        if let Some(target) = shape.target
            && inside(target)
        {
            leaders.insert(target);
        }
        if ends_block(shape.kind) {
            let next = shape.address.saturating_add(u64::from(shape.length));
            if inside(next) {
                leaders.insert(next);
            }
        }
    }
    let starts: Vec<u64> = leaders.iter().copied().collect();
    // A leader with no instruction at its own address (dead bytes after a
    // branch) still owns the block that follows it: map every address to the
    // last leader at or before it, not only to an exact leader hit, or the
    // next real instruction is absorbed into the branch's block and the
    // block ends up holding two branches.
    let index_of = |address: u64| starts.partition_point(|&s| s <= address).checked_sub(1);
    let mut blocks: Vec<(u64, Vec<u64>, Vec<usize>)> = starts
        .iter()
        .map(|start| (*start, Vec::new(), Vec::new()))
        .collect();
    let mut current = 0usize;
    for shape in unique_shapes() {
        if let Some(found) = index_of(shape.address) {
            current = found;
        }
        blocks[current].1.push(shape.address);
        let next = shape.address.saturating_add(u64::from(shape.length));
        match shape.kind {
            FlowKind::CBranch => {
                // Taken edge first: `sja` refines the index on successor 0.
                if let Some(target) = shape.target.filter(|t| inside(*t)).and_then(index_of) {
                    blocks[current].2.push(target);
                }
                if inside(next)
                    && let Some(fall) = index_of(next)
                {
                    blocks[current].2.push(fall);
                }
            }
            FlowKind::Branch => {
                if let Some(target) = shape.target.filter(|t| inside(*t)).and_then(index_of) {
                    blocks[current].2.push(target);
                }
            }
            FlowKind::BranchInd | FlowKind::Return => {}
            _ => {
                if let Some(fall) = index_of(next)
                    && fall != current
                {
                    blocks[current].2.push(fall);
                }
            }
        }
    }
    blocks
}

/// Keeps only the blocks that can reach one of `dispatches`, renumbering the
/// successor edges.
///
/// The interpreter's cost is the p-code it decodes, and a dispatch's answer
/// depends only on what runs before it: blocks the dispatch cannot be
/// reached from contribute nothing to its index. Ghidra's own jump-table
/// analysis works the same way round -- `JumpBasic::findDeterminingVarnodes`
/// walks *backwards* from the branch rather than forwards from the entry.
///
/// The function's entry block is retained whenever a dispatch is reachable
/// from it, so index 0 remains the block the analysis seeds.
pub(super) fn blocks_reaching(
    blocks: &[(u64, Vec<u64>, Vec<usize>)],
    dispatches: &[u64],
) -> Vec<(u64, Vec<u64>, Vec<usize>)> {
    let mut keep = vec![false; blocks.len()];
    let mut stack: Vec<usize> = Vec::new();
    for (index, (_, addresses, _)) in blocks.iter().enumerate() {
        if addresses.iter().any(|address| dispatches.contains(address)) && !keep[index] {
            keep[index] = true;
            stack.push(index);
        }
    }
    if stack.is_empty() {
        return Vec::new();
    }
    while let Some(index) = stack.pop() {
        for (predecessor, (_, _, successors)) in blocks.iter().enumerate() {
            if successors.contains(&index) && !keep[predecessor] {
                keep[predecessor] = true;
                stack.push(predecessor);
            }
        }
    }
    // Relative order is preserved, so the entry block keeps index 0 when it
    // is kept at all.
    let mut renumbered = vec![usize::MAX; blocks.len()];
    let mut next = 0usize;
    for (index, kept) in keep.iter().enumerate() {
        if *kept {
            renumbered[index] = next;
            next += 1;
        }
    }
    blocks
        .iter()
        .enumerate()
        .filter(|(index, _)| keep[*index])
        .map(|(_, (start, addresses, successors))| {
            (
                *start,
                addresses.clone(),
                successors
                    .iter()
                    .filter_map(|successor| {
                        renumbered
                            .get(*successor)
                            .copied()
                            .filter(|renumbered| *renumbered != usize::MAX)
                    })
                    .collect(),
            )
        })
        .collect()
}

pub(super) fn switch_window(
    shapes: &[&FlowShape],
    branch: u64,
    entry: u64,
    end: u64,
) -> (Vec<u64>, Vec<Vec<u64>>) {
    if shapes.is_empty() || !shapes.iter().any(|shape| shape.address == branch) {
        return (Vec::new(), Vec::new());
    }
    let ends_block = |kind: crate::native_runtime::FlowKind| {
        matches!(
            kind,
            crate::native_runtime::FlowKind::Branch
                | crate::native_runtime::FlowKind::CBranch
                | crate::native_runtime::FlowKind::BranchInd
                | crate::native_runtime::FlowKind::Return
        )
    };
    let mut leaders: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    leaders.insert(entry);
    for shape in shapes {
        if let Some(target) = shape.target {
            if target >= entry && target < end {
                leaders.insert(target);
            }
        }
        if ends_block(shape.kind) {
            let next = shape.address.saturating_add(u64::from(shape.length));
            if next < end {
                leaders.insert(next);
            }
        }
    }
    let leader_of = |address: u64| {
        leaders
            .range(..=address)
            .next_back()
            .copied()
            .unwrap_or(entry)
    };
    let dispatch = leader_of(branch);
    // Predecessors: a block whose last instruction branches to the dispatch,
    // and the block that falls into it.
    let mut predecessors: Vec<u64> = Vec::new();
    for shape in shapes {
        let reaches = shape.target == Some(dispatch)
            || (!ends_block(shape.kind)
                && shape.address.saturating_add(u64::from(shape.length)) == dispatch)
            || (matches!(shape.kind, crate::native_runtime::FlowKind::CBranch)
                && shape.address.saturating_add(u64::from(shape.length)) == dispatch);
        if reaches {
            let block = leader_of(shape.address);
            if block != dispatch && !predecessors.contains(&block) {
                predecessors.push(block);
            }
        }
    }
    predecessors.sort_unstable();
    // Shapes accumulate across discovery rounds, so one address can
    // appear twice; the console and the emulator would both work it twice.
    // Straight-line blocks stay straight-line deduplicated.
    let mut window: Vec<u64> = shapes
        .iter()
        .filter(|shape| shape.address >= dispatch && shape.address <= branch)
        .map(|shape| shape.address)
        .collect();
    window.sort_unstable();
    window.dedup();
    // Each predecessor block on its own: a guard is read by running the
    // block that states it, and one block's call must not clear the index
    // another block compares.
    let mut guard: Vec<Vec<u64>> = Vec::new();
    for &block in predecessors.iter().take(4) {
        let block_end = leaders
            .range((std::ops::Bound::Excluded(block), std::ops::Bound::Unbounded))
            .next()
            .copied()
            .unwrap_or(end);
        let mut addresses: Vec<u64> = shapes
            .iter()
            .filter(|shape| shape.address >= block && shape.address < block_end)
            .map(|shape| shape.address)
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        if !addresses.is_empty() {
            guard.push(addresses);
        }
    }
    (window, guard)
}

/// Recovers tables with value-set analysis over p-code, no decompiler.
///
/// Returns the branches it could not resolve, which the decompiler path then
/// gets, so a body this cannot follow is still recovered.
pub(super) fn recover_switch_tables_native(
    imp: &mut NativeImport,
    session: &mut crate::native_runtime::ConsoleSession,
    branches: &[(u64, u64, u64)],
) -> (usize, Vec<u64>) {
    // The language id names the endianness in its second field
    // (`PowerPC:BE:32:default`), which is how every other reader here takes
    // it.
    let big_endian = imp
        .language
        .split(':')
        .nth(1)
        .is_some_and(|field| field.eq_ignore_ascii_case("BE"));
    let mut resolved: Vec<vsa::SwitchTable> = Vec::new();
    let mut unresolved = Vec::new();
    let mut refusals = vsa::Refusals::default();
    let mut no_window = 0usize;
    let mut undecodable = 0usize;
    let mut sja_refusals = sja::Refusals::default();
    let mut sja_resolved = 0usize;
    // One analysis per function, not per dispatch: interpreting a function
    // answers every indirect branch in it at once, and libc has functions
    // with several. Decoding and interpreting once per candidate did the
    // same work up to a dozen times over.
    let mut interpreted_functions: std::collections::HashMap<u64, Option<sja::Analysis>> =
        std::collections::HashMap::new();
    // Hoisted out of the per-function branch: the sets are the same for
    // every analysis, and rebuilding them per function walked all of
    // `imp.xrefs` once per SJA-analysed function.
    let resolved_jumps: std::collections::HashSet<u64> = imp
        .flow_overrides
        .iter()
        .map(|&(address, _)| address)
        .chain(
            imp.xrefs
                .iter()
                .filter(|xref| xref.kind == "COMPUTED_JUMP")
                .map(|xref| xref.from),
        )
        .collect();
    let thunk_entries: std::collections::HashSet<u64> =
        imp.thunks.iter().map(|thunk| thunk.entry).collect();
    let owner_of = |branch: u64| {
        imp.functions
            .iter()
            .find(|f| f.size > 1 && f.entry <= branch && branch < f.entry + f.size)
            .map(|f| f.entry)
    };
    let flow_shapes = FlowShapeIndex::new(&imp.flow_shapes);
    for &(branch, entry, end) in branches {
        let function_shapes = flow_shapes.range(entry, end);
        let (window_addresses, guard_addresses) =
            switch_window(function_shapes, branch, entry, end);
        if window_addresses.is_empty() {
            no_window += 1;
            unresolved.push(branch);
            continue;
        }
        // One request for both regions: the guard's constants come from the
        // blocks before the dispatch, and only the dispatch block is
        // emulated.
        let mut addresses: Vec<u64> = guard_addresses.iter().flatten().copied().collect();
        addresses.extend(window_addresses.iter().copied());
        let decoded = match session.pcode_batch(&addresses) {
            Ok(decoded) => decoded,
            Err(_) => {
                unresolved.push(branch);
                continue;
            }
        };
        if decoded
            .iter()
            .any(|instruction| instruction.error.is_some())
        {
            undecodable += 1;
            unresolved.push(branch);
            continue;
        }
        // Split the one answer back into the blocks it was asked for.
        let mut cursor = 0usize;
        let mut guard: Vec<Vec<crate::native_runtime::PcodeInstruction>> = Vec::new();
        for block in &guard_addresses {
            let end = (cursor + block.len()).min(decoded.len());
            guard.push(decoded[cursor..end].to_vec());
            cursor = end;
        }
        let window = &decoded[cursor.min(decoded.len())..];
        if std::env::var("ROMWRIGHT_TRACE_VSA_AT")
            .ok()
            .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
            == Some(branch)
        {
            eprintln!(
                "VSA at {branch:#x}: guard {:x?} window {:x?}",
                guard
                    .iter()
                    .map(|block| block.iter().map(|i| i.address).collect::<Vec<_>>())
                    .collect::<Vec<_>>(),
                window.iter().map(|i| i.address).collect::<Vec<_>>(),
            );
            for instruction in window {
                for op in &instruction.ops {
                    eprintln!(
                        "  {:#x} {} {:?} <- {:?}",
                        instruction.address,
                        op.opcode,
                        op.output
                            .as_ref()
                            .map(|v| format!("{}:{:x}:{}", v.space, v.offset, v.size)),
                        op.inputs
                            .iter()
                            .map(|v| format!("{}:{:x}:{}", v.space, v.offset, v.size))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        // The pattern-shaped pass first: it decodes a window around the
        // dispatch, so it is cheap, and it answers most dispatches. The
        // abstract interpretation is the fallback, because it decodes and
        // interprets the whole function.
        let quick = {
            let view = ImageView { imp, big_endian };
            vsa::recover(&view, branch, &guard, window, &mut refusals)
        };
        // The abstract interpretation is opt-in until it is measured to
        // help: `ROMWRIGHT_SJA=1`. It runs only where the pattern-shaped
        // pass refused, so it can only add.
        let proven = if quick.is_some() || std::env::var_os("ROMWRIGHT_SJA").is_none() {
            None
        } else {
            if !interpreted_functions.contains_key(&entry) {
                // Every dispatch this round asks about in this function, so
                // one analysis answers them all and the slice covers them
                // all.
                let dispatches: Vec<u64> = branches
                    .iter()
                    .filter(|&&(_, candidate_entry, _)| candidate_entry == entry)
                    .map(|&(candidate, _, _)| candidate)
                    .collect();
                let blocks =
                    blocks_reaching(&function_blocks(function_shapes, entry, end), &dispatches);
                let mut wanted: Vec<u64> = blocks
                    .iter()
                    .flat_map(|(_, addresses, _)| addresses.iter().copied())
                    .collect();
                wanted.sort_unstable();
                wanted.dedup();
                let graph: Vec<sja::Block> = match session.pcode_batch(&wanted) {
                    Ok(decoded) if !wanted.is_empty() => {
                        let by_address: std::collections::HashMap<u64, _> = decoded
                            .into_iter()
                            .map(|instruction| (instruction.address, instruction))
                            .collect();
                        blocks
                            .iter()
                            .map(|(_, addresses, successors)| sja::Block {
                                instructions: addresses
                                    .iter()
                                    .filter_map(|address| by_address.get(address).cloned())
                                    .collect(),
                                successors: successors.clone(),
                            })
                            .collect()
                    }
                    _ => Vec::new(),
                };
                // A function whose blocks or p-code could not be had is
                // cached as unanalysable, so the next dispatch in it does
                // not pay for the same failure again.
                let analysed = (!graph.is_empty()).then(|| {
                    let view = ImageView { imp, big_endian };
                    sja::analyse(&view, &graph, (entry, end))
                });
                // One analysis answers every indirect branch in the
                // function, and a dispatch asked in an earlier round -- when
                // the CFG was still missing the case blocks an unresolved
                // jump hid -- is not asked again. Recording only the asked
                // branch's table would drop the rest, so every table the
                // analysis produced is kept for the recording loop. Only
                // real candidates count: a thunk, an overridden flow, or a
                // jump already answered is not a switch.
                if let Some(analysis) = &analysed {
                    for table in &analysis.tables {
                        let is_candidate = imp.indirect_jumps.contains(&table.branch)
                            && !resolved_jumps.contains(&table.branch)
                            && !owner_of(table.branch).is_some_and(|e| thunk_entries.contains(&e));
                        if is_candidate
                            && !imp.switch_tables.contains_key(&table.branch)
                            && !resolved.iter().any(|t| t.branch == table.branch)
                        {
                            resolved.push(table.clone());
                        }
                    }
                }
                interpreted_functions.insert(entry, analysed);
            }
            // Only this candidate's outcome is counted: analysing a function
            // answers every indirect branch in it, and adding all of them
            // made the refusal totals a multiple of the dispatches actually
            // asked about.
            interpreted_functions
                .get(&entry)
                .and_then(|analysis| analysis.as_ref())
                .and_then(|analysis| {
                    let table = analysis
                        .tables
                        .iter()
                        .find(|table| table.branch == branch)
                        .cloned();
                    if table.is_none() {
                        sja_refusals.merge_for(branch, analysis);
                    }
                    table
                })
        };
        let table = match proven {
            Some(table) => {
                sja_resolved += 1;
                Some(table)
            }
            None => quick,
        };
        match table {
            // The analysis's tables were already recorded above; pushing the
            // asked branch's again would double its xrefs.
            Some(table) if !resolved.iter().any(|t| t.branch == table.branch) => {
                resolved.push(table)
            }
            Some(_) => {}
            None => unresolved.push(branch),
        }
    }
    if std::env::var_os("ROMWRIGHT_TRACE_VSA").is_some() {
        eprintln!(
            "VSA candidates={} resolved={} no_window={no_window} undecodable={undecodable} \
             no_live_in={} no_strided_load={} too_few_targets={} unmodelled={}",
            branches.len(),
            resolved.len(),
            refusals.no_live_in,
            refusals.no_strided_load,
            refusals.too_few_targets,
            refusals.unmodelled,
        );
        eprintln!(
            "SJA resolved={sja_resolved} unknown={} unbounded={} too_wide={} outside={} \
             too_few={}",
            sja_refusals.unknown_target,
            sja_refusals.unbounded,
            sja_refusals.too_wide,
            sja_refusals.outside_function,
            sja_refusals.too_few_targets,
        );
    }
    let mut added = 0;
    for table in resolved {
        let mut targets = table.targets;
        targets.sort_unstable();
        targets.dedup();
        for &target in &targets {
            imp.xrefs.push(NativeXref::with_provenance(
                table.branch,
                target,
                "COMPUTED_JUMP",
                SWITCH_PROVENANCE,
            ));
        }
        let reaches_new = targets.iter().any(|&target| {
            let index = imp
                .decoded_ranges
                .partition_point(|&(start, _)| start <= target);
            !index
                .checked_sub(1)
                .is_some_and(|i| target < imp.decoded_ranges[i].1)
        });
        if imp.switch_tables.insert(table.branch, targets).is_none() && reaches_new {
            added += 1;
        }
    }
    (added, unresolved)
}
/// A jump whose transfer the image's structure already proved -- a linkage
/// stub through an import slot, a thunk -- is not a switch. Worker
/// computed rows do NOT suppress: a single propagated target can be a
/// first-iteration partial, and suppressing candidacy would hide the
/// branch from every real recovery path.
pub(super) fn switch_candidates(imp: &mut NativeImport) -> Vec<(u64, u64, u64)> {
    let extents: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .filter(|function| function.size > 1)
        .map(|function| (function.entry, function.entry.saturating_add(function.size)))
        .collect();
    // Branches a worker row already resolved are NOT skipped: a
    // single worker-computed target can be a first-iteration partial
    // (observed: loop dispatch recovered as {state0} of {state0,
    // state1}), and skipping candidacy suppresses every real
    // recovery path (VSA, SJA, decompiler) for it. Only flow
    // overrides suppress. Overlap resolves in the union: a switch
    // table covering the branch subsumes the worker row.
    let resolved: std::collections::HashSet<u64> = imp
        .flow_overrides
        .iter()
        .map(|&(address, _)| address)
        .collect();
    let thunk_entries: std::collections::HashSet<u64> =
        imp.thunks.iter().map(|thunk| thunk.entry).collect();
    let mut out = Vec::new();
    for &branch in &imp.indirect_jumps {
        if imp.switch_tables.contains_key(&branch) || resolved.contains(&branch) {
            continue;
        }
        let Some(&(entry, end)) = extents
            .iter()
            .find(|&&(start, end)| start <= branch && branch < end)
        else {
            continue;
        };
        if thunk_entries.contains(&entry) {
            continue;
        }
        if imp.switch_asked.insert(branch, end - entry) != Some(end - entry) {
            out.push((branch, entry, end));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub(super) fn recover_switch_tables(imp: &mut NativeImport) -> usize {
    let extents: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .filter(|function| function.size > 1)
        .map(|function| (function.entry, function.entry.saturating_add(function.size)))
        .collect();
    let owner = |address: u64| {
        extents
            .iter()
            .find(|&&(start, end)| start <= address && address < end)
            .map(|&(start, end)| (start, end - start))
    };
    let started = std::time::Instant::now();
    // A jump whose transfer the image's structure already proved -- a
    // linkage stub through an import slot, a thunk -- is not a switch;
    // `DecompilerSwitchAnalyzer.findLocations` skips an instruction whose
    // flow is overridden or already referenced (:398-431).
    let resolved: std::collections::HashSet<u64> = imp
        .flow_overrides
        .iter()
        .map(|&(address, _)| address)
        .chain(
            imp.xrefs
                .iter()
                .filter(|xref| xref.kind == "COMPUTED_JUMP")
                .map(|xref| xref.from),
        )
        .collect();
    let thunk_entries: std::collections::HashSet<u64> =
        imp.thunks.iter().map(|thunk| thunk.entry).collect();
    let mut owners: Vec<u64> = Vec::new();
    for &branch in &imp.indirect_jumps {
        if imp.switch_tables.contains_key(&branch) || resolved.contains(&branch) {
            continue;
        }
        let Some((entry, size)) = owner(branch) else {
            continue;
        };
        if thunk_entries.contains(&entry) {
            continue;
        }
        if imp.switch_asked.insert(branch, size) != Some(size) {
            owners.push(entry);
        }
    }
    owners.sort_unstable();
    owners.dedup();
    // Owner budget: one decompile per owner, so cost scales with this
    // count. Past the budget the rest are recorded refusals, not
    // silent drops. Deterministic (sorted) so reruns agree.
    let budget: usize = std::env::var("ROMWRIGHT_SWITCH_MAX_OWNERS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(1024);
    if owners.len() > budget {
        imp.switch_decompiler_skipped += owners.len() - budget;
        imp.diagnose(romwright_model::DiagnosticSeverity::Partial, "switch", format!(
            "switch recovery asked {} of {} owner functions (budget {})",
            budget,
            owners.len(),
            budget
        ));
        owners.truncate(budget);
    }
    if owners.is_empty() {
        phase(imp, "switch", started);
        return 0;
    }
    let Some(context) = &imp.input_context else {
        imp.diagnose(romwright_model::DiagnosticSeverity::Degraded, "switch", "switch recovery requires captured loader inputs");
        return 0;
    };
    let (input_project, input) = context.as_ref();
    let scratch = ScratchDir::new("romwright-switch");
    let Some(scratch) = scratch else {
        imp.diagnose(romwright_model::DiagnosticSeverity::Degraded, "switch", "switch recovery has no scratch dir");
        return 0;
    };
    let program = "switch-recovery";
    let stored = (|| -> crate::Result<()> {
        // All lanes read one immutable input set and one completed fact store.
        for digest in std::iter::once(&input.binary_digest)
            .chain(input.map_digest.iter())
            .chain(input.keys_digest.iter())
        {
            let artifact = crate::artifact::Artifact::open(input_project, digest)?;
            crate::artifact::Artifact::from_bytes(&scratch.path, artifact.bytes)?;
        }
        let db = ProjectDb::open(&scratch.path.join("project.sqlite"))?;
        store_import(
            &db,
            program,
            imp,
            declared_entry_model(&imp.cfg, &imp.language),
        )?;
        let id = db.program_id(program)?;
        db.set_program_input(id, input)?;
        // The worker decompiles what this store holds, and storing retracts
        // entries the store's rules reject (a const seed swallowing better
        // evidence). Asking for one failed the whole lane's decompile with
        // "Bad decompile address" and marked the import degraded, which also
        // kept it out of the import cache (libc 0x13ff9e, swkotor2
        // 0x40357c). A retracted entry is no function; its switch is not
        // asked.
        let kept: std::collections::HashSet<u64> =
            db.functions(id)?.into_iter().map(|row| row.entry.offset).collect();
        owners.retain(|entry| kept.contains(entry));
        Ok(())
    })();
    if let Err(error) = stored {
        imp.diagnose(romwright_model::DiagnosticSeverity::Degraded, "switch", format!("switch recovery could not store the image: {error}"));
        return 0;
    }
    // One worker per lane, as many at once as the host has cores: the
    // decompiles are independent and each worker loads the language once.
    // Never more lanes than cores: every lane is spawned at once, and more
    // decompilers than cores made each slower.
    let lanes = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 8)
        .min(owners.len());
    // Lanes are balanced by body size, largest first onto the lightest
    // lane. Contiguous address chunks put neighbouring giants in one lane:
    // on libc five functions of 4-13 s each sat together and that lane ran
    // 49 s while the rest idled; balanced, the phase is bounded near the
    // single largest decompile.
    let sizes: std::collections::HashMap<u64, u64> =
        imp.functions.iter().map(|function| (function.entry, function.size)).collect();
    let mut by_size: Vec<u64> = owners.clone();
    by_size.sort_by_key(|entry| (std::cmp::Reverse(sizes.get(entry).copied().unwrap_or(0)), *entry));
    let mut buckets: Vec<(u64, Vec<String>)> = vec![(0, Vec::new()); lanes];
    for entry in by_size {
        let lightest = buckets
            .iter_mut()
            .min_by_key(|(load, _)| *load)
            .expect("at least one lane");
        lightest.0 += sizes.get(&entry).copied().unwrap_or(0).max(1);
        lightest.1.push(format!("{entry:#x}"));
    }
    let chunks: Vec<&[String]> = buckets
        .iter()
        .map(|(_, addresses)| addresses.as_slice())
        .filter(|addresses| !addresses.is_empty())
        .collect();
    let binary = scratch.path.join("artifacts").join(&input.binary_digest);
    let setup = started.elapsed().as_secs_f64();
    let lanes_started = std::time::Instant::now();
    let outcomes: Vec<Result<crate::native_runtime::SwitchRecovery>> =
        std::thread::scope(|scope| {
            let handles: Vec<_> = chunks
                .iter()
                .map(|chunk| {
                    let project = &scratch.path;
                    let cfg = &imp.cfg;
                    let binary = &binary;
                    scope.spawn(move || {
                        let outcome = (|| -> crate::Result<_> {
                            let core = crate::Core::open_with_config(project, cfg.clone())?;
                            let request = core.execution_request(
                                binary,
                                program,
                                None,
                                crate::exec::DEFAULT_BUDGET.saturating_mul(
                                    u32::try_from(chunk.len())
                                        .unwrap_or(u32::MAX)
                                        .saturating_add(1),
                                ),
                            )?;
                            let docs =
                                crate::native_runtime::recover_native_switches(&request, chunk)?;
                            core.check_execution(&request)?;
                            Ok(docs)
                        })();
                        outcome.map_err(|error| ImportError::Bad(error.to_string()))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(ImportError::Bad("switch worker panicked".into())))
                })
                .collect()
        });
    let mut added = 0;
    for outcome in outcomes {
        let docs = match outcome {
            Ok(docs) => docs,
            Err(error) => {
                // A worker that cannot run degrades this round to no
                // answers at all, which reads exactly like a body nothing
                // could follow: the import is incomplete, and is not cached.
                imp.diagnose(romwright_model::DiagnosticSeverity::Degraded, "switch", format!("switch recovery decompile failed: {error}"));
                continue;
            }
        };
        // A function the decompiler rejects is rejected the same way every
        // time: the rest of the round stands, and the import stays
        // reusable. Only the whole-import note used to exist, and one such
        // function kept libc and swkotor2 out of the import cache.
        for failure in &docs.failures {
            imp.diagnose(romwright_model::DiagnosticSeverity::Partial, "switch", failure.clone());
        }
        for table in &docs.tables {
            if table.branch.space != romwright_model::AddressSpace::Ram {
                continue;
            }
            let mut targets: Vec<u64> = table
                .targets
                .iter()
                .filter(|target| target.space == romwright_model::AddressSpace::Ram)
                .map(|target| target.offset)
                .collect();
            targets.sort_unstable();
            targets.dedup();
            if targets.is_empty() {
                continue;
            }
            // The reference Ghidra's switch analyzer lays from the jump
            // to each case (`COMPUTED_JUMP`), before the pattern analyzer
            // runs: a case label is owned by flow from then on
            // (`checkAlreadyInFunctionAbove`, 514-527).
            for &target in &targets {
                imp.xrefs.push(NativeXref::with_provenance(
                    table.branch.offset,
                    target,
                    "COMPUTED_JUMP",
                    SWITCH_PROVENANCE,
                ));
            }
            // A table whose every case the walk already decoded changes
            // no body; only one reaching bytes nothing read is a reason
            // to walk again.
            let reaches_new = targets.iter().any(|&target| {
                let index = imp
                    .decoded_ranges
                    .partition_point(|&(start, _)| start <= target);
                !index
                    .checked_sub(1)
                    .is_some_and(|i| target < imp.decoded_ranges[i].1)
            });
            if imp
                .switch_tables
                .insert(table.branch.offset, targets)
                .is_none()
                && reaches_new
            {
                added += 1;
            }
        }
    }
    if added > 0 {
        demote_case_blocks(imp);
    }
    if std::env::var_os("ROMWRIGHT_TRACE_SWITCH").is_some() {
        eprintln!(
            "switch-decompiler: {} owners, {} lanes, {added} tables, setup {setup:.1}s, lanes {:.1}s, total {:.1}s",
            owners.len(),
            chunks.len(),
            lanes_started.elapsed().as_secs_f64(),
            started.elapsed().as_secs_f64()
        );
    }
    phase(imp, "switch", started);
    added
}

/// Ghidra recovers a jump's table at `CODE_ANALYSIS`, before the pattern
/// analyzer's delayed creator runs at `DATA_ANALYSIS.after()` and finds the
/// case block already inside a function (`PossibleDelayedFunctionCreator`,
/// 1001-1012). Here the patterns ran a round earlier, so a function whose
/// only evidence is a pattern match at a case target is withdrawn; the next
/// walk gives the block to the function that jumps to it. A target anything
/// calls or points at keeps its function.
pub(super) fn demote_case_blocks(imp: &mut NativeImport) {
    let targets: std::collections::HashSet<u64> = imp
        .switch_tables
        .values()
        .flat_map(|targets| targets.iter().copied())
        .collect();
    let evidenced: std::collections::HashSet<u64> = imp
        .xrefs
        .iter()
        .filter(|xref| xref.kind.ends_with("CALL") || xref.kind == "DATA")
        .map(|xref| xref.to)
        .collect();
    imp.functions.retain(|function| {
        !(targets.contains(&function.entry)
            && function.name.starts_with("FUN_")
            && !evidenced.contains(&function.entry))
    });
}
