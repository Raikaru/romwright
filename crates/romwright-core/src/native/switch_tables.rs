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
        .or_else(|| std::env::home_dir().map(|home| home.join(".cache/romwright/scratch")))
        .ok_or_else(|| std::io::Error::other("set ROMWRIGHT_SCRATCH or a home directory for native scratch storage"))?;
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

/// Removes the scratch directories of `prefix` whose process is gone: a run
/// that was killed never reached `Drop`, and each such directory held a copy
/// of the input (4 GB for a Wii disc image). Only a directory named for a
/// process id no longer in `/proc` is touched, so a live run's is never.
fn remove_dead_scratch(root: &std::path::Path, prefix: &str) {
    if !std::path::Path::new("/proc/self").exists() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|name| name.strip_prefix(prefix)).and_then(|rest| rest.strip_prefix('-')) else {
            continue;
        };
        let Some(pid) = rest.split('-').next().and_then(|pid| pid.parse::<u32>().ok()) else { continue };
        if pid != std::process::id() && !std::path::Path::new("/proc").join(pid.to_string()).exists() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Puts the input artifact `digest` of `from_project` into the artifact store
/// of `to_project` without copying its bytes: a hard link where both are on
/// one filesystem, otherwise a symlink to the original (a copy only where the
/// platform has neither). The scratch store used to hold a full copy of the
/// input per round and per program; a Wii disc image made each 4 GB.
fn link_artifact(from_project: &std::path::Path, digest: &str, to_project: &std::path::Path) -> std::io::Result<()> {
    if digest.len() != 64 || !digest.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid artifact digest"));
    }
    let source = from_project.join("artifacts").join(digest).canonicalize()?;
    let root = to_project.join("artifacts");
    std::fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    }
    let target = root.join(digest);
    if target.exists() {
        return Ok(());
    }
    if std::fs::hard_link(&source, &target).is_ok() {
        return Ok(());
    }
    #[cfg(unix)]
    if std::os::unix::fs::symlink(&source, &target).is_ok() {
        return Ok(());
    }
    std::fs::copy(&source, &target).map(|_| ())
}

impl ScratchDir {
    pub(super) fn new(prefix: &str) -> Option<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let root = scratch_root().ok()?;
        remove_dead_scratch(&root, prefix);
        // Programs analysed side by side ask in the same nanosecond: the
        // counter keeps their directories apart.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = root.join(format!("{prefix}-{}-{nanos}-{serial}", std::process::id()));
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
    /// The address space's width as a mask (`vsa::Image::wrap`).
    address_mask: u64,
    /// The function's flow, by address.
    shapes: &'a FlowShapeIndex<'a>,
    /// The registers a call leaves as it found them (`SleighLifter::unaffected`).
    kept: &'a [(u64, u32)],
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

    fn wrap(&self, address: u64) -> u64 {
        address & self.address_mask
    }

    fn big_endian(&self) -> bool {
        self.big_endian
    }

    fn is_call(&self, address: u64) -> bool {
        self.shapes.range(address, address.saturating_add(1)).iter().any(|shape| {
            matches!(shape.kind, crate::native_runtime::FlowKind::Call) && !shape.conditional
        })
    }

    fn unaffected(&self) -> &[(u64, u32)] {
        self.kept
    }
}

/// Address index shared by every switch candidate in a discovery round.
/// Discovery appends unsorted rounds; keep equal-address evidence in its
/// original order without copying or reordering the underlying flow records.
pub(super) struct FlowShapeIndex<'a> {
    by_address: Vec<&'a FlowShape>,
}

impl<'a> FlowShapeIndex<'a> {
    #[cfg(test)]
    pub(super) fn new(shapes: &'a [FlowShape]) -> Self {
        let mut by_address: Vec<_> = shapes.iter().collect();
        by_address.sort_by_key(|shape| shape.address);
        Self { by_address }
    }

    /// The shapes inside `ranges` (sorted, disjoint, end-exclusive).
    pub(super) fn within(shapes: &'a [FlowShape], ranges: &[(u64, u64)]) -> Self {
        let inside = |address: u64| {
            let index = ranges.partition_point(|&(start, _)| start <= address);
            index.checked_sub(1).is_some_and(|index| address < ranges[index].1)
        };
        let mut by_address: Vec<_> = shapes.iter().filter(|shape| inside(shape.address)).collect();
        by_address.sort_by_key(|shape| shape.address);
        Self { by_address }
    }

    pub(super) fn range(&self, entry: u64, end: u64) -> &[&'a FlowShape] {
        let start = self.by_address.partition_point(|shape| shape.address < entry);
        let remaining = &self.by_address[start..];
        &remaining[..remaining.partition_point(|shape| shape.address < end)]
    }
}

/// The most blocks that may enter a dispatch's guard chain for `switch_lines`
/// to list them as its ways in. GCC and SN ProDG schedule the guard's `sltiu`
/// into the delay slot of every branch that reaches the test, so a switch in
/// a loop has one way in per branch (God Hand 0x39a220: five).
const MAX_WAYS: usize = 8;

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

/// `switch_lines` without the ways in.
#[cfg(test)]
pub(super) fn switch_window(
    shapes: &[&FlowShape],
    branch: u64,
    entry: u64,
    end: u64,
) -> (Vec<u64>, Vec<Vec<u64>>) {
    let (window, guard, _) = switch_lines(shapes, branch, entry, end);
    (window, guard)
}

/// `switch_window`, plus the dispatch's ways in: for each block that enters
/// the guard chain (or the dispatch, when it has several predecessors), the
/// instructions from that block's start up to the dispatch block -- the
/// prefix a run needs to see the index each way gives it. Empty when there
/// are none or more than `MAX_WAYS`, which are not trusted to be the whole
/// list.
pub(crate) fn switch_lines(
    shapes: &[&FlowShape],
    branch: u64,
    entry: u64,
    end: u64,
) -> (Vec<u64>, Vec<Vec<u64>>, Vec<Vec<u64>>) {
    if shapes.is_empty() || !shapes.iter().any(|shape| shape.address == branch) {
        return (Vec::new(), Vec::new(), Vec::new());
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
    // and the block that falls into it -- including through a conditional
    // exit (`bgtlr`, a conditional return), which falls through when not
    // taken.
    let predecessors_of = |target: u64| {
        let mut predecessors: Vec<u64> = Vec::new();
        for shape in shapes {
            let reaches = shape.target == Some(target)
                || ((!ends_block(shape.kind)
                    || shape.conditional
                    || matches!(shape.kind, crate::native_runtime::FlowKind::CBranch))
                    && shape.address.saturating_add(u64::from(shape.length)) == target);
            if reaches {
                let block = leader_of(shape.address);
                if block != target && !predecessors.contains(&block) {
                    predecessors.push(block);
                }
            }
        }
        predecessors.sort_unstable();
        predecessors
    };
    let predecessors = predecessors_of(dispatch);
    // Shapes accumulate across discovery rounds, so one address can
    // appear twice; the lifter and the emulator would both work it twice.
    // Straight-line blocks stay straight-line deduplicated.
    let mut window: Vec<u64> = shapes
        .iter()
        .filter(|shape| shape.address >= dispatch && shape.address <= branch)
        .map(|shape| shape.address)
        .collect();
    window.sort_unstable();
    window.dedup();
    let addresses_of = |block: u64| {
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
        addresses
    };
    let ends_conditionally = |addresses: &[u64]| {
        addresses.last().is_some_and(|&last| {
            shapes.iter().any(|shape| {
                shape.address == last
                    && (shape.conditional
                        || matches!(shape.kind, crate::native_runtime::FlowKind::CBranch))
            })
        })
    };
    // Each predecessor block on its own: a guard is read by running the
    // block that states it, and one block's call must not clear the index
    // another block compares.
    let mut guard: Vec<Vec<u64>> = Vec::new();
    for &block in predecessors.iter().take(4) {
        let addresses = addresses_of(block);
        if !addresses.is_empty() {
            guard.push(addresses);
        }
    }
    // A dispatch with one way in has its guards up that one way: Ghidra
    // walks single-predecessor blocks back from the switch and takes up to
    // two conditional branches as guards (`JumpBasic::analyzeGuards`,
    // `maxbranch = 2`) -- `cmp r0,#0; ble default; cmp r0,#7; bgt default`
    // bounds the index from below in one block and above in the next. The
    // blocks of that chain run as one line, earliest first.
    if let [only] = guard.as_mut_slice() {
        let mut branches = usize::from(ends_conditionally(only));
        let mut current = predecessors[0];
        for _ in 0..3 {
            if branches >= 2 {
                break;
            }
            let [previous] = predecessors_of(current)[..] else {
                break;
            };
            let addresses = addresses_of(previous);
            if addresses.is_empty() || addresses.iter().any(|address| only.contains(address)) {
                break;
            }
            branches += usize::from(ends_conditionally(&addresses));
            only.splice(0..0, addresses);
            current = previous;
        }
    }
    let ways: Vec<Vec<u64>> = match guard.as_slice() {
        [chain] => {
            let head = chain.first().map_or(dispatch, |&first| leader_of(first));
            let entering = predecessors_of(head);
            if (1..=MAX_WAYS).contains(&entering.len()) {
                entering
                    .iter()
                    .map(|&block| {
                        let mut line = addresses_of(block);
                        line.extend(chain.iter().copied());
                        line
                    })
                    .collect()
            } else {
                Vec::new()
            }
        }
        blocks if (2..=3).contains(&predecessors.len()) => blocks.to_vec(),
        _ => Vec::new(),
    };
    (window, guard, ways)
}

/// Recovers tables with value-set analysis over p-code, no decompiler.
///
/// Returns the branches it could not resolve, which the decompiler path then
/// gets, so a body this cannot follow is still recovered.
///
/// `final_round`: no later round asks about switches. A table whose cases
/// reach code not decoded yet is then left to the decompiler: decoding
/// those cases may uncover more dispatches no round will ask about, and
/// the decompiler, which follows the function's flow itself, recovers
/// them in the same decompile -- as it did when it answered the whole
/// function from the start. Answering such a table here cost capcom five
/// nested dispatches in 0x186500 (three levels deep: 0x1867bc -> 0x1867e8
/// -> 0x186810 and its siblings).
pub(super) fn recover_switch_tables_native(
    imp: &mut NativeImport,
    lifter: &mut crate::native_runtime::SleighLifter,
    branches: &[(u64, u64, u64)],
    final_round: bool,
) -> (usize, Vec<u64>) {
    // The language id names the endianness in its second field
    // (`PowerPC:BE:32:default`), which is how every other reader here takes
    // it.
    let big_endian = imp
        .language
        .split(':')
        .nth(1)
        .is_some_and(|field| field.eq_ignore_ascii_case("BE"));
    // The address space's width: the language's size field, or the
    // variant's `32addr` where 64-bit registers address 32-bit memory.
    let address_mask = {
        let mut fields = imp.language.split(':').skip(2);
        let size = fields.next().and_then(|size| size.parse::<u32>().ok()).unwrap_or(64);
        let bits = if fields.next().is_some_and(|variant| variant.contains("32addr")) {
            32
        } else {
            size
        };
        if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
    };
    let renarrowed = narrow_recorded_tables(imp, lifter, big_endian, address_mask);
    let kept = lifter.unaffected().to_vec();
    let mut resolved: Vec<vsa::SwitchTable> = Vec::new();
    let mut unresolved = Vec::new();
    let mut refusals = vsa::Refusals::default();
    let mut no_window = 0usize;
    let mut undecodable = 0usize;
    let mut sja_refusals = sja::Refusals::default();
    let mut sja_resolved = 0usize;
    // What each table VSA answered was read from -- guard blocks, ways in,
    // dispatch window -- for `refine_with_facts`.
    let mut lifted_lines: std::collections::HashMap<u64, LiftedLines> = std::collections::HashMap::new();
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
    // Only the candidates' functions are indexed: rounds late in discovery
    // ask about a handful of branches, and sorting every flow record of
    // the image once per round cost more than the analysis itself on NDS.
    let flow_shapes = {
        let mut ranges: Vec<(u64, u64)> = branches.iter().map(|&(_, entry, end)| (entry, end)).collect();
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        FlowShapeIndex::within(&imp.flow_shapes, &merged)
    };
    for &(branch, entry, end) in branches {
        let function_shapes = flow_shapes.range(entry, end);
        let (window_addresses, guard_addresses, way_addresses) =
            switch_lines(function_shapes, branch, entry, end);
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
        let decoded = lifter.lift(&addresses);
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
        // Each way in, lifted only if it lifts whole; a way that does not
        // leaves the list incomplete, which `recover` then does not trust.
        let ways: Vec<Vec<crate::native_runtime::PcodeInstruction>> = {
            let lifted: Vec<_> = way_addresses.iter().map(|line| lifter.lift(line)).collect();
            if lifted.iter().flatten().any(|instruction| instruction.error.is_some()) {
                Vec::new()
            } else {
                lifted
            }
        };
        let quick = {
            let view = ImageView {
                imp,
                big_endian,
                address_mask,
                shapes: &flow_shapes,
                kept: &kept,
            };
            vsa::recover(&view, branch, &guard, &ways, window, None, &mut refusals)
        };
        if quick.is_some() {
            lifted_lines.insert(branch, (guard.clone(), ways.clone(), window.to_vec()));
        }
        // The abstract interpretation is opt-in until it is measured to
        // help: `ROMWRIGHT_SJA=1`. It runs only where the pattern-shaped
        // pass refused, so it can only add.
        let proven = if quick.is_some() || std::env::var_os("ROMWRIGHT_SJA").is_none() {
            None
        } else {
            if let std::collections::hash_map::Entry::Vacant(e) = interpreted_functions.entry(entry) {
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
                let graph: Vec<sja::Block> = if wanted.is_empty() {
                    Vec::new()
                } else {
                    let by_address: std::collections::HashMap<u64, _> = lifter
                        .lift(&wanted)
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
                };
                // A function whose blocks or p-code could not be had is
                // cached as unanalysable, so the next dispatch in it does
                // not pay for the same failure again.
                let analysed = (!graph.is_empty()).then(|| {
                    let view = ImageView {
                        imp,
                        big_endian,
                        address_mask,
                        shapes: &flow_shapes,
                        kept: &kept,
                    };
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
                e.insert(analysed);
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
    let narrowed = {
        let view = ImageView {
            imp,
            big_endian,
            address_mask,
            shapes: &flow_shapes,
            kept: &kept,
        };
        refine_with_facts(&view, lifter, &flow_shapes, branches, &mut resolved, &lifted_lines, &resolved_jumps)
    };
    if std::env::var_os("ROMWRIGHT_TRACE_VSA").is_some() {
        eprintln!(
            "VSA candidates={} resolved={} no_window={no_window} undecodable={undecodable} \
             no_guard={} no_live_in={} no_strided_load={} too_few_targets={} unguarded={} \
             unmodelled={} narrowed={narrowed} renarrowed={renarrowed}",
            branches.len(),
            resolved.len(),
            refusals.no_guard,
            refusals.no_live_in,
            refusals.no_strided_load,
            refusals.too_few_targets,
            refusals.unguarded,
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
    // Why answered tables went to the decompiler, for `ROMWRIGHT_TRACE_VSA`.
    let (mut left_final, mut left_outside, mut left_nested, mut left_deferred) = (0usize, 0usize, 0usize, 0usize);
    // Whether a decompiler pass follows this one. Leaving a table to it
    // (the first and last rules below) only makes sense if it will run: with
    // `ROMWRIGHT_NO_SWITCH_DECOMPILER` the deferred table was simply lost,
    // 42 nested and 40 last-round tables on libc, which is what held the
    // interpreter tier at 67 dispatches against the decompiler's 129.
    let decompiler_follows = imp.cfg.switch_decompiler;
    // Dispatches answered this round: flow that loops back to one of them
    // meets no dispatch the decompiler would find first.
    let answered: std::collections::HashSet<u64> = resolved.iter().map(|table| table.branch).collect();
    let case_labels = CaseLabels::new(imp);
    // A switch's own labels, and those of every other table answered this
    // round: two dispatches of one function put the later one's case labels
    // between the earlier one and its cases, and counting them as the next
    // function sent the earlier table "outside" (God Hand 0x22cca8, whose
    // second dispatch 0x22d56c made 0x22d584 a label inside its range). Only
    // for a table whose cases are all decoded: one that reaches new code is
    // the decompiler's whole-function answer to give, which finds the
    // dispatches in that code too (taking it here lost 6 nested tables of
    // God Hand 0x21a538 to the last round).
    let round_labels = {
        let mut cases: Vec<u64> = resolved.iter().flat_map(|table| table.targets.iter().copied()).collect();
        cases.sort_unstable();
        cases.dedup();
        case_labels.unevidenced(&cases)
    };
    for table in resolved {
        let mut targets = table.targets;
        targets.sort_unstable();
        targets.dedup();
        let reaches_new = targets.iter().any(|&target| {
            let index = imp
                .decoded_ranges
                .partition_point(|&(start, _)| start <= target);
            !index
                .checked_sub(1)
                .is_some_and(|i| target < imp.decoded_ranges[i].1)
        });
        if decompiler_follows && final_round && reaches_new {
            left_final += 1;
            unresolved.push(table.branch);
            continue;
        }
        let owner = branches
            .iter()
            .find(|&&(branch, _, _)| branch == table.branch)
            .map_or(table.branch, |&(_, entry, _)| entry);
        // The functions the table's own cases made are not the end of the
        // dispatching function: a case label nothing but the table's words
        // names is a function only because the walk took those words for
        // code pointers, and `demote_case_blocks` withdraws it once the
        // table is stored. Counting it as the next function put the
        // switch's first case "outside" its own function, the table went
        // to the decompiler, and the labels stayed (God Hand 0x1627d8: 8
        // labels, DDS 0x28f0e0: 13).
        let own_labels = case_labels.unevidenced(&targets);
        let next_function_without = |labels: &std::collections::HashSet<u64>| {
            imp.functions
                .iter()
                .map(|function| function.entry)
                .filter(|&entry| entry > owner && !labels.contains(&entry))
                .min()
                .unwrap_or(u64::MAX)
        };
        let next_function = next_function_without(&own_labels);
        // Inside with the other tables' labels set aside, outside without.
        let only_with_round_labels = !reaches_new && {
            let labels: std::collections::HashSet<u64> = own_labels.iter().chain(round_labels.iter()).copied().collect();
            let next_function = next_function_without(&labels);
            targets.iter().all(|&target| target >= owner && target < next_function)
                && targets.iter().any(|&target| target >= next_function_without(&own_labels))
        };
        // A target outside the dispatching function -- a guard's default
        // that is a tail call, a case in a cold section -- is the
        // decompiler's to place: m13 scores those as unsound, and stock
        // Ghidra folds them in anyway (libc: 5 of 392 targets).
        if std::env::var("ROMWRIGHT_TRACE_VSA_AT")
            .ok()
            .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
            == Some(table.branch)
        {
            eprintln!(
                "VSA at {:#x}: owner {owner:#x} next function {next_function:#x} case labels {:x?} targets {targets:x?} reaches_new {reaches_new}",
                table.branch,
                {
                    let mut labels: Vec<u64> = own_labels.iter().copied().collect();
                    labels.sort_unstable();
                    labels
                },
            );
        }
        if only_with_round_labels {
            // Answered here, but the function is the decompiler's to read
            // whole: a dispatch nested in it that no walk has met answers
            // in the same decompile, and taking this table now made six of
            // God Hand 0x21a538 arrive a round too late. What it leaves
            // unanswered gets this table (`settle_deferred_tables`).
            left_deferred += 1;
            imp.switch_deferred.insert(table.branch, targets);
            unresolved.push(table.branch);
            continue;
        }
        if targets.iter().any(|&target| target < owner || target >= next_function) {
            left_outside += 1;
            unresolved.push(table.branch);
            continue;
        }
        // The decompiler asked about a function answers every dispatch its
        // flow reaches, nested ones included, in one decompile; this pass
        // answers one dispatch per round, and only those already decoded.
        // A table whose new cases lead to another dispatch with no table
        // would put that dispatch a round later than the decompiler path
        // finds it, and with it everything its cases reach -- capcom lost
        // a function to that (`rate_escape0`, 0x1c0740, seven separate
        // tables each enough). Such a table is left to the decompiler.
        if decompiler_follows
            && reaches_new
            && reaches_unanswered_dispatch(lifter, imp, &answered, &targets, owner, next_function)
        {
            left_nested += 1;
            unresolved.push(table.branch);
            continue;
        }
        for &target in &targets {
            imp.xrefs.push(NativeXref::with_provenance(
                table.branch,
                target,
                "COMPUTED_JUMP",
                SWITCH_PROVENANCE,
            ));
        }
        if imp.switch_tables.insert(table.branch, targets).is_none() && reaches_new {
            added += 1;
        }
    }
    if std::env::var_os("ROMWRIGHT_TRACE_VSA").is_some() {
        eprintln!("VSA left final={left_final} outside={left_outside} nested={left_nested} deferred={left_deferred}");
    }
    (added, unresolved)
}

/// Ghidra analyses a switch again when its function's body changes; so
/// does this, once: a table recorded in an earlier round, whose cases are
/// decoded now, is run through `refine_with_facts`, which could not see
/// those cases then. Only a table VSA answers the same way without facts
/// is touched; one that narrows loses the dropped targets' references.
/// `switch_asked` holds 0 for a table re-checked here: a branch with a
/// table is never a candidate again, so nothing else reads its entry.
/// Returns how many narrowed.
fn narrow_recorded_tables(
    imp: &mut NativeImport,
    lifter: &mut crate::native_runtime::SleighLifter,
    big_endian: bool,
    address_mask: u64,
) -> usize {
    let decoded = |imp: &NativeImport, address: u64| {
        let index = imp.decoded_ranges.partition_point(|&(start, _)| start <= address);
        index.checked_sub(1).is_some_and(|i| address < imp.decoded_ranges[i].1)
    };
    let mut branches: Vec<(u64, u64, u64)> = Vec::new();
    for (&branch, targets) in &imp.switch_tables {
        let Some(function) = imp
            .functions
            .iter()
            .find(|function| function.size > 1 && function.entry <= branch && branch < function.entry + function.size)
        else {
            continue;
        };
        let checked = imp.switch_asked.get(&branch) == Some(&0);
        if !checked && targets.iter().all(|&target| decoded(imp, target)) {
            branches.push((branch, function.entry, function.entry + function.size));
        }
    }
    if branches.is_empty() {
        return 0;
    }
    branches.sort_unstable();
    let mut ranges: Vec<(u64, u64)> = branches.iter().map(|&(_, entry, end)| (entry, end)).collect();
    ranges.sort_unstable();
    ranges.dedup();
    let resolved_jumps: std::collections::HashSet<u64> = imp
        .flow_overrides
        .iter()
        .map(|&(address, _)| address)
        .chain(imp.xrefs.iter().filter(|xref| xref.kind == "COMPUTED_JUMP").map(|xref| xref.from))
        .collect();
    let narrowed: Vec<(u64, Vec<u64>)> = {
        let flow_shapes = FlowShapeIndex::within(&imp.flow_shapes, &ranges);
        let kept = lifter.unaffected().to_vec();
        let view = ImageView { imp, big_endian, address_mask, shapes: &flow_shapes, kept: &kept };
        let mut tables: Vec<vsa::SwitchTable> = Vec::new();
        let mut lines: std::collections::HashMap<u64, LiftedLines> = std::collections::HashMap::new();
        for &(branch, entry, end) in &branches {
            let (window, guard, ways) = switch_lines(flow_shapes.range(entry, end), branch, entry, end);
            if window.is_empty() {
                continue;
            }
            let lift_all = |lifter: &mut crate::native_runtime::SleighLifter, blocks: &[Vec<u64>]| {
                let lifted: Vec<_> = blocks.iter().map(|block| lifter.lift(block)).collect();
                (!lifted.iter().flatten().any(|instruction| instruction.error.is_some())).then_some(lifted)
            };
            let (Some(guard), Some(mut window)) = (lift_all(lifter, &guard), lift_all(lifter, &[window])) else {
                continue;
            };
            let window = window.pop().unwrap_or_default();
            let ways = lift_all(lifter, &ways).unwrap_or_default();
            let Some(table) =
                vsa::recover(&view, branch, &guard, &ways, &window, None, &mut vsa::Refusals::default())
            else {
                continue;
            };
            // Flow decoded since can change the guard the lines read; the
            // table stands as recorded unless the facts answer is a strict
            // subset of it (below).
            lines.insert(branch, (guard, ways, window));
            tables.push(table);
        }
        let unrefined: std::collections::HashMap<u64, Vec<u64>> =
            tables.iter().map(|table| (table.branch, table.targets.clone())).collect();
        refine_with_facts(&view, lifter, &flow_shapes, &branches, &mut tables, &lines, &resolved_jumps);
        tables
            .into_iter()
            .map(|table| {
                let mut targets = table.targets;
                targets.sort_unstable();
                targets.dedup();
                (table.branch, targets)
            })
            .filter(|(branch, targets)| {
                // Only where the facts cut VSA's own answer; and then the
                // table as recorded -- with every reference laid from the
                // branch, which a later decompile of the owner may have
                // added to -- must hold all that is left.
                let cut = unrefined
                    .get(branch)
                    .is_some_and(|before| before.iter().any(|target| !targets.contains(target)));
                let mut recorded: Vec<u64> = imp.switch_tables.get(branch).cloned().unwrap_or_default();
                recorded.extend(
                    imp.xrefs
                        .iter()
                        .filter(|xref| {
                            xref.from == *branch
                                && xref.kind == "COMPUTED_JUMP"
                                && xref.provenance == SWITCH_PROVENANCE
                        })
                        .map(|xref| xref.to),
                );
                recorded.sort_unstable();
                recorded.dedup();
                cut && &recorded != targets && targets.iter().all(|target| recorded.contains(target))
            })
            .collect()
    };
    for &(branch, _, _) in &branches {
        imp.switch_asked.insert(branch, 0);
    }
    for (branch, targets) in &narrowed {
        if std::env::var_os("ROMWRIGHT_TRACE_VSA").is_some() {
            eprintln!("VSA renarrowed {branch:#x} to {targets:x?}");
        }
        imp.xrefs.retain(|xref| {
            !(xref.from == *branch
                && xref.kind == "COMPUTED_JUMP"
                && xref.provenance == SWITCH_PROVENANCE
                && !targets.contains(&xref.to))
        });
        imp.switch_tables.insert(*branch, targets.clone());
    }
    narrowed.len()
}

/// Guard blocks, ways in and dispatch window, as lifted for one dispatch.
type LiftedLines = (
    Vec<Vec<crate::native_runtime::PcodeInstruction>>,
    Vec<Vec<crate::native_runtime::PcodeInstruction>>,
    Vec<crate::native_runtime::PcodeInstruction>,
);

/// The most instructions `refine_with_facts` decodes for one function.
const MAX_FACT_INSTRUCTIONS: usize = 20_000;

/// Narrows each table VSA answered to the slots its index can take, given
/// the register bits that hold on every way into the dispatch block
/// (`vsa::entry_facts` over the function's blocks, the ABI's unaffected
/// registers kept across calls). A narrower answer replaces the first only
/// when its cases are a strict subset of it. Returns how many were
/// narrowed.
///
/// The flow has to be whole for the meet to hold: a function with an
/// indirect jump nothing has answered is skipped, and the blocks a jump
/// table lands on, the entry, and blocks nothing branches to start knowing
/// nothing.
fn refine_with_facts(
    view: &ImageView<'_>,
    lifter: &mut crate::native_runtime::SleighLifter,
    flow_shapes: &FlowShapeIndex<'_>,
    branches: &[(u64, u64, u64)],
    resolved: &mut [vsa::SwitchTable],
    lines: &std::collections::HashMap<u64, LiftedLines>,
    resolved_jumps: &std::collections::HashSet<u64>,
) -> usize {
    use crate::native_runtime::{FlowKind, PcodeInstruction};
    type Blocks = (Vec<u64>, Vec<(Vec<PcodeInstruction>, Vec<usize>)>, Vec<bool>);
    let kept = lifter.unaffected().to_vec();
    let answered: std::collections::HashSet<u64> = resolved.iter().map(|table| table.branch).collect();
    let case_starts: std::collections::HashSet<u64> = view
        .imp
        .switch_tables
        .values()
        .flatten()
        .copied()
        .chain(
            view.imp
                .xrefs
                .iter()
                .filter(|xref| xref.kind == "COMPUTED_JUMP")
                .map(|xref| xref.to),
        )
        .chain(resolved.iter().flat_map(|table| table.targets.iter().copied()))
        .collect();
    // A case not decoded yet is flow the blocks do not show: a case body
    // that sets the index (`mov r4,#2` in `__strtoul`'s state machine, NDS
    // 0x20eaf48) and loops back would be missing from the meet, which would
    // then claim values the index never stops taking.
    let decoded = |address: u64| {
        let index = view.imp.decoded_ranges.partition_point(|&(start, _)| start <= address);
        index
            .checked_sub(1)
            .is_some_and(|i| address < view.imp.decoded_ranges[i].1)
    };
    let incomplete: std::collections::HashSet<u64> = resolved
        .iter()
        .filter(|table| table.targets.iter().any(|&target| !decoded(target)))
        .filter_map(|table| {
            branches
                .iter()
                .find(|&&(branch, _, _)| branch == table.branch)
                .map(|&(_, entry, _)| entry)
        })
        .collect();
    let mut functions: std::collections::HashMap<u64, Option<Blocks>> = std::collections::HashMap::new();
    let mut narrowed = 0;
    for table in resolved.iter_mut() {
        let Some(&(_, entry, end)) = branches.iter().find(|&&(branch, _, _)| branch == table.branch) else {
            continue;
        };
        let Some((guard, ways, window)) = lines.get(&table.branch) else {
            continue;
        };
        let function = functions.entry(entry).or_insert_with(|| {
            if incomplete.contains(&entry) {
                return None;
            }
            let shapes = flow_shapes.range(entry, end);
            let unanswered = shapes.iter().any(|shape| {
                shape.kind == FlowKind::BranchInd
                    && !answered.contains(&shape.address)
                    && !resolved_jumps.contains(&shape.address)
            });
            if unanswered {
                return None;
            }
            let mut blocks = function_blocks(shapes, entry, end);
            let starts: Vec<u64> = blocks.iter().map(|block| block.0).collect();
            let index_of = |address: u64| starts.partition_point(|&start| start <= address).checked_sub(1);
            // A conditional exit (`bgtlr`, `bxne lr`) falls through when not
            // taken.
            for shape in shapes {
                let next = shape.address.saturating_add(u64::from(shape.length));
                if shape.conditional
                    && matches!(shape.kind, FlowKind::Return | FlowKind::BranchInd)
                    && next < end
                    && let (Some(from), Some(to)) = (index_of(shape.address), index_of(next))
                    && from != to
                    && !blocks[from].2.contains(&to)
                {
                    blocks[from].2.push(to);
                }
            }
            let addresses: Vec<u64> = blocks.iter().flat_map(|block| block.1.iter().copied()).collect();
            if addresses.len() > MAX_FACT_INSTRUCTIONS {
                return None;
            }
            let decoded = lifter.lift(&addresses);
            if decoded.len() != addresses.len() || decoded.iter().any(|instruction| instruction.error.is_some()) {
                return None;
            }
            let mut entered = vec![false; blocks.len()];
            for block in &blocks {
                for &successor in &block.2 {
                    entered[successor] = true;
                }
            }
            let open: Vec<bool> = blocks
                .iter()
                .enumerate()
                .map(|(index, block)| {
                    index == 0 || block.0 == entry || !entered[index] || case_starts.contains(&block.0)
                })
                .collect();
            let mut cursor = 0;
            let lifted = blocks
                .into_iter()
                .map(|(_, addresses, successors)| {
                    let ops = decoded[cursor..cursor + addresses.len()].to_vec();
                    cursor += addresses.len();
                    (ops, successors)
                })
                .collect();
            Some((starts, lifted, open))
        });
        let traced = std::env::var("ROMWRIGHT_TRACE_VSA_AT")
            .ok()
            .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
            == Some(table.branch);
        let why = |reason: &str| {
            if traced {
                eprintln!("VSA facts at {:#x}: {reason}", table.branch);
            }
        };
        let Some((starts, blocks, open)) = function.as_ref() else {
            why(if incomplete.contains(&entry) { "cases not decoded" } else { "function flow not whole" });
            continue;
        };
        let Some(dispatch) = starts.partition_point(|&start| start <= table.branch).checked_sub(1) else {
            continue;
        };
        // The facts hold where the window starts only if it starts the block.
        if window.first().map(|instruction| instruction.address) != Some(starts[dispatch]) {
            why("window does not start the dispatch block");
            continue;
        }
        let facts = vsa::entry_facts(view, blocks, open, dispatch, &kept);
        if facts.is_empty() {
            why("no facts");
            continue;
        }
        if traced {
            eprintln!("VSA facts at {:#x}: {facts:x?}", table.branch);
        }
        let Some(refined) = vsa::recover(
            view,
            table.branch,
            guard,
            ways,
            window,
            Some(&facts),
            &mut vsa::Refusals::default(),
        ) else {
            why("no answer with facts");
            continue;
        };
        let narrower = refined.targets.iter().all(|target| table.targets.contains(target))
            && table.targets.iter().any(|target| !refined.targets.contains(target));
        if narrower {
            *table = refined;
            narrowed += 1;
        } else {
            why("facts narrow nothing");
        }
    }
    narrowed
}

/// How many instructions `reaches_unanswered_dispatch` decodes before it
/// gives up and answers yes.
const NESTED_SCAN: usize = 512;

/// Whether flow from `starts`, kept to `[lo, hi)` -- the dispatching
/// function, as far as the next known function -- meets an indirect jump
/// with no table yet. Branches and fall-through are followed, calls return;
/// a scan that runs out of budget answers yes, so the decompiler gets the
/// function when this cannot tell.
fn reaches_unanswered_dispatch(
    lifter: &mut crate::native_runtime::SleighLifter,
    imp: &NativeImport,
    answered: &std::collections::HashSet<u64>,
    starts: &[u64],
    lo: u64,
    hi: u64,
) -> bool {
    use crate::ir::Opcode as O;
    let mut seen = std::collections::HashSet::new();
    let mut work: Vec<u64> = starts.to_vec();
    while let Some(address) = work.pop() {
        if address < lo || address >= hi || !seen.insert(address) {
            continue;
        }
        if seen.len() > NESTED_SCAN {
            if std::env::var_os("ROMWRIGHT_TRACE_VSA").is_some() {
                eprintln!("VSA nested budget from {:#x}", starts.first().copied().unwrap_or(0));
            }
            return true;
        }
        let Some(instruction) = lifter.lift(&[address]).pop() else {
            continue;
        };
        if instruction.error.is_some() || instruction.length == 0 {
            continue;
        }
        let mut falls = true;
        for op in &instruction.ops {
            let destination = op.inputs.first().filter(|input| !input.is_const()).map(|input| input.offset);
            match op.opcode.parse::<O>() {
                // A Thumb `pop {..rX..}; bx rX` is a return, as discovery
                // reads it (`thumb_pop_return`): counting it left 562 of
                // pokeemerald's 563 answered tables to the decompiler.
                Ok(O::BranchInd)
                    if !imp.switch_tables.contains_key(&address)
                        && !answered.contains(&address)
                        && !(crate::compiler::rules::applies("thumb-pop-bx-is-return", &crate::compiler::ctx_of(imp))
                            && super::discovery::thumb_pop_return(imp, address)) =>
                {
                    if std::env::var_os("ROMWRIGHT_TRACE_VSA").is_some() {
                        eprintln!("VSA nested dispatch {address:#x}");
                    }
                    return true;
                }
                Ok(O::BranchInd | O::Return) => falls = false,
                Ok(O::Branch) => {
                    work.extend(destination);
                    falls = false;
                }
                Ok(O::CBranch) => work.extend(destination),
                _ => {}
            }
        }
        if falls {
            work.push(address.saturating_add(u64::from(instruction.length)));
        }
    }
    false
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

/// What a lane's decompiler refused, as the import's diagnostics.
fn report_refusals(imp: &mut NativeImport, docs: &mut crate::native_runtime::SwitchRecovery) {
    // Each line starts with the function's address.
    let address = |line: &String| {
        line.split(':')
            .next()
            .and_then(|head| u64::from_str_radix(head.trim_start_matches("0x"), 16).ok())
            .unwrap_or(u64::MAX)
    };
    for list in [&mut docs.failures, &mut docs.over_budget, &mut docs.wall_clock] {
        list.sort_by_key(|line| (address(line), line.clone()));
    }
    // A function the decompiler rejects is rejected the same way every
    // time: the rest of the round stands, and the import stays
    // reusable. Only the whole-import note used to exist, and one such
    // function kept libc and swkotor2 out of the import cache.
    for failure in &docs.failures {
        imp.diagnose(romwright_model::DiagnosticSeverity::Partial, "switch", failure.clone());
    }
    // A function over the work budget is refused the same way on every
    // host: the import says so, and stays reusable.
    for failure in &docs.over_budget {
        imp.diagnose(
            romwright_model::DiagnosticSeverity::Partial,
            "switch",
            format!("{failure} (switch decompile budget {} units)", imp.cfg.switch_work_budget),
        );
    }
    // One the wall-clock guard killed finished or not by the host's
    // load, so no answer of this round can be told from one the host
    // made different: the import is incomplete and is not reused.
    for failure in &docs.wall_clock {
        imp.diagnose(romwright_model::DiagnosticSeverity::Degraded, "switch", failure.clone());
    }
}

/// How many switch worker processes run at once in this process, as many as
/// one program's lanes would use alone: programs analysed side by side
/// (`programs::discover_all`) share the bound, so the decompiler workers'
/// memory does not grow with the number of programs in flight. Which lane
/// answers which function does not change an answer.
struct SwitchSlots {
    free: std::sync::Mutex<usize>,
    freed: std::sync::Condvar,
}

/// A slot held while one worker runs.
struct SwitchSlot(&'static SwitchSlots);

impl SwitchSlots {
    fn take() -> SwitchSlot {
        static SLOTS: std::sync::OnceLock<SwitchSlots> = std::sync::OnceLock::new();
        let slots = SLOTS.get_or_init(|| SwitchSlots {
            free: std::sync::Mutex::new(std::thread::available_parallelism().map_or(1, |n| n.get()).clamp(1, 8)),
            freed: std::sync::Condvar::new(),
        });
        let mut free = slots.free.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while *free == 0 {
            free = slots.freed.wait(free).unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        *free -= 1;
        SwitchSlot(slots)
    }
}

impl Drop for SwitchSlot {
    fn drop(&mut self) {
        *self.0.free.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
        self.0.freed.notify_one();
    }
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
    // A small program alone in its import: the decoders idle in the pool are
    // not used by the stage that follows (a scratch store and worker
    // processes), and the stage can use their memory.
    if crate::native_runtime::single_program() && super::discovery::lanes_for(imp) == 1 {
        crate::native_runtime::release_idle_decoders();
    }
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
            link_artifact(input_project, digest, &scratch.path)?;
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
    // The workers map the image this process holds; they do not each load
    // the input again. A failure here is not reported: the lane that needs
    // the snapshot falls back to the loader and says why it cannot.
    let snapshot_started = std::time::Instant::now();
    let _ = crate::inputs::snapshot_binding_of(&scratch.path, input, imp);
    super::tally::add("switch-snapshot", snapshot_started);
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
    phase(imp, "switch-setup", started);
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
                        // Waiting for a slot happens before the request's
                        // deadline starts, not inside it.
                        let _slot = SwitchSlots::take();
                        let outcome = (|| -> crate::Result<_> {
                            let opening = std::time::Instant::now();
                            let core = crate::Core::open_with_config(project, cfg.clone())?;
                            super::tally::add("switch-core-open", opening);
                            let request = core.execution_request(
                                binary,
                                program,
                                None,
                                std::time::Duration::from_secs(cfg.switch_wall_guard_secs).saturating_mul(
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
    phase(imp, "switch-lanes", lanes_started);
    let mut added = 0;
    let mut refused = crate::native_runtime::SwitchRecovery::default();
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
        refused.failures.extend(docs.failures.iter().cloned());
        refused.over_budget.extend(docs.over_budget.iter().cloned());
        refused.wall_clock.extend(docs.wall_clock.iter().cloned());
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
    // However many lanes answered, in whatever order, the notes read the same.
    report_refusals(imp, &mut refused);
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

/// Stores the tables value-set analysis answered and left to the decompiler
/// (`NativeImport::switch_deferred`) for the dispatches the decompiler did
/// not answer, and forgets the rest. Returns how many it stored.
pub(super) fn settle_deferred_tables(imp: &mut NativeImport) -> usize {
    let deferred = std::mem::take(&mut imp.switch_deferred);
    let mut stored = 0;
    for (branch, targets) in deferred {
        if imp.switch_tables.contains_key(&branch) {
            continue;
        }
        for &target in &targets {
            imp.xrefs.push(NativeXref::with_provenance(branch, target, "COMPUTED_JUMP", SWITCH_PROVENANCE));
        }
        imp.switch_tables.insert(branch, targets);
        stored += 1;
    }
    if stored > 0 {
        demote_case_blocks(imp);
    }
    stored
}

/// What names a function entry other than a switch table's own words, for
/// the entries a table's cases made: the same evidence `demote_case_blocks`
/// reads (a call, or a data reference that is not a word of the table), taken
/// before the table is stored.
struct CaseLabels {
    /// Targets of call references.
    called: std::collections::HashSet<u64>,
    /// Data references: the word that holds an address, and the address.
    data: std::collections::HashMap<u64, u64>,
    /// For an address, the words that hold it.
    held_by: std::collections::HashMap<u64, Vec<u64>>,
    /// Entries of functions the analysis named (`FUN_`), the only ones a
    /// case label can be.
    anonymous: std::collections::HashSet<u64>,
}

impl CaseLabels {
    fn new(imp: &NativeImport) -> Self {
        let mut called = std::collections::HashSet::new();
        let mut data = std::collections::HashMap::new();
        let mut held_by: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
        for xref in &imp.xrefs {
            if xref.kind.ends_with("CALL") {
                called.insert(xref.to);
            } else if xref.kind == "DATA" {
                data.insert(xref.from, xref.to);
                held_by.entry(xref.to).or_default().push(xref.from);
            }
        }
        let anonymous = imp
            .functions
            .iter()
            .filter(|function| function.name.starts_with("FUN_"))
            .map(|function| function.entry)
            .collect();
        Self { called, data, held_by, anonymous }
    }

    /// The entries among `cases` (sorted) that are functions only because
    /// the table's words name them: anonymous, never called, and held only by
    /// words next to another word of the same table.
    fn unevidenced(&self, cases: &[u64]) -> std::collections::HashSet<u64> {
        let table_word = |word: u64| {
            [4u64, 8].iter().any(|stride| {
                [word.wrapping_sub(*stride), word.wrapping_add(*stride)]
                    .iter()
                    .any(|neighbour| self.data.get(neighbour).is_some_and(|other| cases.binary_search(other).is_ok()))
            })
        };
        cases
            .iter()
            .copied()
            .filter(|case| {
                self.anonymous.contains(case)
                    && !self.called.contains(case)
                    && self.held_by.get(case).is_none_or(|words| words.iter().all(|&word| table_word(word)))
            })
            .collect()
    }
}

/// Ghidra recovers a jump's table at `CODE_ANALYSIS`, before the pattern
/// analyzer's delayed creator runs at `DATA_ANALYSIS.after()` and finds the
/// case block already inside a function (`PossibleDelayedFunctionCreator`,
/// 1001-1012). Here the patterns ran a round earlier, so a function whose
/// only evidence is a pattern match at a case target is withdrawn; the next
/// walk gives the block to the function that jumps to it. A target anything
/// calls or points at keeps its function.
pub(super) fn demote_case_blocks(imp: &mut NativeImport) {
    demote_case_blocks_among(imp, None);
}

/// `demote_case_blocks`, sparing the entries in `spared` when given.
pub(super) fn demote_case_blocks_among(imp: &mut NativeImport, spared: Option<&std::collections::HashSet<u64>>) {
    let mut targets: std::collections::HashSet<u64> = imp
        .switch_tables
        .values()
        .flat_map(|targets| targets.iter().copied())
        .collect();
    // The guard's default is no table entry -- the guard's own branch goes
    // there, not the indirect one -- but it is a block of the dispatching
    // function all the same, and a pattern match there is no function
    // either (dungeon_game 0x11b3a8, `beqz v1,default` before the dispatch
    // at 0x11b2e0 in `FirstPersonCamera::move`).
    targets.extend(guard_defaults(imp));
    // A word of the jump table itself is no evidence for its own case label:
    // the ELF pointer scan reads a table in `.rodata` as code pointers
    // (dungeon_game: 163 case labels "pointed at" that way). A table word is
    // one whose neighbour names a case target of the same switch.
    let data: std::collections::HashMap<u64, u64> = imp
        .xrefs
        .iter()
        .filter(|xref| xref.kind == "DATA")
        .map(|xref| (xref.from, xref.to))
        .collect();
    let table_word = |from: u64, to: u64| {
        imp.switch_tables.values().any(|cases| {
            cases.contains(&to)
                && [from.wrapping_sub(4), from + 4]
                    .iter()
                    .any(|neighbour| data.get(neighbour).is_some_and(|other| cases.contains(other)))
        })
    };
    let evidenced: std::collections::HashSet<u64> = imp
        .xrefs
        .iter()
        .filter(|xref| {
            xref.kind.ends_with("CALL")
                || (xref.kind == "DATA" && !(targets.contains(&xref.to) && table_word(xref.from, xref.to)))
        })
        .map(|xref| xref.to)
        .collect();
    imp.functions.retain(|function| {
        !(targets.contains(&function.entry)
            && spared.is_none_or(|spared| !spared.contains(&function.entry))
            && function.name.starts_with("FUN_")
            && !evidenced.contains(&function.entry))
    });
}

/// Where each recorded switch's guard sends an out-of-range index: the
/// taken targets of the conditional branches in the blocks `switch_lines`
/// reads as the dispatch's guard.
fn guard_defaults(imp: &NativeImport) -> Vec<u64> {
    let owners: Vec<(u64, u64, u64)> = imp
        .switch_tables
        .keys()
        .filter_map(|&branch| {
            imp.functions
                .iter()
                .find(|function| function.size > 1 && function.entry <= branch && branch < function.entry + function.size)
                .map(|function| (branch, function.entry, function.entry + function.size))
        })
        .collect();
    let mut ranges: Vec<(u64, u64)> = owners.iter().map(|&(_, entry, end)| (entry, end)).collect();
    ranges.sort_unstable();
    ranges.dedup();
    let shapes = FlowShapeIndex::within(&imp.flow_shapes, &ranges);
    let mut defaults = Vec::new();
    for &(branch, entry, end) in &owners {
        let function_shapes = shapes.range(entry, end);
        let (_, guard, _) = switch_lines(function_shapes, branch, entry, end);
        for address in guard.iter().flatten() {
            defaults.extend(
                function_shapes
                    .iter()
                    .filter(|shape| {
                        shape.address == *address && shape.kind == crate::native_runtime::FlowKind::CBranch
                    })
                    .filter_map(|shape| shape.target),
            );
        }
    }
    defaults
}

#[cfg(test)]
mod scratch_tests {
    use super::*;

    /// God Hand 0x1627d8: the cases of the dispatch are functions the walk
    /// made from the words of the table; the ones something calls or points
    /// at otherwise, and the ones the image names, are not case labels.
    #[test]
    fn a_table_left_to_the_decompiler_is_stored_only_for_a_branch_it_did_not_answer() {
        let mut imp = NativeImport::default();
        imp.switch_deferred.insert(0x1000, vec![0x1010, 0x1020]);
        imp.switch_deferred.insert(0x2000, vec![0x2010, 0x2020]);
        // The decompiler answered 0x2000 with a different table.
        imp.switch_tables.insert(0x2000, vec![0x2010, 0x2030]);
        assert_eq!(settle_deferred_tables(&mut imp), 1);
        assert_eq!(imp.switch_tables[&0x1000], [0x1010, 0x1020]);
        assert_eq!(imp.switch_tables[&0x2000], [0x2010, 0x2030]);
        assert!(imp.switch_deferred.is_empty());
        let stored: Vec<(u64, u64)> =
            imp.xrefs.iter().filter(|xref| xref.kind == "COMPUTED_JUMP").map(|xref| (xref.from, xref.to)).collect();
        assert_eq!(stored, [(0x1000, 0x1010), (0x1000, 0x1020)]);
        assert_eq!(settle_deferred_tables(&mut imp), 0);
    }

    #[test]
    fn only_functions_the_tables_own_words_made_are_case_labels() {
        let function = |entry: u64, name: &str| NativeFunction { entry, size: 8, name: name.into() };
        let mut imp = NativeImport {
            functions: vec![
                function(0x1000, "FUN_00001000"),
                function(0x1020, "FUN_00001020"),
                function(0x1040, "FUN_00001040"),
                function(0x1060, "FUN_00001060"),
                function(0x1080, "named_handler"),
                function(0x10a0, "FUN_000010a0"),
            ],
            ..Default::default()
        };
        // A table of six words at 0x4000.
        for (word, case) in [0x1000u64, 0x1020, 0x1040, 0x1060, 0x1080, 0x10a0].into_iter().enumerate() {
            imp.xrefs.push(NativeXref::new(0x4000 + 4 * word as u64, case, "DATA"));
        }
        // 0x1040 is also called, 0x1060 is also taken from a word that sits
        // beside no other word of the table.
        imp.xrefs.push(NativeXref::new(0x2000, 0x1040, "UNCONDITIONAL_CALL"));
        imp.xrefs.push(NativeXref::new(0x9000, 0x1060, "DATA"));
        let cases = [0x1000, 0x1020, 0x1040, 0x1060, 0x1080, 0x10a0];
        let mut labels: Vec<u64> = CaseLabels::new(&imp).unevidenced(&cases).into_iter().collect();
        labels.sort_unstable();
        assert_eq!(labels, [0x1000, 0x1020, 0x10a0]);
    }

    fn fresh(name: &str) -> std::path::PathBuf {
        let root = std::env::home_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join(".cache/romwright/test-scratch")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// Whether the import can be reused is decided by whether the host
    /// decided the answer: a function over the work budget is a note, one the
    /// wall-clock guard killed is not.
    #[test]
    fn only_a_wall_clock_kill_makes_the_import_unreusable() {
        use crate::native_runtime::SwitchRecovery;
        let mut refused = SwitchRecovery {
            over_budget: vec!["0x1000: decompiler exception: WorkBudgetExceeded: over".into()],
            failures: vec!["0x1010: decompiler exception: Low-level Error: no data".into()],
            ..Default::default()
        };
        let mut imp = NativeImport::default();
        report_refusals(&mut imp, &mut refused);
        assert!(!imp.degraded(), "{:?}", imp.diagnostics);
        assert_eq!(imp.diagnostics.len(), 2);
        assert!(
            imp.diagnostics.iter().any(|diagnostic| diagnostic.message.contains("WorkBudgetExceeded")
                && diagnostic.message.contains("budget 75000000 units")),
            "{:?}",
            imp.diagnostics
        );

        let mut killed = SwitchRecovery {
            wall_clock: vec!["0x1020: decompiler timed out after 900s".into()],
            ..Default::default()
        };
        report_refusals(&mut imp, &mut killed);
        assert!(imp.degraded(), "{:?}", imp.diagnostics);
    }

    /// Lane counts differ between hosts and lanes finish in any order; the
    /// notes an import carries must not.
    #[test]
    fn refusal_notes_are_ordered_by_address_whichever_lane_answered_first() {
        use crate::native_runtime::SwitchRecovery;
        let mut refused = SwitchRecovery {
            failures: vec!["0x20a0: b".into(), "0x9: c".into(), "0x1000: a".into()],
            ..Default::default()
        };
        let mut imp = NativeImport::default();
        report_refusals(&mut imp, &mut refused);
        let order: Vec<&str> = imp.diagnostics.iter().map(|diagnostic| diagnostic.message.as_str()).collect();
        assert_eq!(order, ["0x9: c", "0x1000: a", "0x20a0: b"]);
    }

    #[test]
    fn the_input_artifact_is_linked_into_the_scratch_store_not_copied() {
        let root = fresh("link");
        let digest = "ab".repeat(32);
        let project = root.join("project");
        std::fs::create_dir_all(project.join("artifacts")).unwrap();
        std::fs::write(project.join("artifacts").join(&digest), vec![7u8; 1 << 20]).unwrap();
        let scratch = root.join("scratch");
        link_artifact(&project, &digest, &scratch).unwrap();
        // Twice is the same answer: every lane's round links the same input.
        link_artifact(&project, &digest, &scratch).unwrap();
        let linked = scratch.join("artifacts").join(&digest);
        assert_eq!(std::fs::read(&linked).unwrap().len(), 1 << 20);
        let symlink = std::fs::symlink_metadata(&linked).unwrap().file_type().is_symlink();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let original = std::fs::metadata(project.join("artifacts").join(&digest)).unwrap();
            assert!(symlink || std::fs::metadata(&linked).unwrap().ino() == original.ino(), "a copy, not a link");
        }
        assert!(link_artifact(&project, "../escape", &scratch).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Programs analysed side by side ask for scratch directories in the same
    /// instant; each must get its own, or two stores would share one database.
    #[test]
    fn scratch_directories_made_at_once_are_distinct() {
        let made: Vec<ScratchDir> = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| (0..16).filter_map(|_| ScratchDir::new("romwright-switch-concurrent")).collect::<Vec<_>>()))
                .collect();
            threads.into_iter().flat_map(|thread| thread.join().unwrap()).collect()
        });
        let paths: std::collections::HashSet<_> = made.iter().map(|scratch| scratch.path.clone()).collect();
        assert_eq!((made.len(), paths.len()), (64, 64));
    }

    #[test]
    fn scratch_of_a_dead_process_is_removed_and_a_live_ones_is_not() {
        let root = fresh("dead");
        // No process has this id: it exceeds the kernel's pid limit.
        let dead = root.join("romwright-switch-4294967295-1");
        let live = root.join(format!("romwright-switch-{}-1", std::process::id()));
        let other = root.join("romwright-input-4294967295-1");
        let unrelated = root.join("keep-me");
        for dir in [&dead, &live, &other, &unrelated] {
            std::fs::create_dir_all(dir).unwrap();
        }
        remove_dead_scratch(&root, "romwright-switch");
        if std::path::Path::new("/proc/self").exists() {
            assert!(!dead.exists());
        }
        assert!(live.exists() && other.exists() && unrelated.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
