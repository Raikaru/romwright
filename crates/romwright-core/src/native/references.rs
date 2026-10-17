use super::*;

/// The address width the language id declares (`ARM:LE:32:v5t`), which is
/// the width a stack offset travels in.
fn language_pointer_bits(language: &str) -> u32 {
    language
        .split(':')
        .nth(2)
        .and_then(|bits| bits.parse().ok())
        .unwrap_or(64)
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    if bits == 0 || bits >= 64 {
        return value as i64;
    }
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// Ghidra's stack analyzer, from the accesses one function makes through
/// its stack pointer (`NewFunctionStackAnalysisCmd`): an offset outside
/// `[-64K, 2048]` is refused (`defineFuncVariable`), every referenced slot
/// becomes a variable sized by its access, overlapping slots merge into one
/// spanning them all (`accumulateVariable`), and -- with the analyzer's
/// default of creating locals but not parameters -- only offsets below the
/// parameter area become variables. The name is
/// `SymbolUtilities.getDefaultLocalName`: `local_` and the offset's
/// magnitude in hex; the type is `undefined<size>`.
pub(super) fn stack_frame(function: u64, accesses: &[(i64, u32)]) -> Vec<romwright_model::StackVariableRow> {
    // A local ends at or below the parameter boundary: an access that
    // straddles it (4 bytes at -1, nine of them on kotor2sub's i386 slice)
    // is refused. Kept, it names bytes past the top of a 32-bit stack space,
    // and the decompiler refuses to register the program ("Symbol local_1
    // extends beyond the end of the address space"), so nothing decompiles.
    let mut slots: Vec<(i64, i64)> = accesses
        .iter()
        .filter(|&&(offset, size)| {
            size > 0
                && (-(64 * 1024)..=2048).contains(&offset)
                && offset < 0
                && offset + i64::from(size) <= 0
        })
        .map(|&(offset, size)| (offset, offset + size as i64))
        .collect();
    slots.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::new();
    for (start, end) in slots {
        match merged.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
        .into_iter()
        .enumerate()
        .map(|(ordinal, (start, end))| {
            let size = (end - start) as u64;
            romwright_model::StackVariableRow {
                function: romwright_model::Address::ram(function),
                ordinal: ordinal as u32,
                name: format!("local_{:x}", -start),
                storage: format!("Stack[-0x{:x}]:{size}", -start),
                type_name: Some(format!("undefined{size}")),
                offset: Some(start),
                size: Some(size),
            }
        })
        .collect()
}

/// Digest of everything a reference round reads besides a function's own
/// bytes: the loader's register contexts, the call register, imported
/// slots, decode contexts, and the call fixups installed for
/// pattern-labelled functions that exist this round.
/// Decode contexts by name, ordered by address, for asking which of them a
/// range decodes under. A console context holds from its address to the
/// next one of the same name, and a later one at the same address replaces
/// an earlier one, as the console applies them in order.
struct ContextPoints {
    by_name: Vec<(String, Vec<(u64, u64)>)>,
    /// The dispatch tables the import stored, by branch address with a digest
    /// of the targets: a range's flow follows them.
    tables: Vec<(u64, u64)>,
}

impl ContextPoints {
    fn new(contexts: &[NativeContext], tables: &std::collections::HashMap<u64, Vec<u64>>) -> Self {
        use std::hash::{Hash, Hasher};
        let mut by_name: std::collections::BTreeMap<&str, Vec<(u64, u64)>> = std::collections::BTreeMap::new();
        for context in contexts {
            by_name.entry(&context.name).or_default().push((context.address, context.value));
        }
        let mut tables: Vec<(u64, u64)> = tables
            .iter()
            .map(|(branch, targets)| {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                targets.hash(&mut hasher);
                (*branch, hasher.finish())
            })
            .collect();
        tables.sort_unstable();
        Self {
            by_name: by_name
                .into_iter()
                .map(|(name, mut points)| {
                    points.sort_by_key(|&(address, _)| address);
                    (name.to_string(), points)
                })
                .collect(),
            tables,
        }
    }

    /// Digest of what `[start, end)` decodes under: each context's value in
    /// force at `start`, and every point inside the range, and the dispatch
    /// tables of the branches inside it.
    fn covering(&self, start: u64, end: u64) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for (name, points) in &self.by_name {
            let at = points.partition_point(|&(address, _)| address <= start);
            let inside = points.partition_point(|&(address, _)| address < end);
            name.hash(&mut hasher);
            at.checked_sub(1).map(|index| points[index].1).hash(&mut hasher);
            points[at..inside.max(at)].hash(&mut hasher);
        }
        let first = self.tables.partition_point(|&(branch, _)| branch < start);
        let last = self.tables.partition_point(|&(branch, _)| branch < end);
        self.tables[first..last.max(first)].hash(&mut hasher);
        hasher.finish()
    }
}

fn reference_inputs_digest(import: &NativeImport, labels: &[(u64, String)]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for context in &import.register_contexts {
        (context.start, context.end, &context.register, context.value).hash(&mut hasher);
    }
    import.reference_call_register.hash(&mut hasher);
    for (slot, name) in &import.externals {
        (slot, name).hash(&mut hasher);
    }
    let sized: std::collections::HashSet<u64> = import
        .functions
        .iter()
        .filter(|function| function.size > 1)
        .map(|function| function.entry)
        .collect();
    for (address, label) in labels {
        if sized.contains(address) {
            (address, label).hash(&mut hasher);
        }
    }
    hasher.finish()
}

/// The reference pass: in-process propagation lanes, one per hardware thread.
/// The round's context is fixed while its queries run; what callers show of a
/// call target's register is merged after the round and adopted, sorted.
pub(super) fn infer_data_references(import: &mut NativeImport) -> Result<()> {
    if std::env::var_os("ROMWRIGHT_TRACE_BRANCHIND").is_some() {
        let first = import.mappings.iter().map(|m| m.vaddr).min().unwrap_or(0);
        let bytes: u64 = import.mappings.iter().map(|m| m.size).sum();
        eprintln!("REFPASS {} prog={first:#x}+{bytes:#x} functions={} tables={}", import.language, import.functions.len(), import.switch_tables.len());
    }
    let lane_target = super::discovery::lanes_for(import);
    let mut lanes = crate::native_runtime::open_reference_lanes(import, lane_target);
    if lanes.is_empty() {
        return Err(ImportError::Bad("reference context: no propagation lane started".into()));
    }
    let mut context = crate::native_runtime::ReferenceContext::new(import, &lanes[0]);
    let functions = import
        .functions
        .iter()
        .filter(|function| function.size > 1)
        .map(|function| {
            function
                .entry
                .checked_add(function.size)
                .map(|end| (function.entry, end))
                .ok_or_else(|| ImportError::Bad("reference function range overflows".into()))
        });
    let roots = import
        .reference_roots
        .iter()
        .filter(|&&(start, _)| {
            !import
                .functions
                .iter()
                .any(|function| function.entry == start && function.size > 1)
        })
        .copied();
    // Ranges a lane could not answer. Counted, not hidden.
    let refused = std::sync::atomic::AtomicU64::new(0);
    let mut work = functions
        .map(|range| range.map(|(start, end)| (start, end, Vec::new(), true)))
        .collect::<Result<Vec<_>>>()?;
    let function_count = work.len();
    for (start, end) in roots {
        work.push((start, end, Vec::new(), true));
    }
    // Rounds re-infer every function, but a function whose range and
    // round-level inputs are unchanged gets the same facts (measured on
    // swkotor2: 29,604 repeated ranges over three rounds, every one
    // identical; the same on a PowerPC game module, mipsel and PE64 corpus
    // images). So those ranges reuse the last round's facts, and only when
    // the inputs a range's propagation reads are the same: register
    // contexts, the call register, external slots and the call fixups this
    // round installs, for the whole round; and the decode contexts and
    // stored dispatch tables covering the range itself. Every round adds
    // mode contexts on ARM (GBA: 33,635 then 49,035), and made the whole
    // memo stale when they were part of the round digest.
    let inputs = reference_inputs_digest(import, &import.pattern_labels);
    let reusable = import.reference_memo_inputs == Some(inputs);
    let modes = ContextPoints::new(&import.contexts, &import.switch_tables);
    let mut pending: Vec<usize> = Vec::with_capacity(work.len());
    for index in 0..work.len() {
        let key = (work[index].0, work[index].1);
        let covering = modes.covering(key.0, key.1);
        match import
            .reference_memo
            .get(&key)
            .filter(|(digest, _)| reusable && index < function_count && *digest == covering)
            .map(|(_, facts)| facts)
        {
            Some(facts) => {
                work[index].2 = facts.clone();
                work[index].3 = false;
            }
            None => pending.push(index),
        }
    }
    let mut adopted_any = false;
    let mut jumps = JumpReport::default();
    loop {
        let batch = std::mem::take(&mut pending);
        for &index in &batch {
            work[index].3 = false;
        }
        let mut ranges: Vec<(usize, u64, u64)> = batch.iter().map(|&index| (index, work[index].0, work[index].1)).collect();
        ranges.sort_by_key(|&(index, start, end)| (std::cmp::Reverse(end - start), index));
        let used = lanes.len().min(ranges.len().max(1));
        // Function cost varies by orders of magnitude, so lanes claim the
        // next range instead of taking a fixed stride: one huge function must
        // not decide the round's wall time.
        let cursor = std::sync::atomic::AtomicUsize::new(0);
        type Found = (usize, Vec<crate::native_runtime::ReferenceFact>);
        let outcome: Vec<(Vec<Found>, Vec<(u64, u64)>, JumpReport)> = {
            let (context, import, ranges, cursor, refused) = (&context, &*import, &ranges, &cursor, &refused);
            std::thread::scope(|scope| {
                let handles: Vec<_> = lanes
                    .iter_mut()
                    .take(used)
                    .map(|lane| {
                        scope.spawn(move || {
                            let mut found: Vec<Found> = Vec::new();
                            let mut contexts: Vec<(u64, u64)> = Vec::new();
                            let mut jumps = JumpReport::default();
                            loop {
                                let next = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let Some(&(index, start, end)) = ranges.get(next) else { break };
                                match context.query(lane, import, start, end) {
                                    Ok(Some(answer)) => {
                                        found.push((index, answer.facts));
                                        contexts.extend(answer.contexts);
                                        jumps.take(answer.truncated, answer.recovered, answer.refused);
                                    }
                                    Ok(None) => {}
                                    // One range a lane cannot answer costs that
                                    // range's references, never the image.
                                    Err(_) => {
                                        refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                            }
                            (found, contexts, jumps)
                        })
                    })
                    .collect();
                handles.into_iter().map(|handle| handle.join().unwrap_or_default()).collect()
            })
        };
        let mut discovered: Vec<(u64, u64)> = Vec::new();
        for (found, contexts, report) in outcome {
            jumps.merge(report);
            for (index, facts) in found {
                let known = &mut work[index].2;
                if known.is_empty() {
                    *known = facts;
                } else {
                    known.extend(facts);
                    known.sort_unstable_by_key(|fact| (fact.from, fact.to, fact.kind as u8));
                    known.dedup();
                }
            }
            discovered.extend(contexts);
        }
        // Finish local evidence before applying this round's call context.
        let mut targets = context.adopt(discovered);
        adopted_any |= !targets.is_empty();
        targets.sort_unstable();
        targets.dedup();
        for target in targets {
            if let Some(next) = work.iter().position(|item| item.0 == target) {
                if !work[next].3 {
                    work[next].3 = true;
                    pending.push(next);
                }
            }
        }
        if pending.is_empty() {
            break;
        }
    }
    // The lanes have answered every range; the decoders they hold are free for
    // what follows (a lifter for the propagated linkages) instead of both
    // being alive.
    drop(lanes);
    finish_references(import, work, function_count, &refused, adopted_any, inputs, &modes)?;
    // After the facts: demoting a case block may remove a function this
    // pass framed, which the next round's pass rebuilds anyway.
    settle_jumps(import, jumps);
    Ok(())
}

/// What the reference flow made of the indirect jumps no table was stored
/// for, over one pass: the jumps it turned into calls (with the shape of the
/// computation that makes their target), the tables it recovered itself, and
/// the jumps it asked the recovery about and was refused.
#[derive(Default)]
struct JumpReport {
    truncated: Vec<(u64, crate::native_runtime::JumpShape)>,
    recovered: Vec<(u64, crate::native_runtime::JumpShape, Vec<u64>)>,
    refused: Vec<(u64, crate::native_runtime::JumpShape, crate::native_runtime::Refusal)>,
}

impl JumpReport {
    fn take(
        &mut self,
        truncated: Vec<(u64, crate::native_runtime::JumpShape)>,
        recovered: Vec<(u64, crate::native_runtime::JumpShape, Vec<u64>)>,
        refused: Vec<(u64, crate::native_runtime::JumpShape, crate::native_runtime::Refusal)>,
    ) {
        self.truncated.extend(truncated);
        self.recovered.extend(recovered);
        self.refused.extend(refused);
    }

    fn merge(&mut self, other: JumpReport) {
        self.take(other.truncated, other.recovered, other.refused);
    }
}

/// Keeps what the pass learned of indirect jumps: the tables the flow
/// recovered are stored as the switch stage stores its own (a table, and a
/// `COMPUTED_JUMP` reference from the branch to each case), so the walk
/// follows the cases and later rounds start from them; the jumps that
/// compute their target from an index and stayed calls are asked of the
/// switch stage of this round, whether or not the walk listed them.
fn settle_jumps(import: &mut NativeImport, mut report: JumpReport) {
    use crate::native_runtime::JumpShape;
    report.truncated.sort_unstable_by_key(|&(branch, shape)| (branch, shape as u8));
    report.truncated.dedup();
    report.recovered.sort_unstable_by(|left, right| (left.0, &left.2).cmp(&(right.0, &right.2)));
    report.recovered.dedup_by_key(|entry| entry.0);
    report.refused.sort_unstable_by_key(|&(branch, shape, reason)| (branch, shape as u8, format!("{reason:?}")));
    report.refused.dedup();
    if std::env::var_os("ROMWRIGHT_TRACE_BRANCHIND").is_some() {
        let known: std::collections::HashSet<u64> = import.indirect_jumps.iter().copied().collect();
        let count = |shape: JumpShape| report.truncated.iter().filter(|&&(_, s)| s == shape).count();
        let missing = report.truncated.iter().filter(|(branch, _)| !known.contains(branch)).count();
        eprintln!(
            "REFSTAT truncated={} island={} table_load={} pointer={} not_in_indirect_jumps={missing} recovered={} refused={}",
            report.truncated.len(),
            count(JumpShape::Island),
            count(JumpShape::TableLoad),
            count(JumpShape::Pointer),
            report.recovered.len(),
            report.refused.len(),
        );
    }
    let mut reaching_new = 0;
    let mut stored = 0;
    for (branch, _, targets) in &report.recovered {
        if import.switch_tables.contains_key(branch) {
            continue;
        }
        for &target in targets {
            import.xrefs.push(NativeXref::with_provenance(*branch, target, "COMPUTED_JUMP", SWITCH_PROVENANCE));
        }
        // A table whose every case the walk already decoded changes no body;
        // only one reaching bytes nothing read is a reason to walk again.
        let reaches_new = targets.iter().any(|&target| {
            let index = import.decoded_ranges.partition_point(|&(start, _)| start <= target);
            !index.checked_sub(1).is_some_and(|i| target < import.decoded_ranges[i].1)
        });
        import.switch_tables.insert(*branch, targets.clone());
        stored += 1;
        reaching_new += usize::from(reaches_new);
    }
    import.reference_tables_added = reaching_new;
    if stored > 0 {
        switch_tables::demote_case_blocks(import);
    }
    // The walk lists the indirect jumps it decoded; the flow of this pass met
    // others (a body the walk had not reached, or decoded in another mode).
    // The recovery bounded the index of some of them and could not finish:
    // the table leaves the traced range, is a single case, did not hold over
    // the flow it opened, or a computed jump found no table to read. Those
    // are the switch stage's to answer (value-set analysis with its facts,
    // then the decompiler), whether or not the walk listed them. A jump with
    // nothing that bounds the index (a function pointer loaded from an array
    // is the common one: about 2,400 of them on pokeemerald, which the decompiler
    // refuses in turn and which would crowd the owner budget) and one handed
    // a pointer are calls, not dispatches.
    if import.cfg.branchind_candidates {
        use crate::native_runtime::Refusal;
        let asked: Vec<u64> = report
            .refused
            .iter()
            .filter(|&&(_, shape, reason)| {
                shape != JumpShape::Pointer
                    && matches!(reason, Refusal::Outside | Refusal::TooFewTargets | Refusal::Unstable | Refusal::NoStridedLoad)
            })
            .map(|&(branch, _, _)| branch)
            .filter(|branch| !import.switch_tables.contains_key(branch))
            .collect();
        if std::env::var_os("ROMWRIGHT_TRACE_BRANCHIND").is_some() {
            let known: std::collections::HashSet<u64> = import.indirect_jumps.iter().copied().collect();
            for &(branch, shape, reason) in &report.refused {
                if asked.contains(&branch) && !known.contains(&branch) {
                    eprintln!("CANDIDATE {branch:#x} {shape:?} {reason:?}");
                }
            }
        }
        let before = import.indirect_jumps.len();
        import.indirect_jumps.extend(asked);
        if import.indirect_jumps.len() != before {
            import.indirect_jumps.sort_unstable();
            import.indirect_jumps.dedup();
        }
    }
}

/// What a pass keeps of its facts: the memo for the next round, the linkage
/// thunks propagated caller context resolves, the stack frames, the access
/// widths and the references themselves.
#[allow(clippy::too_many_arguments)]
fn finish_references(
    import: &mut NativeImport,
    work: Vec<(u64, u64, Vec<crate::native_runtime::ReferenceFact>, bool)>,
    function_count: usize,
    refused: &std::sync::atomic::AtomicU64,
    adopted_any: bool,
    inputs: u64,
    modes: &ContextPoints,
) -> Result<()> {
    use crate::native_runtime::ReferenceKind;
    // Keep this round's facts for the next one only when nothing was
    // adopted mid-pass: a reused range is not re-queried, so it cannot
    // re-discover a caller context the next round's fresh console would
    // otherwise adopt from it.
    if adopted_any {
        import.reference_memo.clear();
        import.reference_memo_inputs = None;
    } else {
        import.reference_memo = work
            .iter()
            .take(function_count)
            .map(|(start, end, facts, _)| ((*start, *end), (modes.covering(*start, *end), facts.clone())))
            .collect();
        import.reference_memo_inputs = Some(inputs);
    }
    // Propagated caller context can resolve a linkage whose base register was
    // unknown during discovery. Require the existing pure-linkage proof and
    // one consistent imported read slot within that exact instruction extent.
    let imported: std::collections::HashMap<_, _> = import
        .externals
        .iter()
        .filter(|(address, _)| *address != 0)
        .map(|(address, name)| (*address, name.as_str()))
        .collect();
    let candidates: Vec<_> = work[..function_count]
        .iter()
        .enumerate()
        .filter(|(_, (start, _, facts, _))| {
            !imported.contains_key(start)
                && facts
                    .iter()
                    .any(|fact| fact.kind == ReferenceKind::Read && imported.contains_key(&fact.to))
        })
        .map(|(index, _)| index)
        .collect();
    let mut linked = Vec::new();
    let mut thunked: Vec<NativeThunk> = Vec::new();
    let addresses: Vec<u64> = candidates.iter().map(|&index| work[index].0).collect();
    let all_shapes = if addresses.is_empty() {
        Vec::new()
    } else {
        crate::native_runtime::SleighLifter::mapped_pooled(&import.cfg, import)
            .map(|mut lifter| lifter.linkages(&addresses, false))
            .map_err(|error| ImportError::Bad(format!("propagated linkage: {error}")))?
    };
    for (chunk, shapes) in candidates.chunks(1024).zip(all_shapes.chunks(1024)) {
        for (&index, shape) in chunk.iter().zip(shapes) {
            let (start, end, facts, _) = &work[index];
            let Some(limit) = start
                .checked_add(shape.length as u64)
                .filter(|limit| shape.length != 0 && *limit <= *end)
            else {
                continue;
            };
            let mut slot = None;
            let mut consistent = true;
            for fact in facts.iter().filter(|fact| {
                fact.kind == ReferenceKind::Read && *start <= fact.from && fact.from < limit
            }) {
                if !imported.contains_key(&fact.to)
                    || slot.is_some_and(|previous| previous != fact.to)
                    || shape.slot.is_some_and(|resolved| resolved != fact.to)
                {
                    consistent = false;
                    break;
                }
                slot = Some(fact.to);
            }
            if consistent
                && let Some((slot, name)) = slot.zip(slot.and_then(|slot| imported.get(&slot)))
            {
                linked.push((*start, (*name).to_owned()));
                // The slot that names this stub is the destination it reaches,
                // so the stub is a linkage thunk. Stock Ghidra converts the
                // function it already created (CreateThunkFunctionCmd); the
                // slot is the address the stub's own instructions read.
                if !import.thunks.iter().any(|thunk| thunk.entry == *start) {
                    thunked.push(NativeThunk {
                        entry: *start,
                        destination: slot,
                        kind: romwright_model::ThunkKind::Linkage,
                        source: crate::native::THUNK_SOURCE,
                    });
                }
            }
        }
    }
    import.externals.extend(linked);
    import.thunks.extend(thunked);
    // Context adds precise accesses; existing speculative DATA remains evidence.
    // Publish no partial pass if any query fails.
    let pointer_bits = language_pointer_bits(&import.language);
    // A pass covers every function, and a later round covers them again with
    // more of the image known: the frames, the references and the access
    // widths are this pass's, not a sum. A fact an earlier round laid down on
    // a flow that was cut short (a dispatch whose table was not stored yet
    // reads as a call there) must not outlive the round that knows better.
    import.stack_variables.clear();
    import.xrefs.retain(|xref| xref.provenance != "native-analysis:constant-propagation");
    import.reference_widths.clear();
    let mut width_index: std::collections::HashMap<u64, usize> =
        std::collections::HashMap::with_capacity(import.reference_widths.len());
    for (index, &(address, _)) in import.reference_widths.iter().enumerate() {
        width_index.entry(address).or_insert(index);
    }
    for (index, (start, _, facts, _)) in work.into_iter().enumerate() {
        // The frame this function's own accesses describe. Roots that are
        // not functions carry no frame.
        if index < function_count {
            let accesses: Vec<(i64, u32)> = facts
                .iter()
                .filter(|fact| fact.kind == ReferenceKind::Stack)
                .map(|fact| (sign_extend(fact.to, pointer_bits), fact.size))
                .collect();
            import.stack_variables.extend(stack_frame(start, &accesses));
        }
        let facts: Vec<crate::native_runtime::ReferenceFact> = facts
            .into_iter()
            .filter(|fact| fact.kind != ReferenceKind::Stack)
            .collect();
        // The width of an access is a fact about the location, not about the
        // instruction: stock defines data of the access size at every
        // referenced location, which is what keeps a wider read from
        // overlapping a one-byte symbol.
        for fact in &facts {
            if fact.size == 0
                || fact.size > 8
                || matches!(
                    fact.kind,
                    ReferenceKind::Data | ReferenceKind::ComputedCall | ReferenceKind::ComputedJump
                )
            {
                continue;
            }
            // `find` over the list was 99% of this function's own CPU on GBA
            // (47k locations, scanned per fact); the index answers the same
            // first entry.
            match width_index.entry(fact.to) {
                std::collections::hash_map::Entry::Occupied(slot) => {
                    let width = &mut import.reference_widths[*slot.get()].1;
                    *width = (*width).max(fact.size as u64);
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(import.reference_widths.len());
                    import.reference_widths.push((fact.to, fact.size as u64));
                }
            }
        }
        if low_bit_code_mode(&import.language) {
            for fact in &facts {
                if fact.kind == ReferenceKind::ComputedCall && fact.to & 1 != 0 {
                    import.computed_mode_targets.push(fact.to & !1);
                }
            }
        }
        let mode = low_bit_code_mode(&import.language);
        import.xrefs.extend(facts.into_iter().map(|fact| {
            // The reference lands where the flow does; on a language that
            // carries the instruction-set mode in the low bit, that bit is a
            // mode, not part of the address, and the mode is recorded
            // separately (`computed_mode_targets`).
            let aligned = if mode { fact.to & !1 } else { fact.to };
            let (kind, to) = match fact.kind {
                ReferenceKind::Read => ("READ", fact.to),
                ReferenceKind::Write => ("WRITE", fact.to),
                ReferenceKind::ReadWrite => ("READ_WRITE", fact.to),
                ReferenceKind::Data => ("DATA", fact.to),
                ReferenceKind::ComputedCall => ("COMPUTED_CALL", aligned),
                ReferenceKind::ComputedJump => ("COMPUTED_JUMP", aligned),
                ReferenceKind::Stack => unreachable!("stack facts were taken out above"),
            };
            NativeXref::with_provenance(fact.from, to, kind, "native-analysis:constant-propagation")
        }));
    }
    import.references_refused = refused.load(std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Adds FUN_<hex> functions for every xref target inside a code mapping
/// (the direct-call closure; mirrors Ghidra's FUN_ naming).
pub fn close_call_targets(imp: &mut NativeImport) {
    // Membership mirror: one linear scan per call xref is O(xrefs) over
    // the function list, which never converges past a few hundred
    // thousand functions.
    let mut known: std::collections::HashSet<u64> = imp.functions.iter().map(|f| f.entry).collect();
    for x in &imp.xrefs {
        if !x.kind.contains("CALL") {
            continue;
        }
        let in_code = imp
            .mappings
            .iter()
            .any(|m| m.flags & 0x4 != 0 && x.to >= m.vaddr && x.to < m.vaddr + m.size);
        // A call into fill is junk decoded as code calling more of it
        // (`discovery::opens_with_fill`), not a function.
        if !in_code || known.contains(&x.to) || super::discovery::opens_with_fill(imp, x.to) {
            continue;
        }
        known.insert(x.to);
        imp.functions.push(NativeFunction {
            entry: x.to,
            name: format!("FUN_{:08x}", x.to),
            size: 1,
        });
    }
    imp.functions.sort_by_key(|f| f.entry);
    imp.functions.dedup_by_key(|f| f.entry);
}
