use super::*;

/// One console reference query. ConstantPropagationAnalyzer's default trusts
/// initial writable values; this inferred-reference policy does not change
/// strict constant queries. A root or stripped entry that does not decode
/// contributes no references and must not abort the whole image's import.
fn query_references(
    session: &mut crate::native_runtime::ConsoleSession,
    start: u64,
    end: u64,
    mappings: &[Mapping],
    refused: &std::sync::atomic::AtomicU64,
) -> Result<Option<Vec<crate::native_runtime::ReferenceFact>>> {
    match session.optional_references(start, end, mappings, true) {
        Ok(facts) => Ok(facts),
        // One range the console cannot answer costs that range's references,
        // never the image. A 53 MB game executable always holds bytes that
        // are not instructions; the count is reported so the loss stays
        // visible instead of being swallowed.
        Err(_) => {
            refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(None)
        }
    }
}

/// One lane of a sharded round: claim ranges until the round is drained.
fn claim_references(
    session: &mut crate::native_runtime::ConsoleSession,
    ranges: &[(usize, u64, u64)],
    cursor: &std::sync::atomic::AtomicUsize,
    mappings: &[Mapping],
    refused: &std::sync::atomic::AtomicU64,
) -> Result<Vec<(usize, Vec<crate::native_runtime::ReferenceFact>)>> {
    let mut facts = Vec::new();
    loop {
        let next = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(&(index, start, end)) = ranges.get(next) else {
            return Ok(facts);
        };
        if let Some(found) = query_references(session, start, end, mappings, refused)? {
            facts.push((index, found));
        }
    }
}

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
}

impl ContextPoints {
    fn new(contexts: &[NativeContext]) -> Self {
        let mut by_name: std::collections::BTreeMap<&str, Vec<(u64, u64)>> = std::collections::BTreeMap::new();
        for context in contexts {
            by_name.entry(&context.name).or_default().push((context.address, context.value));
        }
        Self {
            by_name: by_name
                .into_iter()
                .map(|(name, mut points)| {
                    points.sort_by_key(|&(address, _)| address);
                    (name.to_string(), points)
                })
                .collect(),
        }
    }

    /// Digest of what `[start, end)` decodes under: each context's value in
    /// force at `start`, and every point inside the range.
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

pub(super) fn infer_data_references(
    import: &mut NativeImport,
    session: &mut crate::native_runtime::ConsoleSession,
    lanes: Vec<crate::native_runtime::ConsoleSession>,
) -> Result<()> {
    use crate::native_runtime::ReferenceKind;
    session
        .prepare_reference_context(import)
        .map_err(|error| ImportError::Bad(format!("reference context: {error}")))?;
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
    // Ranges the console could not answer. Counted, not hidden.
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
    // identical; the same on a PowerPC game module, mipsel and PE64
    // corpus images). So those ranges reuse the last round's facts, and
    // only when the inputs the console reads for a range are the same:
    // register contexts, the call register, external slots and the call
    // fixups this round installs, for the whole round; and the decode
    // contexts covering the range itself. Every round adds mode contexts
    // on ARM (GBA: 33,635 then 49,035), and made the whole memo stale
    // when they were part of the round digest.
    let inputs = reference_inputs_digest(import, session.pattern_labels());
    let reusable = import.reference_memo_inputs == Some(inputs);
    let modes = ContextPoints::new(&import.contexts);
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
    // One console per hardware thread: the per-function cost is the console
    // lifting that function, so the pass scales with processes, not with
    // fewer requests. Shards start from the round's context and never read
    // one discovered inside it, so their facts equal a single session's.
    // The round opened these consoles on this image; they only need this
    // pass's context, not another startup.
    let mut shards = lanes;
    let mut prepared = false;
    let shard_target = import.cfg.console_shards.max(1);
    loop {
        let batch = std::mem::take(&mut pending);
        for &index in &batch {
            work[index].3 = false;
        }
        let ranges: Vec<(usize, u64, u64)> = batch
            .iter()
            .map(|&index| (index, work[index].0, work[index].1))
            .collect();
        let wanted = shard_target.min(ranges.len()).saturating_sub(1);
        shards.truncate(wanted);
        if !prepared && !shards.is_empty() {
            let spec = session.reference_shard_spec();
            // A shard is an optimization: one that cannot take the context is
            // dropped, and the pass stays correct on the remaining lanes.
            shards.retain_mut(|shard| shard.prepare_as_reference_shard(&spec, import).is_ok());
            prepared = true;
        }
        if shards.len() < wanted {
            let spec = session.reference_shard_spec();
            let mut opened = crate::native_runtime::ConsoleSession::open_image_shards(
                import,
                wanted - shards.len(),
            );
            opened.retain_mut(|shard| shard.prepare_as_reference_shard(&spec, import).is_ok());
            shards.extend(opened);
        }
        let keep = session.reference_contexts().len();
        let mut results: Vec<(usize, Vec<crate::native_runtime::ReferenceFact>)> = Vec::new();
        let mut discovered: Vec<NativeRegisterContext> = Vec::new();
        if shards.is_empty() || ranges.len() < 2 {
            for &(index, start, end) in &ranges {
                if let Some(facts) =
                    query_references(session, start, end, &import.mappings, &refused)?
                {
                    results.push((index, facts));
                }
            }
        } else {
            let mappings = &import.mappings;
            for shard in shards.iter_mut() {
                shard.sync_reference_context(session.reference_contexts());
            }
            // Function cost varies by orders of magnitude, so lanes claim the
            // next range instead of taking a fixed stride: one huge function
            // must not decide the round's wall time.
            let cursor = std::sync::atomic::AtomicUsize::new(0);
            let outcome: Result<Vec<_>> =
                std::thread::scope(|scope| {
                    let mut handles = Vec::with_capacity(shards.len());
                    for shard in shards.iter_mut() {
                        let ranges = &ranges;
                        let cursor = &cursor;
                        let refused = &refused;
                        handles.push(scope.spawn(move || {
                            claim_references(shard, ranges, cursor, mappings, refused)
                        }));
                    }
                    let mut collected = vec![claim_references(
                        session, &ranges, &cursor, mappings, &refused,
                    )?];
                    for handle in handles {
                        collected.push(handle.join().unwrap_or_else(|_| {
                            Err(ImportError::Bad("reference shard panicked".into()))
                        })?);
                    }
                    Ok(collected)
                });
            for lane in outcome? {
                results.extend(lane);
            }
            for shard in shards.iter_mut() {
                discovered.extend(shard.drain_discovered_contexts(keep));
            }
        }
        for (index, facts) in results {
            let known = &mut work[index].2;
            if known.is_empty() {
                *known = facts;
            } else {
                known.extend(facts);
                known.sort_unstable_by_key(|fact| (fact.from, fact.to, fact.kind as u8));
                known.dedup();
            }
        }
        // Finish local evidence before applying this round's call context.
        // Shard order must not decide the context list, so merge sorted.
        discovered.extend(session.drain_discovered_contexts(keep));
        discovered.sort_by(|left, right| {
            (left.start, left.end, &left.register, left.value).cmp(&(
                right.start,
                right.end,
                &right.register,
                right.value,
            ))
        });
        discovered.dedup_by(|left, right| {
            left.start == right.start
                && left.end == right.end
                && left.register == right.register
                && left.value == right.value
        });
        adopted_any |= !discovered.is_empty();
        let mut targets = session.adopt_reference_contexts(discovered);
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
    let mut addresses = Vec::with_capacity(candidates.len().min(1024));
    for chunk in candidates.chunks(1024) {
        addresses.clear();
        addresses.extend(chunk.iter().map(|&index| work[index].0));
        let shapes = session
            .linkage_batch(&addresses)
            .map_err(|error| ImportError::Bad(format!("propagated linkage: {error}")))?;
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
    // more of the image known: the frames are this pass's, not a sum.
    import.stack_variables.clear();
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
            match import
                .reference_widths
                .iter_mut()
                .find(|(address, _)| *address == fact.to)
            {
                Some((_, width)) => *width = (*width).max(fact.size as u64),
                None => import.reference_widths.push((fact.to, fact.size as u64)),
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
        if !in_code || known.contains(&x.to) {
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
