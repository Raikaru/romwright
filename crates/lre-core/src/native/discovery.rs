//! Mapped-image discovery: SLEIGH supplies instruction lengths and call targets;
//! the existing worklist supplies control-flow closure. No ISA-specific decoder.
use super::{
    candidate_address_is_valid, candidate_flow_is_valid, close_call_targets, code_ranges,
    extern_name, CandidateFilterContext, ImportError, NativeFunction, NativeImport, NativeXref,
    Result,
};
use crate::native_runtime::{
    ConsoleSession, FlowKind, FlowResult, LinkageContext, LinkageResult, NativeRuntimeError,
};
use std::collections::{HashMap, HashSet};

mod patterns;

#[cfg(test)]
mod tests;

/// Carries each decoded instruction's instruction set to the branch and
/// call targets it flows to, as Ghidra's disassembler does
/// (`DisassemblerContextImpl` flows the context register along every flow).
/// The console names only the targets whose held value differs, and a target
/// already decoded keeps the value it was decoded under: Ghidra's first
/// disassembly of an address wins the same way.
fn flow_modes_into_targets(
    flows: &[FlowResult],
    visited: &HashSet<u64>,
    flowed: &mut HashMap<u64, u64>,
    flow_provider: &mut dyn FlowProvider,
) {
    for info in flows {
        for &(target, mode) in &info.target_modes {
            if visited.contains(&target) || flowed.contains_key(&target) {
                continue;
            }
            flowed.insert(target, mode);
            flow_provider.set_context("LowBitCodeMode", target, mode);
        }
    }
}

trait FlowProvider {
    fn flow(&mut self, addresses: &[u64]) -> Vec<FlowResult>;
    /// Applies a processor mode value at an address, before anything there is
    /// decoded. A provider with no console has nothing to tell.
    fn set_context(&mut self, _name: &str, _address: u64, _value: u64) {}
    fn linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult>;
    fn plt_linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult>;
    fn context_linkages(&mut self, contexts: &[LinkageContext]) -> Vec<LinkageResult>;
}

struct ConsoleProvider {
    session: ConsoleSession,
    /// Extra consoles on the same image; one flow batch splits across them.
    shards: Vec<ConsoleSession>,
    decoded: Option<HashMap<u64, FlowResult>>,
    failure: Option<NativeRuntimeError>,
    /// Instructions the consoles decoded for this walk.
    instructions: u64,
}

/// Splits one flow batch across the shard consoles. Requests inside a batch
/// are independent, so each lane answers a contiguous slice and the results
/// concatenate in input order.
fn flow_batch_sharded(
    session: &mut ConsoleSession,
    shards: &mut [ConsoleSession],
    addresses: &[u64],
) -> std::result::Result<Vec<FlowResult>, NativeRuntimeError> {
    let lanes = shards.len() + 1;
    if lanes == 1 || addresses.len() < 2 * lanes {
        return session.flow_batch(addresses);
    }
    let span = addresses.len().div_ceil(lanes);
    let slices: Vec<&[u64]> = addresses.chunks(span).collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = shards
            .iter_mut()
            .zip(slices.iter().skip(1).copied())
            .map(|(shard, slice)| scope.spawn(move || shard.flow_batch(slice)))
            .collect();
        let mut flows = session.flow_batch(slices[0])?;
        for handle in handles {
            flows.extend(
                handle
                    .join()
                    .unwrap_or_else(|_| Err(NativeRuntimeError("flow shard panicked".into())))?,
            );
        }
        Ok(flows)
    })
}

impl ConsoleProvider {
    /// Console requests and decoded instructions for this walk.
    fn flow_stats(&self) -> lre_model::FlowStats {
        lre_model::FlowStats {
            requests: self.session.requests()
                + self.shards.iter().map(ConsoleSession::requests).sum::<u64>(),
            instructions: self.instructions,
        }
    }
}

impl FlowProvider for ConsoleProvider {
    fn set_context(&mut self, name: &str, address: u64, value: u64) {
        let context = [crate::native::NativeContext {
            name: name.to_string(),
            address,
            value,
        }];
        if let Err(error) = self.session.set_contexts(&context) {
            self.failure = Some(error);
            return;
        }
        for shard in self.shards.iter_mut() {
            if let Err(error) = shard.set_contexts(&context) {
                self.failure = Some(error);
                return;
            }
        }
    }

    fn flow(&mut self, addresses: &[u64]) -> Vec<FlowResult> {
        // Seeded walking already visits each instruction once. Only the
        // section sweep has decoded results worth retaining and reusing.
        let Some(decoded) = self.decoded.as_mut() else {
            let flows = flow_batch_sharded(&mut self.session, &mut self.shards, addresses)
                .unwrap_or_else(|error| {
                    self.failure = Some(error);
                    Vec::new()
                });
            self.instructions += flows.len() as u64;
            return flows;
        };
        let missing: Vec<_> = addresses
            .iter()
            .copied()
            .filter(|address| !decoded.contains_key(address))
            .collect();
        if !missing.is_empty() {
            match flow_batch_sharded(&mut self.session, &mut self.shards, &missing) {
                Ok(flows) => {
                    self.instructions += flows.len() as u64;
                    let decoded = self.decoded.as_mut().expect("decoded cache");
                    decoded.extend(flows.into_iter().map(|flow| (flow.address, flow)));
                }
                Err(error) => {
                    self.failure = Some(error);
                    return Vec::new();
                }
            }
        }
        let decoded = self.decoded.as_ref().expect("decoded cache");
        addresses
            .iter()
            .filter_map(|address| decoded.get(address).cloned())
            .collect()
    }

    fn linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult> {
        match self.session.linkage_batch(addresses) {
            Ok(results) => results,
            Err(error) => {
                self.failure = Some(error);
                Vec::new()
            }
        }
    }

    fn plt_linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult> {
        match self.session.plt_linkage_batch(addresses) {
            Ok(results) => results,
            Err(error) => {
                self.failure = Some(error);
                Vec::new()
            }
        }
    }

    fn context_linkages(&mut self, contexts: &[LinkageContext]) -> Vec<LinkageResult> {
        match self.session.context_linkage_batch(contexts) {
            Ok(results) => results,
            Err(error) => {
                self.failure = Some(error);
                Vec::new()
            }
        }
    }
}

/// The consoles a finished discovery hands to later passes: the session that
/// walked the image, plus its shards on the same image.
pub(super) struct ConsoleLanes {
    pub session: ConsoleSession,
    pub shards: Vec<ConsoleSession>,
}

/// ELF/PE retain structural facts when the optional console is unavailable.
/// All supported languages use the same mapped addresses and flow worklist.
pub(super) fn discover_seeded(import: &mut NativeImport) -> Option<ConsoleLanes> {
    if import.mappings.is_empty() {
        import.discovery_note = Some("the image has no mapped bytes".into());
        return None;
    }
    if import
        .cfg
        .console_path
        .as_ref()
        .map_or(true, |path| !path.is_file())
    {
        import.discovery_note = Some("no SLEIGH console is configured".into());
        return None;
    }
    let mut session = match ConsoleSession::new(&import.cfg) {
        Ok(session) => session,
        Err(error) => {
            import.discovery_note = Some(format!("console did not start: {error}"));
            return None;
        }
    };
    if let Err(error) = session.load_mapped(import) {
        import.discovery_note = Some(format!("console did not load the image: {error}"));
        return None;
    }
    let patterns_started = std::time::Instant::now();
    let ranges = code_ranges(import);
    if ranges.is_empty() {
        return None;
    }
    let patterns = match session.function_patterns(&ranges) {
        Ok(patterns) => patterns,
        Err(error) => {
            import.discovery_note = Some(format!("console refused the pattern search: {error}"));
            return None;
        }
    };
    import.pattern_labels = session.pattern_labels().to_vec();
    super::phase(import, "patterns", patterns_started);
    let flow_started = std::time::Instant::now();
    let mut provider = ConsoleProvider {
        session,
        shards: ConsoleSession::open_image_shards(import, import.cfg.console_shards.max(1) - 1),
        decoded: None,
        failure: None,
        instructions: 0,
    };
    let walked = flow_discover_with_candidates(import, &[], Some(&patterns), &mut provider);
    if let Err(error) = walked {
        import.discovery_note = Some(format!("console-driven flow failed: {error}"));
        return None;
    }
    if let Some(failure) = provider.failure.as_ref().map(ToString::to_string) {
        import.discovery_note = Some(format!("console-driven flow failed: {failure}"));
        return None;
    }
    super::phase(import, "flow", flow_started);
    import.flow = Some(provider.flow_stats());
    Some(ConsoleLanes {
        session: provider.session,
        shards: provider.shards,
    })
}

pub(super) fn discover_mapped(import: &mut NativeImport) -> Result<ConsoleLanes> {
    let mut session =
        ConsoleSession::new(&import.cfg).map_err(|e| ImportError::Bad(e.to_string()))?;
    session
        .load_mapped(import)
        .map_err(|e| ImportError::Bad(e.to_string()))?;
    let ranges = code_ranges(import);
    if ranges.is_empty() {
        return Ok(ConsoleLanes { session, shards: Vec::new() });
    }
    let in_code = |address| {
        ranges
            .iter()
            .any(|&(start, end)| start <= address && address < end)
    };
    let mut cursors: Vec<_> = ranges
        .iter()
        .map(|&(start, end)| (start, end, true))
        .collect();
    let mut candidates = Vec::new();
    let mut addresses = Vec::with_capacity(cursors.len());
    let mut decoded = HashMap::new();
    // Stripped images retain calls in code that is not reachable from startup.
    // Walk section bytes by the decoder's lengths, including after terminators.
    while !cursors.is_empty() {
        addresses.clear();
        addresses.extend(cursors.iter().map(|&(address, _, _)| address));
        let flows = session.try_flow_batch(&addresses);
        if flows.len() != addresses.len() {
            return super::err("incomplete SLEIGH seed scan");
        }
        for ((address, end, boundary), flow) in cursors.iter_mut().zip(flows) {
            if flow.address != *address || flow.length == 0 {
                return super::err("invalid SLEIGH seed-scan response");
            }
            if !matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl) {
                if *boundary {
                    candidates.push(*address);
                }
                *boundary = flow.kind == FlowKind::Return;
            }
            if flow.kind == FlowKind::Call {
                for &target in &flow.targets {
                    if in_code(target) {
                        import
                            .xrefs
                            .push(NativeXref::new(*address, target, "UNCONDITIONAL_CALL"));
                    }
                }
            }
            let next = address.saturating_add(flow.length as u64).min(*end);
            decoded.insert(*address, flow);
            *address = next;
        }
        cursors.retain(|&(address, end, _)| address < end);
    }
    close_call_targets(import);
    let patterns = session
        .function_patterns(&ranges)
        .map_err(|error| ImportError::Bad(error.to_string()))?;
    import.pattern_labels = session.pattern_labels().to_vec();
    let mut provider = ConsoleProvider {
        session,
        shards: ConsoleSession::open_image_shards(import, import.cfg.console_shards.max(1) - 1),
        decoded: Some(decoded),
        failure: None,
        instructions: 0,
    };
    flow_discover_with_candidates(import, &candidates, Some(&patterns), &mut provider)?;
    if let Some(error) = provider.failure {
        return Err(ImportError::Bad(error.to_string()));
    }
    import.flow = Some(provider.flow_stats());
    Ok(ConsoleLanes {
        session: provider.session,
        shards: provider.shards,
    })
}
fn get_canonical_origin(mut addr: u64, addr_origin: &std::collections::HashMap<u64, u64>) -> u64 {
    let mut hops = 0;
    while let Some(&parent) = addr_origin.get(&addr) {
        if parent == addr || hops >= 64 {
            break;
        }
        addr = parent;
        hops += 1;
    }
    addr
}

fn merge_reached_candidate(
    target: u64,
    origin: u64,
    reloc_set: &HashSet<u64>,
    addr_origin: &mut std::collections::HashMap<u64, u64>,
    proven_bodies: &mut std::collections::HashMap<u64, u64>,
) {
    if !reloc_set.contains(&target) {
        return;
    }
    let canon_origin = get_canonical_origin(origin, addr_origin);
    let canon_target = get_canonical_origin(target, addr_origin);
    if canon_target != canon_origin {
        addr_origin.insert(target, canon_origin);
        addr_origin.insert(canon_target, canon_origin);
        for v in addr_origin.values_mut() {
            if *v == target || *v == canon_target {
                *v = canon_origin;
            }
        }
        if let Some(t_span) = proven_bodies.remove(&target) {
            proven_bodies
                .entry(canon_origin)
                .and_modify(|e| *e = (*e).max(t_span))
                .or_insert(t_span);
        }
        if let Some(t_span) = proven_bodies.remove(&canon_target) {
            proven_bodies
                .entry(canon_origin)
                .and_modify(|e| *e = (*e).max(t_span))
                .or_insert(t_span);
        }
    }
}

/// Core flow-based discovery over a provided control-flow resolver.
#[cfg(test)]
pub fn flow_discover_with_provider<F: FnMut(&[u64]) -> Vec<crate::native_runtime::FlowResult>>(
    imp: &mut NativeImport,
    flow_provider: F,
) {
    struct TestProvider<F>(F);
    impl<F: FnMut(&[u64]) -> Vec<FlowResult>> FlowProvider for TestProvider<F> {
        fn flow(&mut self, addresses: &[u64]) -> Vec<FlowResult> {
            (self.0)(addresses)
        }
        fn linkages(&mut self, _: &[u64]) -> Vec<LinkageResult> {
            Vec::new()
        }
        fn plt_linkages(&mut self, _: &[u64]) -> Vec<LinkageResult> {
            Vec::new()
        }
        fn context_linkages(&mut self, _: &[LinkageContext]) -> Vec<LinkageResult> {
            Vec::new()
        }
    }
    flow_discover_with_candidates(imp, &[], None, &mut TestProvider(flow_provider))
        .expect("flow-only discovery has no pattern prerequisites");
}

fn flow_discover_with_candidates<P: FlowProvider>(
    imp: &mut NativeImport,
    candidates: &[u64],
    patterns: Option<&crate::native_runtime::FunctionPatterns>,
    flow_provider: &mut P,
) -> Result<()> {
    use crate::native_runtime::FlowKind;
    let code = code_ranges(imp);
    let in_code = |a: u64| code.iter().any(|(v, e)| a >= *v && a < *e);
    let has_linkage_slots = imp.externals.iter().any(|(address, _)| *address != 0);
    let mut linkage_candidates = HashSet::new();
    let mut conditional_targets = HashSet::new();
    // Addresses the instruction above falls into. Ghidra refuses a pattern
    // match there: the flow above already owns it
    // (FunctionStartAnalyzer.checkAlreadyInFunctionAbove, 491-530).
    let mut fell_into: HashSet<u64> = HashSet::new();
    let mut flow_endings = Vec::new();
    let mut context_edges = Vec::new();
    let mut branch_targets = Vec::new();
    // Table metadata supplies boundaries, not functions. Each entry still needs
    // bounded p-code evidence ending in an indirect transfer through a known slot.
    if has_linkage_slots {
        for chunk in imp.plt_candidates.chunks(1024) {
            let addresses: Vec<_> = chunk.iter().map(|&(address, _)| address).collect();
            for (&(address, width), linkage) in
                chunk.iter().zip(flow_provider.plt_linkages(&addresses))
            {
                let known = imp
                    .functions
                    .iter()
                    .any(|function| function.entry == address);
                if linkage.address != address
                    || linkage.length == 0
                    || linkage.length as u64 > width
                    || !code.iter().any(|&(start, end)| {
                        start <= address && address < end && linkage.length as u64 <= end - address
                    })
                {
                    continue;
                }
                let Some(slot) = linkage.slot else {
                    continue;
                };
                let external = imp
                    .externals
                    .iter()
                    .find(|(slot_address, _)| *slot_address == slot && slot != 0)
                    .map(|(_, name)| name.clone());
                let Some(name) = external else {
                    // An ifunc slot names no import, but its relocation proves
                    // one in-image resolver: the same evidence that promotes an
                    // imported stub, without a name to copy.
                    if let Ok(index) = imp
                        .ifunc_slots
                        .binary_search_by_key(&slot, |&(candidate, _)| candidate)
                    {
                        let destination = imp.ifunc_slots[index].1;
                        if !known {
                            imp.functions.push(NativeFunction {
                                entry: address,
                                name: format!("FUN_{address:08x}"),
                                size: linkage.length as u64,
                            });
                        }
                        imp.thunks.push(crate::native::NativeThunk {
                            entry: address,
                            destination,
                            kind: lre_model::ThunkKind::Direct,
                            source: crate::native::THUNK_SOURCE,
                        });
                    }
                    continue;
                };
                if !known {
                    imp.functions.push(NativeFunction {
                        entry: address,
                        name: name.clone(),
                        size: linkage.length as u64,
                    });
                    imp.externals.push((address, name));
                }
                imp.thunks.push(crate::native::NativeThunk {
                    entry: address,
                    destination: slot,
                    kind: lre_model::ThunkKind::Linkage,
                    source: crate::native::THUNK_SOURCE,
                });
            }
        }
    }
    // Initial discovery from trusted seeds first:
    let mut entries: Vec<u64> = imp
        .functions
        .iter()
        .map(|f| f.entry)
        .chain(imp.externals.iter().map(|(a, _)| *a))
        .filter(|a| *a != 0 && in_code(*a))
        .collect();
    entries.sort_unstable();
    entries.dedup();

    let mut calls: Vec<(u64, u64)> = Vec::new();
    // Every unconditional direct branch, kept until function extents are
    // known: only then can a transfer out of a function be told apart from a
    // loop inside one.
    let mut branch_transfers: Vec<(u64, u64)> = Vec::new();
    let mut instruction_extents = Vec::new();
    let mut thunk_candidates = HashSet::new();
    let mut thunk_jumps = Vec::new();
    let mut thunk_roots = HashMap::new();
    let mut thunk_continuations = HashMap::new();
    let mut landing_entries = HashMap::new();
    // Ghidra CreateThunkFunctionCmd.getSimpleFlow: one unconditional transfer
    // is a thunk when it is a jump, or a call that terminates flow. Only a
    // proven non-returning destination makes a call terminal here.
    let mut terminal_transfers: HashMap<u64, u64> = HashMap::new();
    let mut proven_bodies: std::collections::HashMap<u64, u64> =
        std::collections::HashMap::with_capacity(4096);
    // The instruction set each function entry was decoded in, taken at the
    // moment its first instruction was read: a later console -- the reference
    // pass, a decompile worker -- must read the same bytes the same way, and
    // asking this console afterwards would not do, because every probe it
    // has made since has written the mode switches those bytes carry into its
    // one context database (SLEIGH `globalset`; Ghidra keeps pseudo-
    // disassembly out of the program's context, this console cannot).
    let mut entry_modes: Vec<(u64, u64)> = Vec::new();
    let mut addr_origin: std::collections::HashMap<u64, u64> =
        std::collections::HashMap::with_capacity(32768);
    for &s in &entries {
        addr_origin.insert(s, s);
    }
    let mut visited: HashSet<u64> = HashSet::with_capacity(32768);
    let mut flowed_modes: HashMap<u64, u64> = HashMap::new();
    // Entries a data pointer proposed, as opposed to a seed the loader
    // declared or a call reached: only these are retractable below.
    let mut data_derived: HashSet<u64> = HashSet::new();
    let mut active: Vec<u64> = entries.clone();
    while !active.is_empty() {
        active.sort_unstable();
        active.dedup();
        let to_query: Vec<u64> = active
            .drain(..)
            .filter(|a| *a != 0 && in_code(*a) && visited.insert(*a))
            .collect();
        if to_query.is_empty() {
            break;
        }

        let mut next_active: Vec<u64> = Vec::new();
        for chunk in to_query.chunks(1024) {
            let flows = flow_provider.flow(chunk);
            flow_modes_into_targets(&flows, &visited, &mut flowed_modes, flow_provider);
            // Branch targets need an unconditional transfer to a proven import
            // stub; direct calls independently establish their target entries.
            if has_linkage_slots {
                for target in chunk
                    .iter()
                    .zip(&flows)
                    .filter(|(address, flow)| {
                        flow.address == **address
                            && flow.length != 0
                            && flow.kind == FlowKind::Branch
                            && flow.targets.len() == 1
                    })
                    .map(|(_, flow)| flow.targets[0])
                {
                    if linkage_candidates.contains(&target)
                        || visited.contains(&target)
                        || !in_code(target)
                        || entries.contains(&target)
                        || instruction_extents
                            .iter()
                            .any(|&(start, size)| target > start && target - start < size)
                        || flows.iter().any(|flow| {
                            target > flow.address && target - flow.address < flow.length as u64
                        })
                    {
                        continue;
                    }
                    linkage_candidates.insert(target);
                }
            }
            let thunks = confirmed_thunks(
                imp,
                &entries,
                &landing_entries,
                &visited,
                &instruction_extents,
                chunk,
                &flows,
                flow_provider,
            );
            for (addr, info) in chunk.iter().copied().zip(flows) {
                if let Some(mode) = info.mode {
                    if addr_origin.get(&addr) == Some(&addr) {
                        entry_modes.push((addr, mode));
                    }
                }
                if info.address == addr
                    && info.no_op
                    && info.length != 0
                    && info.kind == FlowKind::Fallthrough
                    && info.targets.is_empty()
                    && info.fallthrough == addr.checked_add(info.length as u64)
                    && entries.contains(&addr)
                    && imp.mappings.iter().any(|m| {
                        m.flags & 4 != 0
                            && addr >= m.vaddr
                            && addr - m.vaddr < m.size
                            && info.length as u64 <= m.size - (addr - m.vaddr)
                    })
                {
                    // Only the first instruction may be skipped, never a no-op chain.
                    if let Some(fall) = info.fallthrough {
                        landing_entries.insert(fall, addr);
                    }
                }
                // A jump chain reaching its source's continuation is an internal
                // branch-over-body sequence, not a set of separate functions.
                if let Some(&root) = thunk_continuations.get(&addr) {
                    if thunk_roots.get(&get_canonical_origin(addr, &addr_origin)) == Some(&root) {
                        for (&target, &owner) in &thunk_roots {
                            if owner == root {
                                merge_reached_candidate(
                                    target,
                                    root,
                                    &thunk_candidates,
                                    &mut addr_origin,
                                    &mut proven_bodies,
                                );
                            }
                        }
                    }
                }
                let origin = get_canonical_origin(addr, &addr_origin);
                let span = addr + info.length as u64;
                if !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl) {
                    instruction_extents.push((addr, info.length as u64));
                }
                if has_linkage_slots && info.kind != FlowKind::Fallthrough {
                    flow_endings.push((addr, info.kind == FlowKind::BranchInd));
                }
                if info.conditional {
                    conditional_targets.extend(info.targets.iter().copied());
                }
                proven_bodies
                    .entry(origin)
                    .and_modify(|e| *e = (*e).max(span))
                    .or_insert(span);

                match info.kind {
                    FlowKind::Call => {
                        if info.targets.len() == 1 && !info.conditional {
                            terminal_transfers.insert(addr, info.targets[0]);
                        }
                        for t in &info.targets {
                            if has_linkage_slots && in_code(*t) {
                                linkage_candidates.insert(*t);
                            }
                            if in_code(*t) && !entries.contains(t) {
                                entries.push(*t);
                                addr_origin.insert(*t, *t);
                                next_active.push(*t);
                            }
                            if *t != 0 {
                                calls.push((addr, *t));
                            }
                        }
                    }
                    FlowKind::Branch => {
                        if info.targets.len() == 1 && !info.conditional {
                            terminal_transfers.insert(addr, info.targets[0]);
                            // A transfer worth recording has a target of its
                            // own; the fallthrough address is not one.
                            if info.targets[0] != 0
                                && info.targets[0] != span
                                && in_code(info.targets[0])
                            {
                                branch_transfers.push((addr, info.targets[0]));
                            }
                        }
                        if let Some(&t) = info.targets.first() {
                            if has_linkage_slots && t != span {
                                branch_targets.push(t);
                            }
                            if linkage_candidates.contains(&t)
                                && code
                                    .iter()
                                    .any(|&(start, end)| start <= addr && span <= end)
                            {
                                context_edges.push((t, addr));
                            }
                            if thunks.get(&addr) == Some(&t) {
                                if !entries.contains(&t) {
                                    entries.push(t);
                                    thunk_candidates.insert(t);
                                    let root = thunk_roots.get(&origin).copied().unwrap_or(origin);
                                    thunk_roots.insert(t, root);
                                    thunk_continuations.insert(addr + info.length as u64, root);
                                }
                                thunk_jumps.push((addr, t));
                                // The thunk is the owning entry, not the jump
                                // address: one leading no-op may precede it.
                                if let Some(&entry) = landing_entries
                                    .get(&addr)
                                    .or(Some(&addr).filter(|_| entries.contains(&addr)))
                                {
                                    imp.thunks.push(crate::native::NativeThunk {
                                        entry,
                                        destination: t,
                                        kind: lre_model::ThunkKind::Direct,
                                        source: crate::native::THUNK_SOURCE,
                                    });
                                }
                                addr_origin.insert(t, t);
                                if !visited.contains(&t) {
                                    next_active.push(t);
                                }
                                continue;
                            }
                            merge_reached_candidate(
                                t,
                                origin,
                                &thunk_candidates,
                                &mut addr_origin,
                                &mut proven_bodies,
                            );
                            if in_code(t) && !visited.contains(&t) {
                                addr_origin.insert(t, origin);
                                next_active.push(t);
                            }
                        }
                    }
                    FlowKind::CBranch => {
                        if let Some(&t) = info.targets.first() {
                            if has_linkage_slots && t != span {
                                branch_targets.push(t);
                            }
                            merge_reached_candidate(
                                t,
                                origin,
                                &thunk_candidates,
                                &mut addr_origin,
                                &mut proven_bodies,
                            );
                            if in_code(t) && !visited.contains(&t) {
                                addr_origin.insert(t, origin);
                                next_active.push(t);
                            }
                        }
                    }
                    FlowKind::CallInd
                    | FlowKind::Fallthrough
                    | FlowKind::BranchInd
                    | FlowKind::Return
                    | FlowKind::Bad
                    | FlowKind::Unimpl => {}
                }
                if let Some(fall) = info
                    .fallthrough
                    .filter(|_| !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl))
                {
                    fell_into.insert(fall);
                    merge_reached_candidate(
                        fall,
                        origin,
                        &thunk_candidates,
                        &mut addr_origin,
                        &mut proven_bodies,
                    );
                    if in_code(fall) && !visited.contains(&fall) {
                        addr_origin.insert(fall, origin);
                        next_active.push(fall);
                    }
                }
            }
        }
        active = next_active;
    }

    // Only decoded bytes prove containment. A branch over a gap does not.
    let mut extents: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .filter(|f| f.size > 1)
        .map(|f| (f.entry, f.size))
        .collect();
    let instruction_start = extents.len();
    extents.extend(instruction_extents);

    // Settle loader/call-derived ownership before testing pattern prerequisites.
    // Pattern entries are a separate creation batch, not mergeable relocations.
    //
    // The pattern round repeats until it accepts nothing new. A pattern with
    // an `after="function"` prerequisite needs the bytes before it decoded,
    // and the function that decodes them is often itself a pattern match --
    // Ghidra's FunctionStartAnalyzer runs again on every range of new
    // instructions, so its prerequisites are met one function at a time. One
    // pass refused 8293 of 10837 matches on a DS ARM9 module whose Thumb half
    // nothing else reaches.
    let mut round = 0usize;
    let mut pattern_accepted = 0u64;
    loop {
        let pattern_round = round != 0;
        let mut round_accepted = false;
        let pattern_candidates = if pattern_round {
            if let Some(patterns) = patterns {
                extents[instruction_start..].sort_unstable();
                {
                    let mut refused = std::collections::BTreeMap::new();
                    let mut applied = Vec::new();
                    let collected = patterns::collect(
                        imp,
                        patterns,
                        &entries,
                        &extents[instruction_start..],
                        &conditional_targets,
                        &fell_into,
                        &mut refused,
                        &mut applied,
                        flow_provider,
                    )?;
                    // Every later console -- the reference pass, a decompile
                    // worker -- must decode these addresses in the same mode.
                    imp.contexts.extend(applied);
                    // A match accepted in an earlier round is a known entry
                    // now; that is not a refusal of the match.
                    if let Some(known) = refused.get_mut("known-entry") {
                        *known = known.saturating_sub(pattern_accepted);
                        if *known == 0 {
                            refused.remove("known-entry");
                        }
                    }
                    pattern_accepted += collected.len() as u64;
                    imp.patterns_seen = Some(lre_model::PatternStats {
                        hits: patterns.matches.len() as u64,
                        accepted: pattern_accepted,
                        refused,
                    });
                    collected
                }
            } else {
                break;
            }
        } else {
            Vec::new()
        };
        let existing_entry_count = entries.len();
        let mut pattern_edges = Vec::new();
        let filter_ctx = CandidateFilterContext {
            mappings: &imp.mappings,
            known_extents: &extents,
            initial_seeds: &entries.iter().copied().collect(),
        };

        // Relocation candidates: reject candidates already visited inside trusted bodies
        let mut unvisited_relocs: Vec<u64> = if pattern_round {
            pattern_candidates
                .iter()
                .map(|candidate| candidate.address)
                .collect()
        } else {
            imp.reloc_candidates
                .iter()
                .chain(imp.pointer_candidates.iter())
                .chain(imp.initializer_candidates.iter())
                .chain(candidates.iter())
                // A tail call's target is a candidate, never a conclusion: it
                // faces the same address and flow evidence as a relocation
                // candidate below. II.1 reserves enabling this by default.
                .chain(
                    branch_transfers
                        .iter()
                        .map(|(_, target)| target)
                        .filter(|_| imp.cfg.promote_tailcalls),
                )
                .copied()
                .collect()
        };
        unvisited_relocs.retain(|&cand| {
            // A pattern match on already-decoded bytes is still a function
            // start: Ghidra creates one whenever the instruction there is in no
            // function body and nothing above flows into it, which
            // `patterns::collect` has already established
            // (FunctionStartAnalyzer.applyActionToSet, 289-324). Requiring an
            // unvisited address hid every start the walk had passed through --
            // 798 of 5633 matches on a PlayStation 2 executable.
            in_code(cand)
                && !filter_ctx.initial_seeds.contains(&cand)
                && (pattern_round
                    || (!visited.contains(&cand)
                        && candidate_address_is_valid(cand, &filter_ctx)))
        });
        unvisited_relocs.sort_unstable();
        unvisited_relocs.dedup();

        if !unvisited_relocs.is_empty() {
            let flows = flow_provider.flow(&unvisited_relocs);
            let confirmed_relocs: Vec<u64> = unvisited_relocs
                .into_iter()
                .zip(flows)
                .filter(|&(c, ref info)| {
                    if pattern_round {
                        info.address == c
                            && info.length != 0
                            && !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl)
                    } else {
                        candidate_flow_is_valid(c, &filter_ctx, info)
                    }
                })
                .map(|(c, _)| c)
                .collect();

            if !confirmed_relocs.is_empty() {
                for &r in &confirmed_relocs {
                    if !entries.contains(&r) {
                        entries.push(r);
                        addr_origin.insert(r, r);
                        round_accepted = true;
                        // Where this entry came from, for the containment
                        // reconciliation once every body is proven. A byte
                        // pattern is not an address taken from data: the
                        // overlap rule below exists for switch case labels
                        // read out of a relocation table, and applying it to
                        // prologue matches deleted 618 of 4835 real function
                        // starts on a PlayStation 2 executable.
                        if !pattern_round {
                            data_derived.insert(r);
                        }
                    }
                }
                let reloc_set: HashSet<u64> = if pattern_round {
                    HashSet::new()
                } else {
                    confirmed_relocs
                        .iter()
                        .chain(thunk_candidates.iter())
                        .copied()
                        .collect()
                };
                let mut reloc_active = confirmed_relocs;
                while !reloc_active.is_empty() {
                    reloc_active.sort_unstable();
                    reloc_active.dedup();
                    let to_query: Vec<u64> = reloc_active
                        .drain(..)
                        .filter(|a| *a != 0 && in_code(*a) && visited.insert(*a))
                        .collect();
                    if to_query.is_empty() {
                        break;
                    }
                    let mut next_active: Vec<u64> = Vec::new();
                    for chunk in to_query.chunks(1024) {
                        let flows = flow_provider.flow(chunk);
                        flow_modes_into_targets(&flows, &visited, &mut flowed_modes, flow_provider);
                        for (addr, info) in chunk.iter().copied().zip(flows) {
                            if let Some(mode) = info.mode {
                                if addr_origin.get(&addr) == Some(&addr) {
                                    entry_modes.push((addr, mode));
                                }
                            }
                            let origin = get_canonical_origin(addr, &addr_origin);
                            let span = addr + info.length as u64;
                            if pattern_round
                                && !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl)
                            {
                                for target in info
                                    .targets
                                    .iter()
                                    .copied()
                                    .filter(|_| {
                                        matches!(
                                            info.kind,
                                            FlowKind::Branch
                                                | FlowKind::CBranch
                                                | FlowKind::BranchInd
                                        )
                                    })
                                    .chain(info.fallthrough)
                                {
                                    if pattern_candidates
                                        .binary_search_by_key(&target, |candidate| {
                                            candidate.address
                                        })
                                        .is_ok()
                                    {
                                        pattern_edges.push((target, addr));
                                    }
                                }
                            }
                            if info.conditional {
                                conditional_targets.extend(info.targets.iter().copied());
                            }
                            if !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl) {
                                extents.push((addr, info.length as u64));
                            }
                            if has_linkage_slots {
                                if info.kind != FlowKind::Fallthrough {
                                    flow_endings.push((addr, info.kind == FlowKind::BranchInd));
                                }
                            }
                            proven_bodies
                                .entry(origin)
                                .and_modify(|e| *e = (*e).max(span))
                                .or_insert(span);

                            match info.kind {
                                FlowKind::Call => {
                                    if info.targets.len() == 1 && !info.conditional {
                                        terminal_transfers.insert(addr, info.targets[0]);
                                    }
                                    for t in &info.targets {
                                        if has_linkage_slots && in_code(*t) {
                                            linkage_candidates.insert(*t);
                                        }
                                        if in_code(*t) && !entries.contains(t) {
                                            entries.push(*t);
                                            addr_origin.insert(*t, *t);
                                            next_active.push(*t);
                                        }
                                        if *t != 0 {
                                            calls.push((addr, *t));
                                        }
                                    }
                                }
                                FlowKind::Branch => {
                                    if info.targets.len() == 1 && !info.conditional {
                                        terminal_transfers.insert(addr, info.targets[0]);
                                    }
                                    if let Some(&t) = info.targets.first() {
                                        if has_linkage_slots && t != span {
                                            branch_targets.push(t);
                                        }
                                        if linkage_candidates.contains(&t)
                                            && code
                                                .iter()
                                                .any(|&(start, end)| start <= addr && span <= end)
                                        {
                                            context_edges.push((t, addr));
                                        }
                                        merge_reached_candidate(
                                            t,
                                            origin,
                                            &reloc_set,
                                            &mut addr_origin,
                                            &mut proven_bodies,
                                        );
                                        if in_code(t) && !visited.contains(&t) {
                                            addr_origin.insert(t, origin);
                                            next_active.push(t);
                                        }
                                    }
                                }
                                FlowKind::CBranch => {
                                    if let Some(&t) = info.targets.first() {
                                        if has_linkage_slots && t != span {
                                            branch_targets.push(t);
                                        }
                                        merge_reached_candidate(
                                            t,
                                            origin,
                                            &reloc_set,
                                            &mut addr_origin,
                                            &mut proven_bodies,
                                        );
                                        if in_code(t) && !visited.contains(&t) {
                                            addr_origin.insert(t, origin);
                                            next_active.push(t);
                                        }
                                    }
                                }
                                _ => {}
                            }
                            if let Some(fall) = info
                                .fallthrough
                                .filter(|_| !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl))
                            {
                                merge_reached_candidate(
                                    fall,
                                    origin,
                                    &reloc_set,
                                    &mut addr_origin,
                                    &mut proven_bodies,
                                );
                                if in_code(fall) && !visited.contains(&fall) {
                                    addr_origin.insert(fall, origin);
                                    next_active.push(fall);
                                }
                            }
                        }
                    }
                    reloc_active = next_active;
                }
            }
        }
        if pattern_round {
            let called = |address| calls.iter().any(|&(_, target)| target == address);
            let established = |address| {
                entries[..existing_entry_count].contains(&address)
                    || called(address)
                    || pattern_candidates
                        .binary_search_by_key(&address, |candidate| candidate.address)
                        .is_ok_and(|index| !pattern_candidates[index].possible)
            };
            let mut rejected = HashSet::new();
            loop {
                let mut changed = false;
                for candidate in &pattern_candidates {
                    if !candidate.possible
                        || called(candidate.address)
                        || rejected.contains(&candidate.address)
                    {
                        continue;
                    }
                    let owner = pattern_edges
                        .iter()
                        .filter(|&&(target, _)| target == candidate.address)
                        .map(|&(_, source)| get_canonical_origin(source, &addr_origin))
                        .filter(|&origin| {
                            origin != candidate.address && !rejected.contains(&origin)
                        })
                        .min_by_key(|&origin| (!established(origin), origin));
                    if conditional_targets.contains(&candidate.address)
                        || owner.is_some_and(established)
                    {
                        rejected.insert(candidate.address);
                        if let Some(owner) = owner {
                            merge_reached_candidate(
                                candidate.address,
                                owner,
                                &rejected,
                                &mut addr_origin,
                                &mut proven_bodies,
                            );
                        }
                        changed = true;
                    }
                }
                if !changed {
                    break;
                }
            }
            entries.retain(|entry| !rejected.contains(entry));
        }
        round += 1;
        // The first pattern round always runs; a later one runs only while the
        // one before it created a function. Every round adds at least one
        // entry and the matches are finite, so this ends; the bound only
        // guards the loop against a defect, not against a long chain of
        // adjacent functions each proving the next.
        if pattern_round && (!round_accepted || round > 100_000) {
            break;
        }
    }
    // A local linkage must reach an indirect branch in at most eight contiguous
    // instructions. Reuse decoded flow to avoid probing ordinary branch labels.
    let mut changed = false;
    let mut context_targets = HashSet::new();
    if !linkage_candidates.is_empty() {
        extents[instruction_start..].sort_unstable();
        flow_endings.sort_unstable();
        let instructions = &extents[instruction_start..];
        let mut targets: Vec<_> = linkage_candidates
            .into_iter()
            .filter(|&target| linkage_flow_shape(target, instructions, &flow_endings))
            .collect();
        targets.sort_unstable();
        for chunk in targets.chunks(1024) {
            for (&target, linkage) in chunk.iter().zip(flow_provider.linkages(chunk)) {
                if linkage.address != target {
                    continue;
                }
                if linkage.needs_context && !conditional_targets.contains(&target) {
                    context_targets.insert(target);
                } else {
                    changed |= promote_linkage(
                        imp,
                        &mut entries,
                        &mut addr_origin,
                        instructions,
                        &code,
                        &linkage,
                    );
                }
            }
        }
    }

    // A local unresolved slot is only a request for evidence. Wait until every
    // validated caller has been walked; no first-caller/global-register assumption.
    if !context_targets.is_empty() {
        context_edges
            .retain(|(target, _)| context_targets.contains(target) && !entries.contains(target));
        context_edges.sort_unstable();
        context_edges.dedup();
        branch_targets.sort_unstable();
        branch_targets.dedup();
        let mut pending = context_edges.as_slice();
        let mut requests = Vec::new();
        'candidate: while let Some(&(target, _)) = pending.first() {
            let count = pending.partition_point(|&(address, _)| address == target);
            let (group, rest) = pending.split_at(count);
            pending = rest;
            let mut proof = None;
            for chunk in group.chunks(1024) {
                requests.clear();
                for &(_, branch) in chunk {
                    let origin = get_canonical_origin(branch, &addr_origin);
                    let incoming = branch_targets.partition_point(|address| *address <= origin);
                    if origin > branch
                        || branch_targets
                            .get(incoming)
                            .is_some_and(|address| *address <= branch)
                        || entries
                            .iter()
                            .any(|entry| *entry > origin && *entry <= branch)
                        || !code
                            .iter()
                            .any(|&(start, end)| start <= origin && branch < end)
                    {
                        continue 'candidate;
                    }
                    requests.push(LinkageContext {
                        origin,
                        branch,
                        target,
                    });
                }
                let results = flow_provider.context_linkages(&requests);
                if results.len() != requests.len() {
                    continue 'candidate;
                }
                for result in results {
                    let Some(slot) = result.slot.filter(|slot| *slot != 0) else {
                        continue 'candidate;
                    };
                    let evidence = (slot, result.length);
                    if result.address != target
                        || result.length == 0
                        || result.needs_context
                        || proof.is_some_and(|previous| previous != evidence)
                    {
                        continue 'candidate;
                    }
                    proof = Some(evidence);
                }
            }
            let Some((slot, length)) = proof else {
                continue;
            };
            changed |= promote_linkage(
                imp,
                &mut entries,
                &mut addr_origin,
                &extents[instruction_start..],
                &code,
                &LinkageResult {
                    address: target,
                    length,
                    slot: Some(slot),
                    needs_context: false,
                },
            );
        }
    }
    if changed {
        proven_bodies.clear();
        for &(address, length) in &extents[instruction_start..] {
            let origin = get_canonical_origin(address, &addr_origin);
            let end = address + length;
            proven_bodies
                .entry(origin)
                .and_modify(|span| *span = (*span).max(end))
                .or_insert(end);
        }
    }

    // Canonicalize proven_bodies so descendant spans are merged into their root origins:
    let mut canon_bodies: std::collections::HashMap<u64, u64> =
        std::collections::HashMap::with_capacity(proven_bodies.len());
    for (root, span_end) in proven_bodies.drain() {
        let canon = get_canonical_origin(root, &addr_origin);
        canon_bodies
            .entry(canon)
            .and_modify(|e| *e = (*e).max(span_end))
            .or_insert(span_end);
    }
    proven_bodies = canon_bodies;

    // Reconcile batched relocation candidates after discovering their bodies:
    // an entry plus an internal relocation target cannot both become functions.
    entries.retain(|&e| get_canonical_origin(e, &addr_origin) == e);

    // Two functions cannot share code. A PE32 switch table holds absolute
    // addresses, so every case label carries a base relocation and reaches
    // this point looking exactly like a function address taken from data --
    // and the container's own walk never reaches them, because the transfer
    // is indirect. What separates them is the shape of their flow-proven
    // spans: case labels of one switch overlap each other, because every case
    // falls into the same shared tail, while a real function's span abuts its
    // neighbour's without overlapping it. Retract the overlapping ones. A
    // seed the loader declared, or an address some call reaches, is untouched.
    if !data_derived.is_empty() {
        let called: HashSet<u64> = calls.iter().map(|&(_, target)| target).collect();
        let mut spans: Vec<(u64, u64)> = entries
            .iter()
            .filter(|entry| data_derived.contains(entry) && !called.contains(entry))
            .map(|&entry| (entry, proven_bodies.get(&entry).copied().unwrap_or(entry + 1)))
            .collect();
        spans.sort_unstable();
        let mut sharing: HashSet<u64> = HashSet::new();
        let mut furthest = (0u64, 0u64); // (entry, span end) reaching deepest so far
        for (entry, end) in spans {
            if entry < furthest.1 {
                sharing.insert(entry);
                sharing.insert(furthest.0);
            }
            if end > furthest.1 {
                furthest = (entry, end);
            }
        }
        entries.retain(|entry| !sharing.contains(entry));
    }

    entries.sort_unstable();
    entries.dedup();
    for (from, to) in thunk_jumps {
        if !imp
            .xrefs
            .iter()
            .any(|x| x.from == from && x.to == to && x.kind == "UNCONDITIONAL_JUMP")
        {
            let provenance = if entries.contains(&to) {
                crate::native::THUNK_SOURCE
            } else {
                "native-import"
            };
            imp.xrefs.push(NativeXref::with_provenance(
                from,
                to,
                "UNCONDITIONAL_JUMP",
                provenance,
            ));
        }
    }

    // A tail call's target is a function only with its own evidence: the
    // address must be code, must not sit inside a body another entry already
    // proved, and its own flow must decode from that address to a terminator.
    // Stock Ghidra creates none of these, so II.1 keeps the pass off unless
    // asked (`VENTRIS_PROMOTE_TAILCALLS`).
    if imp.cfg.promote_tailcalls {
        let known: HashSet<u64> = entries.iter().copied().collect();
        let mut candidates: Vec<u64> = branch_transfers
            .iter()
            .map(|&(_, target)| target)
            .filter(|target| {
                in_code(*target)
                    && !known.contains(target)
                    && !proven_bodies
                        .iter()
                        .any(|(&origin, &end)| origin < *target && *target < end)
            })
            .collect();
        candidates.sort_unstable();
        candidates.dedup();
        for candidate in candidates {
            if let Some(end) = proven_body_end(candidate, flow_provider, &known, &in_code) {
                entries.push(candidate);
                addr_origin.insert(candidate, candidate);
                proven_bodies.insert(candidate, end);
            }
        }
        entries.sort_unstable();
        entries.dedup();
    }

    let mut merged = imp.functions.clone();
    for e in entries {
        if !merged.iter().any(|f| f.entry == e) {
            let name = extern_name(imp, e).unwrap_or_else(|| format!("FUN_{e:08x}"));
            merged.push(NativeFunction {
                entry: e,
                name,
                size: 1,
            });
        }
    }
    merged.sort_by_key(|f| f.entry);
    merged.dedup_by_key(|f| f.entry);

    // A body ends where the next function begins. A proven span is the
    // furthest instruction attributed to an origin, so a single fallthrough
    // across inter-function padding stretches it over everything that
    // follows -- 27 KB across dozens of functions on the MinGW CRT. Two
    // functions cannot overlap, so the next entry is the hard boundary.
    // A size of zero says "no body was proven" and lets the store fill it from
    // the next entry; a proven size of one is a one-byte function, which the
    // MinGW CRT really has, and must survive that fill.
    for index in 0..merged.len() {
        let entry = merged[index].entry;
        merged[index].size = match proven_bodies.get(&entry) {
            Some(&span_end) => {
                let boundary = merged.get(index + 1).map_or(u64::MAX, |next| next.entry);
                span_end.min(boundary).saturating_sub(entry).max(1)
            }
            None => 0,
        };
    }
    imp.functions = merged;
    {
        let entries: HashSet<u64> = imp.functions.iter().map(|f| f.entry).collect();
        entry_modes.sort_unstable();
        entry_modes.dedup();
        // Flowed values were set before their targets decoded, so an entry's
        // recorded mode already agrees; the rest name mid-body targets a
        // later decode must read the same way.
        let mut flowed: Vec<(u64, u64)> = flowed_modes.drain().collect();
        flowed.sort_unstable();
        imp.contexts.extend(flowed.into_iter().map(|(address, value)| {
            crate::native::NativeContext {
                name: "LowBitCodeMode".into(),
                address,
                value,
            }
        }));
        imp.contexts.extend(
            entry_modes
                .iter()
                .filter(|(entry, _)| entries.contains(entry))
                .map(|&(entry, mode)| crate::native::NativeContext {
                    name: "LowBitCodeMode".into(),
                    address: entry,
                    value: mode,
                }),
        );
    }
    // Bodies are known now, so a stub's terminal branch can be identified.
    flow_endings.sort_unstable();
    record_stub_transfers(imp, &flow_endings);
    imp.indirect_transfers = flow_endings
        .iter()
        .filter(|&&(_, indirect)| indirect)
        .map(|&(address, _)| address)
        .collect();
    let no_return: HashSet<u64> = imp
        .functions
        .iter()
        .filter(|f| crate::nonreturn::known_no_return(&imp.format, &f.name))
        .map(|f| f.entry)
        .collect();
    // A transfer that cannot return ends the body, so an entry holding one is
    // a thunk to that destination. Unknown destinations stay ordinary flow.
    for (&entry, &destination) in &terminal_transfers {
        if no_return.contains(&destination) {
            imp.thunks.push(crate::native::NativeThunk {
                entry,
                destination,
                kind: lre_model::ThunkKind::Direct,
                source: crate::native::THUNK_SOURCE,
            });
        }
    }
    // Only retained functions carry facts, and a direct destination must be a
    // retained entry of its own. Unproven candidates leave no thunk row.
    let retained: HashSet<u64> = imp.functions.iter().map(|f| f.entry).collect();
    let mut owners = HashSet::new();
    let mut thunks = std::mem::take(&mut imp.thunks);
    thunks.retain(|thunk| {
        retained.contains(&thunk.entry)
            && thunk.destination != thunk.entry
            && (thunk.kind != lre_model::ThunkKind::Direct
                || retained.contains(&thunk.destination))
            && owners.insert(thunk.entry)
    });
    thunks.sort_unstable_by_key(|thunk| thunk.entry);
    imp.thunks = thunks;

    let mut xrefs = imp.xrefs.clone();
    let mut seen_xrefs: HashSet<(u64, u64)> = xrefs.iter().map(|x| (x.from, x.to)).collect();
    for (from, to) in calls {
        if seen_xrefs.insert((from, to)) {
            xrefs.push(NativeXref::new(from, to, "UNCONDITIONAL_CALL"));
        }
    }
    imp.xrefs = xrefs;
    close_call_targets(imp);
    imp.branch_transfers = branch_transfers;
    imp.branch_transfers.sort_unstable();
    imp.branch_transfers.dedup();
    record_branch_transfers(imp);
    Ok(())
}

/// Proves a candidate entry's own body, returning the address after its last
/// instruction.
///
/// The walk follows fallthrough only, so the extent it proves is a lower
/// bound rather than a guess: it starts at the candidate, requires every
/// instruction to decode, and stops at the first instruction that does not
/// fall through. `None` refuses the candidate -- an instruction that does not
/// decode, a body that runs into another entry (the code belongs to that
/// function, reached without a prologue), or a body with no terminator inside
/// the bound.
fn proven_body_end<P: FlowProvider>(
    entry: u64,
    flow_provider: &mut P,
    known_entries: &HashSet<u64>,
    in_code: &impl Fn(u64) -> bool,
) -> Option<u64> {
    // A function longer than this is not being refused for being long: the
    // bound stops a runaway walk through decoded padding.
    const MAX_INSTRUCTIONS: usize = 4096;
    let mut address = entry;
    for _ in 0..MAX_INSTRUCTIONS {
        if !in_code(address) || (address != entry && known_entries.contains(&address)) {
            return None;
        }
        let info = flow_provider.flow(&[address]).into_iter().next()?;
        if info.address != address
            || info.length == 0
            || matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl)
        {
            return None;
        }
        let end = address.checked_add(info.length as u64)?;
        match info.fallthrough {
            // Conditional terminators and ordinary instructions continue.
            Some(next) if next == end => address = next,
            // A fallthrough that is not the next address is a decoder
            // disagreement, not a body.
            Some(_) => return None,
            None => return Some(end),
        }
    }
    None
}

/// The provenance of a reference recorded from an unconditional branch that
/// leaves its function.
const BRANCH_PROVENANCE: &str = "native-import:branch";

/// Records every unconditional direct branch that leaves its own function.
///
/// A tail call reaches its target this way, and without the reference nothing
/// in the program model says the target is reached at all. A branch landing
/// inside the branching function is a loop; recording those would bury the
/// transfers under every `while`.
///
/// Idempotent: rows from an earlier run are replaced, because a target only
/// becomes a function once later passes have run.
pub fn record_branch_transfers(imp: &mut NativeImport) {
    if imp.branch_transfers.is_empty() {
        return;
    }
    imp.xrefs.retain(|xref| xref.provenance != BRANCH_PROVENANCE);
    let mut extents: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .filter(|function| function.size > 1)
        .map(|function| (function.entry, function.entry.saturating_add(function.size)))
        .collect();
    extents.sort_unstable();
    let entries: HashSet<u64> = imp.functions.iter().map(|function| function.entry).collect();
    let mut placed: std::collections::HashMap<(u64, u64), usize> = imp
        .xrefs
        .iter()
        .enumerate()
        .map(|(index, xref)| ((xref.from, xref.to), index))
        .collect();
    let transfers = std::mem::take(&mut imp.branch_transfers);
    for &(from, to) in &transfers {
        let Some(index) = extents
            .partition_point(|&(entry, _)| entry <= from)
            .checked_sub(1)
        else {
            continue;
        };
        let (entry, end) = extents[index];
        if from >= end || (entry <= to && to < end) {
            continue;
        }
        // Ghidra SharedReturnAnalysisCmd.processFunctionJumpReferences:376-425
        // gives an unconditional jump that leaves its function for another
        // function's entry a CALL_RETURN flow override, which turns the
        // reference into a call. A jump to an address that is not a function
        // entry keeps its jump reference: that is the tail call into code
        // nobody recovered, and the only record that it is reached.
        // The override is not applied when the branch instruction is itself a
        // function entry: Ghidra treats that as a thunk and leaves the jump
        // reference alone (`funcMgr.getFunctionAt(refInstrAddr) != null`).
        let kind = if entries.contains(&to) && !entries.contains(&from) {
            // The same rule sets the override that makes it one. A single
            // decoded unconditional branch is one flow reference by
            // construction, which is Ghidra's `getSingleFlowReferenceFrom`
            // condition; the jump leaving its own body is checked above.
            imp.shared_return_branches.push(from);
            "UNCONDITIONAL_CALL"
        } else {
            "UNCONDITIONAL_JUMP"
        };
        match placed.get(&(from, to)) {
            // Another pass recorded the same transfer -- the thunk pass does.
            // The kind of a branch reference is decided here, in one place;
            // the row keeps the provenance of whichever pass produced it.
            Some(&index) => {
                let existing = &mut imp.xrefs[index];
                if existing.kind == "UNCONDITIONAL_JUMP" || existing.kind == "UNCONDITIONAL_CALL" {
                    existing.kind = kind.into();
                }
            }
            None => {
                placed.insert((from, to), imp.xrefs.len());
                imp.xrefs
                    .push(NativeXref::with_provenance(from, to, kind, BRANCH_PROVENANCE));
            }
        }
    }
    imp.branch_transfers = transfers;
}

/// Turns each proven shared-return branch into the override that carries it.
///
/// Ghidra sets `FlowOverride.CALL_RETURN` on the branching instruction and
/// leaves an instruction that already carries an override alone
/// (`SharedReturnAnalysisCmd.processFunctionJumpReferences`, :417-423), so a
/// stub's own transfer keeps the thunk rule's override and its provenance.
pub fn apply_shared_returns(imp: &mut NativeImport) {
    let mut branches = std::mem::take(&mut imp.shared_return_branches);
    branches.sort_unstable();
    branches.dedup();
    for branch in &branches {
        if imp.flow_overrides.iter().any(|(address, _)| address == branch) {
            continue;
        }
        imp.flow_overrides.push((*branch, crate::native::SHARED_RETURN_SOURCE));
    }
    imp.shared_return_branches = branches;
}

fn linkage_flow_shape(target: u64, instructions: &[(u64, u64)], endings: &[(u64, bool)]) -> bool {
    let ending = endings.partition_point(|&(address, _)| address < target);
    let Some(&(terminal, true)) = endings.get(ending) else {
        return false;
    };
    let start = instructions.partition_point(|&(address, _)| address < target);
    let mut next = target;
    for &(address, length) in instructions[start..].iter().take(8) {
        if address != next || length == 0 {
            return false;
        }
        if address == terminal {
            return true;
        }
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        next = end;
    }
    false
}

fn promote_linkage(
    imp: &mut NativeImport,
    entries: &mut Vec<u64>,
    origins: &mut HashMap<u64, u64>,
    instructions: &[(u64, u64)],
    code: &[(u64, u64)],
    linkage: &LinkageResult,
) -> bool {
    let target = linkage.address;
    if linkage.needs_context
        || linkage.length == 0
        || !code.iter().any(|&(start, end)| {
            start <= target && target < end && linkage.length as u64 <= end - target
        })
    {
        return false;
    }
    let Some(slot) = linkage.slot.filter(|slot| *slot != 0) else {
        return false;
    };
    let Some((_, name)) = imp.externals.iter().find(|(address, _)| *address == slot) else {
        return false;
    };
    let name = name.clone();
    // A stub the walk already reached is still a linkage stub: the slot names
    // it. Ghidra applies the name to whatever function is there rather than
    // refusing (`ElfDefaultGotPltMarkup.processLinkageTable`), which is the
    // difference between calling `printf` and calling `FUN_00020750`. Only an
    // auto-name is replaced; a name from the image stays.
    if let Some(existing) = imp.functions.iter_mut().find(|f| f.entry == target) {
        if !existing.name.starts_with("FUN_") {
            return false;
        }
        existing.name = name.clone();
        existing.size = existing.size.max(linkage.length as u64);
    } else {
        imp.functions.push(NativeFunction {
            entry: target,
            name: name.clone(),
            size: linkage.length as u64,
        });
    }
    // The slot that named this stub is also the destination it reaches, so
    // the stub is a linkage thunk. Stock Ghidra records the same fact with
    // its own EXTERNAL-block stub as the destination; the slot is the
    // address the stub's own instructions read.
    imp.thunks.push(crate::native::NativeThunk {
        entry: target,
        destination: slot,
        kind: lre_model::ThunkKind::Linkage,
        source: crate::native::THUNK_SOURCE,
    });
    imp.externals.push((target, name.clone()));
    entries.push(target);
    origins.insert(target, target);
    let start = instructions.partition_point(|&(address, _)| address < target);
    for &(address, _) in &instructions[start..] {
        if address - target >= linkage.length as u64 {
            break;
        }
        origins.insert(address, target);
    }
    true
}

/// Conservative subset of Ghidra CreateThunkFunctionCmd.getSimpleFlow:
/// an established entry's pure branch, optionally after one proven no-op.
/// Unlike arbitrary branch closure, the destination must independently decode.
fn confirmed_thunks<P: FlowProvider>(
    imp: &NativeImport,
    entries: &[u64],
    landing_entries: &HashMap<u64, u64>,
    visited: &HashSet<u64>,
    extents: &[(u64, u64)],
    addresses: &[u64],
    flows: &[crate::native_runtime::FlowResult],
    provider: &mut P,
) -> HashMap<u64, u64> {
    let mut candidates = HashMap::new();
    for (&address, flow) in addresses.iter().zip(flows) {
        if flow.address != address
            || flow.length == 0
            || !flow.pure_jump
            || flow.kind != FlowKind::Branch
            || flow.fallthrough.is_some()
            || flow.targets.len() != 1
            || !imp.mappings.iter().any(|m| {
                m.flags & 4 != 0
                    && address >= m.vaddr
                    && address - m.vaddr < m.size
                    && flow.length as u64 <= m.size - (address - m.vaddr)
            })
        {
            continue;
        }
        let entry = if entries.contains(&address) {
            address
        } else if let Some(&entry) = landing_entries.get(&address) {
            entry
        } else {
            continue;
        };
        let target = flow.targets[0];
        if target == address
            || target == entry
            || (visited.contains(&target) && !entries.contains(&target))
            || !imp
                .mappings
                .iter()
                .any(|m| m.flags & 4 != 0 && target >= m.vaddr && target - m.vaddr < m.size)
            || imp
                .functions
                .iter()
                .any(|f| target > f.entry && target - f.entry < f.size)
            || extents
                .iter()
                .any(|&(start, size)| target > start && target - start < size)
        {
            continue;
        }
        candidates.insert(address, target);
    }
    if candidates.is_empty() {
        return candidates;
    }
    let mut targets: Vec<_> = candidates.values().copied().collect();
    targets.sort_unstable();
    targets.dedup();
    let valid: Vec<_> = targets
        .iter()
        .copied()
        .zip(provider.flow(&targets))
        .filter(|&(target, ref flow)| {
            flow.address == target
                && flow.length != 0
                && !matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl)
                && imp.mappings.iter().any(|m| {
                    m.flags & 4 != 0
                        && target >= m.vaddr
                        && target - m.vaddr < m.size
                        && flow.length as u64 <= m.size - (target - m.vaddr)
                })
        })
        .map(|(target, _)| target)
        .collect();
    candidates.retain(|_, target| valid.binary_search(target).is_ok());
    candidates
}

/// Records the PLT header's transfer as call-like flow, from the image's ABI.
///
/// The System V ABI reserves the first three `DT_PLTGOT` words: the
/// `.dynamic` address, the link-map, and the resolver the PLT header jumps
/// through. A data reference to that third word from inside a function is
/// therefore a call to the dynamic linker, which is why stock Ghidra reports
/// no jumptable there. Nothing is inferred when the image declares no
/// `DT_PLTGOT` or nothing reads the slot.
pub(crate) fn record_plt_header_flow(imp: &mut NativeImport) {
    let Some(slot) = imp.plt_resolver_slot else {
        return;
    };
    let readers: Vec<u64> = imp
        .xrefs
        .iter()
        .filter(|xref| {
            xref.to == slot && matches!(xref.kind.as_str(), "DATA" | "READ" | "WRITE")
        })
        .map(|xref| xref.from)
        .collect();
    // Stock Ghidra records no thunk here -- its own thunk table is empty for
    // this image -- so the fact is what it is: one instruction whose transfer
    // behaves like a call. A thunk row would break set-level thunk parity.
    for from in readers {
        let Some(index) = imp
            .functions
            .iter()
            .rposition(|function| function.entry <= from)
        else {
            continue;
        };
        let entry = imp.functions[index].entry;
        // A size of zero means the store fills the body from the next entry,
        // so use that boundary rather than treating it as one byte.
        let span = match imp.functions[index].size {
            0 => imp
                .functions
                .get(index + 1)
                .map_or(u64::MAX, |next| next.entry)
                .saturating_sub(entry),
            size => size,
        };
        if from >= entry.saturating_add(span) {
            continue;
        }
        // The load proves which function it is; the branch is what transfers.
        // A function that reads the slot and never branches through it is not
        // a PLT header -- an ordinary guard byte can share the address of a
        // word the PLT object does not reach -- and an override on a load
        // truncates the flow it was meant to describe (m4-022).
        let Some(branch) = imp
            .indirect_transfers
            .iter()
            .copied()
            .filter(|address| *address >= entry && *address < entry + span)
            .next_back()
        else {
            continue;
        };
        if !imp
            .flow_overrides
            .iter()
            .any(|(address, _)| *address == branch)
        {
            imp.flow_overrides
                .push((branch, crate::native::PLT_HEADER_SOURCE));
        }
    }

}

/// Records the branch that performs each thunk's transfer.
///
/// A linkage stub loads a slot and branches through it; on AArch64 and PowerPC
/// those are different instructions, so the override has to name the branch --
/// the indirect ending the same walk proved when it accepted the stub's shape
/// (`linkage_flow_shape`). A direct thunk's transfer is a direct branch, which
/// the reference pass records as an edge to the thunked address.
///
/// Ghidra sets no shared-return override when the branch instruction is itself
/// a function entry (`SharedReturnAnalysisCmd.processFunctionJumpReferences`,
/// SharedReturnAnalysisCmd.java:400-423). A linkage stub is the exception: its
/// transfer goes through a slot the image names as an import, so it is a call
/// whatever its shape.
fn record_stub_transfers(imp: &mut NativeImport, endings: &[(u64, bool)]) {
    let entries: HashSet<u64> = imp.functions.iter().map(|function| function.entry).collect();
    let thunks: Vec<(u64, u64, u64, lre_model::ThunkKind)> = imp
        .thunks
        .iter()
        .filter_map(|thunk| {
            let size = imp
                .functions
                .iter()
                .find(|function| function.entry == thunk.entry)
                .map(|function| function.size.max(1))?;
            Some((thunk.entry, size, thunk.destination, thunk.kind))
        })
        .collect();
    for (entry, size, destination, kind) in thunks {
        let end = entry.saturating_add(size);
        let branch = match kind {
            lre_model::ThunkKind::Linkage => {
                let start = endings.partition_point(|&(address, _)| address < entry);
                endings[start..]
                    .iter()
                    .take_while(|&&(address, _)| address < end)
                    .filter(|&&(_, indirect)| indirect)
                    .map(|&(address, _)| address)
                    .last()
            }
            lre_model::ThunkKind::Direct => imp
                .xrefs
                .iter()
                .filter(|xref| {
                    xref.to == destination && xref.from >= entry && xref.from < end
                })
                .map(|xref| xref.from)
                .max(),
        };
        let Some(address) = branch else {
            continue;
        };
        if kind == lre_model::ThunkKind::Direct && entries.contains(&address) {
            continue;
        }
        if !imp
            .flow_overrides
            .iter()
            .any(|(recorded, _)| *recorded == address)
        {
            imp.flow_overrides
                .push((address, crate::native::THUNK_SOURCE));
        }
    }
}
