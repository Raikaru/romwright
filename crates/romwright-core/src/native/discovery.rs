//! Mapped-image discovery: SLEIGH supplies instruction lengths and call targets;
//! the existing worklist supplies control-flow closure. No ISA-specific decoder.
use super::{
    candidate_address_is_valid, candidate_flow_is_valid, close_call_targets, code_ranges,
    extern_name, CandidateFilterContext, ImportError, NativeFunction, NativeImport, NativeXref,
    Result,
};
use crate::native_runtime::{
    FlowKind, FlowResult, LinkageContext, LinkageResult, NativeRuntimeError, SleighFlow, SleighLifter,
};

/// The module's sets and maps hash with `WordHasher`: their keys are
/// addresses, which SipHash spent a measurable share of every walk on, and
/// nothing here depends on iteration order (every iterated collection is
/// sorted, max-merged or drained into a sorted list first).
type HashMap<K, V> = std::collections::HashMap<K, V, std::hash::BuildHasherDefault<WordHasher>>;
type HashSet<T> = std::collections::HashSet<T, std::hash::BuildHasherDefault<WordHasher>>;

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
    /// decoded. A provider with no decoder has nothing to tell.
    fn set_context(&mut self, _name: &str, _address: u64, _value: u64) {}
    /// The instruction set held at an address, decodable or not; `None` for a
    /// provider with no decoder or a language without one.
    fn mode_at(&mut self, _address: u64) -> Option<u64> {
        None
    }
    fn linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult>;
    fn plt_linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult>;
    fn context_linkages(&mut self, contexts: &[LinkageContext]) -> Vec<LinkageResult>;
}

/// Decoder lanes for an image's reference pass: the configured count
/// (`console_shards`), but no more lanes than the image has code for. A lane
/// is a decoder, which holds the language's tables (megabytes), and it pays
/// for itself only when there is a lot to walk: one lane answers every range
/// of a 20 KiB program in milliseconds. One lane per [`SMALL_IMAGE`] of
/// mapped bytes, so every image of a megabyte or more runs the configured
/// count and nothing large changes. (The reference lanes claim ranges as they
/// finish them, so no result can depend on which lane took which; the
/// discovery lanes' slicing is fixed by the count, so a small image keeps all
/// of them and shares one decoder between them: [`Lanes`].)
pub(super) fn lanes_for(import: &NativeImport) -> usize {
    import.cfg.console_shards.max(1).min(1 + (mapped_bytes(import) / SMALL_IMAGE) as usize)
}

/// Mapped bytes below which a program is small enough to be walked by one
/// decoder before a second would pay for itself.
const SMALL_IMAGE: u64 = 256 * 1024;

fn mapped_bytes(import: &NativeImport) -> u64 {
    import.mappings.iter().map(|mapping| mapping.bytes.len() as u64).sum()
}

/// The walk's in-process SLEIGH flow decoders (`SleighFlow`), one per lane
/// a batch splits across. Each lane is what one console of the walk was:
/// its own context database, into which its own decodes commit their
/// `globalset`s, while a mode the walk sets reaches every lane. A batch
/// splits into the same contiguous slices it split into across the main
/// console and its shards, so every decode sees exactly the commits it saw
/// on a console; requests inside a batch are otherwise independent and the
/// results concatenate in input order.
///
/// A lane is a database of committed modes and a decoder, and the decoder is
/// the language's tables, megabytes. A small program (under [`SMALL_IMAGE`])
/// is walked in milliseconds, so its lanes, and the plain lifter, share one
/// decoder: it holds the first lane's database and swaps in a later lane's
/// for the slice that lane answers, and the lifter's, with the language's own
/// templates in place of the marked ones, for a lifter call. Every lane then
/// sees exactly the decodes, and commits, it would have seen with a decoder of
/// its own: only the order the slices run in differs, and they never touched
/// each other.
struct Lanes {
    lanes: Vec<SleighFlow>,
    /// Lanes batches split across (the configured count).
    target: usize,
    /// A small image: the databases of lanes `1..target`, not in use, while
    /// the one decoder in `lanes` serves every lane.
    shadows: Vec<Option<Box<dyn kuna_sleigh::globalcontext::ContextDatabase>>>,
    /// The walk's plain p-code lifter: linkage evidence reads p-code, which a
    /// flow decoder's markers would disturb, and the pattern search reads the
    /// loaded bytes. It holds every mode the walk sets, as the lanes do.
    /// `None` when the one decoder in `lanes` is the lifter too
    /// ([`Lanes::with_lifter`]).
    lifter: Option<SleighLifter>,
    /// The lifter's database while the shared decoder holds a lane's.
    lifter_db: Option<Box<dyn kuna_sleigh::globalcontext::ContextDatabase>>,
    /// Batches handed to the lanes.
    batches: u64,
}

impl Lanes {
    /// The lifter and `count` flow lanes on the image and its contexts,
    /// built concurrently; a small image gets one decoder for all its lanes
    /// (see the type).
    fn open(import: &NativeImport, count: usize) -> std::result::Result<Self, NativeRuntimeError> {
        Self::open_with(import, count, count > 1 && mapped_bytes(import) < SMALL_IMAGE)
    }

    /// `open`, with whether the decoder is shared given.
    fn open_with(import: &NativeImport, count: usize, shared: bool) -> std::result::Result<Self, NativeRuntimeError> {
        let target = count.max(1);
        let (lanes, lifter) = std::thread::scope(|scope| {
            let lifter = (!shared).then(|| scope.spawn(|| SleighLifter::mapped_pooled(&import.cfg, import)));
            let handles: Vec<_> = (0..if shared { 1 } else { target })
                .map(|_| scope.spawn(|| SleighFlow::mapped_pooled(&import.cfg, import)))
                .collect();
            let lanes = handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(NativeRuntimeError("flow decoder panicked".into())))
                })
                .collect::<std::result::Result<Vec<_>, _>>();
            let lifter = lifter
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(NativeRuntimeError("SLEIGH lifter panicked".into())))
                })
                .transpose();
            (lanes, lifter)
        });
        let lanes = lanes?;
        // Every lane starts from the same database: the spec's, with the
        // image's modes set.
        let shadows = if shared { (1..target).map(|_| Some(lanes[0].clone_context_db())).collect() } else { Vec::new() };
        let lifter_db = shared.then(|| lanes[0].clone_context_db());
        Ok(Self { lanes, target, shadows, lifter: lifter?, lifter_db, batches: 0 })
    }

    /// Runs `f` on the plain lifter. When the decoder is shared it takes the
    /// lifter's database and the language's own templates for the call, and
    /// goes back to the first lane's and the marked ones after.
    fn with_lifter<R>(&mut self, f: impl FnOnce(&mut SleighLifter) -> R) -> R {
        if let Some(lifter) = self.lifter.as_mut() {
            return f(lifter);
        }
        let own = self.lifter_db.take().expect("the lifter's database is back after its call");
        let decoder = &mut self.lanes[0];
        let lane = decoder.swap_context_db(own);
        decoder.set_plain_templates(true);
        let answer = f(decoder.lifter_mut());
        decoder.set_plain_templates(false);
        self.lifter_db = Some(decoder.swap_context_db(lane));
        answer
    }

    /// The slice of a batch of `len` each lane answers, in lane order
    /// (`flow_batch_sharded`'s split: everything to the first lane when
    /// there are fewer than two requests per lane).
    fn spans(lanes: usize, len: usize) -> usize {
        if lanes == 1 || len < 2 * lanes { len.max(1) } else { len.div_ceil(lanes) }
    }

    fn flow(&mut self, addresses: &[u64]) -> std::result::Result<Vec<FlowResult>, NativeRuntimeError> {
        self.batches += 1;
        let span = Self::spans(self.target, addresses.len());
        if span >= addresses.len() {
            return Ok(self.lanes[0].flow(addresses));
        }
        if !self.shadows.is_empty() {
            // One decoder, every lane's slice in turn.
            let mut chunks = addresses.chunks(span);
            let mut flows = self.lanes[0].flow(chunks.next().expect("a batch has a first slice"));
            for (shadow, slice) in self.shadows.iter_mut().zip(chunks) {
                let own = shadow.take().expect("a lane's database is back after its slice");
                let first = self.lanes[0].swap_context_db(own);
                flows.extend(self.lanes[0].flow(slice));
                *shadow = Some(self.lanes[0].swap_context_db(first));
            }
            return Ok(flows);
        }
        std::thread::scope(|scope| {
            let mut lanes = self.lanes.iter_mut().zip(addresses.chunks(span));
            let (first, first_slice) = lanes.next().expect("a batch has a first slice");
            let handles: Vec<_> = lanes.map(|(lane, slice)| scope.spawn(move || lane.flow(slice))).collect();
            let mut flows = first.flow(first_slice);
            for handle in handles {
                flows.extend(handle.join().map_err(|_| NativeRuntimeError("flow lane panicked".into()))?);
            }
            Ok(flows)
        })
    }

    fn set_contexts(&mut self, contexts: &[crate::native::NativeContext]) -> std::result::Result<(), NativeRuntimeError> {
        self.with_lifter(|lifter| lifter.set_contexts(contexts))?;
        for shadow in &mut self.shadows {
            let own = shadow.take().expect("a lane's database is back after its slice");
            let first = self.lanes[0].swap_context_db(own);
            let set = self.lanes[0].set_contexts(contexts);
            *shadow = Some(self.lanes[0].swap_context_db(first));
            set?;
        }
        self.lanes.iter_mut().try_for_each(|lane| lane.set_contexts(contexts))
    }
}

/// Discovery's flow: the in-process decoder lanes answer flow, and the
/// walk's plain lifter answers the pattern search and linkage questions,
/// which decode under the modes the walk sets (every context reaches the
/// lifter as it reaches the lanes).
struct LaneProvider {
    lanes: Lanes,
    decoded: Option<std::collections::BTreeMap<u64, FlowResult>>,
    /// Set when `decoded` holds an earlier round's walk: the contexts that
    /// walk set, and every context address known, by name. A context this
    /// walk sets that the last one did not drops what it could re-mode.
    remodel: Option<Remodel>,
    failure: Option<NativeRuntimeError>,
    /// Instructions decoded for this walk.
    instructions: u64,
}

struct Remodel {
    previous: std::collections::HashSet<(String, u64, u64)>,
    points: HashMap<String, std::collections::BTreeSet<u64>>,
    set: Vec<crate::native::NativeContext>,
}

impl LaneProvider {
    fn new(
        lanes: Lanes,
        decoded: std::collections::BTreeMap<u64, FlowResult>,
        remodel: Option<Remodel>,
    ) -> Self {
        Self {
            lanes,
            decoded: Some(decoded),
            remodel,
            failure: None,
            instructions: 0,
        }
    }

    /// Decoder batches and decoded instructions for this walk.
    fn flow_stats(&self) -> romwright_model::FlowStats {
        romwright_model::FlowStats {
            requests: self.lanes.batches,
            instructions: self.instructions,
            // Set by the caller, which owns the round loop.
            rounds: 0,
        }
    }

    /// One batch through the lanes (through the first only, for the seed
    /// scan).
    fn decode(&mut self, addresses: &[u64], first_lane: bool) -> std::result::Result<Vec<FlowResult>, NativeRuntimeError> {
        let flows = if first_lane {
            self.lanes.batches += 1;
            self.lanes.lanes[0].flow(addresses)
        } else {
            self.lanes.flow(addresses)?
        };
        self.instructions += flows.len() as u64;
        Ok(flows)
    }
}

impl FlowProvider for LaneProvider {
    fn set_context(&mut self, name: &str, address: u64, value: u64) {
        if let (Some(remodel), Some(decoded)) = (self.remodel.as_mut(), self.decoded.as_mut()) {
            let points = remodel.points.entry(name.to_string()).or_default();
            if !remodel.previous.contains(&(name.to_string(), address, value)) {
                let next = points.range(address + 1..).next().copied().unwrap_or(u64::MAX);
                let stale: Vec<u64> = decoded.range(address..next).map(|(&key, _)| key).collect();
                for key in stale {
                    decoded.remove(&key);
                }
            }
            points.insert(address);
            remodel.set.push(crate::native::NativeContext { name: name.to_string(), address, value });
        }
        let context = crate::native::NativeContext {
            name: name.to_string(),
            address,
            value,
        };
        if let Err(error) = self.lanes.set_contexts(std::slice::from_ref(&context)) {
            self.failure = Some(error);
        }
    }

    fn mode_at(&mut self, address: u64) -> Option<u64> {
        self.lanes.lanes[0].mode_at(address)
    }

    fn flow(&mut self, addresses: &[u64]) -> Vec<FlowResult> {
        // A walk visits each instruction once; the cache serves the next
        // round's walk and the section sweep. Every address is looked up
        // once: later rounds answer nearly all of them from here.
        let decoded = self.decoded.as_ref().expect("decoded cache");
        let mut answers: Vec<Option<FlowResult>> =
            addresses.iter().map(|address| decoded.get(address).cloned()).collect();
        let missing: Vec<u64> = addresses
            .iter()
            .zip(&answers)
            .filter(|(_, answer)| answer.is_none())
            .map(|(&address, _)| address)
            .collect();
        if missing.is_empty() {
            return answers.into_iter().flatten().collect();
        }
        let flows = match self.decode(&missing, false) {
            Ok(flows) => flows,
            Err(error) => {
                self.failure = Some(error);
                return Vec::new();
            }
        };
        let asked: HashSet<u64> = missing.iter().copied().collect();
        // A decoded flow keyed at an address that was already answered
        // replaces that answer in the cache; read every address back then.
        let replaced = flows.iter().any(|flow| !asked.contains(&flow.address));
        let decoded = self.decoded.as_mut().expect("decoded cache");
        decoded.extend(flows.into_iter().map(|flow| (flow.address, flow)));
        for (address, answer) in addresses.iter().zip(answers.iter_mut()) {
            if replaced || answer.is_none() {
                *answer = decoded.get(address).cloned();
            }
        }
        answers.into_iter().flatten().collect()
    }
    fn linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult> {
        self.lanes.with_lifter(|lifter| lifter.linkages(addresses, false))
    }

    fn plt_linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult> {
        self.lanes.with_lifter(|lifter| lifter.linkages(addresses, true))
    }

    fn context_linkages(&mut self, contexts: &[LinkageContext]) -> Vec<LinkageResult> {
        self.lanes.with_lifter(|lifter| lifter.context_linkages(contexts))
    }
}

/// All supported languages use the same mapped addresses and flow worklist.
/// Whether discovery ran: false when the image has nothing to walk or the
/// decoders could not load it, which the import's diagnostics then say.
pub(super) fn discover_seeded(import: &mut NativeImport) -> bool {
    if import.mappings.is_empty() {
        import.diagnose(romwright_model::DiagnosticSeverity::Info, "discovery", "the image has no mapped bytes");
        return false;
    }
    // The walk's decoders build. Nothing before the walk changes the image
    // or its contexts.
    let mut decoders = match Lanes::open(import, import.cfg.console_shards.max(1)) {
        Ok(decoders) => decoders,
        Err(error) => {
            import.diagnose(romwright_model::DiagnosticSeverity::Degraded, "discovery", format!("SLEIGH flow decoder did not load the image: {error}"));
            return false;
        }
    };
    let patterns_started = std::time::Instant::now();
    let ranges = code_ranges(import);
    if ranges.is_empty() {
        return false;
    }
    let patterns = match decoders.with_lifter(|lifter| lifter.function_patterns(&ranges)) {
        Ok(patterns) => patterns,
        Err(error) => {
            import.diagnose(romwright_model::DiagnosticSeverity::Degraded, "discovery", format!("the pattern search failed: {error}"));
            return false;
        }
    };
    import.pattern_labels = patterns.labels();
    super::phase(import, "patterns", patterns_started);
    let flow_started = std::time::Instant::now();
    forget_remodeled_flows(import);
    let mut points: HashMap<String, std::collections::BTreeSet<u64>> = HashMap::default();
    for context in import.contexts.iter().chain(&import.flow_cache_walk_contexts) {
        points.entry(context.name.clone()).or_default().insert(context.address);
    }
    let previous = import
        .flow_cache_walk_contexts
        .iter()
        .map(|context| (context.name.clone(), context.address, context.value))
        .collect();
    let mut provider = LaneProvider::new(
        decoders,
        std::mem::take(&mut import.flow_cache),
        Some(Remodel { previous, points, set: Vec::new() }),
    );
    let walked = flow_discover_with_candidates(import, &[], Some(&patterns), &mut provider);
    if let Err(error) = walked {
        import.diagnose(romwright_model::DiagnosticSeverity::Degraded, "discovery", format!("SLEIGH flow failed: {error}"));
        return false;
    }
    if let Some(failure) = provider.failure.as_ref().map(ToString::to_string) {
        import.diagnose(romwright_model::DiagnosticSeverity::Degraded, "discovery", format!("SLEIGH flow failed: {failure}"));
        return false;
    }
    // PE: the function behind a walked function's fill (pe/fill.rs), then the one behind that: a run of
    // unreferenced functions is found one hop per pass, each pass walking only what is new.
    for _ in 0..super::pe::fill::PASSES {
        let starts = super::pe::fill::starts(import);
        if starts.is_empty() {
            break;
        }
        import.fill_starts.extend(starts.iter().copied());
        import.functions.extend(starts.into_iter().map(|entry| NativeFunction { entry, name: format!("FUN_{entry:08x}"), size: 1 }));
        if let Err(error) = flow_discover_with_candidates(import, &[], Some(&patterns), &mut provider) {
            import.diagnose(romwright_model::DiagnosticSeverity::Degraded, "discovery", format!("SLEIGH flow failed: {error}"));
            return false;
        }
    }
    super::phase(import, "flow", flow_started);
    import.flow = Some(provider.flow_stats());
    import.flow_cache = provider.decoded.take().unwrap_or_default();
    import.flow_cache_contexts = import.contexts.len();
    import.flow_cache_walk_contexts = provider.remodel.take().map(|remodel| remodel.set).unwrap_or_default();
    true
}

/// Drops the cached flow a context added since the last walk could change:
/// a console context holds from its address to the next one of the same
/// name, so everything in between may now decode in another mode.
fn forget_remodeled_flows(import: &mut NativeImport) {
    let added = import.flow_cache_contexts.min(import.contexts.len());
    if added == import.contexts.len() || import.flow_cache.is_empty() {
        return;
    }
    let mut ranges: Vec<(u64, u64)> = import.contexts[added..]
        .iter()
        .map(|context| {
            let next = import
                .contexts
                .iter()
                .filter(|other| other.name == context.name && other.address > context.address)
                .map(|other| other.address)
                .min()
                .unwrap_or(u64::MAX);
            (context.address, next)
        })
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    for (start, end) in merged {
        let stale: Vec<u64> = import.flow_cache.range(start..end).map(|(&key, _)| key).collect();
        for key in stale {
            import.flow_cache.remove(&key);
        }
    }
}

pub(super) fn discover_mapped(import: &mut NativeImport) -> Result<()> {
    let bad = |error: NativeRuntimeError| ImportError::Bad(error.to_string());
    let ranges = code_ranges(import);
    if ranges.is_empty() {
        return Ok(());
    }
    let in_code = |address| {
        ranges
            .iter()
            .any(|&(start, end)| start <= address && address < end)
    };
    let decoders = Lanes::open(import, import.cfg.console_shards.max(1)).map_err(bad)?;
    let mut provider = LaneProvider::new(decoders, std::collections::BTreeMap::new(), None);
    let mut cursors: Vec<_> = ranges
        .iter()
        .map(|&(start, end)| (start, end, true))
        .collect();
    let mut candidates = Vec::new();
    let recorded = import.xrefs.len();
    let mut addresses = Vec::with_capacity(cursors.len());
    // Stripped images retain calls in code that is not reachable from startup.
    // Walk section bytes by the decoder's lengths, including after terminators.
    // The scan is the first lane's alone.
    while !cursors.is_empty() {
        addresses.clear();
        addresses.extend(cursors.iter().map(|&(address, _, _)| address));
        let flows = provider.decode(&addresses, true).map_err(bad)?;
        if flows.len() != addresses.len() {
            return super::err("incomplete SLEIGH seed scan");
        }
        for ((address, end, boundary), flow) in cursors.iter_mut().zip(flows) {
            if flow.address != *address || flow.length == 0 {
                return super::err("invalid SLEIGH seed-scan response");
            }
            if !matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl) {
                // Fill between two objects (MIPS decodes a zero word as a
                // `nop`) is no start, and it does not end the boundary: the
                // first instruction after it is the next object's.
                let fill = opens_with_fill(import, *address);
                if *boundary && !fill && !after_fill(import, *address) {
                    candidates.push(*address);
                }
                *boundary = flow.kind == FlowKind::Return || *boundary && fill;
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
            provider.decoded.as_mut().expect("decoded cache").insert(*address, flow);
            *address = next;
        }
        cursors.retain(|&(address, end, _)| address < end);
    }
    // On the r5900 (the other MIPS sets decode coprocessor words SLEIGH lacks in
    // real code), a call sits among instructions: within 16 words either side of a real
    // `jal` every word decodes, and a `jal`-shaped word of data has bytes SLEIGH
    // has no instruction for next to it. Of Persona 4's 63,382 `jal` words
    // 63,039 of the 63,040 inside truth rows have none such near them, and
    // every one of the 342 outside has; the 3 beyond that (God Hand 2 of
    // 40,411) are calls whose targets other calls reach. The data between the
    // code and the `.sdata` made 37 functions of 1 to 13 bytes there (Dark
    // Cloud 3, Dark Chronicle 3), none in any truth row of the 8 PS2 games.
    if import.language.starts_with("r5900") {
        let decoded = provider.decoded.as_ref().expect("decoded cache");
        let mut index = 0;
        import.xrefs.retain(|xref| {
            index += 1;
            index <= recorded || !xref.kind.ends_with("CALL") || !has_undecodable_neighbour(decoded, xref.from)
        });
    }
    // Data that shares the executable flag decodes as plausible instructions:
    // every word that looks like a return would start a "function", and every
    // one that looks like a call would make a function of its target.
    let dense = call_dense_ranges(import);
    let in_dense = |address: u64| dense.iter().any(|&(start, end)| start <= address && address < end);
    candidates.retain(|&address| in_dense(address));
    let mut index = 0;
    import.xrefs.retain(|xref| {
        index += 1;
        index <= recorded || !xref.kind.ends_with("CALL") || in_dense(xref.from)
    });
    close_call_targets(import);
    if import.unrelocated_data_pointers && super::mips_language(&import.language) {
        let known: HashSet<u64> = import.functions.iter().map(|function| function.entry).collect();
        let starts: Vec<u64> = after_fill_starts(import, &dense).into_iter().filter(|start| !known.contains(start)).collect();
        import.fill_starts.extend(starts.iter().copied());
        import.functions.extend(starts.into_iter().map(|entry| NativeFunction { entry, name: format!("FUN_{entry:08x}"), size: 1 }));
    }
    let patterns = provider
        .lanes
        .with_lifter(|lifter| lifter.function_patterns(&ranges))
        .map_err(|error| ImportError::Bad(error.to_string()))?;
    // An instruction set decodes at its own alignment only: an entry between
    // two words is the decode of a misaligned stretch of data (a big-endian
    // console DOL's "Metrowerks Target Resident Kernel" string, read from +2).
    let alignment = patterns::instruction_alignment(&import.language, patterns.alignment);
    candidates.retain(|&address| address % alignment == 0);
    import.pattern_labels = patterns.labels();
    let walked = flow_discover_with_candidates(import, &candidates, Some(&patterns), &mut provider);
    walked?;
    if let Some(error) = provider.failure.take() {
        return Err(ImportError::Bad(error.to_string()));
    }
    import.flow = Some(provider.flow_stats());
    Ok(())
}

/// The most bytes of code between two calls into it, for the boundary sweep to
/// trust a range. Real code is called once per 290-930 bytes (the MIPS rule's
/// plausible targets, 8 PS2 games: Ratchet & Clank `core.text` 290, God Hand
/// `.text` 483, Persona 4 929); data flagged executable is called by none
/// (God Hand `.data`, 320 KB; the `.vutext` VU microcode of Fatal Frame,
/// Ratchet & Clank and Digital Devil Saga).
const SWEEP_CALL_SPAN: u64 = 4096;

/// The executable ranges code fills, as far as calls say: at least one
/// distinct call target inside per `SWEEP_CALL_SPAN` bytes (a range of no more
/// than that is kept, a stub section nothing need call). A range nothing
/// calls is data the loader flagged executable (PS2 `.data` is `WAX`, and
/// `.vutext` holds VU microcode): the boundary sweep proposes no start in it
/// and the data-pointer seeding names no entry in it. Call targets are the
/// call references recorded so far, which include every direct call the
/// sweep's scan decoded, junk too: God Hand's `.data` decodes 140 `jal` into
/// itself. On MIPS a target counts when it could start a function, a frame
/// opener or the instruction after a `jr ra`/`j`/`b` and its delay slot;
/// none of those 140 does, against 81-85% of the calls into the code ranges
/// of God Hand, Fatal Frame, Persona 4 and Ratchet & Clank.
pub(crate) fn call_dense_ranges(imp: &NativeImport) -> Vec<(u64, u64)> {
    let mips = super::mips_language(&imp.language);
    // Measured on MIPS only: a GameCube overlay is called mostly by relocation,
    // which a scan of its unrelocated bytes cannot see (Mario Party 4 lost 0.4
    // points of recall to the rule).
    if !mips {
        return code_ranges(imp);
    }
    let big = imp.language.contains(":BE:");
    let word = |address: u64| -> Option<u32> {
        imp.mappings.iter().find_map(|mapping| {
            let at = usize::try_from(address.checked_sub(mapping.vaddr)?).ok()?;
            let raw: [u8; 4] = mapping.bytes.get(at..at + 4)?.try_into().ok()?;
            Some(if big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
        })
    };
    let starts_function = |target: u64| {
        word(target).is_some_and(|first| first >> 16 == 0x27bd && first & 0x8000 != 0)
            || target
                .checked_sub(8)
                .and_then(word)
                .is_some_and(|before| before == 0x03e0_0008 || before >> 26 == 2 || before >> 16 == 0x1000)
    };
    let mut targets: Vec<u64> = imp
        .xrefs
        .iter()
        .filter(|xref| xref.kind.ends_with("CALL") && starts_function(xref.to))
        .map(|xref| xref.to)
        .collect();
    targets.sort_unstable();
    targets.dedup();
    code_ranges(imp)
        .into_iter()
        .filter(|&(start, end)| {
            let inside = targets.partition_point(|&target| target < end) - targets.partition_point(|&target| target < start);
            end - start <= SWEEP_CALL_SPAN || inside as u64 * SWEEP_CALL_SPAN >= end - start
        })
        .collect()
}

/// Zero bytes before which a sweep start is not a function start: the longest
/// run of zeros before a symbol-named function is 20 bytes on the GameCube
/// DOLs (bond, 8,565 functions), 63 on PS2 Capcom Fighting Evolution (8,794)
/// and 0 on dungeon_game (783); the `gTRKInterruptVectorTable` handlers that
/// followed a `rfi` sit after 120-1,228 zero bytes (bond, base, Animal Crossing).
const FILL_GAP: u64 = 64;

/// Whether the `FILL_GAP` bytes before `address` are all zero.
fn after_fill(imp: &NativeImport, address: u64) -> bool {
    imp.mappings.iter().any(|mapping| {
        address >= mapping.vaddr + FILL_GAP
            && address - mapping.vaddr <= mapping.bytes.len() as u64
            && mapping.bytes[(address - mapping.vaddr - FILL_GAP) as usize..(address - mapping.vaddr) as usize]
                .iter()
                .all(|&byte| byte == 0)
    })
}

/// Ghidra's disassembler stops a block at the seventeenth consecutive
/// instruction whose bytes are all one repeated value, the same value as the
/// instruction before: `Disassembler.disassembleInstructionBlock` asks
/// `RepeatInstructionByteTracker.exceedsRepeatBytePattern` of every parsed
/// instruction (limit `MAX_REPEAT_PATTERN_LENGTH`, 16) and ends the block on
/// a parse conflict there ("Maximum run of repeated byte instructions
/// exceeded"). The tracker resets where a block starts: an entry, a branch
/// target, and the fallthrough of a call, which ends its block
/// (`endBlockOnCall`). Zero fill decodes as an ordinary instruction in most
/// sets (Thumb `lsls r0, r0, #0`), so without the limit one seed in a zeroed
/// region walks all of it: on pokeemerald, runs of 12-108 KB of zeros
/// between its data sections, each a function body the reference pass then
/// propagated through.
///
/// Unlike Ghidra, an instruction with no p-code does not count: a MIPS `nop`
/// is `0x00000000`, and real code carries runs of them (ps2 dungeon_game's
/// `padlib::init` and two `GamePad` methods each wait on 20), which Ghidra's
/// limit cuts out of their bodies.
#[derive(Default)]
struct RepeatRuns {
    /// The run each fallthrough continues: the repeated byte and how many
    /// instructions of it precede the address in its block.
    falls: HashMap<u64, (u8, u32)>,
}

impl RepeatRuns {
    const LIMIT: u32 = 16;

    /// The chunk's flows without the instructions the limit refuses, nor the
    /// entries `refuse` turns away (collected in `refused`), with each kept
    /// instruction's run: `(byte, length)`, or `None` for an instruction
    /// whose bytes differ. An address the limit refuses stays visited, as
    /// Ghidra leaves the conflict where its block stopped.
    fn admit<'a>(
        &self,
        imp: &NativeImport,
        chunk: &'a [u64],
        flows: Vec<FlowResult>,
        refuse: impl Fn(u64, &FlowResult) -> bool,
        refused: &mut Vec<u64>,
    ) -> (std::borrow::Cow<'a, [u64]>, Vec<FlowResult>, Vec<Option<(u8, u32)>>) {
        let runs: Vec<Option<(u8, u32)>> = chunk
            .iter()
            .zip(&flows)
            .map(|(&address, flow)| {
                if matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl) || flow.no_op {
                    return None;
                }
                let byte = repeated_byte(imp, address, u64::from(flow.length))?;
                let length = match self.falls.get(&address) {
                    Some(&(previous, length)) if previous == byte => length + 1,
                    _ => 1,
                };
                Some((byte, length))
            })
            .collect();
        let first = refused.len();
        refused.extend(chunk.iter().zip(&flows).filter(|&(&address, flow)| refuse(address, flow)).map(|(&address, _)| address));
        let turned_away = &refused[first..];
        if turned_away.is_empty() && !runs.iter().any(|run| run.is_some_and(|(_, length)| length > Self::LIMIT)) {
            return (std::borrow::Cow::Borrowed(chunk), flows, runs);
        }
        let mut kept_chunk = Vec::with_capacity(chunk.len());
        let mut kept_flows = Vec::with_capacity(flows.len());
        let mut kept_runs = Vec::with_capacity(runs.len());
        for ((&address, flow), run) in chunk.iter().zip(flows).zip(runs) {
            if run.is_some_and(|(_, length)| length > Self::LIMIT) || turned_away.contains(&address) {
                continue;
            }
            kept_chunk.push(address);
            kept_flows.push(flow);
            kept_runs.push(run);
        }
        (std::borrow::Cow::Owned(kept_chunk), kept_flows, kept_runs)
    }

    /// Carries an instruction's run to its fallthrough; a call ends its
    /// block, so the instruction after it starts a new run.
    fn follow(&mut self, fall: u64, flow: &FlowResult, run: Option<(u8, u32)>) {
        if let Some(run) = run.filter(|_| !matches!(flow.kind, FlowKind::Call | FlowKind::CallInd)) {
            self.falls.insert(fall, run);
        }
    }
}

/// The byte every byte of `[address, address + length)` holds, when they
/// are all one value.
fn repeated_byte(imp: &NativeImport, address: u64, length: u64) -> Option<u8> {
    let mapping = imp
        .mappings
        .iter()
        .find(|mapping| address >= mapping.vaddr && address - mapping.vaddr < mapping.bytes.len() as u64)?;
    let start = (address - mapping.vaddr) as usize;
    let bytes = mapping.bytes.get(start..start.checked_add(usize::try_from(length).ok()?)?)?;
    let (&first, rest) = bytes.split_first()?;
    rest.iter().all(|&byte| byte == first).then_some(first)
}

/// Whether the bytes at `address` are fill rather than code: its first 16
/// bytes, all zero or all 0xff (zero padding, erased flash). Every instruction set
/// decodes some fill (Thumb `0xffff` is the second half of a `bl` and falls
/// through; zero is `lsls r0, r0, #0`), so a call decoded from data that
/// lands in fill walks all of it. On pokeemerald 41 such "functions" sat in
/// the 0xff padding past the ROM's data, 727 KB of bodies the reference pass
/// propagated through, all called from junk decoded out of graphics and the
/// multiboot image.
pub(crate) fn opens_with_fill(imp: &NativeImport, address: u64) -> bool {
    // Four words read one by one, so fill that runs on into the next mapping
    // (God Hand's `.text` ends 0x3bbf20, its zeros go on to 0x3bbf80) is fill,
    // and so are the last words of the last mapping.
    let first = repeated_byte(imp, address, 4);
    (matches!(first, Some(0x00 | 0xff))
        && (1..4).all(|word| {
            let next = address + 4 * word;
            repeated_byte(imp, next, 4) == first || repeated_byte(imp, next, 1).is_none()
        }))
        || opens_with_alignment_fill(imp, address)
}

/// Bytes toolchains and allocators fill unused space with, which no
/// instruction word of a 32-bit set is made of: the debug allocator's
/// uninitialised (`cd`), freed (`dd`) and guard (`fd`) bytes, `int3`
/// padding (`cc`) and erased flash (`ff`).
const FILL_BYTES: [u8; 5] = [0xcd, 0xcc, 0xdd, 0xfd, 0xff];

/// Whether the word at `address` is the linker's alignment fill between two
/// objects, on a set of fixed 4-byte instructions: a word of one repeated
/// fill byte (`cdcdcdcd`), or zero words (one to three: four are
/// `opens_with_fill`'s) that run up to an 8-byte boundary, where the next
/// object starts. A zero word that is no function's first instruction is the
/// gap before the next object; one that is followed by code at an address
/// 4 mod 8 is the leading `nop` of a function nothing aligned, unless more
/// fill follows (`cdcdcdcd`) or two code pointers, the padding before a table.
/// Measured on the 8 PS2 games' truth (54,361 rows): 10,777 starts follow 2-3
/// zero words, and 9 rows open with a zero word, of which this reads 3 (2
/// verified) as fill.
///
/// Ratchet & Clank: 637 (PAL 40) of the truth's old rows were one such word,
/// and the import made functions of 21 (PAL 24). God Hand 0x133940: the two
/// zero words before the verified function at 0x133948 were a sweep entry.
pub(crate) fn opens_with_alignment_fill(imp: &NativeImport, address: u64) -> bool {
    if patterns::instruction_alignment(&imp.language, 1) != 4 || address % 4 != 0 {
        return false;
    }
    match repeated_byte(imp, address, 4) {
        Some(0) => {
            let mut end = address + 4;
            while repeated_byte(imp, end, 4) == Some(0) {
                end += 4;
                if end - address > 12 {
                    return false;
                }
            }
            // The word that ends the run must exist: zeros at the end of a
            // mapping are no gap before an object. It is on the boundary the
            // next object starts at, or it is more fill (Ratchet & Clank
            // 0x15eff8: three zero words, then `cdcdcdcd`).
            // Or it is the start of a table of pointers (Ratchet & Clank PAL
            // 0x12f578: three zero words, then `0x12f764`, `0x12f7bc`, ..., which name
            // the `.rodata` after them, not code).
            let mapped = |value: u64| {
                value % 4 == 0
                    && imp.mappings.iter().any(|mapping| value >= mapping.vaddr && value - mapping.vaddr < mapping.size)
            };
            let pointers = [end, end + 4]
                .iter()
                .all(|&at| word_at(imp, at).is_some_and(|word| mapped(u64::from(word))));
            (end % 8 == 0
                || repeated_byte(imp, end, 4).is_some_and(|byte| FILL_BYTES.contains(&byte))
                || pointers)
                && repeated_byte(imp, end, 1).is_some()
        }
        Some(byte) => FILL_BYTES.contains(&byte),
        None => false,
    }
}

/// The 32-bit instruction word at `address`, in the image's byte order.
fn word_at(imp: &NativeImport, address: u64) -> Option<u32> {
    let big = imp.language.contains(":BE:");
    imp.mappings.iter().find_map(|mapping| {
        let at = usize::try_from(address.checked_sub(mapping.vaddr)?).ok()?;
        let raw: [u8; 4] = mapping.bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
    })
}

/// The 8-byte-aligned addresses in `ranges` right after a zero word (a `nop`),
/// where an instruction that is not fill begins, with the first word there.
/// The zero word is the delay slot or the padding of the code above.
fn after_nop(imp: &NativeImport, ranges: &[(u64, u64)]) -> Vec<(u64, u32)> {
    let mut found = Vec::new();
    for &(start, end) in ranges {
        let mut address = (start + 7) & !7;
        while address < end {
            if let Some(first) = word_at(imp, address).filter(|&first| first != 0) {
                if address.checked_sub(4).and_then(|before| word_at(imp, before)) == Some(0) {
                    found.push((address, first));
                }
            }
            address += 8;
        }
    }
    found
}

/// The MIPS function starts that the code above falls into, in `ranges`: an
/// address right after a `nop` (`after_nop`) that opens a stack frame
/// (`addiu sp, sp, -N`). The zero word is the delay slot or the padding of
/// the code above, which Ghidra's flow ownership hands the start to, and a
/// function opens its frame once. Measured on 6 PS2 games, over the
/// 8-aligned addresses after a `nop` that are no function of the import: 187
/// frame openers are truth starts and 8 lie inside a truth function (God Hand
/// 126 and 2, Persona 4 41 and 0, Fatal Frame 13 and 0, Ratchet & Clank PAL 1
/// and 6); without a `nop` before, 4 frame openers are starts and 221 are
/// not. God Hand 0x107e18 is `addiu sp, sp, 16; nop` and falls into 0x107e20.
fn after_fill_starts(imp: &NativeImport, ranges: &[(u64, u64)]) -> Vec<u64> {
    after_nop(imp, ranges)
        .into_iter()
        .filter(|&(_, first)| first >> 16 == 0x27bd && first & 0x8000 != 0)
        .map(|(address, _)| address)
        .collect()
}

/// The fewest `j` targets after a `nop` that no function is yet, for them to
/// be read as an image's way of calling: a compiler that tail-calls with `j`
/// leaves the callee with no `jal` at all (Ratchet & Clank PAL: 31 such
/// targets, 31 truth starts; God Hand 22 and 2), where an image that jumps
/// inside functions has a handful (Digital Devil Saga 3 and 1, Dark Chronicle
/// 1 and 3). With the rule on for them, Digital Devil Saga lost 15 functions
/// (0.12 points of recall) and Dark Chronicle precision.
const JUMP_START_QUORUM: usize = 16;

/// The `j` targets after a `nop` that are no function yet, when there are
/// `JUMP_START_QUORUM` of them (`after_fill_starts`'s other half), in the
/// ranges calls reach. They are functions the image reaches by `j` only.
pub(crate) fn jump_starts_after_fill(imp: &NativeImport) -> Vec<u64> {
    if !imp.unrelocated_data_pointers || !super::mips_language(&imp.language) {
        return Vec::new();
    }
    let ranges = call_dense_ranges(imp);
    let mut jumped: HashSet<u64> = HashSet::default();
    for &(start, end) in &ranges {
        let mut address = start & !3;
        while address < end {
            if let Some(word) = word_at(imp, address).filter(|word| word >> 26 == 2) {
                jumped.insert(((address + 4) & 0xf000_0000) | (u64::from(word & 0x03ff_ffff) << 2));
            }
            address += 4;
        }
    }
    let known: HashSet<u64> = imp.functions.iter().map(|function| function.entry).collect();
    let starts: Vec<u64> = after_nop(imp, &ranges)
        .into_iter()
        .map(|(address, _)| address)
        .filter(|address| jumped.contains(address) && !known.contains(address))
        .collect();
    if starts.len() >= JUMP_START_QUORUM { starts } else { Vec::new() }
}

/// Whether the straight-line Thumb-1 code at `target` decodes up to its
/// first terminator: a return (`bx`, `pop {.., pc}`), a write to `pc`
/// (`mov`/`add pc, rN`, a switch dispatch) or an unconditional `b`. A
/// `bl`/`blx` half without its partner, or an undefined encoding, before
/// that says the bytes are not code: graphics, script bytecode and tables
/// decode a few plausible instructions, then one of these. On pokeemerald
/// this holds for every Thumb function its symbols name that the import
/// found, and fails for 235 of the 471 it invented. 64 halfwords without a
/// terminator decide nothing.
pub(crate) fn thumb1_fallthrough_decodes(imp: &NativeImport, target: u64) -> bool {
    // ARMv5T adds `blx`, whose suffix pairs with the same prefix.
    let blx = imp.language.ends_with(":v5t");
    let mut address = target;
    for _ in 0..64 {
        let Some(half) = super::thumb_halfword(imp, address) else {
            return false;
        };
        if matches!(half & 0xff87, 0x4700 | 0x4487 | 0x4687) || half & 0xff00 == 0xbd00 || half & 0xf800 == 0xe000 {
            return true;
        }
        // `udf` (conditional-branch space, condition 0b1110) and the
        // `blx` suffix, which only follows a prefix.
        if half & 0xff00 == 0xde00 || half & 0xf800 == 0xe800 {
            return false;
        }
        match half & 0xf800 {
            // A `bl` (or `blx`) prefix needs its suffix next.
            0xf000 => {
                let suffix = super::thumb_halfword(imp, address + 2).unwrap_or(0);
                if !(suffix & 0xf800 == 0xf800 || blx && suffix & 0xf800 == 0xe800) {
                    return false;
                }
                address += 4;
            }
            // A suffix without its prefix.
            0xf800 => return false,
            _ => address += 2,
        }
    }
    true
}

/// Whether a proven tail-call target is promoted to a function: the global
/// switch (`ROMWRIGHT_PROMOTE_TAILCALLS`, `cfg.promote_tailcalls`) or the
/// `tailcall-promotion` compiler rule for this program's compiler.
fn promote_tailcalls(imp: &NativeImport) -> bool {
    imp.cfg.promote_tailcalls || crate::compiler::rules::applies("tailcall-promotion", &crate::compiler::ctx_of(imp))
}

/// An entry, as yet unwalked, that decodes in Thumb on a Thumb-1 language
/// and whose straight-line code does not (`thumb1_fallthrough_decodes`): it
/// is data some pointer, pattern or junk call named, and walking it decodes
/// more junk and calls into more. A symbol the image declares is kept.
fn refuses_entry(
    imp: &NativeImport,
    addr_origin: &HashMap<u64, u64>,
    entries: &HashSet<u64>,
    address: u64,
    flow: &FlowResult,
) -> bool {
    flow.mode == Some(1)
        && addr_origin.get(&address) == Some(&address)
        && entries.contains(&address)
        && (!thumb1_fallthrough_decodes(imp, address) || tears_down_frame(imp, address))
        && !imp.symbol_named.contains(&address)
}

/// Whether a Thumb entry's first instruction is a `push`: it builds its own frame.
fn thumb_halfword_opens_frame(imp: &NativeImport, address: u64) -> bool {
    super::thumb_halfword(imp, address).is_some_and(|first| first & 0xfe00 == 0xb400)
}

/// A Thumb entry whose first instruction gives back a frame it never
/// built: `add sp, #imm` or a `pop`. That is the tail of the function
/// above, reached by a `bl` the compiler used as a long jump (agbcc does,
/// past a conditional branch's range), and no function opens that way.
/// pokeemerald: 13 entries (12 `add sp`, 1 `pop`) against none of the 15,856
/// FUNC symbols.
fn tears_down_frame(imp: &NativeImport, address: u64) -> bool {
    crate::compiler::rules::applies("thumb-frame-teardown-entry", &crate::compiler::ctx_of(imp))
        && super::thumb_halfword(imp, address).is_some_and(|first| first & 0xff80 == 0xb000 || first & 0xfe00 == 0xbc00)
}

/// The words of stack a Thumb-1 entry's straight-line code leaves given back
/// at its first return (`pop {.., pc}`, `bx`, `mov pc`): pushes and `sub sp`
/// count up, pops and `add sp` count down, a `bl` is skipped whole. Negative
/// means the code releases more than it took, so it is the tail of a body
/// that took it. `None` when no return comes within 256 halfwords.
fn thumb_stack_released(imp: &NativeImport, entry: u64) -> Option<i32> {
    let mut delta = 0i32;
    let mut address = entry;
    for _ in 0..256 {
        let half = super::thumb_halfword(imp, address)?;
        address += 2;
        let count = |bits: u16| (bits & 0xff).count_ones() as i32 + i32::from(bits >> 8 & 1);
        match half {
            half if half & 0xfe00 == 0xb400 => delta += count(half),
            half if half & 0xfe00 == 0xbc00 => {
                delta -= count(half);
                if half & 0x100 != 0 {
                    return Some(delta);
                }
            }
            half if half & 0xff80 == 0xb080 => delta += i32::from(half & 0x7f),
            half if half & 0xff80 == 0xb000 => delta -= i32::from(half & 0x7f),
            half if half & 0xff87 == 0x4700 || half & 0xff87 == 0x4687 => return Some(delta),
            half if half >> 11 == 0b11110 => address += 2,
            _ => {}
        }
    }
    None
}

/// Whether the MIPS code at `entry` reaches a `jr ra` within 12 words with no
/// unconditional jump or branch before it: the shape of a loop's test and
/// exit laid out after the function's own return.
fn returns_within_a_few_words(imp: &NativeImport, entry: u64) -> bool {
    let jumps = |address: u64| word_at(imp, address).is_some_and(|w| w >> 26 == 2 || w >> 26 == 3 || w >> 16 == 0x1000);
    (0..12u64).any(|index| {
        word_at(imp, entry + 4 * index) == Some(0x03e0_0008) && (0..index).all(|before| !jumps(entry + 4 * before))
    })
}

/// The longest run of code pointers read as the table of a dispatch's case
/// blocks (`interior_entries`). A longer one is a table the whole range of an
/// opcode byte indexes, most of its words the default: Digital Devil Saga
/// 0x30c344 has 528 words, 0x30c858 the default, and the verified function
/// 0x30c838 holds it.
const MAX_CASE_RUN: usize = 64;

/// The longest run (`wide-switch-case-blocks`) and the widest stretch of code its targets may span
/// (a 1,151-entry jump table over cases of 24 bytes each is 6 KiB): Pac-Man Rally's one switch
/// at 0x109b0 made 258 functions of its case blocks.
const MAX_WIDE_CASE_RUN: usize = 4096;

/// The fewest called frameless functions an image needs for `ido-leaf-return-pair` to read its habit.
const IDO_PAIR_QUORUM: usize = 32;
const MAX_WIDE_CASE_SPAN: u64 = 0x1_0000;

/// Whether the scan decoded bytes SLEIGH has no instruction for within
/// `CALL_NEIGHBOURHOOD` bytes either side of `address`.
fn has_undecodable_neighbour(decoded: &std::collections::BTreeMap<u64, FlowResult>, address: u64) -> bool {
    decoded
        .range(address.saturating_sub(CALL_NEIGHBOURHOOD)..=address.saturating_add(CALL_NEIGHBOURHOOD))
        .any(|(_, flow)| matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl))
}

/// How far either side of a call the scan's decode must hold no bytes SLEIGH
/// has no instruction for, on MIPS (`discover_mapped`): 16 words.
const CALL_NEIGHBOURHOOD: u64 = 64;

/// Entries the walk created without evidence of their own that sit inside
/// another function's code, each with the function that owns it (`None`
/// when the evidence is the bytes, not a flow). An entry something calls,
/// the image's symbols or unwind tables declare, or the loader named is
/// kept. The rules, measured offline on the m21 images against truth:
///
/// - reached by a fallthrough or a conditional branch, in its own
///   instruction set, from an instruction of another function: dungeon_game
///   30 entries its symbols do not name against 0 they do, Capcom 7 against
///   0, Vita NFS 393 against 11 (Ghidra keeps a flow-reached address in the
///   body that reaches it);
/// - a switch case target after its dispatch with no entry between them
///   but the same table's cases: Capcom 34 against 1 (a jump table of
///   handlers lies before its dispatch, or across other functions);
/// - on MIPS, an entry with no `addiu sp, sp, -N` whose previous word is
///   neither the delay slot of a `jr ra`/`j`/`b` nor zero padding: it
///   continues the code above it. dungeon_game 21 against 0, Capcom 7
///   against 0, among entries nothing calls;
/// - on MIPS, the same reach through the walk's attribution: the entry's own
///   flow looped back into the code of the branch and took it first, and the
///   short piece (a `jr ra` within 12 words, no jump before it) is the
///   function above's (`returns_within_a_few_words`);
/// - on MIPS, the case blocks of a dispatch no table was recovered for:
///   uncalled, no frame opener, not right after a `jr ra` or padding, held by
///   a run of 3 to `MAX_CASE_RUN` code pointers whose lowest target is within
///   16 bytes after an indirect `jr` through a register other than `ra`;
/// - on MIPS, the block right after a `j L`/`b L` that is 8 to 32 plain
///   instructions up to `L`.
///
/// PS2, against the audited truth of the 8 games (`docs/console-research.md`,
/// "PS2 precision"): none of the last three shapes has a truth row, except
/// two the block rule is bounded away from (God Hand 0x347208, Digital Devil
/// Saga 0x3059d0). Capcom Fighting Evolution, whose truth is its own symbol
/// table, names some of the case blocks the third retracts: its recall reads
/// 0.9741 against 0.9762 with it off.
///
/// Imported: dungeon_game precision 0.9305 -> 0.988, Capcom 0.989 ->
/// 0.9964, Vita 0.957 -> 0.9712 (STATUS, 2026-10-07).
fn interior_entries<P: FlowProvider>(
    imp: &NativeImport,
    entries: &[u64],
    entries_set: &HashSet<u64>,
    callers: &HashMap<u64, Vec<u64>>,
    thunk_targets: &HashSet<u64>,
    addr_origin: &HashMap<u64, u64>,
    provider: &mut P,
) -> Vec<(u64, Option<u64>)> {
    let externals: HashSet<u64> = imp.externals.iter().map(|&(address, _)| address).collect();
    let declared: HashSet<u64> = imp.symbol_named.iter().copied().collect();
    let patterned: HashSet<u64> = imp.pattern_starts.iter().copied().collect();
    let named: HashSet<u64> = imp
        .functions
        .iter()
        .filter(|function| !function.name.starts_with("FUN_"))
        .map(|function| function.entry)
        .collect();
    // An unwind table entry declares a function start (Black Ops 2: two
    // functions whose `.pdata` rows begin where another body runs on).
    let unwound: HashSet<u64> = imp
        .xrefs
        .iter()
        .filter(|x| x.provenance == "native-import:pe-unwind" || x.provenance == "native-import:elf-unwind")
        .map(|x| x.to)
        .collect();
    // An address an instruction loads from is data -- a literal pool word
    // seeded as an entry -- and owns nothing it runs into (pokeemerald:
    // three such words would have swallowed `HBlankIntr` and two others).
    let read: HashSet<u64> = imp.xrefs.iter().filter(|x| x.kind == "READ").map(|x| x.to).collect();
    // What the image itself declares an entry.
    let declared_kept = |entry: u64| {
        declared.contains(&entry)
            || externals.contains(&entry)
            || named.contains(&entry)
            || unwound.contains(&entry)
            || Some(entry) == imp.process_entry
    };
    let kept = |entry: u64| callers.contains_key(&entry) || declared_kept(entry);
    // The function an instruction belongs to, when it is another entry.
    let owner = |address: u64, entry: u64| {
        addr_origin.contains_key(&address).then(|| get_canonical_origin(address, addr_origin)).filter(|&owner| {
            owner != entry && entries_set.contains(&owner) && !read.contains(&owner)
        })
    };
    // Edges from the recorded shapes, checked against the decode the walk
    // holds now: a shape of an earlier round may have read the bytes in the
    // other instruction set, and an instruction only reaches an entry of
    // its own instruction set (vita NFS: ARM reads of Thumb returns
    // "fell" into the next function).
    let mut edges: Vec<(u64, u64)> = Vec::new();
    let mut sled: Vec<(u64, u64)> = Vec::new();
    for shape in &imp.flow_shapes {
        let falls = !matches!(
            shape.kind,
            FlowKind::Branch | FlowKind::Return | FlowKind::BranchInd | FlowKind::Bad | FlowKind::Unimpl
        );
        let fall = shape.address + u64::from(shape.length);
        let branch = shape.target.filter(|_| shape.conditional || shape.kind == FlowKind::CBranch);
        for target in falls.then_some(fall).into_iter().chain(branch) {
            if entries_set.contains(&target)
                && !kept(target)
                && !imp.fill_starts.contains(&target)
            {
                edges.push((shape.address, target));
            }
        }
        // A called entry that a plain instruction -- not a call, not a
        // branch -- of another function runs into is a label of that
        // function's straight-line code: the `_savegpr_N` and `_restgpr_N`
        // entries of a register save sled, each reached by its callers and
        // by the store above it.
        if shape.kind == FlowKind::Fallthrough
            && !shape.conditional
            && entries_set.contains(&fall)
            && callers.contains_key(&fall)
            && !declared_kept(fall)
            // ARM code carries literal pools, whose words decode as plain
            // instructions that fall into the function after them, and MIPS
            // a delay slot, a plain instruction that falls into the next
            // function after a `jr ra`.
            && !imp.language.starts_with("ARM")
            && !super::mips_language(&imp.language)
        {
            sled.push((shape.address, fall));
        }
    }
    let mut asked: Vec<u64> =
        edges.iter().chain(&sled).flat_map(|&(source, target)| [source, target]).collect();
    asked.sort_unstable();
    asked.dedup();
    let decoded: HashMap<u64, FlowResult> = asked
        .chunks(1024)
        .flat_map(|chunk| provider.flow(chunk))
        .map(|flow| (flow.address, flow))
        .collect();
    let mut found: HashMap<u64, Option<u64>> = HashMap::default();
    let mut sorted: Vec<u64> = entries.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mips = super::mips_language(&imp.language);
    // A landing pad the image's own exception tables declare is a block of the
    // function whose frame description holds the call site: the unwinder
    // enters it, nothing else does, so no call, branch or pointer names it
    // and the gap rule and the data scan coin it as a function after a
    // `jr ra`. Of Hot Pixel's 9,983 truth functions none is a landing pad;
    // 554 of the 656 entries it holds inside verified functions are.
    let pads: HashMap<u64, u64> = if crate::compiler::rules::applies("landing-pad-not-entry", &crate::compiler::ctx_of(imp)) {
        imp.exception_sites.iter().map(|site| (site.landing_pad, site.function)).collect()
    } else {
        HashMap::default()
    };
    for &entry in &sorted {
        if let Some(&function) = pads.get(&entry) {
            if function != entry && !kept(entry) && !thunk_targets.contains(&entry) && !found.contains_key(&entry) {
                let owner = (entries_set.contains(&function) && !read.contains(&function)).then_some(function);
                found.insert(entry, owner);
            }
        }
    }
    for (source, target) in edges {
        if found.contains_key(&target) {
            continue;
        }
        let (Some(from), Some(to)) = (decoded.get(&source), decoded.get(&target)) else {
            continue;
        };
        let reaches = from.fallthrough == Some(target)
            && !matches!(from.kind, FlowKind::Bad | FlowKind::Unimpl)
            || from.conditional && from.targets.contains(&target);
        if !reaches || from.mode != to.mode {
            continue;
        }
        if let Some(owner) = owner(source, target) {
            found.insert(target, Some(owner));
        } else if mips
           
            && source < target
            && get_canonical_origin(source, addr_origin) == target
            && returns_within_a_few_words(imp, target)
        {
            // The walk gave the code the branch sits in to the entry it
            // branches to: the entry's own flow loops back into it (a loop
            // whose test, `sltu; bnez top; ...; jr ra`, was laid out after the
            // function's return), and it reached the loop body before the
            // function above did. That function is the owner, the nearest entry
            // below the branch (God Hand 0x1594f8 into 0x1594a0: 6 of this
            // shape, Fatal Frame 8, Dark Chronicle 3). Only a short piece that
            // returns itself is meant: a block that jumps on into the loop's
            // common tail is a case of the function, and Digital Devil Saga's
            // verified 0x30c838 is one.
            let above = sorted.partition_point(|&entry| entry <= source);
            if let Some(&owner) = above.checked_sub(1).map(|index| &sorted[index]) {
                if owner != target && !read.contains(&owner) && !found.contains_key(&owner) {
                    found.insert(target, Some(owner));
                }
            }
        }
    }
    for (&jump, targets) in &imp.switch_tables {
        for &target in targets {
            if target <= jump || !entries_set.contains(&target) || kept(target) || found.contains_key(&target) {
                continue;
            }
            let from = sorted.partition_point(|&entry| entry <= jump);
            let to = sorted.partition_point(|&entry| entry < target);
            if sorted[from..to].iter().all(|entry| targets.contains(entry)) {
                if let Some(owner) = owner(jump, target) {
                    found.insert(target, Some(owner));
                }
            }
        }
    }
    if super::mips_language(&imp.language) {
        let be = imp.language.contains(":BE:");
        // Addresses below an image's base are asked about (an entry near 0 on a
        // PRX linked at 0, less 4 or 8, wraps): no mapping holds them.
        let word = |address: u64| -> Option<u32> { word_at(imp, address) };
        for &entry in &sorted {
            if kept(entry)
                || callers.contains_key(&entry)
                || found.contains_key(&entry)
                || thunk_targets.contains(&entry)
                || patterned.contains(&entry)
            {
                continue;
            }
            let (Some(first), Some(slot_of), Some(before)) =
                (word(entry), entry.checked_sub(8).and_then(word), entry.checked_sub(4).and_then(word))
            else {
                continue;
            };
            let frame = first >> 16 == 0x27bd && first & 0x8000 != 0;
            let after_end = slot_of == 0x03e0_0008 || slot_of >> 26 == 2 || slot_of >> 16 == 0x1000;
            if !frame && !after_end && before != 0 {
                found.insert(entry, None);
            }
        }
        // The case blocks of a dispatch no table was recovered for: nothing
        // calls them, none opens a frame, and the only word that holds one is
        // in a run of code pointers whose lowest target sits right after an
        // indirect `jr` through a register other than `ra`, the dispatch. Its
        // function owns them. Of the 8 PS2 games' truth rows, none has this
        // shape (it was met by 60 invented entries: God Hand 23, Digital Devil
        // Saga 8, Ratchet & Clank 6 and PAL 6, Fatal Frame 6, Persona 4 5).
        // The block a jump hops over: the code right after a `j L` (or `b L`)
        // and its delay slot that is plain instructions up to `L` itself, at
        // least eight of them. It is the jump's own function, laid out between
        // the jump and its target (Ratchet & Clank's hand-written assembly:
        // 0x217b38 under `j 0x217b58`); a function that follows a jump to
        // somewhere else returns or jumps before it gets there. Of the 8 PS2
        // games' truth rows 2 have it at all (God Hand 0x347208 and Digital
        // Devil Saga 0x3059d0, both of 4 words or fewer).
        // IDO ends every function that opens no frame with a second `jr ra; nop` after its
        // own: a leaf function is `... jr ra; nop; jr ra; nop`. Nothing reaches the second
        // return, so the walk coins it as a function after the first. Super Mario 64: 320 of
        // its 3,813 truth functions end so, 0 of the 2,968 that open a frame do, and 332
        // entries inside verified functions are these. The function above, in address order
        // from the entries that stay, owns an uncalled, unpointed `jr ra; nop` that follows
        // exactly one return of its own and opens no frame; when it already ends in a pair,
        // the next `jr ra; nop` is a function of its own (SM64's empty stubs, two returns each).
        //
        // Only an image that does it all over: Banjo-Kazooie and Majora's Mask have real 8-byte
        // `jr ra; nop` functions after a leaf function (the rule lost 29 and 44 truth functions
        // there), so the rule needs the image's own habit first. Of the called functions that open no frame, 59.7% of Super Mario
        // 64's are followed by a bare `jr ra; nop` entry (296 of 496), 0.7% of Dr. Mario 64's.
        let bare_return_after = |at: u64| word(at) == Some(0x03e0_0008) && word(at + 4) == Some(0) && at.checked_sub(8).and_then(word) == Some(0x03e0_0008);
        let doubles_returns = crate::compiler::rules::applies("ido-leaf-return-pair", &crate::compiler::ctx_of(imp)) && {
            let (mut frameless, mut followed) = (0usize, 0usize);
            for pair in sorted.windows(2) {
                let opens_frame = word(pair[0]).map_or(true, |first| first >> 16 == 0x27bd && first & 0x8000 != 0);
                if callers.contains_key(&pair[0]) && !opens_frame {
                    frameless += 1;
                    followed += usize::from(bare_return_after(pair[1]));
                }
            }
            frameless >= IDO_PAIR_QUORUM && followed * 4 >= frameless
        };
        if doubles_returns {
            let referenced: HashSet<u64> = imp.xrefs.iter().map(|x| x.to).collect();
            let mut current: Option<u64> = None;
            for &entry in &sorted {
                if found.contains_key(&entry) {
                    continue;
                }
                let bare_return = word(entry) == Some(0x03e0_0008) && word(entry + 4) == Some(0);
                if bare_return && !kept(entry) && !thunk_targets.contains(&entry) && !referenced.contains(&entry) {
                    if let Some(function) = current {
                        let leaf = word(function).is_some_and(|first| !(first >> 16 == 0x27bd && first & 0x8000 != 0));
                        let mut returns = 0;
                        let mut at = entry;
                        while at >= function + 8 && word(at - 8) == Some(0x03e0_0008) {
                            returns += 1;
                            at -= 8;
                        }
                        // Two returns in a row are the function's own and its second when the first
                        // fills its delay slot (`jr ra; move`, then two bare `jr ra; nop`): 57 of
                        // SM64's truth functions end so, and 261 end in a bare return and its twin.
                        let first_fills_slot = word(at + 4).is_some_and(|slot| slot != 0);
                        if leaf && (returns == 1 || returns == 2 && first_fills_slot) {
                            found.insert(entry, Some(function));
                            continue;
                        }
                    }
                }
                current = Some(entry);
            }
        }
        // `jr rX; nop` followed by `b L; <slot>` pairs, one after another, is a dispatch into a
        // table of branches (Tetris: a copy loop entered at an offset by `jr v0`): each pair is
        // a case of the function that jumps in, not a function. The first pair must follow a
        // `jr` through a register other than `ra`, the rest follow a pair already read so.
        if crate::compiler::rules::applies("branch-table-after-dispatch", &crate::compiler::ctx_of(imp)) {
            let branch = |at: u64| word(at).is_some_and(|w| w >> 16 == 0x1000 || w >> 26 == 2);
            for &entry in &sorted {
                if kept(entry)
                    || callers.contains_key(&entry)
                    || found.contains_key(&entry)
                    || patterned.contains(&entry)
                    || !branch(entry)
                {
                    continue;
                }
                let Some(before) = entry.checked_sub(8) else { continue };
                let after_dispatch = word(before).is_some_and(|w| w & 0xfc1f_ffff == 8 && (w >> 21) & 31 != 31);
                if after_dispatch || (found.contains_key(&before) && branch(before)) {
                    found.insert(entry, None);
                }
            }
        }
        // A block that opens by reloading the return address from the stack gives back a frame
        // it never built: it is the epilogue of the function above, laid out after a loop that
        // never exits (IDO: Dr. Mario 64's `while (1)` bodies end `j top; nop` and the dead
        // epilogue follows). No function starts with `lw ra, N(sp)`, nor with `b .+8` (a branch
        // over its own delay slot: IDO's dead `b end; nop` in front of such an epilogue).
        if crate::compiler::rules::applies("epilogue-not-entry", &crate::compiler::ctx_of(imp)) {
            for (index, &entry) in sorted.iter().enumerate() {
                if kept(entry)
                    || callers.contains_key(&entry)
                    || found.contains_key(&entry)
                    || thunk_targets.contains(&entry)
                    || patterned.contains(&entry)
                    || !word(entry).is_some_and(|first| first >> 16 == 0x8fbf || first == 0x1000_0001)
                {
                    continue;
                }
                let owner = sorted[..index].iter().rev().copied().find(|above| !found.contains_key(above) && !read.contains(above));
                found.insert(entry, owner);
            }
        }
        let hopped = |entry: u64| -> bool {
            let Some(jump) = entry.checked_sub(8).and_then(word) else { return false };
            let target = if jump >> 26 == 2 {
                (entry & 0xf000_0000) | ((u64::from(jump) & 0x03ff_ffff) << 2)
            } else if jump >> 16 == 0x1000 {
                (entry - 4).wrapping_add_signed(i64::from(jump as u16 as i16) * 4)
            } else {
                return false;
            };
            target > entry
                && target - entry >= 0x20
                && target - entry <= 0x80
                && (entry..target).step_by(4).all(|address| {
                    word(address).is_some_and(|w| {
                        let op = w >> 26;
                        // No branch, jump or call (`bc1t` and `bc2f` are COP branches).
                        !matches!(op, 1..=7 | 20..=23)
                            && !(op == 0 && matches!(w & 0x3f, 8 | 9))
                            && !(matches!(op, 17 | 18) && (w >> 21) & 31 == 8)
                    })
                })
        };
        for &entry in &sorted {
            if !(kept(entry)
                || callers.contains_key(&entry)
                || found.contains_key(&entry)
                || thunk_targets.contains(&entry)
                || patterned.contains(&entry))
                && word(entry).is_some_and(|first| !(first >> 16 == 0x27bd && first & 0x8000 != 0))
                && hopped(entry)
            {
                found.insert(entry, None);
            }
        }
        // Code right after a function's `jr ra` and its delay slot (and the
        // zero padding the linker leaves) is a function start: Capcom Fighting
        // Evolution's 100 uncalled leaf handlers, reached through tables of
        // function pointers, follow each other that way.
        let follows_a_return = |entry: u64| -> bool {
            (0..4u64).any(|padding| {
                let jump = entry.wrapping_sub(8 + 4 * padding);
                word(jump) == Some(0x03e0_0008) && (jump + 8..entry).step_by(4).all(|at| word(at) == Some(0))
            })
        };
        // A zero word of padding after a jump and its delay slot, or two
        // zero words: the toolchain aligned this start, which case blocks laid
        // out one after another do not have (Capcom Fighting Evolution's
        // tail-calling state handlers and its 24-byte case blocks, each a
        // symbol of its own). The delay slot of the dispatch itself is one
        // zero word after the `jr`, which is not this.
        let after_padding = |entry: u64| -> bool {
            let jump = |address: u64| {
                word(address).is_some_and(|w| w >> 26 == 2 || w >> 16 == 0x1000 || w & 0xfc1f_ffff == 8)
            };
            word(entry.wrapping_sub(4)) == Some(0)
                && (word(entry.wrapping_sub(8)) == Some(0) || jump(entry.wrapping_sub(12)))
        };
        // A switch's dispatch bounds its index: a `slt`/`sltu` family compare a few instructions
        // before the `jr`. A `jr` that ends a function in a tail call has none (Digital Devil Saga
        // 0x30c838 follows one, and a 528-word table names it).
        let bounded_jump = |jump: u64| -> bool {
            (1..=12u64).any(|back| {
                jump.checked_sub(4 * back).and_then(word).is_some_and(|w| {
                    matches!(w >> 26, 10 | 11) || (w >> 26 == 0 && matches!(w & 0x3f, 42 | 43))
                })
            })
        };
        let wide_cases = crate::compiler::rules::applies("wide-switch-case-blocks", &crate::compiler::ctx_of(imp));
        let labels: Vec<u64> = sorted
            .iter()
            .copied()
            .filter(|entry| {
                !(kept(*entry)
                    || callers.contains_key(entry)
                    || found.contains_key(entry)
                    || thunk_targets.contains(entry)
                    || patterned.contains(entry))
                    && word(*entry).is_some_and(|first| !(first >> 16 == 0x27bd && first & 0x8000 != 0))
                    && (wide_cases || !follows_a_return(*entry))
                    && !after_padding(*entry)
            })
            .collect();
        if !labels.is_empty() {
            let wanted: HashSet<u64> = labels.iter().copied().collect();
            // A zero word is no pointer, even into an image linked at 0 (a PSP `.init` is code at 0).
            let executable = |address: u64| {
                address % 4 == 0
                    && address != 0
                    && imp.mappings.iter().any(|mapping| {
                        mapping.flags & 4 != 0 && address >= mapping.vaddr && address - mapping.vaddr < mapping.size
                    })
            };
            let mut holders: HashMap<u64, Vec<u64>> = HashMap::default();
            for mapping in &imp.mappings {
                for (index, raw) in mapping.bytes.chunks_exact(4).enumerate() {
                    let raw: [u8; 4] = raw.try_into().expect("a word");
                    let value = u64::from(if be { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) });
                    if wanted.contains(&value) {
                        holders.entry(value).or_default().push(mapping.vaddr + 4 * index as u64);
                    }
                }
            }
            for &entry in &labels {
                for &holder in holders.get(&entry).into_iter().flatten() {
                    let mut run = vec![entry];
                    for step in [-4i64, 4] {
                        let mut at = holder.wrapping_add_signed(step);
                        while let Some(target) = word(at).map(u64::from).filter(|&target| executable(target)) {
                            run.push(target);
                            at = at.wrapping_add_signed(step);
                        }
                    }
                    let lowest = run.iter().copied().min().unwrap_or(entry);
                    let highest = run.iter().copied().max().unwrap_or(entry);
                    // A run past `MAX_CASE_RUN` is a switch's table when its cases all lie in
                    // one stretch of code: a table of function pointers spans the image.
                    let wide = run.len() > MAX_CASE_RUN
                        && run.len() <= MAX_WIDE_CASE_RUN
                        && highest - lowest <= MAX_WIDE_CASE_SPAN
                        && wide_cases;
                    if run.len() < 3 || (run.len() > MAX_CASE_RUN && !wide) {
                        continue;
                    }
                    // Case blocks that each end in a `jr ra` follow one another like functions
                    // do (Pac-Man Rally's 24-byte blocks); only a wide run says they are not.
                    if follows_a_return(entry) && !wide {
                        continue;
                    }
                    let dispatch = (lowest.saturating_sub(16)..lowest).step_by(4).find(|&address| {
                        word(address).is_some_and(|w| w & 0xfc1f_ffff == 8 && (w >> 21) & 31 != 31)
                            && (!wide || bounded_jump(address))
                    });
                    let Some(dispatch) = dispatch else { continue };
                    let above = sorted.partition_point(|&other| other <= dispatch);
                    if let Some(&owner) = above.checked_sub(1).map(|index| &sorted[index]) {
                        if !run.contains(&owner) && !read.contains(&owner) {
                            found.insert(entry, None);
                            break;
                        }
                    }
                }
            }
        }
        // The case blocks of a dispatch, wherever its table puts the default: a run of code
        // pointers none of which is a function by itself (nothing calls it, the image
        // declares none, none opens a frame) and all of which lie between one function the
        // evidence names and the next, with an indirect `jr` in that function above the
        // last of them. A table of function pointers spans functions, and some of them are
        // called or open a frame.
        if crate::compiler::rules::applies("case-run-in-one-function", &crate::compiler::ctx_of(imp)) {
            let opens_frame = |entry: u64| word(entry).is_some_and(|first| first >> 16 == 0x27bd && first & 0x8000 != 0);
            let evidenced: Vec<u64> = sorted
                .iter()
                .copied()
                .filter(|&entry| kept(entry) || callers.contains_key(&entry) || opens_frame(entry))
                .collect();
            let candidates: HashSet<u64> = sorted
                .iter()
                .copied()
                .filter(|&entry| {
                    !(kept(entry)
                        || callers.contains_key(&entry)
                        || found.contains_key(&entry)
                        || thunk_targets.contains(&entry)
                        || patterned.contains(&entry)
                        || opens_frame(entry)
                        // A bare return is a function of its own, as the entries of a table of
                        // trivial virtual methods are (Tetris: three `jr ra; move v0, zero`).
                        || word(entry) == Some(0x03e0_0008))
                })
                .collect();
            if !candidates.is_empty() {
                let be = imp.language.contains(":BE:");
                let executable = |address: u64| {
                    address % 4 == 0
                        && address != 0
                        && imp.mappings.iter().any(|mapping| {
                            mapping.flags & 4 != 0 && address >= mapping.vaddr && address - mapping.vaddr < mapping.size
                        })
                };
                let mut holders: HashMap<u64, Vec<u64>> = HashMap::default();
                for mapping in &imp.mappings {
                    for (index, raw) in mapping.bytes.chunks_exact(4).enumerate() {
                        let raw: [u8; 4] = raw.try_into().expect("a word");
                        let value = u64::from(if be { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) });
                        if candidates.contains(&value) {
                            holders.entry(value).or_default().push(mapping.vaddr + 4 * index as u64);
                        }
                    }
                }
                let mut seen_runs: HashSet<u64> = HashSet::default();
                for &entry in &sorted {
                    for &holder in holders.get(&entry).into_iter().flatten() {
                        let mut first = holder;
                        while let Some(previous) = first.checked_sub(4).filter(|&at| word(at).is_some_and(|w| executable(u64::from(w)))) {
                            first = previous;
                        }
                        if !seen_runs.insert(first) {
                            continue;
                        }
                        let mut run = Vec::new();
                        let mut at = first;
                        while let Some(target) = word(at).map(u64::from).filter(|&target| executable(target)) {
                            run.push(target);
                            at += 4;
                        }
                        if run.len() < 3 || run.len() > MAX_WIDE_CASE_RUN {
                            continue;
                        }
                        // The whole run first: every target between one function the evidence names and
                        // the next, an indirect `jr` after a bounds compare in that function above them.
                        let (lowest, highest) = (run.iter().copied().min().unwrap_or(0), run.iter().copied().max().unwrap_or(0));
                        let names_function = |target: &u64| {
                            entries_set.contains(target)
                                && !candidates.contains(target)
                                && !found.contains_key(target)
                                && word(*target) != Some(0x03e0_0008)
                        };
                        let above = evidenced.partition_point(|&other| other <= lowest);
                        if highest - lowest <= MAX_WIDE_CASE_SPAN && !run.iter().any(names_function) {
                            if let Some(&function) = above.checked_sub(1).map(|index| &evidenced[index]) {
                                let one_function = evidenced.get(above).is_none_or(|&next| next > highest) && !read.contains(&function);
                                let dispatch = one_function
                                    && (function..highest).step_by(4).any(|address| {
                                        word(address).is_some_and(|w| w & 0xfc1f_ffff == 8 && (w >> 21) & 31 != 31)
                                            && bounded_jump(address)
                                    });
                                if dispatch {
                                    for &target in &run {
                                        if candidates.contains(&target) && !found.contains_key(&target) {
                                            found.insert(target, None);
                                        }
                                    }
                                    continue;
                                }
                            }
                        }
                        // Otherwise the run holds more than one table's words (Pac-Man Rally's 1,151-word
                        // table follows another one) or the words of functions: the members that are
                        // candidates, grouped by the function the evidence names above them, are judged
                        // one group at a time, and only a group as large as a table the older rule reads
                        // (`MAX_CASE_RUN` members) is retracted. Smaller groups are a block of uncalled
                        // methods as often as a switch (Pac-Man Rally lost 35 truth functions that way).
                        let mut groups: Vec<(u64, Vec<u64>)> = Vec::new();
                        let mut members: Vec<u64> = run.iter().copied().filter(|target| candidates.contains(target)).collect();
                        members.sort_unstable();
                        members.dedup();
                        for target in members {
                            let above = evidenced.partition_point(|&other| other <= target);
                            let Some(&function) = above.checked_sub(1).map(|index| &evidenced[index]) else { continue };
                            match groups.last_mut() {
                                Some((owner, cases)) if *owner == function => cases.push(target),
                                _ => groups.push((function, vec![target])),
                            }
                        }
                        for (function, cases) in groups {
                            let last = *cases.last().expect("a group has a member");
                            if cases.len() < MAX_CASE_RUN || read.contains(&function) || last - function > MAX_WIDE_CASE_SPAN {
                                continue;
                            }
                            let dispatch = (function..last).step_by(4).any(|address| {
                                word(address).is_some_and(|w| w & 0xfc1f_ffff == 8 && (w >> 21) & 31 != 31)
                                    && bounded_jump(address)
                            });
                            if dispatch {
                                for target in cases {
                                    if !found.contains_key(&target) {
                                        found.insert(target, None);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // On ARMv4T/v5T, a Thumb entry that opens by giving back a frame
    // (`tears_down_frame`) is the tail of the function above, whoever calls
    // it: the call is a long jump.
    if super::thumb1(&imp.language) {
        let opens: Vec<u64> = sorted
            .iter()
            .copied()
            .filter(|&entry| !declared_kept(entry) && !found.contains_key(&entry) && tears_down_frame(imp, entry))
            .collect();
        for flow in provider.flow(&opens) {
            if flow.mode == Some(1) {
                found.insert(flow.address, None);
            }
        }
        // Called only from the function directly above, opening without a
        // frame of its own and releasing one at its first return: a label
        // inside that function, reached by a `bl` used as a long jump. It has
        // no owner to absorb it: the walk from the label ran on into code
        // that is not the owner's.
        // pokeemerald: 28 entries against 1 of 15,856 symbols (a `push`
        // opener is excluded; with it, 27 symbols qualify).
        let mut labels: Vec<u64> = Vec::new();
        for &entry in &sorted {
            if declared_kept(entry) || found.contains_key(&entry) || !entries_set.contains(&entry) {
                continue;
            }
            let Some(from) = callers.get(&entry) else { continue };
            let Some(&caller) = from.first() else { continue };
            let function = get_canonical_origin(caller, addr_origin);
            if function >= entry
                || !from.iter().all(|&c| get_canonical_origin(c, addr_origin) == function)
                || thumb_halfword_opens_frame(imp, entry)
            {
                continue;
            }
            let above = sorted.partition_point(|&other| other <= function);
            let below = sorted.partition_point(|&other| other < entry);
            if sorted[above..below].iter().any(|other| !found.contains_key(other) && !labels.contains(other)) {
                continue;
            }
            if thumb_stack_released(imp, entry).is_some_and(|delta| delta < 0) {
                labels.push(entry);
            }
        }
        for flow in provider.flow(&labels) {
            if flow.mode == Some(1) {
                found.insert(flow.address, None);
            }
        }
    }
    let mut found: Vec<(u64, Option<u64>)> = found.into_iter().collect();
    found.sort_unstable();
    found
}

fn get_canonical_origin(mut addr: u64, addr_origin: &HashMap<u64, u64>) -> u64 {
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
    addr_origin: &mut HashMap<u64, u64>,
    proven_bodies: &mut HashMap<u64, u64>,
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

/// A test resolver: the closure answers each flow request.
#[cfg(test)]
struct TestProvider<F>(F);

#[cfg(test)]
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

#[cfg(test)]
/// Core flow-based discovery over a provided control-flow resolver.
pub fn flow_discover_with_provider<F: FnMut(&[u64]) -> Vec<crate::native_runtime::FlowResult>>(
    imp: &mut NativeImport,
    flow_provider: F,
) {
    flow_discover_with_candidates(imp, &[], None, &mut TestProvider(flow_provider))
        .expect("flow-only discovery has no pattern prerequisites");
}

/// The same walk with the boundary sweep's candidates, as `discover_mapped` runs it.
#[cfg(test)]
fn flow_discover_with_sweep<F: FnMut(&[u64]) -> Vec<crate::native_runtime::FlowResult>>(
    imp: &mut NativeImport,
    candidates: &[u64],
    flow_provider: F,
) {
    flow_discover_with_candidates(imp, candidates, None, &mut TestProvider(flow_provider))
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
    let mut linkage_candidates = HashSet::default();
    let mut conditional_targets = HashSet::default();
    // Addresses the instruction above falls into. Ghidra refuses a pattern
    // match there: the flow above already owns it
    // (FunctionStartAnalyzer.checkAlreadyInFunctionAbove, 491-530).
    let mut fell_into: HashSet<u64> = HashSet::default();
    let mut flow_endings = Vec::new();
    let mut indirect_jumps: Vec<u64> = Vec::new();
    let mut context_edges = Vec::new();
    let mut branch_targets = Vec::new();
    // Table metadata supplies boundaries, not functions. Each entry still needs
    // bounded p-code evidence ending in an indirect transfer through a known slot.
    // Membership mirror for the scan below: per-candidate linear search
    // over the function list.
    let mut known_functions: HashSet<u64> =
        imp.functions.iter().map(|f| f.entry).collect();
    if has_linkage_slots {
        for chunk in imp.plt_candidates.chunks(1024) {
            let addresses: Vec<_> = chunk.iter().map(|&(address, _)| address).collect();
            for (&(address, width), linkage) in
                chunk.iter().zip(flow_provider.plt_linkages(&addresses))
            {
                let known = known_functions.contains(&address);
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
                            known_functions.insert(address);
                            imp.functions.push(NativeFunction {
                                entry: address,
                                name: format!("FUN_{address:08x}"),
                                size: linkage.length as u64,
                            });
                        }
                        imp.thunks.push(crate::native::NativeThunk {
                            entry: address,
                            destination,
                            kind: romwright_model::ThunkKind::Direct,
                            source: crate::native::THUNK_SOURCE,
                        });
                    }
                    continue;
                };
                if !known {
                    known_functions.insert(address);
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
                    kind: romwright_model::ThunkKind::Linkage,
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
        .filter(|a| !opens_with_alignment_fill(imp, *a) || imp.symbol_named.contains(a))
        .collect();
    entries.sort_unstable();
    entries.dedup();
    // Membership mirror: the walk tests entryhood per decoded target,
    // which is O(n) over this Vec at 590k entries. The Vec keeps iteration
    // order; the set answers membership.
    let mut entries_set: HashSet<u64> =
        entries.iter().copied().collect();

    let mut calls: Vec<(u64, u64)> = Vec::new();
    // Every unconditional direct branch, kept until function extents are
    // known: only then can a transfer out of a function be told apart from a
    // loop inside one.
    let mut branch_transfers: Vec<(u64, u64)> = Vec::new();
    let mut instruction_extents = Vec::new();
    // Index over the same extents for the mid-instruction test below: a
    // linear scan per branch target is O(decoded) each, which never
    // converges on a 56MB text. Any extent covering a target starts
    // within max_extent bytes before it, so probing those starts is exact.
    let mut extent_index: HashMap<u64, u64> = HashMap::default();
    let mut max_extent: u64 = 0;
    // Every shape recorded so far, this walk's and earlier rounds'. Every
    // round re-walks from its seeds, so the same instruction used to be
    // recorded once per round: 2.56 M records for 930 k instructions by
    // swkotor2's third round, all written to each switch-recovery scratch
    // store and measured again at store time. An exact repeat carries
    // nothing; first-seen order is kept.
    let mut shapes_seen: HashSet<crate::native::FlowShape> =
        HashSet::with_capacity_and_hasher(imp.flow_shapes.len(), Default::default());
    imp.flow_shapes.retain(|shape| shapes_seen.insert(*shape));
    // `imp.functions` does not change during the walk below.
    let function_extents = crate::native::ExtentIndex::build(
        &imp.functions.iter().map(|function| (function.entry, function.size)).collect::<Vec<_>>(),
    );
    let mut thunk_candidates = HashSet::default();
    let mut thunk_jumps = Vec::new();
    let mut thunk_roots = HashMap::default();
    let mut thunk_continuations = HashMap::default();
    let mut landing_entries = HashMap::default();
    // Ghidra CreateThunkFunctionCmd.getSimpleFlow: one unconditional transfer
    // is a thunk when it is a jump, or a call that terminates flow. Only a
    // proven non-returning destination makes a call terminal here.
    let mut terminal_transfers: HashMap<u64, u64> = HashMap::default();
    let mut proven_bodies: HashMap<u64, u64> =
        HashMap::with_capacity_and_hasher(4096, Default::default());
    // The instruction set each function entry was decoded in, taken at the
    // moment its first instruction was read: a later console -- the reference
    // pass, a decompile worker -- must read the same bytes the same way, and
    // asking this console afterwards would not do, because every probe it
    // has made since has written the mode switches those bytes carry into its
    // one context database (SLEIGH `globalset`; Ghidra keeps pseudo-
    // disassembly out of the program's context, this console cannot).
    let mut entry_modes: Vec<(u64, u64)> = Vec::new();
    let mut addr_origin: HashMap<u64, u64> =
        HashMap::with_capacity_and_hasher(32768, Default::default());
    for &s in &entries {
        addr_origin.insert(s, s);
    }
    let mut visited: HashSet<u64> = HashSet::with_capacity_and_hasher(32768, Default::default());
    let mut repeats = RepeatRuns::default();
    // Entries whose Thumb-1 code does not decode (`refuses_entry`), over the
    // whole walk: they are never walked, and leave the function list below.
    let thumb_entries = super::thumb1(&imp.language);
    let mut refused_entries: Vec<u64> = Vec::new();
    let mut walked_entries: std::collections::HashSet<u64> = std::mem::take(&mut imp.walk_entries);
    let mut flowed_modes: HashMap<u64, u64> = HashMap::default();
    // Entries a data pointer proposed, as opposed to a seed the loader
    // declared or a call reached: only these are retractable below.
    let mut data_derived: HashSet<u64> = HashSet::default();
    // Candidates only the boundary sweep proposed (the first instruction after
    // a return): their evidence is the boundary, not an address read from
    // data, so the case-label overlap rule below does not apply to them. It
    // chains on the furthest span, and one tail-call stub whose span stretches
    // over its callee retracted every entry between them: 11,130 of 11,210 on
    // Skyward Sword, 9,110 of 14,367 on GameCube Pikmin 2 (one stub).
    let sweep_only: HashSet<u64> = if candidates.is_empty() {
        HashSet::default()
    } else {
        let data: HashSet<u64> = imp
            .reloc_candidates
            .iter()
            .chain(&imp.pointer_candidates)
            .chain(&imp.initializer_candidates)
            .copied()
            .collect();
        candidates.iter().copied().filter(|candidate| !data.contains(candidate)).collect()
    };
    let mut active: Vec<u64> = entries.clone();
    walked_entries.extend(entries.iter().copied());
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
            let before = refused_entries.len();
            let (chunk, flows, runs) = repeats.admit(
                imp,
                chunk,
                flow_provider.flow(chunk),
                |address, flow| thumb_entries && refuses_entry(imp, &addr_origin, &entries_set, address, flow),
                &mut refused_entries,
            );
            let chunk = &chunk[..];
            // Code another function reaches at a refused address is that
            // function's to decode.
            for address in &refused_entries[before..] {
                visited.remove(address);
            }
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
                        || entries_set.contains(&target)
                        || covers_inside(&extent_index, max_extent, target)
                        || flows.iter().any(|flow| {
                            // The current chunk is indexed only after this
                            // loop, so its fresh instructions need their
                            // own bounded check (1024 entries at most).
                            target > flow.address
                                && target - flow.address < flow.length as u64
                        })
                    {
                        continue;
                    }
                    linkage_candidates.insert(target);
                }
            }
            let thunks = confirmed_thunks(
                imp,
                &entries_set,
                &landing_entries,
                &visited,
                &function_extents,
                &extent_index,
                max_extent,
                chunk,
                &flows,
                flow_provider,
            );
            for ((addr, info), run) in chunk.iter().copied().zip(flows).zip(runs) {
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
                    && entries_set.contains(&addr)
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
                    // Same start decoded twice (shared code reached from two
                    // entries, or two modes): the scan matched any of them,
                    // so the index keeps the widest -- same start means the
                    // widest covers the union exactly.
                    extent_index
                        .entry(addr)
                        .and_modify(|size| *size = (*size).max(info.length as u64))
                        .or_insert(info.length as u64);
                    max_extent = max_extent.max(info.length as u64);
                }
                if !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl) {
                    // The shape of what was just decoded, for the structural
                    // features a whole-program diff matches on. A conditional
                    // or indirect flow's extra targets are recorded elsewhere
                    // (`switch_tables`); this carries the single direct one.
                    let shape = crate::native::FlowShape {
                        address: addr,
                        length: info.length,
                        kind: info.kind,
                        conditional: info.conditional,
                        target: match info.kind {
                            FlowKind::Branch | FlowKind::CBranch if info.targets.len() == 1 => {
                                Some(info.targets[0])
                            }
                            _ => None,
                        },
                    };
                    if shapes_seen.insert(shape) {
                        imp.flow_shapes.push(shape);
                    }
                }
                if has_linkage_slots && info.kind != FlowKind::Fallthrough {
                    flow_endings.push((addr, info.kind == FlowKind::BranchInd));
                }
                if info.kind == FlowKind::BranchInd {
                    indirect_jumps.push(addr);
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
                            if in_code(*t) && !entries_set.contains(t) && !opens_with_fill(imp, *t) {
                                entries.push(*t);
                                entries_set.insert(*t);
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
                                if !entries_set.contains(&t) {
                                    entries.push(t);
                                    entries_set.insert(t);
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
                                    .or(Some(&addr).filter(|_| entries_set.contains(&addr)))
                                {
                                    imp.thunks.push(crate::native::NativeThunk {
                                        entry,
                                        destination: t,
                                        kind: romwright_model::ThunkKind::Direct,
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
                    FlowKind::BranchInd => {
                        // A table the decompiler recovered here: each case is
                        // the jump's own flow, owned by the function it is in.
                        if let Some(targets) = imp.switch_tables.get(&addr) {
                            for &t in targets {
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
                    }
                    FlowKind::CallInd
                    | FlowKind::Fallthrough
                    | FlowKind::Return
                    | FlowKind::Bad
                    | FlowKind::Unimpl => {}
                }
                if let Some(fall) = info
                    .fallthrough
                    .filter(|_| !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl))
                {
                    fell_into.insert(fall);
                    repeats.follow(fall, &info, run);
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
                    let pattern_indexes =
                        patterns::PatternIndexes::build(imp, &entries_set);
                    let collected = patterns::collect(
                        imp,
                        patterns,
                        &pattern_indexes,
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
                    imp.patterns_seen = Some(romwright_model::PatternStats {
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
            // Only the relocation round's address and flow checks read the
            // extents; a pattern round's candidates face neither, and the
            // index over every decoded instruction is costly to rebuild.
            known_extents: crate::native::ExtentIndex::build(if pattern_round { &[] } else { &extents }),
            initial_seeds: &entries.iter().copied().collect(),
        };

        // Relocation candidates: reject candidates already visited inside trusted bodies
        let mut unvisited_relocs: Vec<u64> = if pattern_round {
            pattern_candidates
                .iter()
                .map(|candidate| candidate.address)
                .collect()
        } else {
            let mut jump_tables = super::elf_pointers::jump_table_targets(
                imp,
                |target| visited.contains(&target) && !entries_set.contains(&target),
                |target| entries_set.contains(&target),
            );
            jump_tables.extend(super::pe::operand_hooks::dense_table_targets(imp, |target| entries_set.contains(&target)));
            // A jump table behind its function (Visual C++ on i386) is named by the `jmp`'s displacement:
            // data read as memory, not a function pointer.
            let operand_data = super::pe::operand_hooks::memory_only_targets(imp);
            imp.reloc_candidates
                .iter()
                // A PE has no pointer candidates: its relocated words are the evidence, and
                // a run of them that only case labels name is a jump table.
                .filter(|target| imp.format != "PE" || !jump_tables.contains(target))
                .filter(|target| !operand_data.contains(target))
                .chain(imp.pointer_candidates.iter().filter(|target| !jump_tables.contains(target)))
                .chain(imp.initializer_candidates.iter())
                .chain(candidates.iter())
                // A tail call's target is a candidate, never a conclusion: it
                // faces the same address and flow evidence as a relocation
                // candidate below. II.1 reserves enabling this by default.
                .chain(
                    branch_transfers
                        .iter()
                        .map(|(_, target)| target)
                        .filter(|_| promote_tailcalls(imp)),
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
                && !opens_with_alignment_fill(imp, cand)
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
                    if !entries_set.contains(&r) {
                        entries.push(r);
                        entries_set.insert(r);
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
                            if !sweep_only.contains(&r) {
                                data_derived.insert(r);
                            }
                        } else {
                            // Recorded on acceptance, not on match: a match
                            // the decode then refuses (an offcut once its
                            // owner is decoded) is no start, and as a
                            // recorded one the store's const rule counted it
                            // as a stronger entry and retracted the real
                            // function around it (swkotor2 0x727010).
                            imp.pattern_starts.push(r);
                        }
                    }
                }
                let reloc_set: HashSet<u64> = if pattern_round {
                    HashSet::default()
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
                        let before = refused_entries.len();
                        let (chunk, flows, runs) = repeats.admit(
                            imp,
                            chunk,
                            flow_provider.flow(chunk),
                            |address, flow| thumb_entries && refuses_entry(imp, &addr_origin, &entries_set, address, flow),
                            &mut refused_entries,
                        );
                        let chunk = &chunk[..];
                        for address in &refused_entries[before..] {
                            visited.remove(address);
                        }
                        flow_modes_into_targets(&flows, &visited, &mut flowed_modes, flow_provider);
                        for ((addr, info), run) in chunk.iter().copied().zip(flows).zip(runs) {
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
                                // Same shape record as the main walk: bodies
                                // the reloc round confirms are decoded here,
                                // and without shapes they get no features and
                                // no body digest downstream.
                                let shape = crate::native::FlowShape {
                                    address: addr,
                                    length: info.length,
                                    kind: info.kind,
                                    conditional: info.conditional,
                                    target: match info.kind {
                                        FlowKind::Branch | FlowKind::CBranch
                                            if info.targets.len() == 1 =>
                                        {
                                            Some(info.targets[0])
                                        }
                                        _ => None,
                                    },
                                };
                                if shapes_seen.insert(shape) {
                                    imp.flow_shapes.push(shape);
                                }
                            }
                            if has_linkage_slots {
                                if info.kind != FlowKind::Fallthrough {
                                    flow_endings.push((addr, info.kind == FlowKind::BranchInd));
                                }
                                if info.kind == FlowKind::BranchInd {
                                    indirect_jumps.push(addr);
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
                                        if in_code(*t) && !entries_set.contains(t) && !opens_with_fill(imp, *t) {
                                            entries.push(*t);
                                            entries_set.insert(*t);
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
                                FlowKind::BranchInd => {
                                    if let Some(targets) = imp.switch_tables.get(&addr) {
                                        for &t in targets {
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
                                }
                                _ => {}
                            }
                            if let Some(fall) = info
                                .fallthrough
                                .filter(|_| !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl))
                            {
                                repeats.follow(fall, &info, run);
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
            // Per-round precomputes: the inner fixpoint below used to scan
            // every call edge, the entry prefix and all pattern edges per
            // candidate per iteration.
            let call_targets: HashSet<u64> =
                calls.iter().map(|&(_, target)| target).collect();
            let existing: HashSet<u64> =
                entries[..existing_entry_count].iter().copied().collect();
            let mut edges_by_target: HashMap<u64, Vec<u64>> =
                HashMap::default();
            for &(target, source) in &pattern_edges {
                edges_by_target.entry(target).or_default().push(source);
            }
            let called = |address| call_targets.contains(&address);
            let established = |address| {
                existing.contains(&address)
                    || called(address)
                    || pattern_candidates
                        .binary_search_by_key(&address, |candidate| candidate.address)
                        .is_ok_and(|index| !pattern_candidates[index].possible)
            };
            let mut rejected = HashSet::default();
            loop {
                let mut changed = false;
                for candidate in &pattern_candidates {
                    if !candidate.possible
                        || called(candidate.address)
                        || rejected.contains(&candidate.address)
                    {
                        continue;
                    }
                    let owner = edges_by_target
                        .get(&candidate.address)
                        .into_iter()
                        .flatten()
                        .map(|&source| get_canonical_origin(source, &addr_origin))
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
            entries_set.retain(|entry| !rejected.contains(entry));
            // A rejected start is its owner's code, not a start.
            imp.pattern_starts.retain(|start| !rejected.contains(start));
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
    let mut context_targets = HashSet::default();
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
            .retain(|(target, _)| context_targets.contains(target) && !entries_set.contains(target));
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

    // A pattern start that the function right above it branches to, over
    // its own return, is that function's code. Ghidra refuses a start any
    // flow reference already owns (checkAlreadyInFunctionAbove), but the
    // branch may decode only after the pattern round accepted the start,
    // when its owner is reached late. swkotor2 0x4cfd97: the `jge` past
    // 0x4cfd80's early return, accepted on its push-ebx/esi/edi prologue,
    // cut its owner to a 23-byte guard (eight such splits in that image).
    // Only the adjacent owner absorbs: a far conditional branch is a tail
    // call to a real function (swkotor2 0x76fa60's SSE2 test jumping 37 KB
    // to the x87 fallback at 0x778b77, which has its own frame), and a
    // called, declared or thunk entry is a function whoever branches to it.
    {
        let called: HashSet<u64> = calls.iter().map(|&(_, target)| target).collect();
        let declared: HashSet<u64> = imp.symbol_named.iter().copied().collect();
        // A start accepted in an earlier discovery round is already a row
        // in `imp.functions`; its owner may only be walked in a later round,
        // so it stays eligible (swkotor2 0x6a339a and 0x6a9763). Only the
        // loader's own declarations are exempt.
        let pattern_only: HashSet<u64> = imp
            .pattern_starts
            .iter()
            .copied()
            .filter(|entry| {
                !called.contains(entry)
                    && !thunk_candidates.contains(entry)
                    && !declared.contains(entry)
            })
            .collect();
        let mut absorbed: HashSet<u64> = HashSet::default();
        if !pattern_only.is_empty() {
            let mut sorted: Vec<u64> = entries.clone();
            sorted.sort_unstable();
            sorted.dedup();
            // Where each decoded return ends: a guard clause's return is the
            // instruction right before the body it jumps over.
            let return_ending_at: HashMap<u64, u64> = imp
                .flow_shapes
                .iter()
                .filter(|shape| shape.kind == FlowKind::Return)
                .map(|shape| (shape.address + u64::from(shape.length), shape.address))
                .collect();
            let owned: Vec<(u64, u64)> = imp
                .flow_shapes
                .iter()
                .filter(|shape| shape.conditional)
                .filter_map(|shape| shape.target.map(|target| (shape.address, target)))
                .filter(|&(source, target)| source < target && pattern_only.contains(&target))
                .collect();
            for (source, target) in owned {
                let owner = get_canonical_origin(source, &addr_origin);
                // The owner is the entry immediately below the target, and a
                // return of its own ends exactly where the target begins:
                // the branch jumps over that return. The proven span is no
                // evidence here -- it only ever grows, so an owner whose walk
                // once ran on into the target's body reads past it (5 of
                // swkotor2's 8 splits), and padding after a tail-calling
                // function can read contiguous the same way.
                let below = sorted.partition_point(|&entry| entry < target);
                let returns_into = return_ending_at.get(&target).is_some_and(|&ret| {
                    owner < ret && get_canonical_origin(ret, &addr_origin) == owner
                });
                if owner < source && below > 0 && sorted[below - 1] == owner && returns_into {
                    merge_reached_candidate(
                        target,
                        owner,
                        &pattern_only,
                        &mut addr_origin,
                        &mut proven_bodies,
                    );
                    absorbed.insert(target);
                }
            }
        }
        // An absorbed start is its owner's code, not a start: its earlier
        // round's row must go (kept, it returns as an entry and the next-
        // entry boundary cuts its owner at it again), and so must its
        // pattern-start record, which the store's const rule counts as a
        // stronger entry swallowed (swkotor2 0x7270ff inside the callback
        // 0x727010 retracted the callback).
        if !absorbed.is_empty() {
            imp.functions.retain(|function| !absorbed.contains(&function.entry));
            imp.pattern_starts.retain(|start| !absorbed.contains(start));
            imp.absorbed_starts.extend(absorbed.iter().copied());
        }
    }
    // Entries with no evidence of their own that sit inside another
    // function's code are that function's code (`interior_entries`).
    {
        let mut callers: HashMap<u64, Vec<u64>> = HashMap::default();
        for &(from, target) in &calls {
            callers.entry(target).or_default().push(from);
        }
        for x in imp.xrefs.iter().filter(|x| x.kind.contains("CALL")) {
            callers.entry(x.to).or_default().push(x.from);
        }
        let interior = interior_entries(
            imp,
            &entries,
            &entries_set,
            &callers,
            &thunk_candidates,
            &addr_origin,
            flow_provider,
        );
        if !interior.is_empty() {
            let retractable: HashSet<u64> = interior.iter().map(|&(entry, _)| entry).collect();
            // The owner absorbs the entry's proven span; an entry only the
            // MIPS boundary rule refuses has no owner, and its bytes stay
            // with whatever function reaches them.
            for &(entry, owner) in &interior {
                if let Some(owner) = owner {
                    merge_reached_candidate(entry, owner, &retractable, &mut addr_origin, &mut proven_bodies);
                }
            }
            entries.retain(|entry| !retractable.contains(entry));
            entries_set.retain(|entry| !retractable.contains(entry));
            imp.functions.retain(|function| !retractable.contains(&function.entry));
            imp.pattern_starts.retain(|start| !retractable.contains(start));
            // A call xref names an address inside a body; it does not bring
            // the entry back (`close_call_targets`).
            refused_entries.extend(retractable.iter().copied().filter(|entry| callers.contains_key(entry)));
        }
    }
    // Canonicalize proven_bodies so descendant spans are merged into their root origins:
    let mut canon_bodies: HashMap<u64, u64> =
        HashMap::with_capacity_and_hasher(proven_bodies.len(), Default::default());
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
    entries_set.retain(|&e| get_canonical_origin(e, &addr_origin) == e);

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
        let mut sharing: HashSet<u64> = HashSet::default();
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
        entries_set.retain(|entry| !sharing.contains(entry));
    }
    // Read off the walk's own attribution, which the span rule above cannot
    // see. The walk gives a shared address to whichever entry reaches it
    // first, so spans can abut where code is shared: a case label near the
    // tail of a switch reaches the dispatching function's loop head in a few
    // instructions, the function itself in dozens, and the head, the
    // dispatch and the first cases then belong to a label that sits above
    // them. The function ends where its own walk was stopped, the dispatch
    // is in no function extent, and its table is never asked for (God Hand
    // 0x1627d8: label 0x1629e4 owned 0x162898..0x1628ec; Fatal Frame
    // 0x1b8be8's second dispatch, in every round). An entry that only data
    // names -- a word of a pointer table, in this walk or an earlier one --
    // and nothing calls, whose reached code starts below it and joins the
    // span of the entry above, has run into that function's code: the
    // function takes the span. The entry stays until something decides it
    // (the table of the dispatch, once the function holds it); dropping it
    // here only made the data-pointer seeding of the next round put it back.
    {
        let called: HashSet<u64> = calls.iter().map(|&(_, target)| target).collect();
        let declared: HashSet<u64> = imp.symbol_named.iter().copied().collect();
        let weak: HashSet<u64> = data_derived
            .iter()
            .chain(&imp.reloc_candidates)
            .chain(&imp.pointer_candidates)
            .chain(&imp.initializer_candidates)
            .chain(&imp.table_seeds)
            .copied()
            .filter(|entry| entries_set.contains(entry) && !called.contains(entry) && !declared.contains(entry))
            .collect();
        // The label's reach below it.
        let mut below: HashMap<u64, Vec<u64>> = HashMap::default();
        if !weak.is_empty() {
            for &address in addr_origin.keys() {
                let origin = get_canonical_origin(address, &addr_origin);
                if origin > address && weak.contains(&origin) {
                    below.entry(origin).or_default().push(address);
                }
            }
        }
        // As instruction starts, with their lengths: the shapes every round
        // recorded (the walk of the candidates' round keeps no extents).
        let lengths: HashMap<u64, u64> = if below.is_empty() {
            HashMap::default()
        } else {
            let wanted: HashSet<u64> = below.values().flatten().copied().collect();
            imp.flow_shapes
                .iter()
                .filter(|shape| wanted.contains(&shape.address))
                .map(|shape| (shape.address, u64::from(shape.length)))
                .collect()
        };
        for reached in below.values_mut() {
            reached.retain(|address| lengths.contains_key(address));
        }
        below.retain(|_, reached| !reached.is_empty());
        // Where an instruction that falls through ends: the owner has to run
        // into the label's code, not merely end where it begins (a function
        // that returns just below a tail-calling label, God Hand 0x34c930).
        let lows: HashSet<u64> = below.values().filter_map(|reached| reached.iter().min().copied()).collect();
        let fallen_into: HashSet<u64> = imp
            .flow_shapes
            .iter()
            .filter(|shape| {
                shape.conditional || matches!(shape.kind, FlowKind::Fallthrough | FlowKind::Call | FlowKind::CallInd | FlowKind::CBranch)
            })
            .map(|shape| shape.address + u64::from(shape.length))
            .filter(|end| lows.contains(end))
            .collect();
        if !below.is_empty() {
            let mut sorted: Vec<u64> = entries.clone();
            sorted.sort_unstable();
            sorted.dedup();
            let mut labels: Vec<u64> = below.keys().copied().collect();
            labels.sort_unstable();
            for label in labels {
                let reached = below.get_mut(&label).expect("a label with a reach");
                reached.sort_unstable();
                let low = reached[0];
                let above = sorted.partition_point(|&entry| entry <= low);
                let Some(owner) = above.checked_sub(1).map(|index| sorted[index]) else { continue };
                if owner == label
                    || below.contains_key(&owner)
                    || !fallen_into.contains(&low)
                    || !proven_bodies.get(&owner).is_some_and(|&end| end >= low)
                {
                    continue;
                }
                // The run of decoded instructions from the lowest one, which
                // is what the function takes: the label's own flow beyond
                // it is not the owner's.
                let reached = &below[&label];
                let mut reach = low;
                for &address in reached {
                    if address > reach {
                        break;
                    }
                    reach = reach.max(address + lengths[&address]);
                }
                proven_bodies.entry(owner).and_modify(|end| *end = (*end).max(reach));
            }
        }
    }

    let mut refused: HashSet<u64> = refused_entries.iter().copied().collect();
    if !refused.is_empty() {
        entries.retain(|entry| !refused.contains(entry));
        entries_set.retain(|entry| !refused.contains(entry));
        imp.pattern_starts.retain(|start| !refused.contains(start));
    }
    entries.sort_unstable();
    entries.dedup();
    let mut jumps: HashSet<(u64, u64)> = if thunk_jumps.is_empty() {
        HashSet::default()
    } else {
        imp.xrefs
            .iter()
            .filter(|x| x.kind == "UNCONDITIONAL_JUMP")
            .map(|x| (x.from, x.to))
            .collect()
    };
    for (from, to) in thunk_jumps {
        if jumps.insert((from, to)) {
            let provenance = if entries_set.contains(&to) {
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
    // asked (`ROMWRIGHT_PROMOTE_TAILCALLS`).
    if promote_tailcalls(imp) {
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
                entries_set.insert(candidate);
                addr_origin.insert(candidate, candidate);
                proven_bodies.insert(candidate, end);
            }
        }
        entries.sort_unstable();
        entries.dedup();
    }

    let mut merged = imp.functions.clone();
    // `entries` is sorted and deduplicated, so only the loader's rows can
    // already hold an entry.
    let present: HashSet<u64> = merged.iter().map(|f| f.entry).collect();
    for e in entries {
        if !present.contains(&e) {
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
    // An earlier round's row for a refused entry goes too, before it bounds
    // the body below it.
    merged.retain(|f| !refused.contains(&f.entry));
    // An entry that opens in the linker's alignment fill is no function, whoever
    // seeded it, unless the image declares it (`opens_with_alignment_fill`).
    merged.retain(|f| !opens_with_alignment_fill(imp, f.entry) || imp.symbol_named.contains(&f.entry));

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
    // A MIPS body is whole instructions, so one whose proven span ends off the
    // word grid decoded into bytes that are no instruction: the entry is a
    // call or a branch out of data (`undecodable_bodies`).
    if imp.language.starts_with("r5900") {
        let undecodable = undecodable_bodies(imp, &merged);
        if !undecodable.is_empty() {
            merged.retain(|function| !undecodable.contains(&function.entry));
            refused.extend(undecodable);
        }
    }
    imp.functions = merged;
    // Hand the walk's state back for the next round to resume from.
    imp.walk_entries = walked_entries;
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
    indirect_jumps.sort_unstable();
    indirect_jumps.dedup();
    // A Thumb `pop {..rX..}; bx rX` is a return, not a computed jump: agbcc
    // and older GCC return this way from nearly every function. As switch
    // candidates they made recovery decompile 12,607 owners of
    // pokeemerald (budget-capped at 1,024, 1,400 s) to find no table; 14,635
    // of the ROM's 15,991 `bx rX` are this pair.
    if crate::compiler::rules::applies("thumb-pop-bx-is-return", &crate::compiler::ctx_of(imp)) {
        indirect_jumps.retain(|&address| !thumb_pop_return(imp, address));
    }
    imp.indirect_jumps = indirect_jumps;
    // The bytes this walk decoded, merged into ranges: what a later pass
    // reads to tell a target it has seen from one it has not.
    let mut decoded: Vec<(u64, u64)> = Vec::new();
    let mut sorted_extents: Vec<(u64, u64)> = extents[instruction_start..]
        .iter()
        .map(|&(start, length)| (start, start + length))
        .collect();
    sorted_extents.sort_unstable();
    for (start, end) in sorted_extents {
        match decoded.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => decoded.push((start, end)),
        }
    }
    imp.decoded_ranges = decoded;
    let transfers: Vec<u64> = flow_endings
        .iter()
        .filter(|&&(_, indirect)| indirect)
        .map(|&(address, _)| address)
        .collect();
    imp.indirect_transfers = transfers;
    let rules = crate::compiler::ctx_of(imp);
    let no_return: HashSet<u64> = imp
        .functions
        .iter()
        .filter(|f| crate::nonreturn::known_no_return(&rules, &f.name))
        .map(|f| f.entry)
        .collect();
    // A transfer that cannot return ends the body, so an entry holding one is
    // a thunk to that destination. Unknown destinations stay ordinary flow.
    for (&entry, &destination) in &terminal_transfers {
        if no_return.contains(&destination) {
            imp.thunks.push(crate::native::NativeThunk {
                entry,
                destination,
                kind: romwright_model::ThunkKind::Direct,
                source: crate::native::THUNK_SOURCE,
            });
        }
    }
    // Only retained functions carry facts, and a direct destination must be a
    // retained entry of its own. Unproven candidates leave no thunk row.
    let retained: HashSet<u64> = imp.functions.iter().map(|f| f.entry).collect();
    let mut owners = HashSet::default();
    let mut thunks = std::mem::take(&mut imp.thunks);
    thunks.retain(|thunk| {
        retained.contains(&thunk.entry)
            && thunk.destination != thunk.entry
            && (thunk.kind != romwright_model::ThunkKind::Direct
                || retained.contains(&thunk.destination))
            && owners.insert(thunk.entry)
    });
    thunks.sort_unstable_by_key(|thunk| thunk.entry);
    imp.thunks = thunks;
    // Every function this run kept as an ordinary function is decided: a
    // later run may find its jump target has become a function, and, as
    // Ghidra, leaves the function as it was created.
    imp.thunk_settled.extend(
        imp.functions
            .iter()
            .map(|function| function.entry)
            .filter(|entry| !imp.thunks.iter().any(|thunk| thunk.entry == *entry)),
    );

    let mut seen_xrefs: HashSet<(u64, u64)> = imp.xrefs.iter().map(|x| (x.from, x.to)).collect();
    for (from, to) in calls {
        if seen_xrefs.insert((from, to)) {
            imp.xrefs.push(NativeXref::new(from, to, "UNCONDITIONAL_CALL"));
        }
    }
    close_call_targets(imp);
    // A call xref (the reference pass records them too) does not bring a
    // refused entry back.
    if !refused.is_empty() {
        imp.functions.retain(|f| !refused.contains(&f.entry));
    }
    imp.branch_transfers = branch_transfers;
    imp.branch_transfers.sort_unstable();
    imp.branch_transfers.dedup();
    record_branch_transfers(imp);
    Ok(())
}

/// The entries of `functions` (sizes just proven) whose body ends where no
/// r5900 instruction does (the PS1's GTE and the PSP's VFPU decode to bytes
/// SLEIGH has no instruction for in real functions: Rage Racer 0x80062dc4): the walk from the entry met bytes SLEIGH has no
/// instruction for, and the span it proved stops at a width that is not a
/// multiple of the instruction's. Real code never decodes that way: of the 8
/// PS2 games' functions the import made, none of the 52,000 the truth names
/// had such a size, and the 45 that did were all invented (Persona 4 37, Dark
/// Cloud 3, Dark Chronicle 3, God Hand 1, Digital Devil Saga 1): calls made
/// by jal-shaped words of the data between the code and the `.sdata`, whose
/// targets the walk then decoded as junk. An entry the image declares is kept.
fn undecodable_bodies(imp: &NativeImport, functions: &[NativeFunction]) -> HashSet<u64> {
    let declared: HashSet<u64> = imp
        .symbol_named
        .iter()
        .copied()
        .chain(imp.externals.iter().map(|&(address, _)| address))
        .chain(imp.process_entry)
        .collect();
    functions
        .iter()
        .filter(|function| function.size % 4 != 0 && !declared.contains(&function.entry))
        .map(|function| function.entry)
        .collect()
}

/// Whether an indexed extent strictly covers `target`: one starts before it,
/// within the widest extent's length, and ends after it.
fn covers_inside(index: &HashMap<u64, u64>, max_extent: u64, target: u64) -> bool {
    (target.saturating_sub(max_extent)..target)
        .any(|start| index.get(&start).is_some_and(|&size| target - start < size))
}

/// FxHash's multiply-rotate over each word a value hashes, for the module's
/// sets and maps (see `HashMap` above) and the shape dedupe: they only need
/// equality, and with SipHash the dedupe alone was about a tenth of the
/// import process's own CPU on GBA. `finish` rotates the product as
/// rustc-hash 2 does: an aligned address leaves the low bits of the product
/// zero, and the table indexes buckets by the low bits.
#[derive(Default)]
struct WordHasher(u64);

impl WordHasher {
    fn add(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}

impl std::hash::Hasher for WordHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.add(u64::from(byte));
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.add(u64::from(value));
    }

    fn write_u64(&mut self, value: u64) {
        self.add(value);
    }

    fn write_usize(&mut self, value: usize) {
        self.add(value as u64);
    }

    fn write_isize(&mut self, value: isize) {
        self.add(value as u64);
    }

    fn finish(&self) -> u64 {
        self.0.rotate_left(26)
    }
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
pub(crate) const BRANCH_PROVENANCE: &str = "native-import:branch";

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
        kind: romwright_model::ThunkKind::Linkage,
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
    entries: &HashSet<u64>,
    landing_entries: &HashMap<u64, u64>,
    visited: &HashSet<u64>,
    functions: &crate::native::ExtentIndex,
    extents: &HashMap<u64, u64>,
    max_extent: u64,
    addresses: &[u64],
    flows: &[crate::native_runtime::FlowResult],
    provider: &mut P,
) -> HashMap<u64, u64> {
    // Ghidra decides whether a function is a thunk when it creates it
    // (`CreateFunctionCmd` -> `CreateThunkFunctionCmd`): a jump to an address
    // that is not yet a function makes an ordinary function, and no later
    // pass revisits it once the target becomes one. A function this import
    // already proved a body for -- an earlier round created it -- keeps that
    // decision; only an entry created in this round is a thunk candidate.
    let settled = &imp.thunk_settled;
    let mut candidates = HashMap::default();
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
        if settled.contains(&entry) {
            continue;
        }
        let target = flow.targets[0];
        if target == address
            || target == entry
            || (visited.contains(&target) && !entries.contains(&target))
            || !imp
                .mappings
                .iter()
                .any(|m| m.flags & 4 != 0 && target >= m.vaddr && target - m.vaddr < m.size)
            || functions.contains(target)
            || covers_inside(extents, max_extent, target)
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
/// A linkage stub loads a slot and branches through it; on languages where
/// those are different instructions the override has to name the branch --
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
    let thunks: Vec<(u64, u64, u64, romwright_model::ThunkKind)> = imp
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
            romwright_model::ThunkKind::Linkage => {
                let start = endings.partition_point(|&(address, _)| address < entry);
                endings[start..]
                    .iter()
                    .take_while(|&&(address, _)| address < end)
                    .filter(|&&(_, indirect)| indirect)
                    .map(|&(address, _)| address)
                    .last()
            }
            romwright_model::ThunkKind::Direct => imp
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
        if kind == romwright_model::ThunkKind::Direct && entries.contains(&address) {
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

/// Whether the halfwords at `address` are a Thumb `bx rX` directly after a
/// `pop` whose register list holds `rX`: the return idiom of Thumb code
/// that predates `pop {pc}` interworking.
pub(super) fn thumb_pop_return(imp: &NativeImport, address: u64) -> bool {
    let halfword = |at: u64| -> Option<u16> {
        imp.mappings.iter().find_map(|mapping| {
            let offset = at.checked_sub(mapping.vaddr)?;
            let offset = usize::try_from(offset).ok()?;
            let bytes = mapping.bytes.get(offset..offset + 2)?;
            Some(u16::from_le_bytes([bytes[0], bytes[1]]))
        })
    };
    let (Some(branch), Some(previous)) = (halfword(address), address.checked_sub(2).and_then(halfword))
    else {
        return false;
    };
    // BX Rm: 0100 0111 0 Rm(4) 000; POP {list}: 1011 110 0 list(8).
    if branch & 0xff87 != 0x4700 {
        return false;
    }
    let register = (branch >> 3) & 0xf;
    register < 8 && previous & 0xff00 == 0xbc00 && (previous >> register) & 1 == 1
}
