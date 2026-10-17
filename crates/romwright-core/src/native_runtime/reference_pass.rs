//! The reference pass's context and lanes: what the reference pass holds
//! between queries (its `reference_*` state, once a console's), over
//! in-process propagation lanes.
//!
//! One round of the pass never reads a context discovered inside that round,
//! so lanes observe identical inputs and a lane's discoveries are only
//! merged, sorted, after the round (the console shards did the same, each
//! keeping the first context it saw per call target; here every value a
//! caller shows is kept and the smallest wins, so the result does not depend
//! on how ranges fell to lanes).
use super::propagation::{JumpShape, Propagator, Query, Refusal};
use super::{ReferenceFact, Result};
use crate::native::{NativeImport, NativeRegisterContext};
use std::collections::{HashMap, HashSet};

/// The register context a round's queries run under.
pub(crate) struct ReferenceContext {
    registers: Vec<NativeRegisterContext>,
    /// How many of `registers` seed queries: the context the round began with.
    active: usize,
    call_register: Option<&'static str>,
    mode_register: Option<String>,
    /// Import slots the loaded image names, sorted: a read of one answers the
    /// external, as `VarnodeContext.getValue` does (:540-544).
    external_slots: Vec<u64>,
    /// Starts that carry a call fixup, by the fixup's index.
    functions: HashMap<u64, usize>,
}

/// One range's reference facts and the call contexts it shows.
pub(crate) struct ReferenceAnswer {
    pub facts: Vec<ReferenceFact>,
    pub contexts: Vec<(u64, u64)>,
    /// Indirect jumps without a stored table that the flow made calls of.
    pub truncated: Vec<(u64, JumpShape)>,
    /// The tables the flow recovered itself: branch, shape, targets.
    pub recovered: Vec<(u64, JumpShape, Vec<u64>)>,
    /// The jumps the recovery was asked about and refused.
    pub refused: Vec<(u64, JumpShape, Refusal)>,
}

impl ReferenceContext {
    /// The context of `import`'s reference pass (`prepare_reference_context`):
    /// the loader's register values, the call register, the import slots, the
    /// instruction-set register of the language and the call fixups of the
    /// pattern-labelled functions the import sized.
    pub(crate) fn new(import: &NativeImport, lane: &Propagator) -> Self {
        let mut external_slots: Vec<u64> =
            import.externals.iter().map(|(slot, _)| *slot).filter(|slot| *slot != 0).collect();
        external_slots.sort_unstable();
        external_slots.dedup();
        let sized: HashSet<u64> =
            import.functions.iter().filter(|function| function.size > 1).map(|function| function.entry).collect();
        Self {
            registers: import.register_contexts.clone(),
            active: import.register_contexts.len(),
            call_register: import.reference_call_register,
            mode_register: super::mode_register_alias(&import.cfg.spec_root, &import.language),
            external_slots,
            functions: lane.fixup_functions(&import.pattern_labels, &sized),
        }
    }

    /// Facts for `[start, end)` under the round's context. `None` is a range
    /// the console would have refused as undecodable.
    pub(crate) fn query(
        &self,
        lane: &mut Propagator,
        import: &NativeImport,
        start: u64,
        end: u64,
    ) -> Result<Option<ReferenceAnswer>> {
        let seeds: Vec<(String, u64)> = self
            .registers
            .iter()
            .take(self.active)
            .filter(|context| context.start <= start && start < context.end)
            .map(|context| (context.register.clone(), context.value))
            .collect();
        let query = Query {
            start,
            end,
            trust_writable: true,
            seeds: &seeds,
            tracked: self.call_register,
            mode_register: self.mode_register.as_deref(),
            externals: &self.external_slots,
            functions: &self.functions,
            tables: &import.switch_tables,
            // The recovery is the value-set pass, so turning that pass off turns it off.
            recover: import.cfg.branchind_recovery && import.cfg.switch_vsa,
        };
        Ok(lane.references(&query)?.map(|answer| ReferenceAnswer {
            facts: answer.references,
            contexts: answer.call_registers.iter().map(|fact| (fact.target, fact.value)).collect(),
            truncated: answer.truncated_jumps,
            recovered: answer.recovered_jumps,
            refused: answer.refused_jumps,
        }))
    }

    /// Adds the call contexts a round found that no context covers yet, as
    /// one-address contexts of the tracked register; returns their targets.
    pub(crate) fn adopt(&mut self, mut found: Vec<(u64, u64)>) -> Vec<u64> {
        let Some(register) = self.call_register else { return Vec::new() };
        found.sort_unstable();
        found.dedup();
        let mut targets = Vec::new();
        for (target, value) in found {
            if self.registers.iter().any(|existing| {
                existing.register == register && existing.start <= target && target < existing.end
            }) {
                continue;
            }
            let Some(end) = target.checked_add(1) else { continue };
            self.registers.push(NativeRegisterContext { start: target, end, register: register.into(), value });
            targets.push(target);
        }
        self.active = self.registers.len();
        targets
    }
}

/// `count` propagation lanes over `import`, built concurrently: a lane's
/// start (the language's `.sla`, the image) dominates a short round.
pub(crate) fn open_lanes(import: &NativeImport, count: usize) -> Vec<Propagator> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..count.max(1)).map(|_| scope.spawn(|| Propagator::mapped(&import.cfg, import))).collect();
        handles.into_iter().filter_map(|handle| handle.join().ok().and_then(|lane| lane.ok())).collect()
    })
}

/// The reference lane a demand-driven walk keeps: one propagation lane and the
/// context of the image it was opened on.
pub(crate) struct DemandReferences {
    lane: Propagator,
    context: ReferenceContext,
}

impl DemandReferences {
    pub(crate) fn open(import: &NativeImport) -> Result<Self> {
        let lane = Propagator::mapped(&import.cfg, import)?;
        let context = ReferenceContext::new(import, &lane);
        Ok(Self { lane, context })
    }

    /// The facts of one body. Within it the pass iterates to its own context
    /// fixpoint, which is what the whole-image loop does per round: contexts
    /// discovered in *other* functions are what it cannot have. Bounded
    /// because a body that keeps producing new contexts is pathological, not
    /// informative; the whole-image pass is bounded by its rounds for the same
    /// reason. An undecodable body has no facts.
    pub(crate) fn references(&mut self, import: &NativeImport, start: u64, end: u64) -> Result<Vec<ReferenceFact>> {
        let mut facts = Vec::new();
        let mut found = Vec::new();
        if let Some(answer) = self.context.query(&mut self.lane, import, start, end)? {
            facts = answer.facts;
            found = answer.contexts;
        }
        for _ in 0..4 {
            let targets = self.context.adopt(std::mem::take(&mut found));
            if !targets.iter().any(|target| *target >= start && *target < end) {
                break;
            }
            let Some(again) = self.context.query(&mut self.lane, import, start, end)? else { break };
            found = again.contexts;
            facts.extend(again.facts);
            facts.sort_unstable_by_key(|fact| (fact.from, fact.to, fact.kind as u8));
            facts.dedup();
        }
        Ok(facts)
    }
}
