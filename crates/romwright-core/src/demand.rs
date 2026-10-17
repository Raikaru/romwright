//! Demand-driven analysis: one function, on a warm image.
//!
//! Whole-image analysis answers everything and costs minutes. An analyst
//! opening a function wants that function, now. This module walks a single
//! body from its entry, asks the same decoder for the same references over
//! the same range the batch pass would have asked for, and writes the
//! resulting facts for that function alone -- marked with what was actually
//! done to it, so nothing downstream mistakes a loader's declaration for a
//! decoded body.
//!
//! The image and its decoders stay warm between requests: parsing a 53 MB
//! game executable and loading it into SLEIGH costs seconds, and repeating
//! that per function would defeat the point.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use romwright_model::FunctionRow;

use crate::native::{self, NativeImport, NativeXref};
use crate::native_runtime::{
    FlowKind, NativeRuntimeError, ReferenceKind, SleighFlow, SleighLifter,
};
use crate::{CoreError, Result};

/// A parsed image with its decoders, kept across requests.
pub struct LiveProgram {
    binary: PathBuf,
    import: NativeImport,
    /// Walking and reference inference use separate decoders for the same
    /// reason the whole-image pass does: installing call fixups changes what
    /// a decoder reports, and the walk must see the image as discovery sees
    /// it. Each is opened once and kept warm.
    flow: SleighFlow,
    references: Option<crate::native_runtime::DemandReferences>,
    /// P-code is lifted in process, from the image and contexts the walk's
    /// decoder loaded; built on first use.
    lifter: Option<SleighLifter>,
    control: Option<(crate::exec::CancelToken, std::time::Instant)>,
}

/// What one demand-driven analysis did.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionAnalysis {
    pub program: String,
    pub entry: String,
    /// Proven body size: the walk's furthest decoded byte from the entry.
    pub size: u64,
    pub instructions: u64,
    /// Direct call targets this body reaches, as new seeds.
    pub calls: Vec<String>,
    pub xrefs: u64,
    /// `walked` after this call; `reused` when the body was already analysed
    /// at the store's current revision.
    pub state: String,
    pub reused: bool,
    pub seconds: f64,
    /// Where the time went: opening the image (parse plus decoder load,
    /// paid once per image), the flow walk, and the reference query.
    #[serde(default)]
    pub phases: Vec<(String, f64)>,
}

/// Bounded warm images. Each program has at most one current artifact;
/// replacing its input evicts the old parse and its decoders.
pub struct LiveImages {
    programs: Mutex<HashMap<String, WarmImage>>,
    project: PathBuf,
    config: crate::session::RuntimeConfig,
}

struct WarmImage {
    input: romwright_model::ProgramInput,
    used: std::time::Instant,
    live: LiveProgram,
}

impl LiveImages {
    pub fn new(project: &Path, config: &crate::session::RuntimeConfig) -> Self {
        Self {
            programs: Mutex::new(HashMap::new()),
            project: project.to_path_buf(),
            config: config.clone(),
        }
    }

    /// Runs `work` against a warm image, opening one if this is the first
    /// request for it. The decoders are held under the same lock as the import
    /// they were loaded from.
    pub fn with<T>(
        &self,
        input: &romwright_model::ProgramInput,
        program: &str,
        request: Option<&crate::exec::ExecutionRequest>,
        work: impl FnOnce(&mut LiveProgram) -> Result<T>,
    ) -> Result<T> {
        let poisoned =
            || CoreError::NativeRuntime(NativeRuntimeError("live image lock poisoned".into()));
        let mut live = if let Some(request) = request {
            loop {
                request.cancel.checkpoint(request.deadline)?;
                match self.programs.try_lock() {
                    Ok(guard) => break guard,
                    Err(std::sync::TryLockError::Poisoned(_)) => return Err(poisoned()),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        std::thread::sleep(std::time::Duration::from_millis(5))
                    }
                }
            }
        } else {
            self.programs.lock().map_err(|_| poisoned())?
        };
        let control = request.map(|request| (request.cancel.clone(), request.deadline));
        let hit = live.get(program).is_some_and(|entry| &entry.input == input);
        if !hit {
            live.remove(program);
            const CAPACITY: usize = 4;
            if live.len() >= CAPACITY {
                let oldest = live
                    .iter()
                    .min_by_key(|(_, entry)| entry.used)
                    .map(|(key, _)| key.clone())
                    .expect("full cache");
                live.remove(&oldest);
            }
            let opened =
                LiveProgram::open(&self.project, program, input, &self.config, control.clone())?;
            live.insert(
                program.to_string(),
                WarmImage {
                    input: input.clone(),
                    used: std::time::Instant::now(),
                    live: opened,
                },
            );
        }
        let entry = live.get_mut(program).expect("opened image");
        if hit {
            entry.live.set_control(control);
        }
        entry.used = std::time::Instant::now();
        let result = work(&mut entry.live);
        entry.live.set_control(None);
        let result = if let Some(request) = request {
            request.cancel.checkpoint(request.deadline).and(result)
        } else {
            result
        };
        // A killed or failed protocol session must never re-enter the cache.
        if result.is_err() {
            live.remove(program);
        }
        result
    }

    /// Drops a warm image, so the next request re-reads the file. An edit to
    /// the binary invalidates everything this image asserted.
    pub fn forget(&self, program: &str) {
        if let Ok(mut live) = self.programs.lock() {
            live.remove(program);
        }
    }

    /// `count` further handles on the same image, each with decoders of its
    /// own and none of them kept: a job that spreads independent walks over
    /// several threads gives each thread one, and they end with the job. The
    /// handles open concurrently.
    pub fn open_extra(
        &self,
        input: &romwright_model::ProgramInput,
        program: &str,
        request: Option<&crate::exec::ExecutionRequest>,
        count: usize,
    ) -> Result<Vec<LiveProgram>> {
        let control = request.map(|request| (request.cancel.clone(), request.deadline));
        let opened: Vec<Result<LiveProgram>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..count)
                .map(|_| {
                    scope.spawn(|| {
                        LiveProgram::open(&self.project, program, input, &self.config, control.clone())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic)))
                .collect()
        });
        opened.into_iter().collect()
    }
}

impl LiveProgram {
    /// The selected image and all loader options come from the import record;
    /// the instruction set at each address is the one the import settled.
    fn open(
        project: &Path,
        program: &str,
        input: &romwright_model::ProgramInput,
        config: &crate::session::RuntimeConfig,
        control: Option<(crate::exec::CancelToken, std::time::Instant)>,
    ) -> Result<Self> {
        let mut import = crate::inputs::load(project, input, config)?;
        import
            .contexts
            .extend(stored_decode_contexts(project, program)?);
        if let Some((cancel, deadline)) = &control {
            cancel.checkpoint(*deadline)?;
        }
        let flow =
            SleighFlow::mapped(&import.cfg, &import).map_err(CoreError::NativeRuntime)?;
        Ok(Self {
            binary: import.binary.clone(),
            import,
            flow,
            references: None,
            lifter: None,
            control,
        })
    }

    fn set_control(&mut self, control: Option<(crate::exec::CancelToken, std::time::Instant)>) {
        self.control = control;
    }

    /// Stops a walk or sweep a request cancelled or ran out of time for; the
    /// decoders run in this process, so nothing else can interrupt them.
    fn checkpoint(&self) -> Result<()> {
        if let Some((cancel, deadline)) = &self.control {
            cancel.checkpoint(*deadline)?;
        }
        Ok(())
    }

    /// Every entry the image declares: the shared-return rule needs to know
    /// whether a branch target is a function.
    pub fn declared_entries(&self) -> HashSet<u64> {
        self.import
            .functions
            .iter()
            .map(|function| function.entry)
            .collect()
    }

    pub fn language(&self) -> &str {
        &self.import.language
    }

    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// True when this address is inside an executable mapping.
    fn in_code(&self, address: u64) -> bool {
        self.import
            .mappings
            .iter()
            .any(|m| m.flags & 0x4 != 0 && address >= m.vaddr && address < m.vaddr + m.size)
    }

    /// Walks one body: the transitive fallthrough/branch closure from the
    /// entry, stopping at returns, calls' targets, and undecodable bytes.
    /// Calls leave the body but seed new functions, exactly as the batch
    /// walk treats them.
    pub fn walk(&mut self, entry: u64) -> Result<BodyWalk> {
        // A branch to another function's entry is a tail call, not more of
        // this body: Ghidra's own analysis stops there, and without this the
        // walk swallows every function reachable by a shared jump.
        let boundaries: HashSet<u64> = self
            .import
            .functions
            .iter()
            .map(|function| function.entry)
            .filter(|address| *address != entry)
            .collect();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut active = vec![entry];
        let mut walk = BodyWalk {
            entry,
            end: entry,
            instructions: 0,
            calls: Vec::new(),
            call_sites: Vec::new(),
            transfers: Vec::new(),
            flow_edges: Vec::new(),
            instruction_extents: Vec::new(),
            target_edges: Vec::new(),
            conditional_sites: Vec::new(),
            undecodable: 0,
        };
        while !active.is_empty() {
            let batch: Vec<u64> = std::mem::take(&mut active)
                .into_iter()
                .filter(|address| {
                    self.in_code(*address)
                        && !boundaries.contains(address)
                        && visited.insert(*address)
                })
                .collect();
            if batch.is_empty() {
                break;
            }
            self.checkpoint()?;
            let flows = self.flow.flow(&batch);
            for (address, flow) in batch.iter().copied().zip(flows) {
                if matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl) {
                    walk.undecodable += 1;
                    continue;
                }
                walk.instructions += 1;
                walk.instruction_extents.push((address, flow.length));
                walk.end = walk.end.max(address.saturating_add(u64::from(flow.length)));
                let fall = flow
                    .fallthrough
                    .unwrap_or_else(|| address.saturating_add(u64::from(flow.length)));
                match flow.kind {
                    // A call leaves and comes back: the callee is a seed for
                    // someone else's walk, the fallthrough is still this body.
                    FlowKind::Call => {
                        walk.calls.extend(flow.targets.iter().copied());
                        walk.call_sites
                            .extend(flow.targets.iter().map(|target| (address, *target)));
                        // A call returns to its fallthrough, so the body's
                        // own control flow continues there; the callee is not
                        // an edge of this graph.
                        walk.flow_edges.push((address, fall));
                        active.push(fall);
                    }
                    FlowKind::CallInd => {
                        walk.flow_edges.push((address, fall));
                        active.push(fall);
                    }
                    FlowKind::Branch => {
                        // A branch out of this body is a transfer, and the
                        // walk stops there; one inside it is control flow.
                        for target in &flow.targets {
                            if boundaries.contains(target) || !self.in_code(*target) {
                                walk.transfers.push((address, *target));
                            }
                        }
                        walk.flow_edges
                            .extend(flow.targets.iter().map(|target| (address, *target)));
                        walk.target_edges
                            .extend(flow.targets.iter().map(|target| (address, *target)));
                        active.extend(flow.targets.iter().copied());
                    }
                    FlowKind::CBranch => {
                        // The taken edge first, then the fallthrough: the
                        // decompiler expects a conditional's false edge in
                        // slot 0, and `ControlFlow::encode` preserves order.
                        walk.flow_edges.push((address, fall));
                        walk.flow_edges
                            .extend(flow.targets.iter().map(|target| (address, *target)));
                        walk.target_edges
                            .extend(flow.targets.iter().map(|target| (address, *target)));
                        walk.conditional_sites.push(address);
                        active.extend(flow.targets.iter().copied());
                        active.push(fall);
                    }
                    // An indirect jump without recovered targets ends this
                    // path; recovering them is the switch pass's job, not a
                    // guess this walk is allowed to make.
                    FlowKind::BranchInd => {
                        walk.flow_edges
                            .extend(flow.targets.iter().map(|target| (address, *target)));
                        walk.target_edges
                            .extend(flow.targets.iter().map(|target| (address, *target)));
                        active.extend(flow.targets.iter().copied());
                    }
                    FlowKind::Fallthrough => {
                        walk.flow_edges.push((address, fall));
                        active.push(fall);
                    }
                    FlowKind::Return => {}
                    FlowKind::Bad | FlowKind::Unimpl => unreachable!("handled above"),
                }
            }
        }
        walk.calls.sort_unstable();
        walk.calls.dedup();
        walk.call_sites.sort_unstable();
        walk.call_sites.dedup();
        walk.transfers.sort_unstable();
        walk.transfers.dedup();
        Ok(walk)
    }

    /// Executable ranges of the image, as the loader mapped them.
    pub fn code_ranges(&self) -> Vec<(u64, u64)> {
        native::code_ranges(&self.import)
    }

    /// Decodes forward through an address range, one instruction at a
    /// time, and reports what each one does.
    ///
    /// This is a sweep, not a walk: it does not follow flow, it asks the
    /// decoder about every address in turn and steps by whatever decoded.
    /// A byte run that decodes to nothing is skipped one unit at a time,
    /// because a stripped image's padding and data are inside the same
    /// mapping as its code.
    pub fn sweep(
        &mut self,
        start: u64,
        end: u64,
        unit: u64,
    ) -> Result<Vec<crate::cfg_functions::Step>> {
        use crate::cfg_functions::Step;
        let mut steps = Vec::new();
        let mut address = start;
        let unit = unit.max(1);
        while address < end {
            // One decoder call per batch of addresses, so a cancel or a
            // deadline is checked once per batch.
            let batch: Vec<u64> = (0..512)
                .map(|index| address + index * unit)
                .take_while(|candidate| *candidate < end)
                .collect();
            if batch.is_empty() {
                break;
            }
            self.checkpoint()?;
            let flows = self.flow.flow(&batch);
            let mut next = address;
            for (candidate, flow) in batch.iter().copied().zip(flows) {
                if candidate < next {
                    continue; // covered by a longer instruction already
                }
                if matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl) || flow.length == 0 {
                    next = candidate + unit;
                    continue;
                }
                let fall = candidate.saturating_add(u64::from(flow.length));
                let (successors, calls, terminal) = match flow.kind {
                    FlowKind::Call => (vec![fall], flow.targets.clone(), false),
                    FlowKind::CallInd => (vec![fall], Vec::new(), false),
                    FlowKind::Branch => (flow.targets.clone(), Vec::new(), true),
                    FlowKind::CBranch => {
                        let mut all = flow.targets.clone();
                        all.push(fall);
                        (all, Vec::new(), true)
                    }
                    FlowKind::BranchInd => (flow.targets.clone(), Vec::new(), true),
                    FlowKind::Return => (Vec::new(), Vec::new(), true),
                    FlowKind::Fallthrough => (vec![fall], Vec::new(), false),
                    FlowKind::Bad | FlowKind::Unimpl => unreachable!("handled above"),
                };
                steps.push(Step {
                    address: candidate,
                    length: flow.length,
                    successors,
                    calls,
                    terminal,
                });
                next = fall;
            }
            if next <= address {
                break;
            }
            address = next;
        }
        Ok(steps)
    }

    /// The p-code of the given instructions, decoded from the image and
    /// contexts the walk's decoder loaded.
    pub fn pcode(
        &mut self,
        addresses: &[u64],
    ) -> Result<Vec<crate::native_runtime::PcodeInstruction>> {
        let lifter = match self.lifter.take() {
            Some(lifter) => lifter,
            None => SleighLifter::mapped(&self.import.cfg, &self.import)
                .map_err(CoreError::NativeRuntime)?,
        };
        Ok(self.lifter.insert(lifter).lift(addresses))
    }

    /// The names of the language's user-defined p-code operations, indexed as
    /// the first input of a `CALLOTHER`.
    pub fn user_op_names(&mut self) -> Result<Vec<String>> {
        if self.lifter.is_none() {
            self.lifter = Some(
                SleighLifter::mapped(&self.import.cfg, &self.import)
                    .map_err(CoreError::NativeRuntime)?,
            );
        }
        Ok(self.lifter.as_ref().expect("lifter was just built").user_op_names())
    }

    /// The references the propagation sees in one address range, converted
    /// the same way the whole-image pass converts them so a demand-driven
    /// fact and a batch fact are the same row.
    ///
    /// Reference inference runs on its own lane: installing the image's call
    /// fixups changes what the propagation reports, and the walk must see
    /// the image as discovery does.
    pub fn references(&mut self, start: u64, end: u64) -> Result<Vec<NativeXref>> {
        if self.references.is_none() {
            self.references = Some(
                crate::native_runtime::DemandReferences::open(&self.import).map_err(CoreError::NativeRuntime)?,
            );
        }
        let facts = self
            .references
            .as_mut()
            .expect("reference lane was just opened")
            .references(&self.import, start, end)
            .map_err(CoreError::NativeRuntime)?;
        let mode = native::low_bit_code_mode(&self.import.language);
        Ok(facts
            .into_iter()
            .filter(|fact| fact.kind != ReferenceKind::Stack)
            .map(|fact| {
                let aligned = if mode { fact.to & !1 } else { fact.to };
                let (kind, to) = match fact.kind {
                    ReferenceKind::Read => ("READ", fact.to),
                    ReferenceKind::Write => ("WRITE", fact.to),
                    ReferenceKind::ReadWrite => ("READ_WRITE", fact.to),
                    ReferenceKind::Data => ("DATA", fact.to),
                    ReferenceKind::ComputedCall => ("COMPUTED_CALL", aligned),
                    ReferenceKind::ComputedJump => ("COMPUTED_JUMP", aligned),
                    ReferenceKind::Stack => unreachable!("stack facts are filtered above"),
                };
                NativeXref::with_provenance(
                    fact.from,
                    to,
                    kind,
                    "native-analysis:constant-propagation",
                )
            })
            .collect())
    }
}

/// The instruction-set contexts the import stored for `program`
/// (`native::store`): the loader's own plus every mode discovery settled,
/// which a fresh container parse does not know. Base-register rows are
/// register values, not context variables, and stay out.
fn stored_decode_contexts(project: &Path, program: &str) -> Result<Vec<native::NativeContext>> {
    let db = crate::ProjectDb::open(&project.join("project.sqlite"))?;
    let mut contexts: Vec<native::NativeContext> = db
        .decode_contexts(db.program_id(program)?)?
        .into_iter()
        .filter(|(address, name, _)| {
            address.space == romwright_model::AddressSpace::Ram
                && !native::STORED_BASE_REGISTERS.contains(&name.as_str())
        })
        .map(|(address, name, value)| native::NativeContext {
            name,
            address: address.offset,
            value,
        })
        .collect();
    contexts.sort_by_key(|context| context.address);
    Ok(contexts)
}

/// One walked body.
#[derive(Debug, Clone)]
pub struct BodyWalk {
    pub entry: u64,
    pub end: u64,
    pub instructions: u64,
    pub calls: Vec<u64>,
    /// Every direct call this body makes, as (call site, target): the same
    /// edges the whole-image walk turns into `UNCONDITIONAL_CALL` rows.
    pub call_sites: Vec<(u64, u64)>,
    /// Control-flow edges inside the body, as (from instruction, to
    /// instruction): what a basic-block graph is built from.
    pub flow_edges: Vec<(u64, u64)>,
    /// Instruction start addresses the walk decoded, with their lengths.
    pub instruction_extents: Vec<(u64, u8)>,
    /// Branch targets, as (branch, target): a block starts at each one.
    pub target_edges: Vec<(u64, u64)>,
    /// Conditional branches: the address after one starts a block too,
    /// because flow reaches it without being branched to.
    pub conditional_sites: Vec<u64>,
    /// Unconditional branches that leave this body, as (branch, target).
    /// Ghidra's `SharedReturnAnalysisCmd` turns one that lands on another
    /// function's entry into a call and leaves the rest a jump; the store
    /// gets the same two kinds from `transfer_facts`.
    pub transfers: Vec<(u64, u64)>,
    pub undecodable: u64,
}

impl BodyWalk {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.entry).max(1)
    }

    /// The store rows this walk's out-of-body branches prove, applying
    /// Ghidra's shared-return rule: a branch that leaves its function for
    /// another function's entry becomes a call, and one into code nobody
    /// recovered stays a jump. `entries` is what the image declares.
    pub fn transfer_facts(&self, entries: &HashSet<u64>) -> Vec<NativeXref> {
        self.transfers
            .iter()
            .map(|(from, to)| {
                let kind = if entries.contains(to) && !entries.contains(from) {
                    "UNCONDITIONAL_CALL"
                } else {
                    "UNCONDITIONAL_JUMP"
                };
                NativeXref::with_provenance(*from, *to, kind, native::BRANCH_PROVENANCE)
            })
            .collect()
    }

    /// The body's basic-block graph: block start addresses in address order,
    /// and edges between block indices.
    ///
    /// The leaders are exactly the ones the whole-image feature pass uses
    /// (`native::features`): the entry, every branch target inside the body,
    /// and the address after a conditional branch -- flow reaches that one
    /// without being branched to. Nothing after an *unconditional* branch is
    /// a leader unless something targets it, and a call does not end a
    /// block. Two constructions that disagree would make a structuring
    /// comparison meaningless, so this is the same one, and the gate
    /// measures that they still agree.
    pub fn basic_blocks(&self) -> (Vec<u64>, Vec<(usize, usize)>) {
        let mut extents: Vec<(u64, u8)> = self.instruction_extents.clone();
        extents.sort_unstable();
        extents.dedup_by_key(|(address, _)| *address);
        if extents.is_empty() {
            return (Vec::new(), Vec::new());
        }
        // The graph is *this function's*: an instruction the walk decoded
        // behind a tail jump into a linkage stub is that stub's, not a block
        // here, and the whole-image pass draws the same line (`inside`).
        let end = extents
            .iter()
            .map(|(address, length)| address.saturating_add(u64::from(*length)))
            .filter(|reach| *reach > self.entry)
            .max()
            .unwrap_or(self.entry);
        let decoded: HashSet<u64> = extents
            .iter()
            .map(|(address, _)| *address)
            .filter(|address| *address >= self.entry && *address < end)
            .collect();
        let mut leaders: HashSet<u64> = HashSet::new();
        leaders.insert(self.entry);
        for (_, target) in &self.target_edges {
            if decoded.contains(target) {
                leaders.insert(*target);
            }
        }
        for address in &self.conditional_sites {
            if !decoded.contains(address) {
                continue;
            }
            if let Ok(index) = extents.binary_search_by_key(address, |(at, _)| *at) {
                let (at, length) = extents[index];
                let next = at.saturating_add(u64::from(length));
                if decoded.contains(&next) {
                    leaders.insert(next);
                }
            }
        }
        let mut blocks: Vec<u64> = leaders.into_iter().collect();
        blocks.sort_unstable();
        let block_of = |address: u64| -> Option<usize> {
            match blocks.binary_search(&address) {
                Ok(index) => Some(index),
                Err(0) => None,
                Err(index) => Some(index - 1),
            }
        };
        // Every real transfer becomes an edge between blocks; flow that stays
        // inside one block is not an edge.
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        let mut edges: Vec<(usize, usize)> = Vec::new();
        for (from, to) in &self.flow_edges {
            if !decoded.contains(to) || !decoded.contains(from) {
                continue;
            }
            let (Some(source), Some(destination)) = (block_of(*from), block_of(*to)) else {
                continue;
            };
            if source == destination && blocks.get(destination) != Some(to) {
                continue;
            }
            if seen.insert((source, destination)) {
                edges.push((source, destination));
            }
        }
        (blocks, edges)
    }

    /// The function row this walk proves.
    pub fn row(&self, name: String) -> FunctionRow {
        FunctionRow {
            entry: romwright_model::Address::ram(self.entry),
            name,
            size: self.size(),
            signature: None,
            traced: false,
            calling_convention: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::native::{Mapping, NativeImport};
    use crate::native_runtime::SleighLifter;

    /// A container parse knows only the loader's modes; the demand path must
    /// decode under the ones the import stored, as the decompile worker does.
    /// Base-register rows are register values and stay out.
    #[test]
    fn live_images_decode_under_stored_modes() {
        let project = std::env::temp_dir().join(format!(
            "romwright-stored-modes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&project).unwrap();
        let db = crate::ProjectDb::open(&project.join("project.sqlite")).unwrap();
        let provenance = romwright_model::Provenance {
            producer: "test".into(),
            upstream_version: "test".into(),
        };
        let program = db.upsert_program("gba", "ARM:LE:32:v4t", &provenance).unwrap();
        db.replace_decode_contexts(
            program,
            &[
                (romwright_model::Address::ram(0x1004), "LowBitCodeMode".into(), 1),
                (romwright_model::Address::ram(0x1000), "r13".into(), 0x3000),
            ],
        )
        .unwrap();
        drop(db);
        let contexts = super::stored_decode_contexts(&project, "gba").unwrap();
        let _ = std::fs::remove_dir_all(&project);
        assert_eq!(
            contexts.iter().map(|c| (c.name.as_str(), c.address, c.value)).collect::<Vec<_>>(),
            [("LowBitCodeMode", 0x1004, 1)]
        );

        let mut cfg = crate::session::RuntimeConfig::from_env();
        if !cfg.ghidra_install.join("Ghidra").is_dir() {
            eprintln!("SKIP: no Ghidra install");
            return;
        }
        cfg.adopt_language("ARM:LE:32:v4t");
        // mov r0,#1 (ARM) then movs r0,#1; bx lr (Thumb).
        let mut bytes = 0xe3a0_0001u32.to_le_bytes().to_vec();
        bytes.extend([0x01, 0x20, 0x70, 0x47]);
        let mut import = NativeImport {
            language: "ARM:LE:32:v4t".into(),
            mappings: vec![Mapping { vaddr: 0x1000, size: 8, file_off: 0, flags: 6, bytes }],
            ..Default::default()
        };
        import.contexts.extend(contexts);
        let lifted = SleighLifter::mapped(&cfg, &import).unwrap().lift(&[0x1000, 0x1004]);
        assert_eq!((lifted[0].length, lifted[1].length), (4, 2));
    }
}
