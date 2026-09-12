//! Demand-driven analysis: one function, on a warm image.
//!
//! Whole-image analysis answers everything and costs minutes. An analyst
//! opening a function wants that function, now. This module walks a single
//! body from its entry, asks the same console for the same references over
//! the same range the batch pass would have asked for, and writes the
//! resulting facts for that function alone -- marked with what was actually
//! done to it, so nothing downstream mistakes a loader's declaration for a
//! decoded body.
//!
//! The image and its console stay warm between requests: parsing a 53 MB
//! game executable and loading it into SLEIGH costs seconds, and repeating
//! that per function would defeat the point.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use lre_model::FunctionRow;

use crate::native::{self, NativeImport, NativeXref};
use crate::native_runtime::{ConsoleSession, FlowKind, NativeRuntimeError, ReferenceKind};
use crate::{CoreError, Result};

/// A parsed image with its consoles, kept across requests.
pub struct LiveProgram {
    binary: PathBuf,
    import: NativeImport,
    /// Walking and reference inference use separate consoles for the same
    /// reason the whole-image pass does: installing call fixups changes what
    /// a console reports, and the walk must see the image as discovery sees
    /// it. One process each, opened once and kept warm.
    flow: ConsoleSession,
    references: Option<ConsoleSession>,
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
    /// Where the time went: opening the image (parse plus console load,
    /// paid once per image), the flow walk, and the reference query.
    #[serde(default)]
    pub phases: Vec<(String, f64)>,
}

/// Warm images, keyed by the binary that produced them.
#[derive(Default)]
pub struct LiveImages {
    programs: Mutex<HashMap<String, LiveProgram>>,
}

impl LiveImages {
    /// Runs `work` against a warm image, opening one if this is the first
    /// request for it. The console is a child process, so it is held under
    /// the same lock as the import it was loaded from.
    pub fn with<T>(
        &self,
        binary: &Path,
        program: &str,
        work: impl FnOnce(&mut LiveProgram) -> Result<T>,
    ) -> Result<T> {
        let key = format!("{}|{program}", binary.display());
        let mut live = self
            .programs
            .lock()
            .map_err(|_| CoreError::NativeRuntime(NativeRuntimeError("live image lock poisoned".into())))?;
        if !live.contains_key(&key) {
            live.insert(key.clone(), LiveProgram::open(binary)?);
        }
        let entry = live
            .get_mut(&key)
            .expect("live image was just inserted under this key");
        work(entry)
    }

    /// Drops a warm image, so the next request re-reads the file. An edit to
    /// the binary invalidates everything this image asserted.
    pub fn forget(&self, binary: &Path, program: &str) {
        let key = format!("{}|{program}", binary.display());
        if let Ok(mut live) = self.programs.lock() {
            live.remove(&key);
        }
    }
}

impl LiveProgram {
    /// Parses the image without analysing it and loads it into a console.
    fn open(binary: &Path) -> Result<Self> {
        // The loader's answer only: parsing is what makes the image usable,
        // and analysing it here would pay for exactly the whole-image pass
        // this module exists to avoid.
        let import = native::load_container_with(binary, false, None)?
            .into_iter()
            .map(|(_, import)| import)
            .next()
            .ok_or_else(|| {
                CoreError::NativeRuntime(NativeRuntimeError(format!(
                    "{}: no image to analyse",
                    binary.display()
                )))
            })?;
        let mut flow = ConsoleSession::new(&import.cfg).map_err(CoreError::NativeRuntime)?;
        flow.load_mapped(&import).map_err(CoreError::NativeRuntime)?;
        Ok(Self {
            binary: binary.to_path_buf(),
            import,
            flow,
            references: None,
        })
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
            let flows = self
                .flow
                .flow_batch(&batch)
                .map_err(CoreError::NativeRuntime)?;
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
    /// console about every address in turn and steps by whatever decoded.
    /// A byte run that decodes to nothing is skipped one unit at a time,
    /// because a stripped image's padding and data are inside the same
    /// mapping as its code.
    pub fn sweep(&mut self, start: u64, end: u64, unit: u64) -> Result<Vec<crate::cfg_functions::Step>> {
        use crate::cfg_functions::Step;
        let mut steps = Vec::new();
        let mut address = start;
        let unit = unit.max(1);
        while address < end {
            // One console request per batch of addresses, because a
            // request per instruction is a syscall per instruction.
            let batch: Vec<u64> = (0..512)
                .map(|index| address + index * unit)
                .take_while(|candidate| *candidate < end)
                .collect();
            if batch.is_empty() {
                break;
            }
            let flows = self
                .flow
                .flow_batch(&batch)
                .map_err(CoreError::NativeRuntime)?;
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

    /// The p-code of the given instructions, from the same console the walk
    /// used, so the operations are the ones it decoded.
    pub fn pcode(
        &mut self,
        addresses: &[u64],
    ) -> Result<Vec<crate::native_runtime::PcodeInstruction>> {
        self.flow
            .pcode_batch(addresses)
            .map_err(CoreError::NativeRuntime)
    }

    /// The references the console sees in one address range, converted the
    /// same way the whole-image pass converts them so a demand-driven fact
    /// and a batch fact are the same row.
    ///
    /// Reference inference runs on its own console: installing the image's
    /// call fixups changes what a console reports, and the walk must see the
    /// image as discovery does. Within one body the pass iterates to its own
    /// context fixpoint, which is what the whole-image loop does per round --
    /// contexts discovered in *other* functions are what it cannot have.
    pub fn references(&mut self, start: u64, end: u64) -> Result<Vec<NativeXref>> {
        let mappings = self.import.mappings.clone();
        if self.references.is_none() {
            let mut session =
                ConsoleSession::new(&self.import.cfg).map_err(CoreError::NativeRuntime)?;
            session
                .load_mapped(&self.import)
                .map_err(CoreError::NativeRuntime)?;
            session
                .prepare_reference_context(&self.import)
                .map_err(CoreError::NativeRuntime)?;
            self.references = Some(session);
        }
        let session = self
            .references
            .as_mut()
            .expect("reference console was just opened");
        let keep = session.reference_contexts().len();
        let mut facts = session
            .optional_references(start, end, &mappings, true)
            .map_err(CoreError::NativeRuntime)?
            .unwrap_or_default();
        // Bounded because a body that keeps producing new contexts is
        // pathological, not informative; the whole-image pass is bounded by
        // its rounds for the same reason.
        for _ in 0..4 {
            let mut discovered = session.drain_discovered_contexts(keep);
            if discovered.is_empty() {
                break;
            }
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
            let targets = session.adopt_reference_contexts(discovered);
            if !targets.iter().any(|target| *target >= start && *target < end) {
                break;
            }
            let again = session
                .optional_references(start, end, &mappings, true)
                .map_err(CoreError::NativeRuntime)?
                .unwrap_or_default();
            facts.extend(again);
            facts.sort_unstable_by_key(|fact| (fact.from, fact.to, fact.kind as u8));
            facts.dedup();
        }
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
            entry: lre_model::Address::ram(self.entry),
            name,
            size: self.size(),
            signature: None,
            calling_convention: None,
        }
    }
}
