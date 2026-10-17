//! Constant and reference propagation over one function range, in process.
//!
//! This is the policy of Ghidra 12.1.3's `ConstantPropagationContextEvaluator`
//! and `SymbolicPropogator` (Apache-2.0), run here over the in-process
//! kuna-sleigh flow (the decompiler's `FlowInfo` ported in `graph.rs`):
//! forward dataflow over the ops of a function's basic blocks, with known-bit
//! register and memory values (`VarnodeContext`/`RegisterValue`, `state.rs`),
//! symbolic offsets from unknown incoming registers, `getOpObjects`-style
//! display-operand queries for stack slots (`NewFunctionStackAnalysisCmd`) and
//! `X86Analyzer.evaluateContext` for address formation. The flow itself is
//! `graph.rs`.
//!
//! The result of one range is its reference facts (read, write, data,
//! computed call and jump, stack) and, for a caller that asks, the registers
//! holding a constant at each call (`ConstantFact`s are the strict mode the
//! tests use).
mod graph;
mod jump;
mod lang;
mod state;

pub(crate) use jump::Refusal;

use super::flow::{SleighFlow, Vn};
use super::lift::SleighLifter;
use super::{ConstantFact, ConstantVarnode, FlowKind, NativeRuntimeError, ReferenceFact, ReferenceKind};
use crate::native::NativeImport;
use crate::session::RuntimeConfig;
use graph::{Environment, Failure, Graph, NONE, Op};
use kuna_base::address::Address;
use kuna_base::space::AddrSpace;
use kuna_num::opbehavior::{register_instructions, FloatFormatProvider, OpBehavior};
use kuna_num::opcodes::OpCode;
use kuna_sleigh::semantics::ConstructTpl;
use kuna_sleigh::translate::Translate;
use lang::{Lang, SpaceKind, Storage, EXTRAPOP_UNKNOWN};
use state::{width_mask, Location, State, Value, Word};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

/// `Architecture::max_instructions`.
const MAX_INSTRUCTIONS: u32 = 100_000;
/// The propagation's bound on ops evaluated per range.
const MAX_OPERATIONS: usize = 1_000_000;

#[derive(Clone, Copy)]
struct Region {
    start: Word,
    end: Word,
    flags: u32,
    /// The end of the bytes the image holds: a mapping's tail past the file
    /// (bss) is memory with no bytes to read.
    backed: Word,
}

impl Region {
    fn contains(&self, address: Word, size: i32) -> bool {
        size > 0 && address >= self.start && address < self.end && (size as Word) <= self.end - address
    }
}

/// A pointer-sized constant observed at an op's output (strict mode).
#[derive(Clone, Copy)]
struct Fact {
    pc: Word,
    value: Word,
    space: i32,
    offset: Word,
    size: i32,
}

#[derive(Clone, Copy)]
struct RefFact {
    pc: Word,
    target: Word,
    access: u32,
    width: u32,
}

const ACCESS_READ: u32 = 1;
const ACCESS_WRITE: u32 = 2;
const ACCESS_DATA: u32 = 4;
const ACCESS_INDIRECTION: u32 = 8;
const ACCESS_CALL: u32 = 16;
const ACCESS_JUMP: u32 = 32;
const ACCESS_STACK: u32 = 64;

impl RefFact {
    /// Ghidra's `RefType` of a flow or access the propagation resolved.
    fn kind(&self) -> ReferenceKind {
        let access = self.access;
        if access & ACCESS_CALL != 0 {
            ReferenceKind::ComputedCall
        } else if access & ACCESS_JUMP != 0 {
            ReferenceKind::ComputedJump
        } else if access & ACCESS_STACK != 0 {
            ReferenceKind::Stack
        } else if access & 3 == 3 {
            ReferenceKind::ReadWrite
        } else if access & ACCESS_INDIRECTION != 0 {
            ReferenceKind::Data
        } else if access & ACCESS_WRITE != 0 {
            ReferenceKind::Write
        } else if access & ACCESS_READ != 0 {
            ReferenceKind::Read
        } else {
            ReferenceKind::Data
        }
    }
}

/// A register's value at a call into a function the tracked register names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CallRegisterFact {
    pub target: u64,
    pub value: u64,
}

#[derive(Clone)]
struct Snapshot {
    registers: State,
    memory: State,
    modified: BTreeMap<Location, u8>,
    unknown_writes: bool,
    call_writes: bool,
}

impl Snapshot {
    fn new(big_endian: bool, unique: i32) -> Self {
        Self {
            registers: State::new(big_endian, unique),
            memory: State::new(big_endian, -1),
            modified: BTreeMap::new(),
            unknown_writes: false,
            call_writes: false,
        }
    }

    fn merge(&mut self, other: &Snapshot) -> bool {
        let mut changed = self.registers.merge(&other.registers);
        changed |= self.memory.merge(&other.memory);
        changed |= (!self.unknown_writes && other.unknown_writes) || (!self.call_writes && other.call_writes);
        self.unknown_writes |= other.unknown_writes;
        self.call_writes |= other.call_writes;
        if self.unknown_writes {
            // Initial-image fallback is already disabled everywhere.
            self.modified.clear();
            return changed;
        }
        for (key, bits) in &other.modified {
            match self.modified.get_mut(key) {
                None => {
                    self.modified.insert(*key, *bits);
                    changed = true;
                }
                Some(existing) => {
                    if *existing | *bits != *existing {
                        *existing |= *bits;
                        changed = true;
                    }
                }
            }
        }
        changed
    }

    fn mark_written(&mut self, space: i32, mut offset: Word, mut size: i32) {
        while size > 0 {
            let first = (offset & 7) as u32;
            let count = size.min(8 - first as i32);
            *self.modified.entry(Location { space, offset: offset & !7 }).or_insert(0) |= (((1u32 << count) - 1) << first) as u8;
            offset += count as Word;
            size -= count;
        }
    }
}

/// The inputs of one propagation query.
pub(crate) struct Query<'a> {
    pub start: u64,
    pub end: u64,
    pub trust_writable: bool,
    /// Register values the loader or an earlier round established.
    pub seeds: &'a [(String, u64)],
    /// The register whose value at each call is reported.
    pub tracked: Option<&'a str>,
    /// The register the language's interworking branch writes the target's
    /// instruction set into, when the spec only aliases it.
    pub mode_register: Option<&'a str>,
    /// Import slots: a read of one is the external itself, not a value.
    pub externals: &'a [u64],
    /// Starts a call fixup was installed on, by the fixup's index.
    pub functions: &'a HashMap<u64, usize>,
    /// The dispatch tables the import stored, by branch address.
    pub tables: &'a HashMap<u64, Vec<u64>>,
    /// Recover the table of an indirect jump the import stored none for.
    pub recover: bool,
}

/// What computes the target of an indirect jump the flow had no stored table
/// for (`Flow::jump_shape`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum JumpShape {
    /// A load whose address holds an index: a table read.
    TableLoad,
    /// Arithmetic on registers, no load: an inline branch island.
    Island,
    /// A pointer the jump is handed: a call through a register or a
    /// fixed slot.
    Pointer,
}

/// What a range gave.
#[derive(Default)]
pub(crate) struct Answer {
    pub references: Vec<ReferenceFact>,
    pub call_registers: Vec<CallRegisterFact>,
    pub constants: Vec<ConstantFact>,
    /// Indirect jumps without a stored table, which flow turned into calls.
    pub truncated_jumps: Vec<(u64, JumpShape)>,
    /// The tables the flow recovered itself, by branch.
    pub recovered_jumps: Vec<(u64, JumpShape, Vec<u64>)>,
    /// The jumps the recovery was asked about and refused.
    pub refused_jumps: Vec<(u64, JumpShape, Refusal)>,
}

struct Decoder<'a> {
    flow: &'a mut SleighFlow,
    functions: &'a HashMap<u64, usize>,
    entry: u64,
    tables: &'a HashMap<u64, Vec<u64>>,
    lang: &'a Lang,
    regions: &'a [Region],
    templates: &'a mut Vec<Option<ConstructTpl>>,
    unique_base: &'a mut u32,
}

impl Environment for Decoder<'_> {
    fn decode(&mut self, address: u64, out: &mut super::flow::RawInsn) -> Result<(), FlowKind> {
        self.flow.decode(address, out)
    }

    fn function_at(&self, address: u64) -> bool {
        address == self.entry || self.functions.contains_key(&address)
    }

    fn has_fixup(&self, address: u64) -> bool {
        self.functions.contains_key(&address)
    }

    fn inject(&mut self, entry: u64, base: u64, out: &mut super::flow::RawInsn) -> Result<(), String> {
        let index = *self.functions.get(&entry).ok_or("no call fixup")?;
        let lang = self.lang;
        let fixup = &lang.callfixups[index];
        self.ensure_template(index, &fixup.name, &fixup.body)?;
        let template = self.templates[index].as_ref().expect("compiled above");
        self.flow.inject(template, base, entry, out).map_err(|error| error.to_string())
    }

    fn userop_fixup(&self, userop: u64) -> Option<usize> {
        self.lang.callotherfixups.iter().position(|fixup| fixup.userop == userop)
    }

    fn inject_userop(&mut self, fixup: usize, base: u64, out: &mut super::flow::RawInsn) -> Result<(), String> {
        let lang = self.lang;
        let replacement = &lang.callotherfixups[fixup];
        self.ensure_template(lang.callfixups.len() + fixup, &replacement.name, &replacement.body)?;
        let template = self.templates[lang.callfixups.len() + fixup].as_ref().expect("compiled above");
        // The injected user op's own inputs are not named by the pinned bodies;
        // `inst_dest` and `inst_next` are the instruction itself.
        self.flow.inject(template, base, base, out).map_err(|error| error.to_string())
    }

    fn stored_table(&self, branch: u64) -> Option<&[u64]> {
        self.tables.get(&branch).map(Vec::as_slice)
    }

    fn assembly(&self, address: u64) -> String {
        let lifter = self.flow.lifter();
        let (mut mnemonic, mut body) = (String::new(), String::new());
        let _ = lifter.sleigh.print_assembly_into(&lifter.address(address), &mut mnemonic, &mut body);
        format!("{mnemonic} {body}")
    }

    fn read_image(&self, address: u64, size: u32) -> Option<u64> {
        if size == 0 || size > 8 {
            return None;
        }
        let last = address.checked_add(u64::from(size) - 1)?;
        if !self.regions.iter().any(|region| address >= region.start && last < region.backed) {
            return None;
        }
        let mut bytes = [0u8; 8];
        let lifter = self.flow.lifter();
        lifter.sleigh.loader_rc().borrow_mut().load_fill(&mut bytes[..size as usize], &lifter.address(address)).ok()?;
        let mut value = 0u64;
        if self.lang.big_endian {
            for byte in &bytes[..size as usize] {
                value = (value << 8) | u64::from(*byte);
            }
        } else {
            for (index, byte) in bytes[..size as usize].iter().enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
        }
        Some(value)
    }

    fn executable(&self, address: u64) -> bool {
        self.regions.iter().any(|region| region.flags & 4 != 0 && address >= region.start && address < region.end)
    }
}

impl Decoder<'_> {
    /// The compiled template of a call or user-op fixup, compiled on first use
    /// (`PcodeInjectLibrarySleigh::parseInject`).
    fn ensure_template(&mut self, index: usize, name: &str, body: &str) -> Result<(), String> {
        if self.templates[index].is_none() {
            let (template, next) = self
                .flow
                .lifter()
                .sleigh
                .compile_snippet(body.as_bytes(), *self.unique_base)
                .map_err(|error| format!("fixup {name}: {error}"))?;
            *self.unique_base = next;
            self.templates[index] = Some(template);
        }
        Ok(())
    }
}

/// One propagation lane: a decoder over the image and the language's model.
pub(crate) struct Propagator {
    lang: Arc<Lang>,
    behaviors: Vec<Option<Rc<dyn OpBehavior>>>,
    regions: Vec<Region>,
    data_space: Rc<AddrSpace>,
    x86: bool,
    /// The compiled call fixups, by index in `Lang::callfixups`.
    templates: Vec<Option<ConstructTpl>>,
    /// The first unique offset a fixup may use for a temporary.
    unique_base: u32,
    /// Last: `behaviors`, `data_space` and `templates` hold reference counts
    /// into the decoder's spaces, which must be gone before its pooled
    /// lifter goes back to the pool and another thread.
    flow: SleighFlow,
}

// SAFETY: as for `SleighLifter`: every `Rc` belongs to this lane's own object
// graph (its translator, spaces and behaviours) and nothing is shared with
// another thread.
unsafe impl Send for Propagator {}

impl Propagator {
    pub fn mapped(cfg: &RuntimeConfig, import: &NativeImport) -> Result<Self, NativeRuntimeError> {
        let mut flow = SleighFlow::mapped_pooled(cfg, import)?;
        let lang = Lang::new(flow.lifter(), &import.language).map_err(|error| NativeRuntimeError(format!("propagation model: {error}")))?;
        if super::lift::single_program() {
            // The model has what it needs of the specs; the decoder is not
            // shared, and the next round parses them again if it wants them.
            flow.lifter_mut().release_specs();
        }
        let provider: Rc<dyn FloatFormatProvider> = Rc::new(Lang::formats(flow.lifter()));
        let mut behaviors = Vec::new();
        register_instructions(&mut behaviors, &provider);
        let data_space = flow
            .lifter()
            .sleigh
            .base()
            .manager()
            .get_space(lang.data_space)
            .cloned()
            .ok_or_else(|| NativeRuntimeError("propagation: no data space".into()))?;
        let mut regions = Vec::with_capacity(import.mappings.len());
        for mapping in import.mappings.iter().filter(|mapping| mapping.size != 0) {
            let end = mapping
                .vaddr
                .checked_add(mapping.size)
                .ok_or_else(|| NativeRuntimeError("constant-propagation mapping range overflows".into()))?;
            regions.push(Region {
                start: mapping.vaddr,
                end,
                flags: (mapping.flags & 7) as u32,
                backed: mapping.vaddr.saturating_add(mapping.bytes.len() as u64).min(end),
            });
        }
        let x86 = lang.x86;
        let templates = vec![None; lang.callfixups.len() + lang.callotherfixups.len()];
        let unique_base = flow.lifter().sleigh.translate_base().get_unique_base();
        Ok(Self { flow, lang: Arc::new(lang), behaviors, regions, data_space, x86, templates, unique_base })
    }

    /// The starts among `labels` that carry a call fixup of the compiler
    /// spec (`CallFixupAnalyzer`: the label is one of a fixup's targets), on
    /// functions the import sized.
    pub fn fixup_functions(&self, labels: &[(u64, String)], sized: &HashSet<u64>) -> HashMap<u64, usize> {
        labels
            .iter()
            .filter(|(address, _)| sized.contains(address))
            .filter_map(|(address, label)| {
                let index = self.lang.callfixups.iter().position(|fixup| fixup.targets.iter().any(|t| t == label))?;
                Some((*address, index))
            })
            .collect()
    }

    /// Reference facts of the range `[start, end)`; `None` when the console
    /// would have refused it as undecodable.
    pub fn references(&mut self, query: &Query) -> Result<Option<Answer>, NativeRuntimeError> {
        self.run(query, true)
    }

    /// Pointer-sized constants of the range (the strict mode).
    #[cfg(test)]
    pub fn constants(&mut self, query: &Query) -> Result<Option<Vec<ConstantFact>>, NativeRuntimeError> {
        Ok(self.run(query, false)?.map(|answer| answer.constants))
    }

    fn run(&mut self, query: &Query, reference_mode: bool) -> Result<Option<Answer>, NativeRuntimeError> {
        if query.start >= query.end {
            return Err(NativeRuntimeError("Expected propagation <start> <end-exclusive>".into()));
        }
        if self.regions.is_empty() {
            return Err(NativeRuntimeError("Constant propagation requires mapped ranges".into()));
        }
        let lang = Arc::clone(&self.lang);
        let code = lang.space(lang.code_space);
        if query.end - 1 > code.highest {
            return Err(NativeRuntimeError("Function range exceeds the code address space".into()));
        }
        let sleigh = &self.flow.lifter().sleigh;
        let register = |name: &str| -> Result<Storage, NativeRuntimeError> {
            let varnode = sleigh
                .get_register_varnode(name.as_bytes())
                .map_err(|error| NativeRuntimeError(format!("unknown register {name}: {error}")))?;
            Ok(Storage {
                space: varnode.space.as_ref().map_or(-1, |space| space.get_index()),
                offset: varnode.offset,
                size: varnode.size as i32,
            })
        };
        let usable = |storage: &Storage| {
            lang.space(storage.space).kind == SpaceKind::Processor
                && storage.space != lang.code_space
                && storage.space != lang.data_space
                && storage.size >= 1
                && storage.size <= 8
        };
        let mut seeds = Vec::with_capacity(query.seeds.len());
        for (name, value) in query.seeds {
            let storage = register(name)?;
            if !usable(&storage) {
                return Err(NativeRuntimeError("Invalid propagation register context".into()));
            }
            if *value > width_mask(storage.size) {
                return Err(NativeRuntimeError("Invalid propagation register value".into()));
            }
            seeds.push((storage, *value));
        }
        let tracked = match query.tracked {
            Some(name) if reference_mode => {
                let storage = register(name)?;
                if !usable(&storage) {
                    return Err(NativeRuntimeError("Invalid propagation register context".into()));
                }
                Some(storage)
            }
            _ => None,
        };
        let mode_register = match query.mode_register {
            Some(name) => register(name).ok().filter(|s| s.size >= 1 && s.size <= 8).or(lang.mode_register),
            None => lang.mode_register,
        }
        .filter(|storage| storage.size >= 1 && storage.size <= 8);
        let mut externals: Vec<Word> = query.externals.to_vec();
        externals.sort_unstable();
        let graph = {
            let mut decoder = Decoder {
                flow: &mut self.flow,
                functions: query.functions,
                entry: query.start,
                tables: query.tables,
                lang: &lang,
                regions: &self.regions,
                templates: &mut self.templates,
                unique_base: &mut self.unique_base,
            };
            match Graph::follow(&lang, &mut decoder, query.start, query.end, MAX_INSTRUCTIONS, query.recover) {
                Ok(graph) => graph,
                Err(Failure::Undecodable) => return Ok(None),
                Err(Failure::Error(message)) => return Err(NativeRuntimeError(message)),
            }
        };
        if graph.blocks.is_empty() {
            return Ok(None);
        }
        let mut propagation = Propagation {
            lang: &lang,
            graph: &graph,
            lifter: self.flow.lifter(),
            behaviors: &self.behaviors,
            regions: &self.regions,
            data_space: &self.data_space,
            first: query.start,
            end: query.end,
            trust_writable: query.trust_writable,
            externals,
            current_pc: !0,
            operations: 0,
            references: Vec::new(),
            instruction_starts: Vec::new(),
            collect_references: false,
            scalar_reference_count: 0,
            pointer_storage: Vec::new(),
            seeds,
            tracked,
            mode_register,
            call_registers: Vec::new(),
            x86: self.x86,
            stack_base: -1,
            parents: Vec::new(),
            inputs: Vec::new(),
        };
        match propagation.run(reference_mode) {
            Ok(facts) => {
                let mut answer = Answer::default();
                answer.truncated_jumps.clone_from(&graph.truncated);
                answer.recovered_jumps.clone_from(&graph.recovered);
                answer.refused_jumps.clone_from(&graph.refused);
                if reference_mode {
                    answer.references = propagation
                        .reference_facts()
                        .into_iter()
                        .map(|fact| ReferenceFact {
                            from: fact.pc,
                            to: fact.target,
                            kind: fact.kind(),
                            size: fact.width,
                        })
                        .collect();
                    answer.call_registers = propagation.call_register_facts();
                } else {
                    answer.constants = facts
                        .into_iter()
                        .map(|fact| ConstantFact {
                            pc: fact.pc,
                            varnode: ConstantVarnode {
                                space: lang.space_names[fact.space as usize].clone(),
                                offset: fact.offset,
                                size: fact.size as u32,
                            },
                            value: fact.value,
                        })
                        .collect();
                }
                Ok(Some(answer))
            }
            Err(Failure::Undecodable) => Ok(None),
            Err(Failure::Error(message)) => Err(NativeRuntimeError(message)),
        }
    }
}

/// Everything one range's propagation reads.
struct Propagation<'a> {
    lang: &'a Lang,
    graph: &'a Graph,
    lifter: &'a SleighLifter,
    behaviors: &'a [Option<Rc<dyn OpBehavior>>],
    regions: &'a [Region],
    data_space: &'a Rc<AddrSpace>,
    first: Word,
    end: Word,
    trust_writable: bool,
    /// Import slots, sorted.
    externals: Vec<Word>,
    /// The instruction being evaluated, for the literal-pool rule in `load`.
    current_pc: Word,
    operations: usize,
    references: Vec<RefFact>,
    instruction_starts: Vec<Word>,
    collect_references: bool,
    scalar_reference_count: usize,
    /// The default prototype's storage for a pointer-sized return value
    /// (index 0) and eight pointer-sized parameters.
    pointer_storage: Vec<Option<Storage>>,
    seeds: Vec<(Storage, Word)>,
    tracked: Option<Storage>,
    mode_register: Option<Storage>,
    call_registers: Vec<(Word, Word, Word)>,
    x86: bool,
    stack_base: i32,
    /// For each op, the block that holds it and its position there.
    parents: Vec<(u32, u32)>,
    /// Each block's predecessors, in edge order.
    inputs: Vec<Vec<u32>>,
}

fn region_of<'r>(regions: &'r [Region], address: Word, size: i32) -> Option<&'r Region> {
    regions.iter().find(|candidate| candidate.contains(address, size))
}

impl<'a> Propagation<'a> {
    fn region(&self, address: Word, size: i32) -> Option<&'a Region> {
        region_of(self.regions, address, size)
    }

    fn memory_space(&self, space: i32) -> bool {
        space == self.lang.data_space || space == self.lang.code_space
    }

    fn space_kind(&self, space: i32) -> SpaceKind {
        self.lang.space(space).kind
    }

    fn failure(message: &str) -> Failure {
        Failure::Error(message.to_string())
    }

    fn insn_info(&self, op: &Op) -> Option<&graph::InsnInfo> {
        (op.insn != NONE).then(|| &self.graph.insns[op.insn as usize])
    }

    /// `loadAccess`'s and `computedFlow`'s classification of an instruction
    /// that holds a jump: the original instruction, not what flow recovery
    /// made of it.
    fn indirect_access(&self, op: &Op) -> u32 {
        if self.insn_info(op).is_some_and(|info| info.branchind) {
            ACCESS_INDIRECTION
        } else {
            ACCESS_READ
        }
    }

    fn load_access(&self, load: u32) -> u32 {
        let op = &self.graph.ops[load as usize];
        let Some(value) = op.out else {
            return if matches!(op.code, OpCode::CPUI_CALLIND | OpCode::CPUI_BRANCHIND) {
                self.indirect_access(op)
            } else {
                ACCESS_READ
            };
        };
        let (block, position) = self.parents[load as usize];
        let ops = &self.graph.blocks[block as usize].ops;
        for &next in &ops[position as usize + 1..] {
            let user = &self.graph.ops[next as usize];
            if user.addr != op.addr {
                break;
            }
            if !matches!(
                user.code,
                OpCode::CPUI_CALLIND | OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND | OpCode::CPUI_CBRANCH
            ) {
                continue;
            }
            let target = self.graph.inputs(user)[0];
            if target.space == value.space && target.offset == value.offset && target.size == value.size {
                return self.indirect_access(op);
            }
        }
        ACCESS_READ
    }

    /// Whether the instruction's decoded display operands name the slot.
    fn operand_names_slot(&self, op: &Op, state: &Snapshot, offset: Word, size: i32) -> bool {
        if self.insn_info(op).is_some_and(|info| info.terminal) {
            // A returning instruction names no slot: `pop {..., pc}` reloads
            // the frame it tears down (`evaluateSymbolicReference`: "if
            // (instr.getFlowType().isTerminal()) return false").
            return false;
        }
        let at = self.lifter.address(op.addr);
        let Ok(operands) = self.lifter.sleigh.operand_objects(&at) else { return false };
        let mask = width_mask(size);
        for operand in &operands {
            let mut local: Word = 0;
            for object in operand {
                if object.register {
                    let value = state.registers.get(object.space.get_index(), object.offset, object.size as i32);
                    if value.base != self.stack_base {
                        continue;
                    }
                    local = local.wrapping_add(value.bits);
                } else {
                    local = local.wrapping_add(object.scalar as Word);
                }
                if (local ^ offset) & mask == 0 || (local ^ offset) & 0xffff == 0 {
                    return true;
                }
            }
        }
        false
    }

    /// `SymbolicPropogator.makeReference`'s address of a value in a space.
    fn location(&self, space: i32, pointer: Value) -> Option<Location> {
        let size = pointer.size;
        if size < 1 || size > 8 || !self.memory_space(space) {
            return None;
        }
        let info = self.lang.space(space);
        if info.word_size == 0 {
            return None;
        }
        let spaces = self.lang.spaces.len() as i64;
        let offset;
        let result_space;
        if pointer.base >= 0 {
            if i64::from(pointer.base) > (i64::from(i32::MAX) - spaces) / spaces {
                return None;
            }
            result_space = -1 - (pointer.base * self.lang.spaces.len() as i32 + space);
            // Bias the virtual origin so ordinary negative stack offsets do not
            // straddle the storage map's unsigned boundary. Never emitted.
            offset = pointer.bits.wrapping_add(1u64 << (size * 8 - 1)) & width_mask(size);
        } else {
            if !pointer.complete(size) {
                return None;
            }
            result_space = space;
            let mut value = pointer.bits;
            // `SymbolicPropogator.makeReference` (:2624-2633): a negative offset
            // was sign-extended past the space (MIPS64 with 32-bit addresses
            // does that to every `lui`) and is chopped to the space's width.
            if (value >> (size * 8 - 1)) & 1 != 0 {
                value = info.wrap(value);
            }
            offset = value;
        }
        if offset > !0u64 / info.word_size {
            return None;
        }
        Some(Location { space: result_space, offset: offset.wrapping_mul(info.word_size) })
    }

    fn forget_memory(&self, state: &mut Snapshot, call: bool) {
        state.memory = State::new(self.lang.big_endian, -1);
        if call {
            state.call_writes = true;
        } else {
            state.unknown_writes = true;
            state.modified.clear();
        }
    }

    fn load(&self, state: &mut Snapshot, space: i32, pointer: Value, size: i32) -> Value {
        let Some(address) = self.location(space, pointer) else { return Value::default() };
        if size < 1 || size > 8 || (size - 1) as Word > !0 - address.offset {
            return Value::default();
        }
        let value = state.memory.get(address.space, address.offset, size);
        if value.base >= 0 || value.complete(size) || address.space < 0 {
            return value;
        }
        if self.externals.binary_search(&address.offset).is_ok() {
            return value;
        }
        // Ghidra reads writable memory without asking the evaluator when it
        // lies within 4096 bytes ahead of the instruction (`VarnodeContext.getValue`:
        // "if the value loaded is too far away, ask the evaluator"), which is
        // what makes a pc-relative literal pool a constant on ARM even though
        // the code was copied into RAM; farther away, writable memory is
        // trusted only on request, and never once something may have written it.
        let nearby = self.current_pc != !0 && address.offset >= self.current_pc && address.offset - self.current_pc <= 4096;
        if !nearby && state.unknown_writes {
            return value;
        }
        let Some(mapping) = self.region(address.offset, size) else { return value };
        if mapping.flags & 2 == 0
            || (mapping.flags & 1 != 0 && !nearby && (!self.trust_writable || state.call_writes))
            || !matches!(size, 1 | 2 | 4 | 8)
        {
            return value;
        }
        let mut bytes = [0u8; 8];
        let at = Address::new(Rc::clone(self.data_space), address.offset);
        if self.lifter.sleigh.loader_rc().borrow_mut().load_fill(&mut bytes[..size as usize], &at).is_err() {
            return value;
        }
        let big = self.lang.space(space).big_endian;
        let mut initial: Word = 0;
        let mut available: Word = 0;
        let mut previous_cell: Word = 0;
        let mut dirty: Option<u8> = None;
        for byte in 0..size {
            let shift = (if big { size - 1 - byte } else { byte } * 8) as u32;
            initial |= (bytes[byte as usize] as Word) << shift;
            let at = address.offset + byte as Word;
            let cell = at & !7;
            if byte == 0 || cell != previous_cell {
                dirty = state.modified.get(&Location { space: address.space, offset: cell }).copied();
                previous_cell = cell;
            }
            if dirty.is_none_or(|bits| bits & (1u8 << (at & 7)) == 0) {
                available |= 0xffu64 << shift;
            }
        }
        // VarnodeContext does not trust zero read from the initial image.
        if initial == 0 {
            return value;
        }
        available &= !value.known;
        Value::new(value.bits | (initial & available), value.known | available, -1, size)
    }

    fn get(&self, state: &mut Snapshot, vn: &Vn) -> Value {
        match self.space_kind(vn.space) {
            SpaceKind::Constant => Value::constant(vn.offset, vn.size),
            _ if self.memory_space(vn.space) => {
                let info = self.lang.space(vn.space);
                let words = vn.offset / info.word_size;
                if words * info.word_size != vn.offset {
                    return Value::default();
                }
                self.load(state, vn.space, Value::constant(words, info.addr_size as i32), vn.size)
            }
            _ => state.registers.get(vn.space, vn.offset, vn.size),
        }
    }

    fn store(&self, state: &mut Snapshot, space: i32, pointer: Value, size: i32, value: Value) {
        let spaces = self.lang.spaces.len() as i32;
        let address = match self.location(space, pointer) {
            Some(address) if size >= 1 && size <= 8 && (size - 1) as Word <= !0 - address.offset => address,
            _ => {
                self.forget_memory(state, false);
                return;
            }
        };
        let stack = address.space < 0 && (-1 - address.space) / spaces == self.stack_base;
        if address.space < 0 && !stack {
            // An opaque incoming pointer may alias any memory.
            self.forget_memory(state, false);
        } else {
            // A concrete store or a frame-relative store can invalidate aliases
            // held through other opaque incoming pointers.
            let mapped = address.space >= 0 && self.region(address.offset, size).is_some();
            let stack_base = self.stack_base;
            state.memory.retain(|id, _, _| id >= 0 || ((stack || mapped) && (-1 - id) / spaces == stack_base));
        }
        state.memory.put(address.space, address.offset, size, value);
        if !state.unknown_writes && address.space >= 0 {
            state.mark_written(address.space, address.offset, size);
        }
    }

    fn evaluate(&self, state: &mut Snapshot, op: &Op) -> Result<Value, Failure> {
        let Some(output) = op.out else { return Ok(Value::default()) };
        if output.size < 1 || output.size > 8 {
            return Ok(Value::default());
        }
        let ins = self.graph.inputs(op);
        let size = output.size;
        let inputs = ins.len();
        if op.code == OpCode::CPUI_LOAD && inputs == 2 {
            let space = self.space_from_const(&ins[0]);
            let pointer = self.get(state, &ins[1]);
            return Ok(self.load(state, space, pointer, size));
        }
        if inputs < 1 || inputs > 2 || ins[0].size > 8 {
            return Ok(Value::default());
        }
        let mut left = self.get(state, &ins[0]);
        if op.code == OpCode::CPUI_COPY {
            return Ok(if size == ins[0].size { left } else { Value::default() });
        }
        let mut right = if inputs == 2 { self.get(state, &ins[1]) } else { Value::default() };
        if inputs == 2 && ins[1].size > 8 {
            return Ok(Value::default());
        }
        let same_storage = inputs == 2
            && !self.memory_space(ins[0].space)
            && ins[0].space == ins[1].space
            && ins[0].offset == ins[1].offset
            && ins[0].size == ins[1].size;
        if same_storage && matches!(op.code, OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_SUB) {
            return Ok(Value::constant(0, size));
        }
        if size == ins[0].size && inputs == 2 {
            if op.code == OpCode::CPUI_INT_AND && right.base >= 0 && left.complete(size) && ins[1].size == size {
                std::mem::swap(&mut left, &mut right);
            }
            if op.code == OpCode::CPUI_INT_AND
                && left.base >= 0
                && right.complete(ins[1].size)
                && right.bits != 0
                && right.bits & 1 == 0
            {
                // VarnodeContext.and preserves a symbolic origin for alignment
                // masks. Rebase it conservatively: old pointers and slots must
                // not alias the new frame merely because both use the same
                // reusable abstract base id.
                let spaces = self.lang.spaces.len() as i32;
                state.registers.forget_relative_base(left.base);
                state.memory.forget_relative_base(left.base);
                let base = left.base;
                state.memory.retain(|id, _, _| id >= 0 || (-1 - id) / spaces != base);
                return Ok(Value::relative(left.base, left.bits & right.bits, size));
            }
            if left.base >= 0 && right.complete(ins[1].size) && matches!(op.code, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB) {
                let bits = if op.code == OpCode::CPUI_INT_ADD { left.bits.wrapping_add(right.bits) } else { left.bits.wrapping_sub(right.bits) };
                return Ok(Value::relative(left.base, bits, size));
            }
            if right.base >= 0 && left.complete(ins[0].size) && op.code == OpCode::CPUI_INT_ADD {
                return Ok(Value::relative(right.base, left.bits.wrapping_add(right.bits), size));
            }
            if left.base >= 0 && left.base == right.base && op.code == OpCode::CPUI_INT_SUB {
                return Ok(Value::constant(left.bits.wrapping_sub(right.bits), size));
            }
            // `or rd, rs, zero` is how MIPS spells a register move; a zero
            // operand leaves the other side, symbolic origin included, exactly
            // as VarnodeContext's or/xor keep a symbolic value when the other
            // operand is the constant zero.
            if matches!(op.code, OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR) {
                if left.base >= 0 && right.complete(ins[1].size) && right.bits == 0 {
                    return Ok(Value::relative(left.base, left.bits, size));
                }
                if right.base >= 0 && left.complete(ins[0].size) && left.bits == 0 && ins[1].size == size {
                    return Ok(Value::relative(right.base, right.bits, size));
                }
            }
        }
        if left.base < 0 && right.base < 0 && inputs == 2 {
            let mask = width_mask(size);
            match op.code {
                OpCode::CPUI_INT_AND => {
                    return Ok(Value::new(
                        left.bits & right.bits,
                        ((left.known & right.known) | (left.known & !left.bits) | (right.known & !right.bits)) & mask,
                        -1,
                        0,
                    ));
                }
                OpCode::CPUI_INT_OR => {
                    return Ok(Value::new(
                        left.bits | right.bits,
                        ((left.known & right.known) | (left.known & left.bits) | (right.known & right.bits)) & mask,
                        -1,
                        0,
                    ));
                }
                OpCode::CPUI_INT_XOR => {
                    return Ok(Value::new(left.bits ^ right.bits, left.known & right.known & mask, -1, 0));
                }
                _ => {}
            }
        }
        if !left.complete(ins[0].size) || (inputs == 2 && !right.complete(ins[1].size)) {
            return Ok(Value::default());
        }
        let Some(Some(behavior)) = self.behaviors.get(op.code as usize) else { return Ok(Value::default()) };
        if behavior.is_special() || behavior.is_unary() != (inputs == 1) {
            return Ok(Value::default());
        }
        let result = if inputs == 1 {
            behavior.evaluate_unary(size, ins[0].size, left.bits)
        } else {
            behavior.evaluate_binary(size, ins[0].size, left.bits, right.bits)
        };
        match result {
            Ok(value) => Ok(Value::constant(value, size)),
            Err(error) => Err(Failure::Error(error.to_string())),
        }
    }

    /// `getSpaceFromConst`: the space a LOAD or STORE names in its first input.
    fn space_from_const(&self, vn: &Vn) -> i32 {
        vn.offset as i32
    }

    fn observe(&self, facts: &mut Vec<Fact>, op: &Op, value: Value) {
        let Some(output) = op.out else { return };
        if output.size != self.lang.pointer_size || !value.complete(self.lang.pointer_size) || self.memory_space(output.space) {
            return;
        }
        let data = self.lang.space(self.lang.data_space);
        let scale = data.word_size;
        if scale == 0 || value.bits > data.highest / scale {
            return;
        }
        let target = value.bits * scale;
        if target < 1024 || data.highest - target < 256 || target == 0xffff || target == 0xffff_ffff || self.region(target, 1).is_none() {
            return;
        }
        facts.push(Fact { pc: op.addr, value: value.bits, space: output.space, offset: output.offset, size: output.size });
    }

    fn reference(&mut self, op: &Op, space: i32, value: Value, access: u32, address_operand: bool, width: u32) {
        if !self.collect_references || value.base >= 0 {
            return;
        }
        let Some(address) = self.location(space, value) else { return };
        let highest = self.lang.space(space).highest;
        if address.offset < 4 || address.offset > highest || self.region(address.offset, 1).is_none() {
            return;
        }
        if access == ACCESS_DATA && !address_operand {
            if address.offset < 1024 || highest - address.offset < 256 || address.offset == 0xffff || address.offset == 0xffff_ffff {
                return;
            }
            // SymbolicPropogator.evaluatePureDataRef rejects speculative pointers
            // to an instruction's fallthrough, including a CALL's saved return PC.
            if space == self.lang.code_space && address.offset > op.addr && address.offset - op.addr <= 32 {
                let at = self.lifter.address(op.addr);
                if let Ok(length) = self.lifter.sleigh.instruction_length(&at) {
                    if address.offset == op.addr + length as Word && self.insn_info(op).is_some_and(|info| info.fallthrough) {
                        return;
                    }
                }
            }
            // Pure data must not point into this function's decoded instructions.
            // Do not use the caller's bounding range as a containment approximation.
            if address.offset != self.first {
                if self.instruction_starts.is_empty() {
                    self.instruction_starts = self.graph.instruction_starts(self.first, self.end);
                }
                if self.instruction_starts.binary_search(&address.offset).is_ok() {
                    return;
                }
            }
        }
        self.references.push(RefFact { pc: op.addr, target: address.offset, access, width });
    }

    /// Operand scalars of a literal pool on an unaligned ISA (`ScalarOperandAnalyzer`).
    fn literal_references(&mut self) {
        if self.lang.alignment != 1 {
            return;
        }
        let mut starts: Vec<u32> = (0..self.graph.ops.len() as u32)
            .filter(|&id| {
                let op = &self.graph.ops[id as usize];
                !op.dead && op.start_insn && op.addr >= self.first && op.addr < self.end
            })
            .collect();
        starts.sort_by_key(|&id| (self.graph.ops[id as usize].addr, self.graph.ops[id as usize].time));
        let mut scalars = Vec::new();
        for id in starts {
            let op = &self.graph.ops[id as usize];
            let at = self.lifter.address(op.addr);
            scalars.clear();
            if self.lifter.sleigh.operand_scalars(&at, &mut scalars).is_err() {
                continue;
            }
            for scalar in &scalars {
                let value = Value::constant(scalar.offset, scalar.size as i32);
                if value.bits < 4096 || self.region(value.bits, 1).is_none() {
                    continue;
                }
                // ScalarOperandAnalyzer's non-relocation-guided exclusions.
                if matches!(
                    value.bits,
                    0xffff | 0xff00 | 0xffffff | 0xff0000 | 0xff00ff | 0xffff_ffff | 0xffff_ff00 | 0xffff_0000 | 0xff00_0000
                ) {
                    continue;
                }
                // Compiler call-fixups can remove CALL ops from the flow.
                // Operand classification keeps the original instruction's
                // flow targets.
                let control = self.insn_info(op).is_some_and(|info| info.targets.contains(&value.bits));
                if !control {
                    let op = &self.graph.ops[id as usize] as *const Op;
                    // SAFETY: the graph outlives the propagation and is never mutated.
                    let op = unsafe { &*op };
                    self.reference(op, self.lang.data_space, value, ACCESS_DATA, false, 0);
                }
            }
        }
    }

    /// A call or branch through a register the propagation knows: Ghidra's
    /// SymbolicPropogator hands such a flow to `evaluateDestination` and
    /// `evaluateReference` with the flow's own RefType, and the ARM analyzer
    /// turns a target's low bit into the instruction-set mode
    /// (`PseudoDisassembler.setTargetContextForDisassembly`). The target is
    /// reported as the register holds it, low bit included, so the consumer can
    /// apply that rule; only a value inside the image is a target at all.
    fn computed_flow(&mut self, op: &Op, state: &mut Snapshot) {
        if !matches!(op.code, OpCode::CPUI_CALLIND | OpCode::CPUI_BRANCHIND) {
            return;
        }
        let ins = self.graph.inputs(op);
        let Some(operand) = ins.first() else { return };
        if self.space_kind(operand.space) == SpaceKind::Constant {
            return; // A literal target is direct flow.
        }
        // A memory-direct branch reads its target from the image -- unless
        // this function's own stores produced a value the propagation still
        // knows (a self-patched dispatch). Unknown memory falls out at complete().
        let target = self.get(state, operand);
        if target.base >= 0 || !target.complete(operand.size) {
            return;
        }
        // The mode bit lives in the target's low bit only on languages with a
        // mode register (ARM Thumb): there the branch cleared it from the
        // address and the switch register hands it back. Elsewhere (x86) bit 0
        // is address payload. Mask only when a mode register exists.
        let mut raw = if self.mode_register.is_some() { target.bits & !1 } else { target.bits };
        if let Some(mode_register) = self.mode_register {
            let mode = state.registers.get(mode_register.space, mode_register.offset, mode_register.size);
            if mode.base < 0 && mode.complete(mode_register.size) && mode.bits & 1 != 0 {
                raw |= 1;
            }
        }
        if raw < 4 || self.region(raw & !1, 1).is_none() {
            return;
        }
        // Classify the original instruction, not a recovery transform.
        let access = if self.indirect_access(op) == ACCESS_INDIRECTION { ACCESS_JUMP } else { ACCESS_CALL };
        self.references.push(RefFact { pc: op.addr, target: raw, access, width: 0 });
    }

    fn call_register(&mut self, op: &Op, state: &mut Snapshot) {
        let Some(tracked) = self.tracked else { return };
        if !matches!(op.code, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) {
            return;
        }
        let value = state.registers.get(tracked.space, tracked.offset, tracked.size);
        if !value.complete(tracked.size) || value.bits == 0 {
            return;
        }
        let target;
        if op.code == OpCode::CPUI_CALL {
            let Some(entry) = self.call_entry(op) else { return };
            target = entry;
        } else {
            let operand = self.graph.inputs(op)[0];
            let destination = self.get(state, &operand);
            if !destination.complete(self.lang.pointer_size) {
                return;
            }
            target = destination.bits;
        }
        if self.region(target, 1).is_some_and(|region| region.flags & 4 != 0) {
            self.call_registers.push((op.addr, target, value.bits));
        }
    }

    fn call_entry(&self, op: &Op) -> Option<Word> {
        (op.call != NONE).then(|| self.graph.calls[op.call as usize].entry).flatten()
    }

    /// `storageReference`: the op that set a pointer argument gets the reference.
    fn storage_reference(&mut self, consumer: u32, storage: Storage, value: Value) -> Result<(), Failure> {
        // VarnodeContext records the written register and its parents, not
        // unwritten child aliases. Preserve that distinction for wide registers.
        let pointer_size = self.lang.pointer_size as u64;
        let return_storage = self.pointer_storage.first().copied().flatten();
        let mut pending: Vec<u32> = vec![self.parents[consumer as usize].0];
        let mut visited: Vec<u32> = Vec::new();
        let mut initial = true;
        while let Some(block) = pending.pop() {
            let ops = &self.graph.blocks[block as usize].ops;
            let mut cursor = ops.len();
            if initial {
                cursor = self.parents[consumer as usize].1 as usize;
                initial = false;
            } else {
                if visited.contains(&block) {
                    continue;
                }
                visited.push(block);
            }
            let mut setter = None;
            while cursor > 0 {
                self.operations += 1;
                if self.operations > MAX_OPERATIONS {
                    return Err(Self::failure("Constant propagation exceeds one million p-code operations"));
                }
                cursor -= 1;
                let id = ops[cursor];
                let op = &self.graph.ops[id as usize];
                if let Some(output) = op.out {
                    if output.space == storage.space
                        && output.offset >= storage.offset
                        && output.size as u64 <= pointer_size
                        && output.offset - storage.offset <= pointer_size - output.size as u64
                    {
                        setter = Some(id);
                        break;
                    }
                }
                if matches!(op.code, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND)
                    && return_storage.is_some_and(|first| first.space == storage.space && first.offset == storage.offset)
                {
                    setter = Some(id);
                    break;
                }
            }
            let data_space = self.lang.data_space;
            match setter {
                Some(id) => {
                    let op = &self.graph.ops[id as usize] as *const Op;
                    // SAFETY: the graph outlives the propagation and is never mutated.
                    self.reference(unsafe { &*op }, data_space, value, ACCESS_DATA, false, 0);
                }
                None if self.inputs[block as usize].is_empty() => {
                    let op = &self.graph.ops[consumer as usize] as *const Op;
                    // SAFETY: as above.
                    self.reference(unsafe { &*op }, data_space, value, ACCESS_DATA, false, 0);
                }
                None => pending.extend(self.inputs[block as usize].iter().copied()),
            }
        }
        Ok(())
    }

    fn use_references(&mut self, id: u32, state: &mut Snapshot) -> Result<(), Failure> {
        let op = &self.graph.ops[id as usize];
        let returning = op.code == OpCode::CPUI_RETURN;
        if !returning && !matches!(op.code, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) {
            return Ok(());
        }
        let target = if op.code == OpCode::CPUI_CALL { self.call_entry(op).unwrap_or(!0) } else { !0 };
        let begin = if returning { 0 } else { 1 };
        let finish = if returning { 1.min(self.pointer_storage.len()) } else { self.pointer_storage.len() };
        for index in begin..finish {
            let Some(storage) = self.pointer_storage[index] else { continue };
            // Unknown signatures do not justify reading guessed stack arguments.
            if self.space_kind(storage.space) != SpaceKind::Processor || self.memory_space(storage.space) {
                continue;
            }
            let value = state.registers.get(storage.space, storage.offset, self.lang.pointer_size);
            if value.complete(self.lang.pointer_size) && value.bits != target && self.region(value.bits, 1).is_some() {
                self.storage_reference(id, storage, value)?;
            }
        }
        Ok(())
    }

    fn memory_references(&mut self, id: u32, state: &mut Snapshot) {
        let op = &self.graph.ops[id as usize] as *const Op;
        // SAFETY: the graph outlives the propagation and is never mutated.
        let op: &Op = unsafe { &*op };
        let ins = self.graph.inputs(op);
        let code = op.code;
        if matches!(code, OpCode::CPUI_LOAD | OpCode::CPUI_STORE) && ins.len() >= 2 {
            let space = self.space_from_const(&ins[0]);
            let mut pointer = self.get(state, &ins[1]);
            let mut access = if code == OpCode::CPUI_LOAD { ACCESS_READ } else { ACCESS_WRITE };
            let accessed = if code == OpCode::CPUI_LOAD { op.out } else { ins.get(2).copied() };
            let width = accessed.map_or(0, |vn| vn.size as u32);
            // A stack access is a fact about the frame, not about memory:
            // Ghidra's stack analyzer turns every operand SymbolicPropogator
            // resolves to the stack space into a stack reference and then a
            // variable (`NewFunctionStackAnalysisCmd.defineFuncVariable`, sized
            // from the LOAD output or STORE value like `getRefSize`). It is
            // reported with the offset relative to the entry stack pointer.
            if self.stack_base >= 0 && pointer.base == self.stack_base && self.collect_references {
                // Only an access an instruction *operand* spells as a stack
                // slot (`getStackOpIndex`). A push or pop stores through the
                // stack pointer too, but names no slot.
                let pointer_size = ins.get(1).map_or(self.lang.pointer_size, |vn| vn.size);
                if width != 0 && self.operand_names_slot(op, state, pointer.bits, pointer_size) {
                    self.references.push(RefFact { pc: op.addr, target: pointer.bits, access: ACCESS_STACK | access, width });
                }
            }
            if pointer.base >= 0 && pointer.base != self.stack_base {
                let plain = Value::new(pointer.bits, pointer.known, -1, pointer.size);
                if self.location(space, plain).is_some_and(|candidate| self.region(candidate.offset, 1).is_some()) {
                    let kind = self.insn_info(op).map(|info| info.kind);
                    if !matches!(kind, Some(FlowKind::Call) | Some(FlowKind::CallInd)) {
                        // A non-stack symbolic offset is speculative DATA, not a proved load/store.
                        pointer.base = -1;
                        access = ACCESS_DATA;
                    }
                }
            }
            // A LOAD's output and a STORE's value are the access: their size
            // is how many bytes the instruction touches at the target.
            self.reference(op, space, pointer, access, false, if access == ACCESS_DATA { 0 } else { width });
            if code == OpCode::CPUI_STORE && ins.len() >= 3 {
                let stored = self.get(state, &ins[2]);
                self.reference(op, self.lang.data_space, stored, ACCESS_DATA, false, 0);
            }
        }
        // Raw flow can represent fixed-address loads/stores as memory varnodes.
        for (index, input) in ins.iter().enumerate() {
            if !self.memory_space(input.space)
                || (matches!(code, OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_CALL) && index == 0)
            {
                continue;
            }
            let info = self.lang.space(input.space);
            let access = self.load_access(id);
            self.reference(
                op,
                input.space,
                Value::constant(input.offset / info.word_size, info.addr_size as i32),
                access,
                false,
                input.size as u32,
            );
        }
        if let Some(output) = op.out {
            if self.memory_space(output.space) {
                let info = self.lang.space(output.space);
                self.reference(
                    op,
                    output.space,
                    Value::constant(output.offset / info.word_size, info.addr_size as i32),
                    ACCESS_WRITE,
                    false,
                    output.size as u32,
                );
            }
        }
    }

    /// One block's transfer; the index of the conditional branch's chosen
    /// edge, `-1` when none, or `-2` when the block leaves the range.
    fn transfer(&mut self, block: u32, state: &mut Snapshot, mut facts: Option<&mut Vec<Fact>>) -> Result<i32, Failure> {
        let mut branch = -1;
        let graph = self.graph;
        let block_ops = &graph.blocks[block as usize].ops;
        for &id in block_ops {
            let op = &graph.ops[id as usize];
            self.current_pc = op.addr;
            self.operations += 1;
            if self.operations > MAX_OPERATIONS {
                return Err(Self::failure("Constant propagation exceeds one million p-code operations"));
            }
            if op.addr < self.first || op.addr >= self.end {
                return Ok(-2);
            }
            state.registers.begin_instruction(self.lang.code_space, op.addr);
            let ins = graph.inputs(op);
            if self.collect_references {
                self.memory_references(id, state);
                self.use_references(id, state)?;
                self.call_register(op, state);
                self.computed_flow(op, state);
            }
            let code = op.code;
            if code == OpCode::CPUI_CBRANCH && ins.len() == 2 {
                let condition = self.get(state, &ins[1]);
                if condition.complete(ins[1].size) {
                    branch = if condition.bits != 0 { 1 } else { 0 };
                }
            } else if code == OpCode::CPUI_STORE && ins.len() == 3 {
                let space = self.space_from_const(&ins[0]);
                let pointer = self.get(state, &ins[1]);
                let value = self.get(state, &ins[2]);
                self.store(state, space, pointer, ins[2].size, value);
            } else if matches!(code, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) {
                let stack = self.lang.stack_pointer;
                let stack_value = stack.map_or_else(Value::default, |sp| state.registers.get(sp.space, sp.offset, sp.size));
                let unique = self.lang.unique_space;
                let lang = self.lang;
                state.registers.retain(|space, offset, size| space == unique || lang.call_unaffected(space, offset, size));
                self.forget_memory(state, true);
                if let Some(sp) = stack {
                    let extra = lang.extra_pop;
                    let size = sp.size;
                    let mut restored = Value::default();
                    if extra != EXTRAPOP_UNKNOWN {
                        let amount = extra as i64 as Word;
                        if stack_value.base >= 0 {
                            restored = Value::relative(stack_value.base, stack_value.bits.wrapping_add(amount), size);
                        } else if stack_value.complete(size) {
                            restored = Value::constant(stack_value.bits.wrapping_add(amount), size);
                        } else if extra == 0 {
                            restored = stack_value;
                        }
                    }
                    // CALL's raw p-code includes its push; the callee's RET does
                    // not occur in this function's flow. Apply the prototype's pop.
                    state.registers.put(sp.space, sp.offset, size, restored);
                }
            }
            // A user-defined operation touches only what it names: Ghidra
            // clears the op's output and nothing else (`SymbolicPropogator.
            // applyPcode`, `case PcodeOp.CALLOTHER`).
            if let Some(output) = op.out {
                let value = if code == OpCode::CPUI_CALLOTHER { Value::default() } else { self.evaluate(state, op)? };
                if self.memory_space(output.space) {
                    let info = self.lang.space(output.space);
                    self.store(
                        state,
                        output.space,
                        Value::constant(output.offset / info.word_size, info.addr_size as i32),
                        output.size,
                        value,
                    );
                } else {
                    state.registers.put(output.space, output.offset, output.size, value);
                }
                if let Some(facts) = facts.as_deref_mut() {
                    self.observe(facts, op, value);
                }
                if self.collect_references
                    && self.space_kind(output.space) == SpaceKind::Processor
                    && !self.memory_space(output.space)
                    && value.complete(value.size)
                    && value.bits > 4096
                    && self.region(value.bits, 1).is_some()
                    && self.address_formation(op.addr)
                {
                    // X86Analyzer preserves an existing reference on the LEA operand.
                    let limit = self.scalar_reference_count;
                    let exists = self.references[..limit].binary_search_by(|fact| fact.pc.cmp(&op.addr)).is_ok();
                    if !exists {
                        self.reference(op, self.lang.data_space, value, ACCESS_DATA, true, 0);
                    }
                }
            }
        }
        Ok(branch)
    }

    /// `X86ReferencePolicy::matches`: the instruction forms an address (`LEA`).
    fn address_formation(&self, pc: Word) -> bool {
        self.x86 && self.lifter.sleigh.mnemonic(&self.lifter.address(pc)).is_ok_and(|mnemonic| mnemonic == "LEA")
    }

    fn initial_state(&mut self) -> Snapshot {
        let mut initial = Snapshot::new(self.lang.big_endian, self.lang.unique_space);
        let mut registers: BTreeMap<Location, i32> = BTreeMap::new();
        for op in self.graph.ops.iter().filter(|op| !op.dead) {
            for input in self.graph.inputs(op) {
                if self.space_kind(input.space) != SpaceKind::Processor
                    || self.memory_space(input.space)
                    || input.size < 1
                    || input.size > 8
                {
                    continue;
                }
                let size = registers.entry(Location { space: input.space, offset: input.offset }).or_insert(0);
                *size = (*size).max(input.size);
            }
        }
        let mut base = 0;
        let mut previous_space = -1;
        let mut previous_end: Word = 0;
        for (key, &size) in &registers {
            if key.space == previous_space && key.offset < previous_end {
                continue;
            }
            initial.registers.put(key.space, key.offset, size, Value::relative(base, 0, size));
            if let Some(sp) = self.lang.stack_pointer {
                if key.space == sp.space && key.offset == sp.offset && size == sp.size {
                    self.stack_base = base;
                }
            }
            base += 1;
            previous_space = key.space;
            previous_end = key.offset + size as Word;
        }
        for (storage, value) in &self.seeds {
            initial.registers.put(storage.space, storage.offset, storage.size, Value::constant(*value, storage.size));
        }
        initial
    }

    fn prepare(&mut self) {
        let blocks = &self.graph.blocks;
        self.parents = vec![(NONE, 0); self.graph.ops.len()];
        for (block, content) in blocks.iter().enumerate() {
            for (position, &op) in content.ops.iter().enumerate() {
                self.parents[op as usize] = (block as u32, position as u32);
            }
        }
        self.inputs = vec![Vec::new(); blocks.len()];
        for (block, content) in blocks.iter().enumerate() {
            for &next in &content.outs {
                self.inputs[next as usize].push(block as u32);
            }
        }
    }

    fn run(&mut self, reference_mode: bool) -> Result<Vec<Fact>, Failure> {
        let graph = self.graph;
        // `Propagation::run`'s refusal of a body with bad or unimplemented
        // instructions is `Graph::follow`'s `Undecodable`.
        self.prepare();
        struct Node {
            input: Snapshot,
            queued: bool,
        }
        let mut nodes: BTreeMap<u32, Node> = BTreeMap::new();
        let mut pending: std::collections::VecDeque<u32> = std::collections::VecDeque::new();
        let initial = self.initial_state();
        nodes.insert(0, Node { input: initial, queued: true });
        pending.push_back(0);
        while let Some(block) = pending.pop_front() {
            let node = nodes.get_mut(&block).expect("a queued block has a node");
            node.queued = false;
            let mut output = node.input.clone();
            let choice = self.transfer(block, &mut output, None)?;
            if choice == -2 {
                continue;
            }
            let outs = &graph.blocks[block as usize].outs;
            for (edge, &next) in outs.iter().enumerate() {
                // Ghidra reference analysis follows false conditional branches too.
                if !reference_mode && choice >= 0 && outs.len() == 2 && edge as i32 != choice {
                    continue;
                }
                let fresh = !nodes.contains_key(&next);
                if fresh {
                    nodes.insert(next, Node { input: output.clone(), queued: true });
                    pending.push_back(next);
                } else {
                    let node = nodes.get_mut(&next).expect("checked above");
                    if !node.input.merge(&output) {
                        continue;
                    }
                    if !node.queued {
                        node.queued = true;
                        pending.push_back(next);
                    }
                }
            }
        }
        let mut facts = Vec::new();
        self.collect_references = reference_mode;
        if reference_mode {
            self.initialize_pointer_storage()?;
            self.literal_references();
            self.scalar_reference_count = self.references.len();
        }
        let blocks: Vec<u32> = nodes.keys().copied().collect();
        for block in blocks {
            let mut state = nodes[&block].input.clone();
            if reference_mode {
                self.transfer(block, &mut state, None)?;
            } else {
                self.transfer(block, &mut state, Some(&mut facts))?;
            }
        }
        facts.sort_by_key(|fact| (fact.pc, fact.space, fact.offset, fact.size, fact.value));
        facts.dedup_by_key(|fact| (fact.pc, fact.space, fact.offset, fact.size, fact.value));
        Ok(facts)
    }

    fn initialize_pointer_storage(&mut self) -> Result<(), Failure> {
        match &self.lang.pointer_storage {
            Ok(storage) => {
                self.pointer_storage = storage.clone();
                Ok(())
            }
            Err(message) => Err(Failure::Error(message.clone())),
        }
    }

    fn reference_facts(&mut self) -> Vec<RefFact> {
        self.references.sort_by_key(|fact| (fact.pc, fact.target));
        let mut merged: Vec<RefFact> = Vec::with_capacity(self.references.len());
        for fact in &self.references {
            match merged.last_mut() {
                Some(last) if last.pc == fact.pc && last.target == fact.target => {
                    last.access |= fact.access;
                    last.width = last.width.max(fact.width);
                }
                _ => merged.push(*fact),
            }
        }
        merged
    }

    fn call_register_facts(&mut self) -> Vec<CallRegisterFact> {
        self.call_registers.sort_by_key(|&(pc, _, _)| pc);
        self.call_registers.iter().map(|&(_, target, value)| CallRegisterFact { target, value }).collect()
    }
}
