//! Instruction flow decoded in process, from the same SLEIGH runtime
//! `super::lift` lifts p-code with. It answers what a SLEIGH console's `flow`
//! command answered before that console (a patch of Ghidra's decompiler
//! console) was retired.
//!
//! An instruction is classified while its p-code is built (Ghidra's
//! `SleighInstructionPrototype.walkTemplates`/`flowListToFlowType`, Apache-2.0): every
//! flow op is noted with its template's target kind (`inst_next`,
//! `inst_start`, a relative label, or an operand), a label resets the
//! no-fallthrough bit, and nothing inside a delay slot counts. Resolved p-code
//! has lost those distinctions (`goto inst_next` and a branch to the next
//! address look the same), and Kuna's builder has no hook, so a flow
//! decoder's templates carry them: before each flow op, label and delay slot,
//! [`instrument`] inserts a marker op the builder dumps like any other, in
//! build order, and [`FlowEmit`] reads the markers back out of the emitted
//! stream. Markers never reach a caller and are not counted, so the p-code
//! count behind `pure_jump`/`no_op` is the console's. A flow decoder is never
//! used to lift p-code: the markers shift relative-branch offsets.
//!
//! Each decode applies its own `globalset` commits to the decoder's context
//! database, as the console's `oneInstructionFlow` did to its own; the one
//! console behaviour not reproduced is the `DisassemblyCache` reuse of an
//! address's earlier parse after a commit changed its context (see
//! `super::lift`).
use super::{FlowKind, FlowResult, NativeRuntimeError, Result, SleighLifter};
use crate::native::{NativeContext, NativeImport};
use crate::session::RuntimeConfig;
use kuna_base::address::Address;
use kuna_base::error::KunaError;
use kuna_base::space::spacetype;
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::semantics::{ConstTpl, ConstType, OpTpl, VarnodeTpl};
use kuna_sleigh::translate::PcodeEmit;
use std::rc::Rc;

/// `SleighInstructionPrototype` flow flag bits (`convertFlowFlags`).
const RETURN: u32 = 0x01;
const CALL_INDIRECT: u32 = 0x02;
const BRANCH_INDIRECT: u32 = 0x04;
const CALL: u32 = 0x08;
const JUMPOUT: u32 = 0x10;
const NO_FALLTHRU: u32 = 0x20;
const BRANCH_TO_END: u32 = 0x40;
const LABEL: u32 = 0x100;

/// A marker is a `CAST` (which no SLEIGH semantic section can emit) of one
/// 8-byte constant: this tag in the high word, the marker kind and its flow
/// value below.
const MARKER_OPCODE: OpCode = OpCode::CPUI_CAST;
const MARKER_TAG: u64 = 0x524f_4d57 << 32;
const MARK_FLOW: u64 = 1 << 16;
const MARK_LABEL: u64 = 2 << 16;
const MARK_DELAY_BEGIN: u64 = 3 << 16;
const MARK_DELAY_END: u64 = 4 << 16;

/// The flow a template op contributes, as `InstructionFlow::record` decides
/// it before the op's target is known; `None` for an op that is not flow.
fn template_flow(op: &OpTpl) -> Option<u32> {
    let target_type = || (op.num_input() > 0).then(|| op.get_in(0).get_offset().get_type());
    Some(match op.get_opcode() {
        OpCode::CPUI_BRANCHIND => BRANCH_INDIRECT | NO_FALLTHRU,
        OpCode::CPUI_BRANCH => match target_type() {
            Some(ConstType::JNext) => BRANCH_TO_END,
            Some(ConstType::JStart | ConstType::JRelative) => NO_FALLTHRU,
            _ => JUMPOUT | NO_FALLTHRU,
        },
        OpCode::CPUI_CBRANCH => match target_type() {
            Some(ConstType::JNext) => BRANCH_TO_END,
            Some(ConstType::JStart | ConstType::JRelative) => 0,
            _ => JUMPOUT,
        },
        OpCode::CPUI_CALL => CALL,
        OpCode::CPUI_CALLIND => CALL_INDIRECT,
        OpCode::CPUI_RETURN => RETURN | NO_FALLTHRU,
        _ => return None,
    })
}

/// Inserts the markers [`FlowEmit`] reads into every constructor template.
/// The builder dispatches `BUILD`/`DELAY_SLOT`/`LABEL`/`CROSSBUILD` by their
/// opcodes (`MULTIEQUAL`/`INDIRECT`/`PTRADD`/`PTRSUB`) and dumps the rest.
fn instrument(lifter: &mut SleighLifter) -> Result<()> {
    let const_space = lifter
        .sleigh
        .base()
        .manager()
        .get_constant_space()
        .cloned()
        .ok_or_else(|| NativeRuntimeError("SLEIGH: no constant space".into()))?;
    let marker = move |code: u64| {
        let mut op = OpTpl::new(MARKER_OPCODE);
        op.add_input(VarnodeTpl::new(
            ConstTpl::new_space(Rc::clone(&const_space)),
            ConstTpl::new_real(ConstType::Real, MARKER_TAG | code),
            ConstTpl::new_real(ConstType::Real, 8),
        ));
        op
    };
    // Templates are decoded when first used: the marked variant of each is made
    // as it is first read, and which variant the decoder reads is a switch.
    let base = lifter.sleigh.base_mut();
    base.set_marked_template_transform(Box::new(move |template| {
        let ops = std::mem::take(template.get_opvec_mut());
        let mut marked = Vec::with_capacity(ops.len() + 4);
        for op in ops {
            match op.get_opcode() {
                OpCode::CPUI_PTRADD => {
                    marked.push(marker(MARK_LABEL));
                    marked.push(op);
                }
                OpCode::CPUI_INDIRECT => {
                    marked.push(marker(MARK_DELAY_BEGIN));
                    marked.push(op);
                    marked.push(marker(MARK_DELAY_END));
                }
                _ => {
                    if let Some(value) = template_flow(&op) {
                        marked.push(marker(MARK_FLOW | u64::from(value)));
                    }
                    marked.push(op);
                }
            }
        }
        *template.get_opvec_mut() = marked;
    }));
    base.set_marked_templates(true);
    Ok(())
}

/// One varnode of a captured instruction: the space by its index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Vn {
    pub space: i32,
    pub offset: u64,
    pub size: i32,
}

/// One captured p-code op: its inputs are `pool[ins..ins + nin]`.
#[derive(Clone, Copy, Debug)]
pub(super) struct RawOp {
    pub code: OpCode,
    pub out: Option<Vn>,
    pub ins: u32,
    pub nin: u32,
    /// Index among everything the builder dumped, markers included.
    raw_index: u32,
}

/// One instruction decoded for the reference propagation: its p-code as the
/// console's `oneInstruction` emitted it (markers removed, relative branches
/// renumbered) and the flow classification `oneInstructionFlow` gave.
#[derive(Default)]
pub(super) struct RawInsn {
    pub length: i32,
    pub ops: Vec<RawOp>,
    pub pool: Vec<Vn>,
    pub kind: Option<FlowKind>,
    pub fallthrough: bool,
    pub terminal: bool,
    pub targets: Vec<u64>,
    /// The instruction's own p-code holds a `BRANCHIND`.
    pub branchind: bool,
    /// The instruction only sometimes transfers: `InstructionFlow`'s conditional flag.
    pub conditional: bool,
}

/// One instruction's flow, read off its emitted p-code (`InstructionFlow`
/// plus `IfcFlow`'s `FlowPcodeEmit`).
#[derive(Default)]
struct FlowEmit {
    flags: u32,
    targets: Vec<(i32, u64)>,
    /// Inside a delay slot: `SleighBuilder::delaySlot` records nothing.
    delay: bool,
    /// The next emitted branch or call is the op a `JUMPOUT`/`CALL` marker
    /// stood before: its target, when not dynamic, is the flow's.
    pending_target: bool,
    /// Emitted p-code ops, markers aside.
    count: u32,
    first_branch: bool,
    return_op: bool,
    /// A `BRANCHIND` through PowerPC's `LR` was emitted.
    lr_branch: bool,
    lr: Option<VarnodeData>,
    /// Keep the ops (propagation decodes) as well as the flow.
    capture: bool,
    ops: Vec<RawOp>,
    pool: Vec<Vn>,
    /// Everything dumped so far, markers included.
    dumped: u32,
    /// For each dumped item, how many captured ops came before it.
    clean_at: Vec<u32>,
}

impl FlowEmit {
    /// `InstructionFlow::note`.
    fn note(&mut self, value: u32) {
        self.flags = (self.flags & !(NO_FALLTHRU | LABEL)) | value;
    }

    fn reset(&mut self) {
        self.flags = 0;
        self.targets.clear();
        self.delay = false;
        self.pending_target = false;
        self.count = 0;
        self.first_branch = false;
        self.return_op = false;
        self.lr_branch = false;
        self.ops.clear();
        self.pool.clear();
        self.dumped = 0;
        self.clean_at.clear();
    }
}

fn space_is(data: &VarnodeData, kind: spacetype) -> bool {
    data.space.as_ref().is_some_and(|space| space.get_type() == kind)
}

impl PcodeEmit for FlowEmit {
    fn dump(&mut self, _addr: &Address, opc: OpCode, outvar: Option<&VarnodeData>, vars: &[VarnodeData]) {
        let raw_index = self.dumped;
        self.dumped += 1;
        if self.capture {
            self.clean_at.push(self.ops.len() as u32);
        }
        if opc == MARKER_OPCODE
            && vars.len() == 1
            && space_is(&vars[0], spacetype::IPTR_CONSTANT)
            && vars[0].offset & !0xffff_ffff == MARKER_TAG
        {
            let code = vars[0].offset & 0xffff_ffff;
            match code & !0xffff {
                MARK_DELAY_BEGIN => self.delay = true,
                MARK_DELAY_END => self.delay = false,
                _ if self.delay => {}
                MARK_LABEL => self.note(LABEL),
                _ => {
                    let value = (code & 0xffff) as u32;
                    self.note(value);
                    self.pending_target = value & (JUMPOUT | CALL) != 0;
                }
            }
            return;
        }
        if self.count == 0 {
            self.first_branch =
                opc == OpCode::CPUI_BRANCH && vars.first().is_some_and(|v| space_is(v, spacetype::IPTR_PROCESSOR));
        }
        self.count += 1;
        self.return_op |= opc == OpCode::CPUI_RETURN;
        if let Some(lr) = &self.lr {
            if opc == OpCode::CPUI_BRANCHIND
                && vars.len() == 1
                && vars[0].offset == lr.offset
                && vars[0].size == lr.size
                && match (&vars[0].space, &lr.space) {
                    (Some(a), Some(b)) => Rc::ptr_eq(a, b),
                    (None, None) => true,
                    _ => false,
                }
            {
                self.lr_branch = true;
            }
        }
        if self.capture {
            let vn = |data: &VarnodeData| Vn {
                space: data.space.as_ref().map_or(-1, |space| space.get_index()),
                offset: data.offset,
                size: data.size as i32,
            };
            let ins = self.pool.len() as u32;
            self.pool.extend(vars.iter().map(vn));
            self.ops.push(RawOp { code: opc, out: outvar.map(vn), ins, nin: vars.len() as u32, raw_index });
        }
        if self.pending_target && matches!(opc, OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_CALL) {
            self.pending_target = false;
            // A dynamic target arrives through a `unique` temporary.
            if let Some(target) = vars.first() {
                if let Some(space) = target.space.as_ref().filter(|space| space.get_type() == spacetype::IPTR_PROCESSOR) {
                    self.targets.push((space.get_index(), target.offset));
                }
            }
        }
    }
}

/// `InstructionFlow::type`'s cases: flags, then kind, fallthrough,
/// terminal, conditional.
const FLOW_TYPES: &[(u32, (FlowKind, bool, bool, bool))] = {
    const NF: u32 = NO_FALLTHRU;
    const BE: u32 = BRANCH_TO_END;
    const BI: u32 = BRANCH_INDIRECT;
    const CI: u32 = CALL_INDIRECT;
    &[
        (0, (FlowKind::Fallthrough, true, false, false)),
        (BE, (FlowKind::Fallthrough, true, false, false)),
        (NF | BE, (FlowKind::Fallthrough, true, false, false)),
        (CALL, (FlowKind::Call, true, false, false)),
        (CALL | NF | BE | RETURN, (FlowKind::Call, true, false, false)),
        (CALL | NF | RETURN, (FlowKind::Call, false, true, false)),
        (CI | NF | RETURN, (FlowKind::CallInd, false, true, false)),
        (CALL | BE, (FlowKind::Call, true, false, true)),
        (CALL | NF | JUMPOUT, (FlowKind::BranchInd, false, false, false)),
        (BI | NF, (FlowKind::BranchInd, false, false, false)),
        (JUMPOUT | NF | BI, (FlowKind::BranchInd, false, false, false)),
        (CI, (FlowKind::CallInd, true, false, false)),
        (BI | BE, (FlowKind::BranchInd, true, false, true)),
        (BI | NF | BE, (FlowKind::BranchInd, true, false, true)),
        (BI | JUMPOUT | NF | BE, (FlowKind::BranchInd, true, false, true)),
        (CI | BE, (FlowKind::CallInd, true, false, true)),
        (CI | NF | BE, (FlowKind::CallInd, true, false, true)),
        (RETURN | NF, (FlowKind::Return, false, true, false)),
        (NF, (FlowKind::Return, false, true, false)),
        (RETURN | BE, (FlowKind::Return, true, true, true)),
        (RETURN | NF | BE, (FlowKind::Return, true, true, true)),
        (JUMPOUT, (FlowKind::CBranch, true, false, true)),
        (JUMPOUT | NF | BE, (FlowKind::CBranch, true, false, true)),
        (BE | JUMPOUT, (FlowKind::CBranch, true, false, true)),
        (JUMPOUT | NF, (FlowKind::Branch, false, false, false)),
        (JUMPOUT | NF | RETURN, (FlowKind::Branch, false, true, false)),
        (BI | NF | RETURN, (FlowKind::BranchInd, false, true, false)),
    ]
};

/// `InstructionFlow::type`: kind, fallthrough, terminal, conditional.
fn flow_type(flags: u32) -> (FlowKind, bool, bool, bool) {
    let mut value = flags;
    if value & LABEL != 0 {
        value |= BRANCH_TO_END;
    }
    value &= !LABEL;
    FLOW_TYPES
        .iter()
        .find(|(case, _)| *case == value)
        .map_or((FlowKind::Bad, false, false, false), |&(_, flow)| flow)
}

/// The answer the console gave an address it could not decode.
fn failed(address: u64, kind: FlowKind) -> FlowResult {
    FlowResult {
        address,
        length: 1,
        fallthrough: None,
        targets: Vec::new(),
        kind,
        pure_jump: false,
        no_op: false,
        terminal: false,
        conditional: false,
        return_op: false,
        delay_slots: Vec::new(),
        mode: None,
        target_modes: Vec::new(),
    }
}

/// A SLEIGH flow decoder over one loaded image, with its own context state:
/// what one console answered to `flow` and `context`.
pub struct SleighFlow {
    /// Declared before `lifter`: it holds a reference count into the
    /// lifter's spaces (`FlowEmit::lr`), which must be gone before a pooled
    /// lifter goes back to the pool and another thread.
    emit: FlowEmit,
    lifter: SleighLifter,
    /// The language has a `LowBitCodeMode` context field.
    mode_field: bool,
    delay_slots: bool,
}

// SAFETY: as for `SleighLifter`: the one `Rc` outside the lifter, the `LR`
// varnode's space, is a clone out of the lifter's own space manager, and the
// decoder is not `Sync`.
unsafe impl Send for SleighFlow {}

impl SleighFlow {
    /// The decoder for a mapped image, with the image's own contexts set.
    pub fn mapped(cfg: &RuntimeConfig, import: &NativeImport) -> Result<Self> {
        let mut lifter = SleighLifter::mapped(cfg, import)?;
        instrument(&mut lifter)?;
        Self::over(lifter)
    }

    /// `mapped` over a pooled lifter (`SleighLifter::mapped_pooled`): the
    /// translator is marked once, and goes back to the pool marked.
    pub fn mapped_pooled(cfg: &RuntimeConfig, import: &NativeImport) -> Result<Self> {
        let mut lifter = SleighLifter::acquire(cfg, import)?;
        if lifter.sleigh.base().has_marked_template_transform() {
            lifter.sleigh.base().set_marked_templates(true);
        } else {
            instrument(&mut lifter)?;
        }
        Self::over(lifter)
    }

    fn over(lifter: SleighLifter) -> Result<Self> {
        let mode_field = lifter
            .sleigh
            .with_context_db_mut(|db| db.get_variable(b"LowBitCodeMode").is_ok());
        let delay_bytes = lifter.sleigh.base().max_delay_slot_bytes();
        let delay_slots = delay_bytes > 0;
        let emit = FlowEmit { lr: lifter.powerpc_lr.clone(), ..FlowEmit::default() };
        Ok(Self { lifter, emit, mode_field, delay_slots })
    }

    /// The console's `context <name> <address> <value>`.
    pub fn set_contexts(&mut self, contexts: &[NativeContext]) -> Result<()> {
        self.lifter.set_contexts(contexts)
    }

    /// A copy of the decoder's context database as it is now.
    pub fn clone_context_db(&self) -> Box<dyn kuna_sleigh::globalcontext::ContextDatabase> {
        self.lifter.sleigh.with_context_db_mut(|db| db.clone_for_speculation())
    }

    /// Exchanges the decoder's context database for `db` and returns the one
    /// it held: one decoder serving several lanes in turn, each with the modes
    /// its own decodes committed (`Sleigh::swap_context_db`).
    pub fn swap_context_db(
        &mut self,
        db: Box<dyn kuna_sleigh::globalcontext::ContextDatabase>,
    ) -> Box<dyn kuna_sleigh::globalcontext::ContextDatabase> {
        self.lifter.sleigh.swap_context_db(db)
    }

    /// The p-code of a compiler spec call fixup as the call at `base` makes
    /// it (`InjectPayloadSleigh::inject`); `inst_dest` is `entry` and
    /// `inst_next` is `base`, as `injectSubFunction` sets them.
    pub(super) fn inject(
        &mut self,
        template: &kuna_sleigh::semantics::ConstructTpl,
        base: u64,
        entry: u64,
        out: &mut RawInsn,
    ) -> std::result::Result<(), KunaError> {
        let at = self.lifter.address(base);
        let call = self.lifter.address(entry);
        self.emit.reset();
        self.emit.capture = true;
        let result = self.lifter.sleigh.inject_pcode(template, &at, &at, &call, &mut self.emit);
        self.emit.capture = false;
        result?;
        std::mem::swap(&mut self.emit.ops, &mut out.ops);
        std::mem::swap(&mut self.emit.pool, &mut out.pool);
        out.length = 0;
        Ok(())
    }

    /// The lifter this decoder decodes with: its translator answers the
    /// operand and mnemonic questions the propagation asks about an address.
    pub(crate) fn lifter_mut(&mut self) -> &mut SleighLifter {
        &mut self.lifter
    }

    /// Whether decodes read the language's own templates (a plain lifter's)
    /// or the marked ones (a flow decoder's).
    pub(crate) fn set_plain_templates(&mut self, plain: bool) {
        self.lifter.sleigh.base().set_marked_templates(!plain);
    }

    pub(super) fn lifter(&self) -> &SleighLifter {
        &self.lifter
    }

    /// Decodes one instruction for the reference propagation: the p-code the
    /// console's `oneInstruction` emitted, relative branches renumbered over
    /// the ops without the flow markers, and the `oneInstructionFlow`
    /// classification. Commits the instruction's context changes, as the
    /// console did.
    pub(super) fn decode(&mut self, address: u64, out: &mut RawInsn) -> std::result::Result<(), FlowKind> {
        let at = self.lifter.address(address);
        self.emit.reset();
        self.emit.capture = true;
        let decoded = if self.lifter.exhausts_parser_states(&at) {
            Err(KunaError::bad_data("Parser state exhausted"))
        } else {
            self.lifter.sleigh.one_instruction(&mut self.emit, &at)
        };
        self.emit.capture = false;
        let length = match decoded {
            Ok(length) => length,
            Err(KunaError::Unimpl { .. }) => return Err(FlowKind::Unimpl),
            Err(_) => return Err(FlowKind::Bad),
        };
        let emit = &mut self.emit;
        if emit.lr_branch && length == 4 && self.lifter.conditional_lr_return(&at) {
            emit.flags = (emit.flags & !BRANCH_INDIRECT) | RETURN;
            if let Some(lr) = &emit.lr {
                let lr_space = lr.space.as_ref().map_or(-1, |space| space.get_index());
                for op in &mut emit.ops {
                    let input = emit.pool[op.ins as usize];
                    if op.code == OpCode::CPUI_BRANCHIND
                        && op.nin == 1
                        && input.space == lr_space
                        && input.offset == lr.offset
                        && input.size == lr.size as i32
                    {
                        op.code = OpCode::CPUI_RETURN;
                    }
                }
            }
        }
        let (kind, fallthrough, terminal, conditional) = flow_type(emit.flags);
        // The markers shifted every relative branch by the markers it spans.
        let const_space = self.lifter.sleigh.base().manager().get_constant_space().map_or(-1, |space| space.get_index());
        let total = emit.ops.len() as i64;
        for (index, op) in emit.ops.iter().enumerate() {
            if !matches!(op.code, OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH) || op.nin == 0 {
                continue;
            }
            let slot = op.ins as usize;
            if emit.pool[slot].space != const_space {
                continue;
            }
            let relative = i64::from(emit.pool[slot].offset as u32 as i32);
            let target = i64::from(op.raw_index) + relative;
            let clean = if target < 0 || target > i64::from(emit.dumped) {
                total + 1000
            } else if (target as usize) < emit.clean_at.len() {
                i64::from(emit.clean_at[target as usize])
            } else {
                total
            };
            let size = emit.pool[slot].size;
            let mask = if size >= 8 { !0 } else { (1u64 << (size * 8)) - 1 };
            emit.pool[slot].offset = ((clean - index as i64) as u64) & mask;
        }
        std::mem::swap(&mut emit.ops, &mut out.ops);
        std::mem::swap(&mut emit.pool, &mut out.pool);
        out.length = length;
        out.kind = Some(kind);
        out.fallthrough = fallthrough;
        out.terminal = terminal;
        out.targets.clear();
        out.targets.extend(emit.targets.iter().map(|&(_, target)| target));
        out.branchind = out.ops.iter().any(|op| op.code == OpCode::CPUI_BRANCHIND);
        out.conditional = conditional;
        Ok(())
    }

    /// The instruction set this console holds at `address`, whether or not
    /// anything decodes there: `flow`'s `mode` is only set for an address that
    /// decodes, and a misaligned or undecodable one still carries a value a
    /// mode painted over it must be handed back.
    pub fn mode_at(&mut self, address: u64) -> Option<u64> {
        if !self.mode_field {
            return None;
        }
        let at = self.lifter.address(address);
        self.lifter
            .sleigh
            .with_context_db_mut(|db| db.get_variable_value(b"LowBitCodeMode", &at).ok().map(u64::from))
    }

    /// Whether a mode value starts at `address`: a context change point the
    /// console was given or a `blx` committed, as against an address that only
    /// sits in a region painted from some earlier point. `None` for a language
    /// without a mode field.
    pub fn mode_starts_at(&mut self, address: u64) -> Option<bool> {
        if !self.mode_field {
            return None;
        }
        let at = self.lifter.address(address);
        let offset = at.get_offset();
        self.lifter.sleigh.with_context_db_mut(|db| {
            let (_, first, _) = db.get_context_bounds(&at);
            Some(first == offset)
        })
    }

    /// The console's `flow` answer for each address, in order. Each decode
    /// commits its context changes before the next.
    pub fn flow(&mut self, addresses: &[u64]) -> Vec<FlowResult> {
        addresses.iter().map(|&address| self.one(address)).collect()
    }

    fn one(&mut self, address: u64) -> FlowResult {
        let at = self.lifter.address(address);
        let offset = at.get_offset();
        self.emit.reset();
        let decoded = if self.lifter.exhausts_parser_states(&at) {
            Err(KunaError::bad_data("Parser state exhausted"))
        } else {
            self.lifter.sleigh.one_instruction(&mut self.emit, &at)
        };
        let length = match decoded {
            Ok(length) => length,
            Err(KunaError::Unimpl { .. }) => return failed(offset, FlowKind::Unimpl),
            Err(_) => return failed(offset, FlowKind::Bad),
        };
        let emit = &mut self.emit;
        if emit.lr_branch && length == 4 && self.lifter.conditional_lr_return(&at) {
            emit.flags = (emit.flags & !BRANCH_INDIRECT) | RETURN;
            emit.return_op = true;
        }
        let (kind, fallthrough, terminal, conditional) = flow_type(emit.flags);
        let code_space = &self.lifter.code_space;
        let mut delay_slots = Vec::new();
        if self.delay_slots {
            // `translateInstruction` names each delay-slot instruction it
            // decoded past the instruction itself.
            if let Ok(own) = self.lifter.sleigh.instruction_length(&at) {
                let mut fall = own;
                while fall < length {
                    let next = Address::new(Rc::clone(code_space), code_space.wrap_offset(offset.wrapping_add(fall as u64)));
                    let Ok(slot) = self.lifter.sleigh.instruction_length(&next) else { break };
                    if slot <= 0 {
                        break;
                    }
                    delay_slots.push(u8::try_from(slot).unwrap_or(u8::MAX));
                    fall += slot;
                }
            }
        }
        let mut result = FlowResult {
            address: offset,
            length: u8::try_from(length).unwrap_or(1),
            fallthrough: fallthrough.then(|| code_space.wrap_offset(offset.wrapping_add(length as u64))),
            targets: emit.targets.iter().map(|&(_, target)| target).collect(),
            kind,
            pure_jump: emit.count == 1 && emit.first_branch,
            no_op: emit.count == 0,
            terminal,
            conditional,
            return_op: emit.return_op,
            delay_slots,
            mode: None,
            target_modes: Vec::new(),
        };
        if self.mode_field {
            // The instruction set this address decoded in, and the one that
            // flows to each same-space target: a change point there (a
            // `blx` commit) wins, otherwise the decoded mode flows and is
            // named only where the held value differs.
            let space = code_space.get_index();
            let targets = &emit.targets;
            self.lifter.sleigh.with_context_db_mut(|db| {
                let Ok(mode) = db.get_variable_value(b"LowBitCodeMode", &at) else {
                    return;
                };
                result.mode = Some(u64::from(mode));
                for &(target_space, target) in targets {
                    if target_space != space {
                        continue;
                    }
                    let target_at = Address::new(Rc::clone(code_space), target);
                    let (_, first, _) = db.get_context_bounds(&target_at);
                    let Ok(held) = db.get_variable_value(b"LowBitCodeMode", &target_at) else {
                        continue;
                    };
                    let change_point = first == target;
                    if !change_point && held == mode {
                        continue;
                    }
                    result.target_modes.push((target, u64::from(if change_point { held } else { mode })));
                }
            });
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::SleighFlow;
    use crate::native::{Mapping, NativeImport};
    use crate::native_runtime::FlowKind;
    use crate::session::RuntimeConfig;

    /// A flow decoder over `words` at 0x1000, or `None` without a Ghidra install.
    fn decoder(language: &str, words: &[(u64, u32)], big_endian: bool) -> Option<SleighFlow> {
        let mut cfg = RuntimeConfig::from_env();
        if !cfg.ghidra_install.join("Ghidra").is_dir() {
            eprintln!("SKIP: no Ghidra install");
            return None;
        }
        cfg.adopt_language(language);
        let end = words.iter().map(|&(address, _)| address + 4).max().unwrap_or(0x1000);
        let mut bytes = vec![0u8; (end - 0x1000) as usize];
        for &(address, word) in words {
            let at = (address - 0x1000) as usize;
            let word = if big_endian { word.to_be_bytes() } else { word.to_le_bytes() };
            bytes[at..at + 4].copy_from_slice(&word);
        }
        let import = NativeImport {
            language: language.into(),
            mappings: vec![Mapping { vaddr: 0x1000, size: bytes.len() as u64, file_off: 0, flags: 6, bytes }],
            ..Default::default()
        };
        Some(SleighFlow::mapped(&cfg, &import).unwrap())
    }

    /// A flow decoder that went back to the pool answers the next image as a
    /// freshly built one does: `blx` made 0x2000 Thumb in the first image and
    /// the second image's 0x2000 is ARM.
    #[test]
    fn a_pooled_flow_decoder_starts_over_with_the_new_image() {
        let words = |blx: bool| {
            [(0x1004u64, if blx { 0xfa00_03fdu32 } else { 0xe1a0_0000 }), (0x2000, 0xe3a0_0001)]
        };
        let language = "ARM:LE:32:v5t";
        let mut cfg = RuntimeConfig::from_env();
        if !cfg.ghidra_install.join("Ghidra").is_dir() {
            eprintln!("SKIP: no Ghidra install");
            return;
        }
        cfg.adopt_language(language);
        let import = |blx: bool| {
            let mut bytes = vec![0u8; 0x1004];
            for (address, word) in words(blx) {
                let at = (address - 0x1000) as usize;
                bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
            }
            NativeImport {
                language: language.into(),
                mappings: vec![Mapping { vaddr: 0x1000, size: 0x1004, file_off: 0, flags: 6, bytes }],
                ..Default::default()
            }
        };
        let mut used = SleighFlow::mapped_pooled(&cfg, &import(true)).unwrap();
        used.flow(&[0x1004]);
        assert_eq!(used.flow(&[0x2000])[0].length, 2, "blx committed Thumb at its target");
        drop(used);
        let second = import(false);
        let mut reused = SleighFlow::mapped_pooled(&cfg, &second).unwrap();
        let mut fresh = SleighFlow::mapped(&cfg, &second).unwrap();
        let (reused, fresh) = (reused.flow(&[0x2000, 0x1004]), fresh.flow(&[0x2000, 0x1004]));
        for (reused, fresh) in reused.iter().zip(&fresh) {
            assert_eq!(
                (reused.length, reused.kind, reused.mode, &reused.targets, reused.fallthrough),
                (fresh.length, fresh.kind, fresh.mode, &fresh.targets, fresh.fallthrough)
            );
        }
        assert_eq!(reused[0].length, 4);
    }

    /// `beq` to the next instruction is a conditional branch with a target;
    /// a conditionally executed `addeq` skips to `inst_next` and only falls
    /// through. Resolved p-code alone cannot tell the two apart.
    #[test]
    fn inst_next_skips_are_not_branch_targets() {
        let Some(mut flow) = decoder(
            "ARM:LE:32:v5t",
            &[(0x1000, 0x0aff_ffff), (0x1004, 0x0280_0001), (0x1008, 0xeaff_fffe)], // beq 0x1004; addeq r0,r0,#1; b .
            false,
        ) else {
            return;
        };
        let flows = flow.flow(&[0x1000, 0x1004, 0x1008]);
        assert_eq!((flows[0].kind, flows[0].targets.as_slice()), (FlowKind::CBranch, &[0x1004][..]));
        assert_eq!(flows[0].fallthrough, Some(0x1004));
        assert_eq!((flows[1].kind, flows[1].targets.len()), (FlowKind::Fallthrough, 0));
        assert_eq!((flows[2].kind, flows[2].targets.as_slice()), (FlowKind::Branch, &[0x1008][..]));
        assert!(flows[2].pure_jump && flows[2].fallthrough.is_none());
        assert_eq!(flows[0].mode, Some(0));
    }

    /// `flow` names the mode only for an address that decodes; `mode_at`
    /// answers for one that does not too, and follows a context painted over it
    /// and handed back.
    #[test]
    fn mode_at_names_the_mode_of_an_address_nothing_decodes_at() {
        use crate::native::NativeContext;
        let Some(mut flow) = decoder(
            "ARM:LE:32:v5t",
            &[(0x1000, 0xffff_0000), (0x1004, 0xffff_ffff), (0x1008, 0xe12f_ff1e)],
            false,
        ) else {
            return;
        };
        let answer = flow.flow(&[0x1002]);
        assert_eq!(answer[0].kind, FlowKind::Bad, "a half of an unallocated ARM word");
        assert_eq!(answer[0].mode, None);
        assert_eq!(flow.mode_at(0x1002), Some(0));
        let paint = |value| NativeContext { name: "TMode".into(), address: 0x1002, value };
        flow.set_contexts(&[paint(1)]).unwrap();
        assert_eq!(flow.mode_at(0x1002), Some(1));
        assert_eq!(flow.mode_at(0x1008), Some(1), "painted until the next change point");
        flow.set_contexts(&[paint(0)]).unwrap();
        assert_eq!(flow.mode_at(0x1002), Some(0));
        assert_eq!(flow.mode_at(0x1008), Some(0));
    }

    /// A `blx` commits Thumb at its target and names it there; the next
    /// decode of that target is Thumb.
    #[test]
    fn blx_commit_names_and_applies_the_target_mode() {
        let Some(mut flow) = decoder(
            "ARM:LE:32:v5t",
            &[(0x1004, 0xfa00_03fd), (0x2000, 0xe3a0_0001)], // blx 0x2000; mov r0,#1
            false,
        ) else {
            return;
        };
        let blx = &flow.flow(&[0x1004])[0];
        assert_eq!((blx.kind, blx.targets.as_slice()), (FlowKind::Call, &[0x2000][..]));
        assert_eq!(blx.target_modes, vec![(0x2000, 1)]);
        assert_eq!(flow.flow(&[0x2000])[0].length, 2);
    }

    /// MIPS branches name their delay slot; the length covers it.
    #[test]
    fn delay_slots_are_named() {
        let Some(mut flow) = decoder(
            "MIPS:BE:32:default",
            &[(0x1000, 0x1000_0003), (0x1004, 0x0000_0000), (0x1008, 0x03e0_0008), (0x100c, 0x0000_0000)], // b +0x10; nop; jr ra; nop
            true,
        ) else {
            return;
        };
        let flows = flow.flow(&[0x1000, 0x1008]);
        assert_eq!((flows[0].length, flows[0].delay_slots.as_slice()), (8, &[4u8][..]));
        assert_eq!((flows[0].kind, flows[0].targets.as_slice()), (FlowKind::Branch, &[0x1010][..]));
        assert_eq!(flows[1].kind, FlowKind::Return);
        assert!(flows[1].return_op);
    }

    /// `oneInstruction` refuses an unaligned address (`UNIMPL`) before it
    /// parses, so bytes there that would exhaust the parser states are never
    /// read: `vpush {d4..}` one byte past an ARM word.
    #[test]
    fn unaligned_is_unimplemented_before_the_parser_limit() {
        let mut cfg = RuntimeConfig::from_env();
        if !cfg.ghidra_install.join("Ghidra").is_dir() {
            eprintln!("SKIP: no Ghidra install");
            return;
        }
        cfg.adopt_language("ARM:LE:32:v8");
        let mut bytes = vec![0u8; 12];
        bytes[1..5].copy_from_slice(&0xed2d_4bf0u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&0xed2d_4bf0u32.to_le_bytes());
        let import = NativeImport {
            language: "ARM:LE:32:v8".into(),
            mappings: vec![Mapping { vaddr: 0x1000, size: 12, file_off: 0, flags: 6, bytes }],
            ..Default::default()
        };
        let flows = SleighFlow::mapped(&cfg, &import).unwrap().flow(&[0x1001, 0x1008]);
        assert_eq!((flows[0].kind, flows[1].kind), (FlowKind::Unimpl, FlowKind::Bad));
    }

    /// `lmw r1,0(r3)` walks ~31 constructors deep: past Kuna's upstream
    /// bound of 32, inside Ghidra's 64 that the vendored copy and the
    /// patched console share.
    #[test]
    fn deep_register_lists_decode_within_ghidras_depth() {
        let Some(mut flow) = decoder("PowerPC:BE:32:default", &[(0x1000, 0xb823_0000), (0x1004, 0xbc23_0000)], true) else {
            return;
        };
        let flows = flow.flow(&[0x1000, 0x1004]);
        assert_eq!((flows[0].kind, flows[0].length), (FlowKind::Fallthrough, 4));
        assert_eq!((flows[1].kind, flows[1].length), (FlowKind::Fallthrough, 4));
    }
}
