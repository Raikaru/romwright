//! Raw p-code flow and basic blocks of one function range.
//!
//! This is `Funcdata::followFlow` of the pinned decompiler (`flow.cc`
//! `FlowInfo::generateOps`, `generateBlocks`; Ghidra 12.1.3, Apache-2.0) over
//! the in-process SLEIGH decoder: instructions are followed from the entry
//! within the bounds, relative branches are resolved to ops, calls get call
//! sites, an indirect jump gets the table the import stored for it or the one
//! `jump.rs` recovers from the traced flow (and otherwise becomes a return or
//! a call), a call to an address already inside the traced flow becomes a
//! branch, and the ops are split into basic blocks with the edges
//! `collectEdges` makes. The decompiler recovers jump tables with its full
//! simplification pipeline; here the table is the value-set pass's, checked
//! again over the flow it opened.
use super::super::flow::{RawInsn, Vn};
use super::super::lift::opcode_name;
use super::super::FlowKind;
use super::jump::{self, Refusal};
use super::lang::Lang;
use super::JumpShape;
use crate::native::FlowShape;
use crate::native_runtime::{PcodeInstruction, PcodeOp, PcodeVarnode};
use kuna_num::opcodes::OpCode;
use std::cell::OnceCell;
use std::collections::BTreeMap;

pub(super) const NONE: u32 = u32::MAX;

/// Why a range has no usable flow.
#[derive(Debug)]
pub(super) enum Failure {
    /// `Propagation::run`'s refusal: the flow met bytes SLEIGH cannot decode.
    Undecodable,
    /// A `LowlevelError` the console would have raised.
    Error(String),
}

pub(super) struct Op {
    pub code: OpCode,
    /// The address of the instruction this op belongs to.
    pub addr: u64,
    pub time: u32,
    pub out: Option<Vn>,
    pub ins: u32,
    pub nin: u32,
    /// The call site of a CALL or CALLIND.
    pub call: u32,
    /// The decoded instruction this op came from.
    pub insn: u32,
    pub start_block: bool,
    pub start_insn: bool,
    pub dead: bool,
}

/// What the flow knows of one decoded instruction.
pub(super) struct InsnInfo {
    pub kind: FlowKind,
    pub fallthrough: bool,
    pub terminal: bool,
    pub targets: Vec<u64>,
    /// The instruction's own p-code holds a `BRANCHIND`.
    pub branchind: bool,
    /// The instruction only sometimes transfers.
    pub conditional: bool,
}

pub(super) struct CallSpec {
    pub op: u32,
    /// The address of a direct call; `None` for an indirect one.
    pub entry: Option<u64>,
    /// A function symbol exists at the target (`FuncCallSpecs::getFuncdata`).
    pub has_function: bool,
}

pub(super) struct Block {
    pub ops: Vec<u32>,
    pub outs: Vec<u32>,
}

#[derive(Clone, Copy)]
struct Visit {
    size: u64,
    /// The first op of the instruction; `NONE` if it made none.
    first: u32,
    /// The instruction's `InsnInfo`; `NONE` for a stub the flow made.
    insn: u32,
    /// How many ops the decoder made for it.
    ops: u32,
    /// The first op the decoder made (`first` moves when a call fixup
    /// replaces it); the decoder's ops of one instruction are consecutive.
    origin: u32,
}

/// What the flow reads about the image around the function.
pub(super) trait Environment {
    /// Decodes the instruction at `address`.
    fn decode(&mut self, address: u64, out: &mut RawInsn) -> Result<(), FlowKind>;
    /// A function symbol at `address`: the entry itself, or a start a call
    /// fixup was installed on.
    fn function_at(&self, address: u64) -> bool;
    /// A call fixup of the compiler spec was installed on the function.
    fn has_fixup(&self, address: u64) -> bool;
    /// The p-code of the call fixup of the function at `entry`, as the call
    /// instruction at `base` would make it.
    fn inject(&mut self, entry: u64, base: u64, out: &mut RawInsn) -> Result<(), String>;
    /// The call-other fixup that replaces the user op with this index.
    fn userop_fixup(&self, userop: u64) -> Option<usize>;
    /// The p-code of that fixup, as the instruction at `base` would make it.
    fn inject_userop(&mut self, fixup: usize, base: u64, out: &mut RawInsn) -> Result<(), String>;
    /// The targets of the dispatch the import stored for the branch.
    fn stored_table(&self, branch: u64) -> Option<&[u64]>;
    /// The assembly text at `address` (tracing).
    fn assembly(&self, address: u64) -> String;
    /// The bytes the image backs at `[address, address + size)`, as one
    /// integer in the language's byte order; `None` where it backs none.
    fn read_image(&self, address: u64, size: u32) -> Option<u64>;
    /// `address` lies in a mapping that can be executed.
    fn executable(&self, address: u64) -> bool;
}

pub(super) struct Graph {
    pub ops: Vec<Op>,
    pub pool: Vec<Vn>,
    pub insns: Vec<InsnInfo>,
    pub calls: Vec<CallSpec>,
    /// The indirect jumps flow recovery turned into calls, with the shape of
    /// the computation that makes their target.
    pub truncated: Vec<(u64, JumpShape)>,
    /// The indirect jumps whose table the flow recovered itself.
    pub recovered: Vec<(u64, JumpShape, Vec<u64>)>,
    /// The indirect jumps the flow asked the recovery about and was refused.
    pub refused: Vec<(u64, JumpShape, Refusal)>,
    pub blocks: Vec<Block>,
    next: Vec<u32>,
    prev: Vec<u32>,
    head: u32,
    tail: u32,
    uniq: u32,
}

/// `FlowInfo`'s working state.
struct Flow<'a, E: Environment> {
    graph: Graph,
    lang: &'a Lang,
    env: &'a mut E,
    /// The range's bounds: `eaddr` is the inclusive last address.
    baddr: u64,
    eaddr: u64,
    visited: BTreeMap<u64, Visit>,
    addrlist: Vec<u64>,
    unprocessed: Vec<u64>,
    tablelist: Vec<u32>,
    tables: Vec<(u32, Vec<u64>)>,
    /// The tables of `tables` the flow recovered itself, as `(op, shape)`.
    recoveries: Vec<(u32, JumpShape)>,
    /// Branches the recovery must not answer: its answer did not hold once
    /// the flow it opened was traced.
    blocked: &'a [u64],
    /// Recover the table of an indirect jump no table is stored for.
    recover: bool,
    insn_count: u32,
    insn_max: u32,
    scratch: RawInsn,
    block_edges: Vec<(u32, u32)>,
    /// The live call sites, in the order they were made (`qlst`).
    qlst: Vec<u32>,
    /// Calls to replace with their fixup p-code.
    injectlist: Vec<u32>,
}

/// `PcodeOp::getEvalType` of the ops `earlyJumpTableFail` classifies.
#[derive(PartialEq, Eq)]
enum Eval {
    Special,
    Unary,
    Binary,
    Other,
}

fn eval_type(code: OpCode) -> Eval {
    use OpCode::*;
    match code {
        CPUI_LOAD | CPUI_STORE | CPUI_BRANCH | CPUI_CBRANCH | CPUI_BRANCHIND | CPUI_CALL | CPUI_CALLIND
        | CPUI_CALLOTHER | CPUI_RETURN | CPUI_MULTIEQUAL | CPUI_INDIRECT | CPUI_SEGMENTOP | CPUI_CPOOLREF
        | CPUI_NEW => Eval::Special,
        CPUI_COPY | CPUI_INT_ZEXT | CPUI_INT_SEXT | CPUI_INT_2COMP | CPUI_INT_NEGATE | CPUI_BOOL_NEGATE
        | CPUI_FLOAT_NAN | CPUI_FLOAT_NEG | CPUI_FLOAT_ABS | CPUI_FLOAT_SQRT | CPUI_FLOAT_INT2FLOAT
        | CPUI_FLOAT_FLOAT2FLOAT | CPUI_FLOAT_TRUNC | CPUI_FLOAT_CEIL | CPUI_FLOAT_FLOOR | CPUI_FLOAT_ROUND
        | CPUI_POPCOUNT | CPUI_LZCOUNT => Eval::Unary,
        CPUI_CAST | CPUI_PTRADD | CPUI_INSERT | CPUI_ZPULL | CPUI_SPULL => Eval::Other,
        _ => Eval::Binary,
    }
}

/// What the flow concludes about a `BRANCHIND`.
enum IndirectJump {
    /// The dispatch table the import stored.
    Table(Vec<u64>),
    /// The dispatch table the flow recovered itself, and the shape of the
    /// computation it came from.
    Recovered(Vec<u64>, JumpShape),
    /// The target is the return address: `fail_return`.
    Return,
    /// Anything else: the jump is treated as a call. The recovery's refusal,
    /// when it was asked.
    Call(Option<Refusal>),
}

impl<'a, E: Environment> Flow<'a, E> {
    fn op_inputs(&self, op: u32) -> &[Vn] {
        let op = &self.graph.ops[op as usize];
        &self.graph.pool[op.ins as usize..(op.ins + op.nin) as usize]
    }

    fn new_op(&mut self, code: OpCode, addr: u64, out: Option<Vn>, ins: &[Vn], insn: u32) -> u32 {
        let id = self.graph.ops.len() as u32;
        let start = self.graph.pool.len() as u32;
        self.graph.pool.extend_from_slice(ins);
        self.graph.ops.push(Op {
            code,
            addr,
            time: self.graph.uniq,
            out,
            ins: start,
            nin: ins.len() as u32,
            call: NONE,
            insn,
            start_block: false,
            start_insn: false,
            dead: false,
        });
        self.graph.uniq += 1;
        self.graph.next.push(NONE);
        self.graph.prev.push(self.graph.tail);
        if self.graph.tail == NONE {
            self.graph.head = id;
        } else {
            self.graph.next[self.graph.tail as usize] = id;
        }
        self.graph.tail = id;
        id
    }

    /// `Funcdata::opDeadInsertAfter`.
    fn insert_after(&mut self, after: u32, op: u32) {
        let g = &mut self.graph;
        // `op` was appended at the tail; unlink it and place it after `after`.
        debug_assert_eq!(g.tail, op);
        let before = g.prev[op as usize];
        g.tail = before;
        if before == NONE {
            g.head = NONE;
        } else {
            g.next[before as usize] = NONE;
        }
        let following = g.next[after as usize];
        g.next[after as usize] = op;
        g.prev[op as usize] = after;
        g.next[op as usize] = following;
        if following == NONE {
            g.tail = op;
        } else {
            g.prev[following as usize] = op;
        }
    }

    /// `Funcdata::opDestroyRaw`: the op leaves the list.
    fn destroy(&mut self, op: u32) {
        let g = &mut self.graph;
        let (before, after) = (g.prev[op as usize], g.next[op as usize]);
        if before == NONE {
            g.head = after;
        } else {
            g.next[before as usize] = after;
        }
        if after == NONE {
            g.tail = before;
        } else {
            g.prev[after as usize] = before;
        }
        g.ops[op as usize].dead = true;
    }

    fn artificial_halt(&mut self, addr: u64, insn: u32) -> u32 {
        let one = Vn { space: self.lang.constant_space, offset: 1, size: 4 };
        self.new_op(OpCode::CPUI_RETURN, addr, None, &[one], insn)
    }

    /// The target of a branch's first input when it is an address, `None`
    /// when it is a relative (constant-space) offset.
    fn code_address(&self, op: u32) -> Result<Option<u64>, Failure> {
        let input = self.op_inputs(op).first().copied().ok_or_else(|| Failure::Error("branch without a target".into()))?;
        Ok((input.space != self.lang.constant_space).then_some(input.offset))
    }

    /// `FlowInfo::target`.
    fn target(&self, address: u64) -> Result<u32, Failure> {
        let mut at = address;
        while let Some(visit) = self.visited.get(&at) {
            if visit.first != NONE {
                if !self.graph.ops[visit.first as usize].dead {
                    return Ok(visit.first);
                }
                break;
            }
            // An instruction without ops: its fall-through address stands in.
            at += visit.size;
        }
        Err(Failure::Error(format!("Could not find op at target address: {address:#x}")))
    }

    /// `FlowInfo::findRelTarget`: the target op of a relative branch, or the
    /// fall-through address when it branches to the end of the instruction.
    fn find_relative(&self, op: u32) -> Result<Result<u32, u64>, Failure> {
        let this = &self.graph.ops[op as usize];
        let relative = self.op_inputs(op)[0].offset as u32;
        let id = this.time.wrapping_add(relative);
        let same_instruction = |time: u32| -> Option<u32> {
            // Ops of one instruction have consecutive times.
            let base = op as i64 - (this.time as i64 - time as i64);
            if base < 0 || base as usize >= self.graph.ops.len() {
                return None;
            }
            let found = &self.graph.ops[base as usize];
            (found.addr == this.addr && found.time == time && !found.dead).then_some(base as u32)
        };
        if let Some(found) = same_instruction(id) {
            return Ok(Ok(found));
        }
        if let Some(before) = same_instruction(id.wrapping_sub(1)) {
            let at = self.graph.ops[before as usize].addr;
            if let Some((start, visit)) = self.visited.range(..=at).next_back() {
                let result = start + visit.size;
                if this.addr < result {
                    return Ok(Err(result));
                }
            }
        }
        Err(Failure::Error(format!("Bad relative branch at instruction : {:#x}", this.addr)))
    }

    /// `FlowInfo::branchTarget`.
    fn branch_target(&self, op: u32) -> Result<u32, Failure> {
        match self.code_address(op)? {
            None => match self.find_relative(op)? {
                Ok(found) => Ok(found),
                Err(address) => self.target(address),
            },
            Some(address) => self.target(address),
        }
    }

    /// `FlowInfo::fallthruOp`.
    fn fallthru_op(&self, op: u32) -> Result<Option<u32>, Failure> {
        let next = self.graph.next[op as usize];
        if next != NONE && !self.graph.ops[next as usize].start_insn {
            return Ok(Some(next));
        }
        let addr = self.graph.ops[op as usize].addr;
        let Some((start, visit)) = self.visited.range(..=addr).next_back() else { return Ok(None) };
        if start + visit.size <= addr {
            return Ok(None);
        }
        self.target(start + visit.size).map(Some)
    }

    fn mark_start_basic(&mut self, op: u32) {
        self.graph.ops[op as usize].start_block = true;
    }

    /// `FlowInfo::newAddress`.
    fn new_address(&mut self, to: u64) -> Result<(), Failure> {
        if to < self.baddr || self.eaddr < to {
            self.unprocessed.push(to);
            return Ok(());
        }
        if self.visited.contains_key(&to) {
            let op = self.target(to)?;
            self.mark_start_basic(op);
            return Ok(());
        }
        self.addrlist.push(to);
        Ok(())
    }

    /// `FlowInfo::deleteRemainingOps`.
    fn delete_remaining(&mut self, mut from: u32) {
        while from != NONE {
            let next = self.graph.next[from as usize];
            self.destroy(from);
            from = next;
        }
    }

    /// `FlowInfo::setupCallSpecs` / `setupCallindSpecs` and `queryCall`.
    fn setup_call(&mut self, op: u32) -> Result<(), Failure> {
        let entry = if self.graph.ops[op as usize].code == OpCode::CPUI_CALL {
            self.code_address(op)?
        } else {
            None
        };
        let has_function = entry.is_some_and(|entry| self.env.function_at(entry));
        let id = self.graph.calls.len() as u32;
        self.graph.ops[op as usize].call = id;
        self.graph.calls.push(CallSpec { op, entry, has_function });
        self.qlst.push(id);
        // `checkForFlowModification`: a call fixup makes the call inline.
        if entry.is_some_and(|entry| has_function && self.env.has_fixup(entry)) {
            self.injectlist.push(op);
        }
        Ok(())
    }

    /// `FlowInfo::xrefControlFlow` over the ops from `first` to the end of the list.
    fn xref_control_flow(&mut self, first: u32, startbasic: &mut bool) -> Result<(u32, bool), Failure> {
        let mut isfallthru = false;
        let mut maxtime = 0u32;
        let mut cursor = first;
        let mut last = NONE;
        while cursor != NONE {
            let op = cursor;
            cursor = self.graph.next[op as usize];
            last = op;
            if *startbasic {
                self.mark_start_basic(op);
                *startbasic = false;
            }
            match self.graph.ops[op as usize].code {
                OpCode::CPUI_CBRANCH => {
                    match self.code_address(op)? {
                        None => match self.find_relative(op)? {
                            Ok(destination) => {
                                self.mark_start_basic(destination);
                                maxtime = maxtime.max(self.graph.ops[destination as usize].time);
                            }
                            Err(_) => isfallthru = true,
                        },
                        Some(address) => self.new_address(address)?,
                    }
                    *startbasic = true;
                }
                OpCode::CPUI_BRANCH => {
                    match self.code_address(op)? {
                        None => match self.find_relative(op)? {
                            Ok(destination) => {
                                self.mark_start_basic(destination);
                                maxtime = maxtime.max(self.graph.ops[destination as usize].time);
                            }
                            Err(_) => isfallthru = true,
                        },
                        Some(address) => self.new_address(address)?,
                    }
                    if self.graph.ops[op as usize].time >= maxtime {
                        self.delete_remaining(cursor);
                        cursor = NONE;
                    }
                    *startbasic = true;
                }
                OpCode::CPUI_BRANCHIND => {
                    self.tablelist.push(op);
                    if self.graph.ops[op as usize].time >= maxtime {
                        self.delete_remaining(cursor);
                        cursor = NONE;
                    }
                    *startbasic = true;
                }
                OpCode::CPUI_RETURN => {
                    if self.graph.ops[op as usize].time >= maxtime {
                        self.delete_remaining(cursor);
                        cursor = NONE;
                    }
                    *startbasic = true;
                }
                OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => self.setup_call(op)?,
                OpCode::CPUI_CALLOTHER => {
                    // A user op the compiler spec injects is replaced by its p-code.
                    let userop = self.op_inputs(op).first().map_or(!0, |vn| vn.offset);
                    if self.env.userop_fixup(userop).is_some() {
                        self.injectlist.push(op);
                    }
                }
                _ => {}
            }
        }
        if isfallthru {
            // An explicit relative branch to the end of the instruction.
            *startbasic = true;
        } else if last == NONE {
            isfallthru = true;
        } else {
            // The fall-through is read off the last op that was reached;
            // `delete_remaining` leaves it as the branch that ended the walk.
            isfallthru = !matches!(
                self.graph.ops[last as usize].code,
                OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND | OpCode::CPUI_RETURN
            );
        }
        Ok((last, isfallthru))
    }

    /// `FlowInfo::processInstruction`.
    fn process_instruction(&mut self, cur: u64, startbasic: &mut bool) -> Result<bool, Failure> {
        if self.insn_count >= self.insn_max {
            // Too many instructions: the flow is truncated here with a halt
            // ahead of the instruction, which is decoded regardless.
            self.artificial_halt(cur, NONE);
        }
        self.insn_count += 1;
        let before = self.graph.tail;
        let mut raw = std::mem::take(&mut self.scratch);
        if self.env.decode(cur, &mut raw).is_err() {
            self.scratch = raw;
            return Err(Failure::Undecodable);
        }
        let insn = self.graph.insns.len() as u32;
        self.graph.insns.push(InsnInfo {
            kind: raw.kind.unwrap_or(FlowKind::Bad),
            fallthrough: raw.fallthrough,
            terminal: raw.terminal,
            targets: raw.targets.clone(),
            branchind: raw.branchind,
            conditional: raw.conditional,
        });
        let step = raw.length as u64;
        let mut first = NONE;
        for op in &raw.ops {
            let id = self.new_op(op.code, cur, op.out, &raw.pool[op.ins as usize..(op.ins + op.nin) as usize], insn);
            if first == NONE {
                first = id;
            }
        }
        let made = raw.ops.len() as u32;
        self.scratch = raw;
        let _ = before;
        self.visited.insert(cur, Visit { size: step, first, insn, ops: made, origin: first });
        let mut isfallthru = true;
        if first != NONE {
            self.graph.ops[first as usize].start_insn = true;
            isfallthru = self.xref_control_flow(first, startbasic)?.1;
        }
        if isfallthru {
            self.addrlist.push(cur + step);
        }
        Ok(isfallthru)
    }

    /// `FlowInfo::setFallthruBound`; `None` when the address was visited.
    fn set_fallthru_bound(&mut self) -> Result<Option<u64>, Failure> {
        let addr = *self.addrlist.last().expect("a pending address");
        let mut bound = self.eaddr;
        let mut iter = self.visited.range(..=addr).next_back();
        if let Some((&start, visit)) = iter {
            if addr == start {
                let op = self.target(addr)?;
                self.mark_start_basic(op);
                self.addrlist.pop();
                return Ok(None);
            }
            let _ = visit;
            // addr < start + size: the bytes are reinterpreted (a warning only).
            iter = self.visited.range((std::ops::Bound::Excluded(addr), std::ops::Bound::Unbounded)).next();
        } else {
            iter = self.visited.range((std::ops::Bound::Excluded(addr), std::ops::Bound::Unbounded)).next();
        }
        if let Some((&next, _)) = iter {
            bound = next;
        }
        Ok(Some(bound))
    }

    /// `FlowInfo::fallthru`.
    fn fallthru(&mut self) -> Result<(), Failure> {
        let Some(mut bound) = self.set_fallthru_bound()? else { return Ok(()) };
        let mut startbasic = true;
        loop {
            let current = self.addrlist.pop().expect("a pending address");
            let fallthruflag = self.process_instruction(current, &mut startbasic)?;
            if !fallthruflag {
                break;
            }
            let Some(&pending) = self.addrlist.last() else { break };
            if bound <= pending {
                if bound == self.eaddr {
                    self.unprocessed.push(pending);
                    self.addrlist.pop();
                    return Ok(());
                }
                if bound == pending {
                    if startbasic {
                        let op = self.target(pending)?;
                        self.mark_start_basic(op);
                    }
                    self.addrlist.pop();
                    break;
                }
                match self.set_fallthru_bound()? {
                    Some(next) => bound = next,
                    None => return Ok(()),
                }
            }
        }
        Ok(())
    }

    /// `Funcdata::earlyJumpTableFail` is a refusal the decompiler makes
    /// before it analyses the table: `true` means the jump surely is not a
    /// dispatch (an address built by an uninjected user op).
    fn early_jump_table_fail(&self, op: u32) -> bool {
        let mut vn = self.op_inputs(op)[0];
        let mut cursor = self.graph.prev[op as usize];
        let mut count_max = 8;
        let intersects = |a: &Vn, b: &Vn| {
            a.space == b.space && a.offset < b.offset + b.size as u64 && b.offset < a.offset + a.size as u64
        };
        while cursor != NONE {
            if vn.size == 1 {
                return false;
            }
            count_max -= 1;
            if count_max < 0 {
                return false;
            }
            let candidate = &self.graph.ops[cursor as usize];
            let ins = self.op_inputs(cursor);
            let outhit = candidate.out.is_some_and(|out| intersects(&vn, &out));
            match eval_type(candidate.code) {
                Eval::Special => match candidate.code {
                    OpCode::CPUI_CALLOTHER => {
                        // Don't back-track through an injection.
                        if ins.first().is_some_and(|userop| self.env.userop_fixup(userop.offset).is_some()) {
                            return false;
                        }
                        // Address formed by an uninjected user op: analysis will fail.
                        if outhit {
                            return true;
                        }
                    }
                    OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => return false,
                    OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND | OpCode::CPUI_RETURN => {
                        return false;
                    }
                    OpCode::CPUI_STORE => return false,
                    _ => {
                        if outhit {
                            return false;
                        }
                    }
                },
                Eval::Unary => {
                    if outhit {
                        if ins[0].size != vn.size {
                            return false;
                        }
                        vn = ins[0];
                    }
                }
                Eval::Binary => {
                    if outhit {
                        if !matches!(candidate.code, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_XOR) {
                            return false;
                        }
                        if ins[1].space != self.lang.constant_space {
                            return false;
                        }
                        if ins[0].size != vn.size {
                            return false;
                        }
                        vn = ins[0];
                    }
                }
                Eval::Other => {
                    if outhit {
                        return false;
                    }
                }
            }
            cursor = self.graph.prev[cursor as usize];
        }
        false
    }

    /// Whether the branch target is the function's return address, followed
    /// back through copies and alignment masks (`Funcdata::testForReturnAddress`)
    /// over the ops that precede the jump.
    fn target_is_return_address(&self, op: u32) -> bool {
        let Some(return_address) = self.lang.return_address else { return false };
        let mut wanted = self.op_inputs(op)[0];
        let mut cursor = self.graph.prev[op as usize];
        let mut budget = 0;
        while cursor != NONE && budget < 64 {
            budget += 1;
            let prior = &self.graph.ops[cursor as usize];
            if let Some(out) = prior.out {
                if out.space == wanted.space && out.offset < wanted.offset + wanted.size as u64 && wanted.offset < out.offset + out.size as u64 {
                    let ins = self.op_inputs(cursor);
                    match prior.code {
                        OpCode::CPUI_COPY => wanted = ins[0],
                        OpCode::CPUI_INT_AND if ins[1].space == self.lang.constant_space => wanted = ins[0],
                        _ => return false,
                    }
                    if wanted.space == self.lang.constant_space {
                        return false;
                    }
                }
            }
            cursor = self.graph.prev[cursor as usize];
        }
        wanted.space == return_address.space && wanted.offset == return_address.offset && wanted.size == return_address.size
    }

    /// What computes the target of the `BRANCHIND` `op`, read off the ops of
    /// its basic block: a load whose address holds an index is a table read,
    /// arithmetic on registers that no load feeds is an inline island
    /// (`addls pc,pc,r0,lsl #2` over a run of `b case`), and anything else
    /// is a pointer the jump is handed.
    fn jump_shape(&self, op: u32) -> JumpShape {
        #[derive(Clone, Copy)]
        struct Wanted {
            vn: Vn,
            /// Inside the address of a load.
            address: bool,
        }
        let intersects = |a: &Vn, b: &Vn| a.space == b.space && a.offset < b.offset + b.size as u64 && b.offset < a.offset + a.size as u64;
        let mut wanted = vec![Wanted { vn: self.op_inputs(op)[0], address: false }];
        let (mut arithmetic, mut loaded, mut indexed) = (false, false, false);
        let mut cursor = self.graph.prev[op as usize];
        let mut budget = 0;
        // The branch's own instruction is part of its block: start from the
        // op before it and stop after the first op that opens the block.
        let mut at_start = self.graph.ops[op as usize].start_block;
        while cursor != NONE && !at_start && budget < 128 && !wanted.is_empty() {
            budget += 1;
            let prior = &self.graph.ops[cursor as usize];
            at_start = prior.start_block;
            if let Some(out) = prior.out {
                if let Some(slot) = wanted.iter().position(|w| intersects(&w.vn, &out)) {
                    let hit = wanted.swap_remove(slot);
                    let ins = self.op_inputs(cursor);
                    let live = |vn: &Vn| vn.space != self.lang.constant_space;
                    match prior.code {
                        OpCode::CPUI_LOAD => {
                            loaded = true;
                            if let Some(pointer) = ins.get(1).filter(|vn| live(vn)) {
                                wanted.push(Wanted { vn: *pointer, address: true });
                            }
                        }
                        OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT | OpCode::CPUI_SUBPIECE | OpCode::CPUI_CAST => {
                            if let Some(first) = ins.first().filter(|vn| live(vn)) {
                                wanted.push(Wanted { vn: *first, address: hit.address });
                            }
                        }
                        OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR if ins.get(1).is_some_and(|vn| !live(vn)) => {
                            if let Some(first) = ins.first().filter(|vn| live(vn)) {
                                wanted.push(Wanted { vn: *first, address: hit.address });
                            }
                        }
                        OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER => {}
                        _ => {
                            let inputs: Vec<&Vn> = ins.iter().filter(|vn| live(vn)).collect();
                            if hit.address {
                                // An address that adds two registers, or scales one,
                                // holds an index.
                                indexed |= inputs.len() > 1
                                    || matches!(prior.code, OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT);
                            } else {
                                arithmetic = true;
                            }
                            for vn in inputs {
                                wanted.push(Wanted { vn: *vn, address: hit.address });
                            }
                        }
                    }
                }
            }
            cursor = self.graph.prev[cursor as usize];
        }
        // A target popped from the stack (`pop {r0}; bx r0`, a Thumb return) is
        // not read out of a table: the address of its load is the stack pointer.
        let from_stack = self.lang.stack_pointer.is_some_and(|sp| {
            wanted.iter().any(|w| w.address && w.vn.space == sp.space && w.vn.offset < sp.offset + sp.size as u64 && sp.offset < w.vn.offset + w.vn.size as u64)
        });
        if from_stack {
            JumpShape::Pointer
        } else if loaded && indexed {
            JumpShape::TableLoad
        } else if arithmetic && !loaded {
            JumpShape::Island
        } else {
            JumpShape::Pointer
        }
    }

    /// The traced instructions as the dispatch analysis reads their shape.
    fn shapes(&self) -> Vec<FlowShape> {
        self.visited
            .iter()
            .filter(|(_, visit)| visit.insn != NONE)
            .map(|(&address, visit)| {
                let info = &self.graph.insns[visit.insn as usize];
                FlowShape {
                    address,
                    length: visit.size.min(u64::from(u8::MAX)) as u8,
                    kind: info.kind,
                    conditional: info.conditional,
                    target: match info.kind {
                        FlowKind::Branch | FlowKind::CBranch if info.targets.len() == 1 => Some(info.targets[0]),
                        _ => None,
                    },
                }
            })
            .collect()
    }

    /// The p-code of the instruction at `address` as the decoder made it,
    /// before a call fixup replaced one of its ops or a branch was turned
    /// into a call: what a lift of the instruction returns.
    fn pcode_at(&self, address: u64) -> Option<PcodeInstruction> {
        let visit = self.visited.get(&address)?;
        if visit.insn == NONE {
            return None;
        }
        let mut ops = Vec::with_capacity(visit.ops as usize);
        if visit.origin != NONE {
            for id in visit.origin..visit.origin + visit.ops {
                let op = &self.graph.ops[id as usize];
                if op.addr != address || op.insn != visit.insn {
                    return None;
                }
                let name = |vn: &Vn| PcodeVarnode { space: self.lang.space_names[vn.space as usize].clone(), offset: vn.offset, size: vn.size as u32 };
                ops.push(PcodeOp {
                    opcode: opcode_name(op.code).to_string(),
                    output: op.out.as_ref().map(name),
                    inputs: self.op_inputs(id).iter().map(name).collect(),
                });
            }
        }
        Some(PcodeInstruction { address, length: u8::try_from(visit.size).ok()?, ops, error: None })
    }

    /// The table of the `BRANCHIND` at `branch`, by the dispatch analysis
    /// over what the flow has traced.
    fn try_recover(&self, shapes: &[FlowShape], branch: u64) -> Result<Vec<u64>, Refusal> {
        let pcode = |address: u64| self.pcode_at(address);
        jump::recover(&*self.env, self.lang, shapes, &pcode, branch, self.baddr, self.eaddr + 1)
    }

    /// The recovered tables that do not hold once the whole flow is traced:
    /// a case that leads back into the dispatch can add a way in the first
    /// answer did not see, so each is asked again over the final flow and
    /// must come out the same.
    fn unstable_recoveries(&self) -> Vec<u64> {
        if self.recoveries.is_empty() {
            return Vec::new();
        }
        let shapes = self.shapes();
        self.recoveries
            .iter()
            .filter_map(|&(op, _)| {
                let branch = self.graph.ops[op as usize].addr;
                let (_, original) = self.tables.iter().find(|(table_op, _)| *table_op == op)?;
                match self.try_recover(&shapes, branch) {
                    Ok(again) if again == *original => None,
                    _ => Some(branch),
                }
            })
            .collect()
    }

    fn recover_indirect_jump(&self, op: u32, shapes: &OnceCell<Vec<FlowShape>>) -> IndirectJump {
        let address = self.graph.ops[op as usize].addr;
        if let Some(targets) = self.env.stored_table(address) {
            return IndirectJump::Table(targets.to_vec());
        }
        if self.early_jump_table_fail(op) {
            return IndirectJump::Call(None);
        }
        // `FlowInfo::recoverJumpTables` tries the table first and only then
        // asks whether the target is the return address.
        let mut refusal = None;
        if self.recover {
            let shape = self.jump_shape(op);
            if shape != JumpShape::Pointer {
                refusal = Some(if self.blocked.contains(&address) {
                    Refusal::Unstable
                } else {
                    match self.try_recover(shapes.get_or_init(|| self.shapes()), address) {
                        Ok(targets) => return IndirectJump::Recovered(targets, shape),
                        Err(reason) => reason,
                    }
                });
            }
        }
        if self.target_is_return_address(op) {
            IndirectJump::Return
        } else {
            IndirectJump::Call(refusal)
        }
    }

    /// `FlowInfo::truncateIndirectJump`.
    fn truncate_indirect_jump(&mut self, op: u32, mode: &IndirectJump) -> Result<(), Failure> {
        match mode {
            IndirectJump::Return => self.graph.ops[op as usize].code = OpCode::CPUI_RETURN,
            _ => {
                let shape = self.jump_shape(op);
                self.graph.truncated.push((self.graph.ops[op as usize].addr, shape));
                self.graph.ops[op as usize].code = OpCode::CPUI_CALLIND;
                self.setup_call(op)?;
                let (addr, insn) = (self.graph.ops[op as usize].addr, self.graph.ops[op as usize].insn);
                let halt = self.artificial_halt(addr, insn);
                self.insert_after(op, halt);
            }
        }
        Ok(())
    }

    /// `FlowInfo::checkContainedCall`: a call whose target is an instruction
    /// the flow already traced is a branch (position-independent code).
    fn check_contained_call(&mut self) -> Result<(), Failure> {
        let mut index = 0;
        while index < self.qlst.len() {
            let spec = self.qlst[index];
            let call = &self.graph.calls[spec as usize];
            let op = call.op;
            let Some(address) = call.entry else {
                index += 1;
                continue;
            };
            if call.has_function || self.graph.ops[op as usize].code != OpCode::CPUI_CALL {
                index += 1;
                continue;
            }
            let Some((&start, visit)) = self.visited.range(..=address).next_back() else {
                index += 1;
                continue;
            };
            if start + visit.size <= address || start != address {
                index += 1;
                continue;
            }
            self.graph.ops[op as usize].code = OpCode::CPUI_BRANCH;
            let target = self.target(address)?;
            self.mark_start_basic(target);
            let following = self.graph.next[op as usize];
            if following != NONE {
                self.mark_start_basic(following);
            }
            self.graph.ops[op as usize].call = NONE;
            self.qlst.remove(index);
            // The decompiler's loop advances past the entry after the one it
            // erased, so the next call is not examined.
            index += 1;
        }
        Ok(())
    }

    /// `PcodeOpBank::moveSequenceDead`: the ops `first..=last` move to follow `after`.
    fn move_sequence_after(&mut self, first: u32, last: u32, after: u32) {
        let g = &mut self.graph;
        // Unlink the sequence.
        let (before, following) = (g.prev[first as usize], g.next[last as usize]);
        if before == NONE {
            g.head = following;
        } else {
            g.next[before as usize] = following;
        }
        if following == NONE {
            g.tail = before;
        } else {
            g.prev[following as usize] = before;
        }
        // Relink after `after`.
        let successor = g.next[after as usize];
        g.next[after as usize] = first;
        g.prev[first as usize] = after;
        g.next[last as usize] = successor;
        if successor == NONE {
            g.tail = last;
        } else {
            g.prev[successor as usize] = last;
        }
    }

    /// `FlowInfo::injectPcode`: the calls to functions that carry a compiler
    /// spec call fixup are replaced by the fixup's p-code.
    fn inject_pcode(&mut self) -> Result<(), Failure> {
        let mut index = 0;
        while index < self.injectlist.len() {
            let op = self.injectlist[index];
            index += 1;
            let call = self.graph.ops[op as usize].call;
            if self.graph.ops[op as usize].dead {
                continue;
            }
            let base = self.graph.ops[op as usize].addr;
            let mut raw = std::mem::take(&mut self.scratch);
            let injected = if self.graph.ops[op as usize].code == OpCode::CPUI_CALLOTHER {
                // A user-defined operation the compiler spec replaces.
                let userop = self.op_inputs(op)[0].offset;
                match self.env.userop_fixup(userop) {
                    Some(fixup) => self.env.inject_userop(fixup, base, &mut raw),
                    None => {
                        self.scratch = raw;
                        continue;
                    }
                }
            } else {
                if call == NONE {
                    self.scratch = raw;
                    continue;
                }
                let Some(entry) = self.graph.calls[call as usize].entry else {
                    self.scratch = raw;
                    continue;
                };
                self.env.inject(entry, base, &mut raw)
            };
            if let Err(message) = injected {
                self.scratch = raw;
                return Err(Failure::Error(message));
            }
            if raw.ops.is_empty() {
                self.scratch = raw;
                return Err(Failure::Error("Empty injection".into()));
            }
            let mut first = NONE;
            let mut last = NONE;
            for item in &raw.ops {
                let id = self.new_op(item.code, base, item.out, &raw.pool[item.ins as usize..(item.ins + item.nin) as usize], NONE);
                if first == NONE {
                    first = id;
                }
                last = id;
            }
            self.scratch = raw;
            let mut startbasic = self.graph.ops[op as usize].start_block;
            let (end, _) = self.xref_control_flow(first, &mut startbasic)?;
            if startbasic {
                let following = self.graph.next[op as usize];
                if following != NONE {
                    self.mark_start_basic(following);
                }
            }
            let last = if end == NONE { last } else { end };
            self.move_sequence_after(first, last, op);
            // The first op of the injection stands for the call as the
            // instruction's target.
            if let Some(visit) = self.visited.get_mut(&base) {
                if visit.first == op {
                    visit.first = first;
                }
            }
            self.destroy(op);
            if call != NONE {
                self.graph.ops[op as usize].call = NONE;
                self.qlst.retain(|&spec| spec != call);
            }
        }
        self.injectlist.clear();
        Ok(())
    }

    /// `FlowInfo::generateOps`.
    fn generate_ops(&mut self) -> Result<(), Failure> {
        self.addrlist.push(self.baddr);
        while !self.addrlist.is_empty() {
            self.fallthru()?;
        }
        if !self.injectlist.is_empty() {
            self.inject_pcode()?;
        }
        loop {
            while !self.tablelist.is_empty() {
                let pending = std::mem::take(&mut self.tablelist);
                let mut recovered = Vec::new();
                let shapes = OnceCell::new();
                for op in pending {
                    let mode = self.recover_indirect_jump(op, &shapes);
                    let at = self.graph.ops[op as usize].addr;
                    if std::env::var_os("ROMWRIGHT_TRACE_BRANCHIND").is_some() {
                        let (kind, why) = match &mode {
                            IndirectJump::Table(_) => ("table", String::new()),
                            IndirectJump::Recovered(targets, _) => (
                                "recovered",
                                format!("{}:{}", targets.len(), targets.iter().map(|target| format!("{target:#x}")).collect::<Vec<_>>().join(",")),
                            ),
                            IndirectJump::Return => ("return", String::new()),
                            IndirectJump::Call(refusal) => ("call", refusal.map_or_else(String::new, |reason| format!("{reason:?}"))),
                        };
                        eprintln!(
                            "BRANCHIND {at:#x} range={:#x}-{:#x} {kind} {why} {:?} | {}",
                            self.baddr,
                            self.eaddr + 1,
                            self.jump_shape(op),
                            self.env.assembly(at)
                        );
                    }
                    match &mode {
                        IndirectJump::Table(targets) => {
                            self.tables.push((op, targets.clone()));
                            recovered.push(targets.clone());
                        }
                        IndirectJump::Recovered(targets, shape) => {
                            self.tables.push((op, targets.clone()));
                            self.recoveries.push((op, *shape));
                            self.graph.recovered.push((at, *shape, targets.clone()));
                            recovered.push(targets.clone());
                        }
                        IndirectJump::Call(Some(reason)) => {
                            let shape = self.jump_shape(op);
                            self.graph.refused.push((at, shape, *reason));
                            self.truncate_indirect_jump(op, &mode)?;
                        }
                        _ => self.truncate_indirect_jump(op, &mode)?,
                    }
                }
                for targets in recovered {
                    for target in targets {
                        self.new_address(target)?;
                    }
                    while !self.addrlist.is_empty() {
                        self.fallthru()?;
                    }
                }
            }
            self.check_contained_call()?;
            if !self.injectlist.is_empty() {
                self.inject_pcode()?;
            }
            if self.tablelist.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// `FlowInfo::fillinBranchStubs`: a halt for every address the flow left.
    fn fill_in_branch_stubs(&mut self) -> Result<(), Failure> {
        let pending = std::mem::take(&mut self.addrlist);
        for address in pending {
            if self.visited.contains_key(&address) {
                let op = self.target(address)?;
                self.mark_start_basic(op);
            } else {
                self.unprocessed.push(address);
            }
        }
        self.unprocessed.sort_unstable();
        self.unprocessed.dedup();
        for address in std::mem::take(&mut self.unprocessed) {
            let op = self.artificial_halt(address, NONE);
            self.mark_start_basic(op);
            self.graph.ops[op as usize].start_insn = true;
            // Explicit bounded exits must be discoverable by `target`.
            self.visited.insert(address, Visit { size: 1, first: op, insn: NONE, ops: 1, origin: NONE });
        }
        Ok(())
    }

    /// `FlowInfo::collectEdges`.
    fn collect_edges(&mut self) -> Result<(), Failure> {
        let mut cursor = self.graph.head;
        while cursor != NONE {
            let op = cursor;
            cursor = self.graph.next[op as usize];
            let nextstart = cursor == NONE || self.graph.ops[cursor as usize].start_block;
            match self.graph.ops[op as usize].code {
                OpCode::CPUI_BRANCH => {
                    let target = self.branch_target(op)?;
                    self.block_edges.push((op, target));
                }
                OpCode::CPUI_BRANCHIND => {
                    if let Some((_, targets)) = self.tables.iter().find(|(branch, _)| *branch == op) {
                        let mut seen: Vec<u32> = Vec::new();
                        for &address in &targets.clone() {
                            let target = self.target(address)?;
                            if seen.contains(&target) {
                                continue;
                            }
                            seen.push(target);
                            self.block_edges.push((op, target));
                        }
                    }
                }
                OpCode::CPUI_RETURN => {}
                OpCode::CPUI_CBRANCH => {
                    let fall = self
                        .fallthru_op(op)?
                        .ok_or_else(|| Failure::Error("conditional branch without a fall-through".into()))?;
                    self.block_edges.push((op, fall));
                    let target = self.branch_target(op)?;
                    self.block_edges.push((op, target));
                }
                _ => {
                    if nextstart {
                        let fall = self
                            .fallthru_op(op)?
                            .ok_or_else(|| Failure::Error("op without a fall-through".into()))?;
                        self.block_edges.push((op, fall));
                    }
                }
            }
        }
        Ok(())
    }

    /// `FlowInfo::splitBasic` and `connectBasic`.
    fn split_and_connect(&mut self) -> Result<(), Failure> {
        let mut parent = vec![NONE; self.graph.ops.len()];
        let mut cursor = self.graph.head;
        if cursor == NONE {
            return Ok(());
        }
        if !self.graph.ops[cursor as usize].start_block {
            return Err(Failure::Error("First op not marked as entry point".into()));
        }
        while cursor != NONE {
            let op = cursor;
            cursor = self.graph.next[op as usize];
            if self.graph.ops[op as usize].start_block || self.graph.blocks.is_empty() {
                self.graph.blocks.push(Block { ops: Vec::new(), outs: Vec::new() });
            }
            let block = self.graph.blocks.len() as u32 - 1;
            parent[op as usize] = block;
            self.graph.blocks[block as usize].ops.push(op);
        }
        let mut has_incoming = false;
        for &(from, to) in &self.block_edges {
            let (source, destination) = (parent[from as usize], parent[to as usize]);
            self.graph.blocks[source as usize].outs.push(destination);
            has_incoming |= destination == 0;
        }
        if has_incoming {
            // The entry block gets no incoming edges: a new one in front flows
            // into the old entry (`generateBlocks`).
            for block in &mut self.graph.blocks {
                for out in &mut block.outs {
                    *out += 1;
                }
            }
            self.graph.blocks.insert(0, Block { ops: Vec::new(), outs: vec![1] });
        }
        Ok(())
    }
}

impl Graph {
    /// `Funcdata::followFlow` over `[start, end)` and the blocks it builds.
    /// With `recover`, an indirect jump no table is stored for is given the
    /// table the dispatch analysis finds (`jump.rs`).
    pub fn follow<E: Environment>(
        lang: &Lang,
        env: &mut E,
        start: u64,
        end: u64,
        insn_max: u32,
        recover: bool,
    ) -> Result<Graph, Failure> {
        // A recovered table is checked over the flow it opened. One that does
        // not hold is struck and the flow traced again without it; the last
        // attempt recovers nothing, so the loop ends.
        const ATTEMPTS: usize = 4;
        let mut blocked: Vec<u64> = Vec::new();
        for attempt in 0..ATTEMPTS {
            let graph = Graph {
                ops: Vec::new(),
                pool: Vec::new(),
                insns: Vec::new(),
                calls: Vec::new(),
                truncated: Vec::new(),
                recovered: Vec::new(),
                refused: Vec::new(),
                blocks: Vec::new(),
                next: Vec::new(),
                prev: Vec::new(),
                head: NONE,
                tail: NONE,
                uniq: 0,
            };
            let mut flow = Flow {
                graph,
                lang,
                env: &mut *env,
                baddr: start,
                eaddr: end - 1,
                visited: BTreeMap::new(),
                addrlist: Vec::new(),
                unprocessed: Vec::new(),
                tablelist: Vec::new(),
                tables: Vec::new(),
                recoveries: Vec::new(),
                blocked: &blocked,
                recover: recover && attempt + 1 < ATTEMPTS,
                qlst: Vec::new(),
                injectlist: Vec::new(),
                insn_count: 0,
                insn_max,
                scratch: RawInsn::default(),
                block_edges: Vec::new(),
            };
            flow.generate_ops()?;
            let unstable = flow.unstable_recoveries();
            if unstable.is_empty() {
                flow.fill_in_branch_stubs()?;
                flow.collect_edges()?;
                flow.split_and_connect()?;
                return Ok(flow.graph);
            }
            drop(flow);
            blocked.extend(unstable);
        }
        unreachable!("the last attempt recovers no table, so none is unstable")
    }

    pub fn inputs(&self, op: &Op) -> &[Vn] {
        &self.pool[op.ins as usize..(op.ins + op.nin) as usize]
    }

    /// Every address an op of the flow sits at, within `[first, end)`, sorted.
    pub fn instruction_starts(&self, first: u64, end: u64) -> Vec<u64> {
        let mut starts: Vec<u64> = self
            .blocks
            .iter()
            .flat_map(|block| block.ops.iter())
            .map(|&op| self.ops[op as usize].addr)
            .filter(|&pc| pc >= first && pc < end)
            .collect();
        starts.sort_unstable();
        starts.dedup();
        starts
    }
}
