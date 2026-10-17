//! A mirror of one function's p-code at the point `ActionAssignHigh` has run,
//! the state Ghidra's merge actions (`merge.cc`, `ActionMarkExplicit`,
//! `ActionMarkImplied`, ...) work on, with the edits those actions make
//! (`Funcdata::opInsert*`, `opSetInput`, ...). Every edit and decision is
//! appended to a log that `native/romwright_merge.hh` replays on the real
//! `Funcdata` (docs/merge-port.md).

use super::cover::Cover;
use super::variant::Variant;
use crate::printc::tree::Tables;
use std::cell::{Cell, RefCell};

pub use crate::printc::render::opc;

/// `Varnode::varnode_flags`.
pub mod vf {
    pub const MARK: u32 = 0x01;
    pub const CONSTANT: u32 = 0x02;
    pub const ANNOTATION: u32 = 0x04;
    pub const INPUT: u32 = 0x08;
    pub const WRITTEN: u32 = 0x10;
    pub const INSERT: u32 = 0x20;
    pub const IMPLIED: u32 = 0x40;
    pub const EXPLICIT: u32 = 0x80;
    pub const TYPELOCK: u32 = 0x100;
    pub const NAMELOCK: u32 = 0x200;
    pub const NOLOCALALIAS: u32 = 0x400;
    pub const PERSIST: u32 = 0x4000;
    pub const ADDRTIED: u32 = 0x8000;
    pub const UNAFFECTED: u32 = 0x10000;
    pub const SPACEBASE: u32 = 0x20000;
    pub const INDIRECTONLY: u32 = 0x40000;
    pub const DIRECTWRITE: u32 = 0x80000;
    pub const ADDRFORCE: u32 = 0x100000;
    pub const MAPPED: u32 = 0x200000;
    pub const INDIRECT_CREATION: u32 = 0x400000;
    pub const PROTO_PARTIAL: u32 = 0x8000_0000;
}

/// `PcodeOp` flags.
pub mod pf {
    pub const BRANCH: u32 = 2;
    pub const CALL: u32 = 4;
    pub const RETURNS: u32 = 8;
    pub const DEAD: u32 = 0x20;
    pub const MARKER: u32 = 0x40;
    pub const BOOLOUTPUT: u32 = 0x80;
    pub const INDIRECT_SOURCE: u32 = 0x400;
    pub const UNARY: u32 = 0x8000;
    pub const BINARY: u32 = 0x10000;
    pub const SPECIAL: u32 = 0x20000;
    pub const TERNARY: u32 = 0x40000;
    pub const NONPRINTING: u32 = 0x100000;
    pub const NORETURN: u32 = 0x1000000;
    pub const INDIRECT_CREATION: u32 = 0x8000000;
    pub const INDIRECT_STORE: u32 = 0x8000_0000;
    /// `PcodeOp::addlflags`.
    pub const SPECIAL_PRINT: u32 = 2;
    pub const CONCAT_ROOT: u32 = 0x100;
}

/// `AddrSpace` kinds the merge distinguishes.
pub const SPACE_PROCESSOR: u8 = 0;
pub const SPACE_SPACEBASE: u8 = 1;
pub const SPACE_INTERNAL: u8 = 2;
pub const SPACE_CONSTANT: u8 = 3;

#[derive(Clone, Copy, Debug, Default)]
pub struct Space {
    pub kind: u8,
    pub big_endian: bool,
}

/// `Address`: ordered by the space's index, then offset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr {
    pub space: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Block {
    pub ins: Vec<usize>,
    pub outs: Vec<usize>,
    /// `getOutRevIndex(i)`: the position of the i-th out-edge among its target's in-edges.
    pub out_rev: Vec<usize>,
    pub idom: Option<usize>,
    pub start: Addr,
    pub stop: Addr,
    /// The ops in order.
    pub ops: Vec<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct Op {
    pub time: u64,
    pub pc: Addr,
    pub code: u32,
    pub block: Option<usize>,
    pub order: u32,
    pub flags: u32,
    pub addl: u32,
    pub ins: Vec<usize>,
    pub out: Option<usize>,
    /// An INDIRECT's effect op (`PcodeOp::getOpFromConst(getIn(1)->getAddr())`).
    pub target: Option<usize>,
    /// Bit `i`: `inputTypeLocal(i)` is the same type as `outputTypeLocal()`.
    pub same_local: Vec<u32>,
    /// Position in the alive list while alive.
    pub alive_at: Option<usize>,
}

impl Op {
    pub fn is_marker(&self) -> bool {
        self.flags & pf::MARKER != 0
    }
    pub fn is_call(&self) -> bool {
        self.flags & pf::CALL != 0
    }
    pub fn is_dead(&self) -> bool {
        self.flags & pf::DEAD != 0
    }
    pub fn is_branch(&self) -> bool {
        self.flags & pf::BRANCH != 0
    }
    pub fn is_flow_break(&self) -> bool {
        self.flags & (pf::BRANCH | pf::RETURNS) != 0
    }
    pub fn not_printed(&self) -> bool {
        self.flags & (pf::MARKER | pf::NONPRINTING | pf::NORETURN) != 0
    }
    pub fn is_special_eval(&self) -> bool {
        self.flags & (pf::UNARY | pf::BINARY | pf::SPECIAL | pf::TERNARY) == pf::SPECIAL
    }
}

#[derive(Clone, Debug, Default)]
pub struct Vn {
    pub create: u32,
    pub size: u32,
    pub addr: Addr,
    pub flags: u32,
    pub ty: usize,
    pub def: Option<usize>,
    /// The readers, in descend-list order (one entry per reading slot).
    pub desc: Vec<usize>,
    pub high: usize,
    pub merge_group: i32,
    pub symbol: Option<usize>,
    /// The `SymbolEntry` (`Varnode::getSymbolEntry`) and its offset within the symbol.
    pub entry: Option<usize>,
    pub entry_offset: i32,
    pub cover: Cover,
    pub cover_dirty: bool,
    pub has_cover_obj: bool,
    pub mark: bool,
    /// Destroyed.
    pub gone: bool,
}

pub const NO_HIGH: usize = usize::MAX;

impl Vn {
    pub fn is_written(&self) -> bool {
        self.flags & vf::WRITTEN != 0
    }
    pub fn is_input(&self) -> bool {
        self.flags & vf::INPUT != 0
    }
    pub fn is_free(&self) -> bool {
        self.flags & (vf::WRITTEN | vf::INPUT) == 0
    }
    pub fn is_constant(&self) -> bool {
        self.flags & vf::CONSTANT != 0
    }
    pub fn is_annotation(&self) -> bool {
        self.flags & vf::ANNOTATION != 0
    }
    pub fn is_implied(&self) -> bool {
        self.flags & vf::IMPLIED != 0
    }
    pub fn is_explicit(&self) -> bool {
        self.flags & vf::EXPLICIT != 0
    }
    pub fn is_addr_tied(&self) -> bool {
        self.flags & vf::ADDRTIED != 0
    }
    pub fn is_spacebase(&self) -> bool {
        self.flags & vf::SPACEBASE != 0
    }
    pub fn is_type_lock(&self) -> bool {
        self.flags & vf::TYPELOCK != 0
    }
    pub fn has_cover(&self) -> bool {
        self.flags & (vf::CONSTANT | vf::ANNOTATION | vf::INSERT) == vf::INSERT
    }
    pub fn has_no_descend(&self) -> bool {
        self.desc.is_empty()
    }
    pub fn is_illegal_input(&self) -> bool {
        self.flags & (vf::INPUT | vf::DIRECTWRITE) == vf::INPUT
    }
}

#[derive(Clone, Debug, Default)]
pub struct High {
    pub inst: Vec<usize>,
    pub merge_classes: i32,
    pub symbol: Option<usize>,
    pub symoff: i32,
    pub cover: Cover,
    pub cover_dirty: bool,
    /// `HighVariable::piece`: the `VariablePiece` of a variable that is part of a group.
    pub piece: Option<usize>,
    pub intersect_dirty: bool,
    pub extend_cover_dirty: bool,
    pub mark: bool,
    pub unmerged: bool,
    pub copy_in1: bool,
    pub copy_in2: bool,
    pub gone: bool,
    pub(super) flags_cache: Cell<Option<u32>>,
    pub(super) type_cache: Cell<Option<(usize, bool)>>,
}

#[derive(Clone, Debug, Default)]
pub struct Symbol {
    pub isolated: bool,
    /// The metatype of the symbol's data-type.
    pub meta: u8,
}

/// `VariableGroup`: the pieces (HighVariables) of one larger variable.
#[derive(Clone, Debug, Default)]
pub struct Group {
    pub size: i32,
    pub symbol_offset: i32,
    /// Piece ids ordered by (offset, size).
    pub pieces: Vec<usize>,
    pub gone: bool,
}

/// `VariablePiece`.
#[derive(Clone, Debug, Default)]
pub struct Piece {
    pub high: usize,
    pub group: usize,
    pub offset: i32,
    pub size: i32,
    pub intersection: Vec<usize>,
    pub cover: Cover,
    pub gone: bool,
}

/// Where a new op takes its address from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrSpec {
    OpAddr(usize),
    BlockStart(usize),
    BlockStop(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    Before(usize),
    After(usize),
    Begin(usize),
    End(usize),
}

/// A decision or edit, in the order the decompiler's actions make it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// `Funcdata::newOp(1,addr)` + `opSetOpcode(COPY)`: the op gets the next op id.
    NewCopy(AddrSpec),
    /// `Funcdata::newUnique(size, type of vn)`: the varnode gets the next varnode id.
    NewUnique { size: u32, ty_from: usize },
    SetOutput { op: usize, vn: usize },
    SetInput { op: usize, vn: usize, slot: usize },
    Insert { op: usize, at: At },
    Uninsert { op: usize },
    Destroy { op: usize },
    TotalReplace { old: usize, new: usize },
    HighRemove { vn: usize },
    /// `HighVariable::merge`: the high of `a` keeps, the high of `b` goes.
    Merge { a: usize, b: usize, speculative: bool },
    SetExplicit(usize),
    ClearImplied(usize),
    /// `Merge::markImplied`.
    MarkImplied(usize),
    NonPrint(usize),
    Print(usize),
    SpecialPrint(usize),
    IndirectOnly(usize),
    /// `HighVariable::groupWith`: the high of `a` joins the group of `b`'s high at `off`.
    GroupWith { a: usize, b: usize, off: i32 },
    /// `Varnode::clearProtoPartial`.
    ClearProtoPartial(usize),
}

/// An op that may change what a cover holds (`StackAffectingOps`): a call, or a guarded STORE.
#[derive(Clone, Debug)]
pub struct Affecting {
    pub op: usize,
    /// STORE guard range: (space, min, max).
    pub guard: Option<(u32, u64, u64)>,
}

/// A for-loop candidate (`romwrightLoopTransform`).
#[derive(Clone, Copy, Debug)]
pub struct LoopCandidate {
    pub head: usize,
    pub test: usize,
    pub tail: usize,
}

#[derive(Default)]
pub struct Func {
    pub address: u64,
    pub max_implied_ref: u32,
    pub max_term_dup: u32,
    pub analyze_loops: bool,
    pub next_time: u64,
    pub next_create: u32,
    pub next_unique: u64,
    pub unique_space: u32,
    pub spaces: Vec<Option<Space>>,
    pub blocks: Vec<Block>,
    pub ops: Vec<Op>,
    pub alive: Vec<Option<usize>>,
    pub vns: Vec<Vn>,
    pub highs: Vec<High>,
    pub groups: Vec<Group>,
    pub pieces: Vec<Piece>,
    pub symbols: Vec<Symbol>,
    pub calls: Vec<usize>,
    pub affecting: Vec<Affecting>,
    pub loop_candidates: Vec<LoopCandidate>,
    pub tables: Tables,
    pub stripped: Vec<Option<usize>>,
    pub variant: Variant,
    pub log: Vec<Entry>,
    /// The loops that survived (`RomwrightLoop`): head, tail, initializer, iterator.
    pub loops: Vec<LoopRec>,
    pub pending_loops: Vec<PendingLoop>,
    pub forbid: std::collections::HashSet<(usize, usize)>,
    loc: RefCell<Option<Vec<usize>>>,
    pub(super) cache: RefCell<std::collections::BTreeMap<(usize, usize), bool>>,
    pub(super) affect_set: RefCell<Option<AffectSet>>,
    pub err: RefCell<Option<String>>,
    /// The ops marked non-printing/printing, for the loop finalize.
    pub copy_trims: Vec<usize>,
    /// `Merge::protoPartial`: the CONCAT roots registered for grouping (op ids).
    pub proto_partial: Vec<usize>,
    /// The STORE ops `ActionMarkImplied` tests loads against.
    pub store_ops: Vec<usize>,
    pub extra: Stats,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PendingLoop {
    pub head: usize,
    pub tail: usize,
    pub loop_def: Option<usize>,
    pub init: Option<usize>,
    pub iter: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LoopRec {
    pub head: usize,
    pub tail: usize,
    pub init: Option<usize>,
    pub iter: Option<usize>,
}

#[derive(Default)]
pub struct AffectSet {
    pub ops: Vec<usize>,
    pub block_start: Vec<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub merges: u32,
    pub speculative: u32,
    pub copies: u32,
    pub explicit: u32,
    pub implied: u32,
}

pub type Result<T, E = String> = std::result::Result<T, E>;

impl Func {
    // ---- spaces and types ----

    pub fn space(&self, index: u32) -> Space {
        self.spaces
            .get(index as usize)
            .copied()
            .flatten()
            .unwrap_or_default()
    }

    pub fn vn_space_kind(&self, v: usize) -> u8 {
        self.space(self.vns[v].addr.space).kind
    }

    pub fn fail(&self, why: impl Into<String>) {
        let mut slot = self.err.borrow_mut();
        if slot.is_none() {
            *slot = Some(why.into());
        }
    }

    /// `Datatype::typeOrderBool`.
    pub fn type_order_bool(&self, a: usize, b: usize) -> i32 {
        if a == b {
            return 0;
        }
        let (x, y) = (&self.tables.types[a], &self.tables.types[b]);
        if x.meta == crate::printc::tree::meta::BOOL {
            return 1;
        }
        if y.meta == crate::printc::tree::meta::BOOL {
            return -1;
        }
        match crate::printc::casts::type_compare(&self.tables, a, b, 10) {
            Ok(order) => order,
            Err(reason) => {
                self.fail(format!("merge:{reason}"));
                0
            }
        }
    }

    // ---- ops ----

    pub fn alive_ops(&self) -> Vec<usize> {
        self.alive.iter().flatten().copied().collect()
    }

    fn mark_alive(&mut self, op: usize) {
        self.ops[op].flags &= !pf::DEAD;
        self.ops[op].alive_at = Some(self.alive.len());
        self.alive.push(Some(op));
    }

    fn mark_dead(&mut self, op: usize) {
        if let Some(at) = self.ops[op].alive_at.take() {
            self.alive[at] = None;
        }
        self.ops[op].flags |= pf::DEAD;
    }

    pub fn op_pos(&self, op: usize) -> Option<usize> {
        let b = self.ops[op].block?;
        self.blocks[b].ops.iter().position(|&o| o == op)
    }

    pub fn previous_op(&self, op: usize) -> Option<usize> {
        let b = self.ops[op].block?;
        let pos = self.op_pos(op)?;
        if pos == 0 { None } else { Some(self.blocks[b].ops[pos - 1]) }
    }

    /// `PcodeOp::nextOp`: crosses into the fall-through block.
    pub fn next_op(&self, op: usize) -> Option<usize> {
        let mut b = self.ops[op].block?;
        let mut pos = self.op_pos(op)? + 1;
        loop {
            if pos < self.blocks[b].ops.len() {
                return Some(self.blocks[b].ops[pos]);
            }
            let outs = self.blocks[b].outs.len();
            if outs != 1 && outs != 2 {
                return None;
            }
            b = self.blocks[b].outs[0];
            pos = 0;
        }
    }

    /// `BlockBasic::insert` at `index`.
    fn block_insert(&mut self, block: usize, index: usize, op: usize) {
        self.ops[op].block = Some(block);
        let n = self.blocks[block].ops.len();
        let before = if index == 0 {
            2
        } else {
            self.ops[self.blocks[block].ops[index - 1]].order
        };
        let after = if index == n {
            let a = before.wrapping_add(0x100_0000);
            if a <= before { u32::MAX } else { a }
        } else {
            self.ops[self.blocks[block].ops[index]].order
        };
        self.blocks[block].ops.insert(index, op);
        if after.wrapping_sub(before) <= 1 {
            // BlockBasic::setOrder
            let n = self.blocks[block].ops.len() as u32;
            let step = (u32::MAX / n).wrapping_sub(1);
            let mut count = 0u32;
            let ids = self.blocks[block].ops.clone();
            for o in ids {
                count = count.wrapping_add(step);
                self.ops[o].order = count;
            }
        } else {
            self.ops[op].order = after / 2 + before / 2;
        }
    }

    fn op_insert(&mut self, op: usize, block: usize, index: usize) {
        self.mark_alive(op);
        self.block_insert(block, index, op);
    }

    pub fn op_insert_before(&mut self, op: usize, follow: usize) {
        self.log.push(Entry::Insert { op, at: At::Before(follow) });
        let parent = self.ops[follow].block.expect("follow in a block");
        let mut iter = self.op_pos(follow).expect("follow position");
        if self.ops[op].code != opc::INDIRECT {
            while iter > 0 {
                let prev = self.blocks[parent].ops[iter - 1];
                if self.ops[prev].code != opc::INDIRECT {
                    break;
                }
                iter -= 1;
            }
        }
        self.op_insert(op, parent, iter);
    }

    pub fn op_insert_after(&mut self, op: usize, prev: usize) {
        self.log.push(Entry::Insert { op, at: At::After(prev) });
        let mut prev = prev;
        if self.ops[prev].is_marker() && self.ops[prev].code == opc::INDIRECT
            && let Some(targ) = self.ops[prev].target
                && !self.ops[targ].is_dead() {
                    prev = targ;
                }
        let parent = self.ops[prev].block.expect("prev in a block");
        let mut iter = self.op_pos(prev).expect("prev position") + 1;
        if self.ops[op].code != opc::MULTIEQUAL {
            while iter < self.blocks[parent].ops.len() {
                let next = self.blocks[parent].ops[iter];
                if self.ops[next].code != opc::MULTIEQUAL {
                    break;
                }
                iter += 1;
            }
        }
        self.op_insert(op, parent, iter);
    }

    pub fn op_insert_begin(&mut self, op: usize, bl: usize) {
        self.log.push(Entry::Insert { op, at: At::Begin(bl) });
        let mut iter = 0;
        if self.ops[op].code != opc::MULTIEQUAL {
            while iter < self.blocks[bl].ops.len()
                && self.ops[self.blocks[bl].ops[iter]].code == opc::MULTIEQUAL
            {
                iter += 1;
            }
        }
        self.op_insert(op, bl, iter);
    }

    pub fn op_insert_end(&mut self, op: usize, bl: usize) {
        self.log.push(Entry::Insert { op, at: At::End(bl) });
        let mut iter = self.blocks[bl].ops.len();
        if iter != 0 && self.ops[self.blocks[bl].ops[iter - 1]].is_flow_break() {
            iter -= 1;
        }
        self.op_insert(op, bl, iter);
    }

    pub fn op_uninsert(&mut self, op: usize) {
        self.log.push(Entry::Uninsert { op });
        self.mark_dead(op);
        if let Some(b) = self.ops[op].block.take() {
            let pos = self.blocks[b].ops.iter().position(|&o| o == op).expect("op in block");
            self.blocks[b].ops.remove(pos);
        }
    }

    /// `Funcdata::newOp(1,addr)` + `opSetOpcode(COPY)`.
    pub fn new_copy_op(&mut self, spec: AddrSpec) -> usize {
        self.log.push(Entry::NewCopy(spec));
        let pc = match spec {
            AddrSpec::OpAddr(o) => self.ops[o].pc,
            AddrSpec::BlockStart(b) => self.blocks[b].start,
            AddrSpec::BlockStop(b) => self.blocks[b].stop,
        };
        let id = self.ops.len();
        self.ops.push(Op {
            time: self.next_time,
            pc,
            code: opc::COPY,
            flags: pf::DEAD | pf::UNARY,
            ins: vec![usize::MAX],
            // `TypeOpCopy`: the input and output local types are both the unknown type of the value's size.
            same_local: vec![1],
            ..Op::default()
        });
        self.next_time += 1;
        id
    }

    // ---- varnodes ----

    pub fn new_unique(&mut self, size: u32, ty_from: usize) -> usize {
        self.log.push(Entry::NewUnique { size, ty_from });
        let ty = self.vns[ty_from].ty;
        let id = self.vns.len();
        let addr = Addr { space: self.unique_space, offset: self.next_unique };
        self.next_unique += u64::from(size);
        let high = self.highs.len();
        self.vns.push(Vn {
            create: self.next_create,
            size,
            addr,
            ty,
            high,
            ..Vn::default()
        });
        self.next_create += 1;
        self.highs.push(High {
            inst: vec![id],
            merge_classes: 1,
            symoff: -1,
            cover_dirty: true,
            ..High::default()
        });
        self.invalidate_loc();
        id
    }

    pub fn invalidate_loc(&self) {
        *self.loc.borrow_mut() = None;
    }

    fn rank(flags: u32) -> u32 {
        (flags & (vf::INPUT | vf::WRITTEN)).wrapping_sub(1)
    }

    /// The varnodes in `VarnodeLocSet` order.
    pub fn loc_order(&self) -> Vec<usize> {
        if let Some(cached) = self.loc.borrow().as_ref() {
            return cached.clone();
        }
        let mut ids: Vec<usize> = (0..self.vns.len()).filter(|&v| !self.vns[v].gone).collect();
        ids.sort_by_key(|&v| {
            let vn = &self.vns[v];
            let (pc, time) = match vn.def {
                Some(d) if vn.is_written() => (self.ops[d].pc, self.ops[d].time),
                _ => (Addr::default(), 0),
            };
            let create = if vn.is_free() { vn.create } else { 0 };
            (vn.addr, vn.size, Self::rank(vn.flags), pc, time, create)
        });
        *self.loc.borrow_mut() = Some(ids.clone());
        ids
    }

    /// The varnodes in `VarnodeDefSet` order, without the free ones.
    pub fn def_order(&self) -> Vec<usize> {
        let mut ids: Vec<usize> = (0..self.vns.len())
            .filter(|&v| !self.vns[v].gone && !self.vns[v].is_free())
            .collect();
        ids.sort_by_key(|&v| {
            let vn = &self.vns[v];
            let (pc, time) = match vn.def {
                Some(d) if vn.is_written() => (self.ops[d].pc, self.ops[d].time),
                _ => (Addr::default(), 0),
            };
            (Self::rank(vn.flags), pc, time, vn.addr, vn.size)
        });
        ids
    }

    pub fn vn_set_flags(&mut self, v: usize, fl: u32) {
        self.vns[v].flags |= fl;
        self.high_flags_dirty(self.vns[v].high);
    }

    pub fn vn_clear_flags(&mut self, v: usize, fl: u32) {
        self.vns[v].flags &= !fl;
        self.high_flags_dirty(self.vns[v].high);
    }

    pub fn high_flags_dirty(&self, h: usize) {
        if h != NO_HIGH {
            self.highs[h].flags_cache.set(None);
        }
    }

    /// `Varnode::setFlags(coverdirty)`.
    pub fn vn_cover_dirty(&mut self, v: usize) {
        self.vns[v].cover_dirty = true;
        let h = self.vns[v].high;
        if h != NO_HIGH {
            self.highs[h].cover_dirty = true;
            if let Some(p) = self.highs[h].piece {
                self.piece_mark_extend_cover_dirty(p);
            }
        }
    }

    /// `Varnode::updateCover`.
    pub fn update_vn_cover(&mut self, v: usize) {
        if self.vns[v].cover_dirty {
            if self.vns[v].has_cover() && self.vns[v].has_cover_obj {
                let mut cover = std::mem::take(&mut self.vns[v].cover);
                cover.rebuild(self, v);
                self.vns[v].cover = cover;
            }
            self.vns[v].cover_dirty = false;
        }
    }

    /// `Funcdata::opSetInput` for a non-constant input.
    pub fn op_set_input(&mut self, op: usize, vn: usize, slot: usize) {
        self.log.push(Entry::SetInput { op, vn, slot });
        if self.ops[op].ins[slot] == vn {
            return;
        }
        let old = self.ops[op].ins[slot];
        if old != usize::MAX {
            self.erase_descend(old, op);
        }
        self.vns[vn].desc.push(op);
        self.vn_cover_dirty(vn);
        self.ops[op].ins[slot] = vn;
    }

    fn erase_descend(&mut self, vn: usize, op: usize) {
        if let Some(pos) = self.vns[vn].desc.iter().position(|&o| o == op) {
            self.vns[vn].desc.remove(pos);
        }
        self.vn_cover_dirty(vn);
    }

    /// `Funcdata::opSetOutput` (the new output must be free, or the op's current output).
    pub fn op_set_output(&mut self, op: usize, vn: usize) {
        self.log.push(Entry::SetOutput { op, vn });
        if self.ops[op].out == Some(vn) {
            return;
        }
        if let Some(cur) = self.ops[op].out {
            self.op_unset_output(op, cur);
        }
        if let Some(d) = self.vns[vn].def {
            self.op_unset_output(d, vn);
        }
        // VarnodeBank::setDef + setVarnodeProperties
        self.vns[vn].def = Some(op);
        self.vns[vn].flags |= vf::WRITTEN | vf::INSERT;
        self.vn_cover_dirty(vn);
        self.high_flags_dirty(self.vns[vn].high);
        if !self.vns[vn].has_cover_obj {
            self.vns[vn].has_cover_obj = true;
            self.vns[vn].cover_dirty = true;
        }
        self.ops[op].out = Some(vn);
        self.invalidate_loc();
    }

    /// `Funcdata::opUnsetOutput` + `VarnodeBank::makeFree`.
    fn op_unset_output(&mut self, op: usize, vn: usize) {
        self.ops[op].out = None;
        self.vns[vn].def = None;
        self.vn_cover_dirty(vn);
        self.vn_clear_flags(vn, vf::WRITTEN | vf::INSERT | vf::INPUT | vf::INDIRECT_CREATION);
        self.vns[vn].cover.clear();
        self.vns[vn].has_cover_obj = false;
        self.invalidate_loc();
    }

    /// `Funcdata::opDestroy`.
    pub fn op_destroy(&mut self, op: usize) {
        self.log.push(Entry::Destroy { op });
        if let Some(out) = self.ops[op].out {
            self.destroy_varnode(out);
        }
        let n = self.ops[op].ins.len();
        for slot in 0..n {
            let vn = self.ops[op].ins[slot];
            if vn != usize::MAX {
                self.erase_descend(vn, op);
                self.ops[op].ins[slot] = usize::MAX;
            }
        }
        if self.ops[op].block.is_some() {
            self.mark_dead(op);
            let b = self.ops[op].block.take().unwrap();
            let pos = self.blocks[b].ops.iter().position(|&o| o == op).expect("op in block");
            self.blocks[b].ops.remove(pos);
        }
    }

    fn destroy_varnode(&mut self, vn: usize) {
        let desc = std::mem::take(&mut self.vns[vn].desc);
        for op in desc {
            if let Some(slot) = self.ops[op].ins.iter().position(|&i| i == vn) {
                self.ops[op].ins[slot] = usize::MAX;
            }
        }
        if let Some(d) = self.vns[vn].def.take() {
            self.ops[d].out = None;
        }
        self.vns[vn].gone = true;
        let h = self.vns[vn].high;
        if h != NO_HIGH && self.highs[h].inst.contains(&vn) {
            // The decompiler removed it from the high before destroying it.
            self.highs[h].inst.retain(|&i| i != vn);
        }
        self.invalidate_loc();
    }

    /// `Funcdata::totalReplace`.
    pub fn total_replace(&mut self, old: usize, new: usize) {
        self.log.push(Entry::TotalReplace { old, new });
        let readers = self.vns[old].desc.clone();
        for op in readers {
            let slot = self.ops[op].ins.iter().position(|&i| i == old).expect("reader slot");
            // The decompiler's own opSetInput (no extra log entry).
            let mark = self.log.len();
            self.op_set_input(op, new, slot);
            self.log.truncate(mark);
        }
    }

    /// `HighVariable::remove`.
    pub fn high_remove(&mut self, vn: usize) {
        self.log.push(Entry::HighRemove { vn });
        let h = self.vns[vn].high;
        if let Some(pos) = self.highs[h].inst.iter().position(|&i| i == vn) {
            self.highs[h].inst.remove(pos);
        }
        let hh = &mut self.highs[h];
        hh.flags_cache.set(None);
        hh.type_cache.set(None);
        hh.cover_dirty = true;
        if let Some(p) = self.highs[h].piece {
            self.piece_mark_extend_cover_dirty(p);
        }
    }

    // ---- flag shorthands ----

    pub fn set_explicit(&mut self, v: usize) {
        self.log.push(Entry::SetExplicit(v));
        self.vn_set_flags(v, vf::EXPLICIT);
        self.extra.explicit += 1;
    }

    pub fn clear_implied(&mut self, v: usize) {
        self.log.push(Entry::ClearImplied(v));
        self.vn_clear_flags(v, vf::IMPLIED);
    }

    /// `Merge::markImplied`.
    pub fn mark_implied(&mut self, v: usize) {
        self.log.push(Entry::MarkImplied(v));
        self.vn_set_flags(v, vf::IMPLIED);
        self.extra.implied += 1;
        let def = self.vns[v].def.expect("implied varnode is written");
        let ins = self.ops[def].ins.clone();
        for i in ins {
            if self.vns[i].has_cover() {
                self.vn_cover_dirty(i);
            }
        }
    }

    pub fn op_mark_non_printing(&mut self, op: usize) {
        self.log.push(Entry::NonPrint(op));
        self.ops[op].flags |= pf::NONPRINTING;
    }

    pub fn op_mark_printing(&mut self, op: usize) {
        self.log.push(Entry::Print(op));
        self.ops[op].flags &= !pf::NONPRINTING;
    }

    pub fn op_mark_special_print(&mut self, op: usize) {
        self.log.push(Entry::SpecialPrint(op));
        self.ops[op].addl |= pf::SPECIAL_PRINT;
    }

    // ---- highs ----

    pub fn high_flags(&self, h: usize) -> u32 {
        let hh = &self.highs[h];
        if let Some(f) = hh.flags_cache.get() {
            return f;
        }
        let mut fl = 0;
        for &i in &hh.inst {
            fl |= self.vns[i].flags;
        }
        let masked = fl & !(vf::MARK | vf::DIRECTWRITE | vf::TYPELOCK);
        hh.flags_cache.set(Some(masked));
        masked
    }

    pub fn h_addr_tied(&self, h: usize) -> bool {
        self.high_flags(h) & vf::ADDRTIED != 0
    }
    pub fn h_input(&self, h: usize) -> bool {
        self.high_flags(h) & vf::INPUT != 0
    }
    pub fn h_persist(&self, h: usize) -> bool {
        self.high_flags(h) & vf::PERSIST != 0
    }
    pub fn h_unaffected(&self, h: usize) -> bool {
        self.high_flags(h) & vf::UNAFFECTED != 0
    }
    pub fn h_proto_partial(&self, h: usize) -> bool {
        self.high_flags(h) & vf::PROTO_PARTIAL != 0
    }
    pub fn h_name_lock(&self, h: usize) -> bool {
        self.high_flags(h) & vf::NAMELOCK != 0
    }
    pub fn h_extra_out(&self, h: usize) -> bool {
        self.high_flags(h) & (vf::INDIRECT_CREATION | vf::ADDRTIED) == vf::INDIRECT_CREATION
    }
    pub fn h_has_cover(&self, h: usize) -> bool {
        self.high_flags(h) & (vf::CONSTANT | vf::ANNOTATION | vf::INSERT) == vf::INSERT
    }
    pub fn h_implied(&self, h: usize) -> bool {
        self.high_flags(h) & vf::IMPLIED != 0
    }
    pub fn h_spacebase(&self, h: usize) -> bool {
        self.high_flags(h) & vf::SPACEBASE != 0
    }

    /// `HighVariable::getTypeRepresentative`.
    pub fn type_rep(&self, h: usize) -> usize {
        let inst = &self.highs[h].inst;
        let mut rep = inst[0];
        for &vn in &inst[1..] {
            if self.vns[rep].is_type_lock() != self.vns[vn].is_type_lock() {
                if self.vns[vn].is_type_lock() {
                    rep = vn;
                }
            } else if self.type_order_bool(self.vns[vn].ty, self.vns[rep].ty) < 0 {
                rep = vn;
            }
        }
        rep
    }

    /// `HighVariable::getType` (`updateType` + `stripType`).
    pub fn h_type(&self, h: usize) -> usize {
        if let Some((t, _)) = self.highs[h].type_cache.get() {
            return t;
        }
        let rep = self.type_rep(h);
        let mut ty = self.vns[rep].ty;
        if let Some(Some(stripped)) = self.stripped.get(ty) {
            // HighVariable::stripType
            let t = &self.tables.types[ty];
            let partial = t.meta == crate::printc::tree::meta::PARTIALUNION || t.meta == crate::printc::tree::meta::PARTIALSTRUCT;
            let strip = if partial {
                let backed = match self.highs[h].symbol {
                    Some(s) => {
                        self.highs[h].symoff != -1
                            && matches!(self.symbols[s].meta, crate::printc::tree::meta::STRUCT | crate::printc::tree::meta::UNION)
                    }
                    None => false,
                };
                !backed
            } else if t.enumerated {
                !(self.highs[h].inst.len() == 1 && self.vns[self.highs[h].inst[0]].is_constant())
            } else {
                true
            };
            if strip {
                ty = *stripped;
            }
        }
        let lock = self.vns[rep].is_type_lock();
        self.highs[h].type_cache.set(Some((ty, lock)));
        ty
    }

    pub fn h_type_lock(&self, h: usize) -> bool {
        self.h_type(h);
        self.highs[h].type_cache.get().map(|(_, l)| l).unwrap_or(false)
    }

    /// `HighVariable::getTiedVarnode`.
    pub fn tied_varnode(&self, h: usize) -> Option<usize> {
        self.highs[h].inst.iter().copied().find(|&v| self.vns[v].is_addr_tied())
    }

    pub fn input_varnode(&self, h: usize) -> Option<usize> {
        self.highs[h].inst.iter().copied().find(|&v| self.vns[v].is_input())
    }

    /// `HighVariable::updateInternalCover`.
    pub fn update_internal_cover(&mut self, h: usize) {
        if !self.highs[h].cover_dirty {
            return;
        }
        let inst = self.highs[h].inst.clone();
        let mut cover = Cover::default();
        if let Some(&first) = inst.first()
            && self.vns[first].has_cover() {
                for &i in &inst {
                    self.update_vn_cover(i);
                }
                for &i in &inst {
                    cover.merge(self, &self.vns[i].cover.clone());
                }
            }
        self.highs[h].cover = cover;
        self.highs[h].cover_dirty = false;
    }

    /// `Varnode::getCover` for a varnode with a cover.
    pub fn vn_cover(&mut self, v: usize) -> &Cover {
        self.update_vn_cover(v);
        &self.vns[v].cover
    }

    /// `HighVariable::mergeInternal` + the bookkeeping of `HighVariable::merge`.
    pub fn merge_high_internal(&mut self, h1: usize, h2: usize, speculative: bool) -> Result<()> {
        if h1 == h2 {
            return Ok(());
        }
        // Symbol inheritance.
        if let Some(sym) = self.highs[h2].symbol {
            self.highs[h1].symbol = Some(sym);
            self.highs[h1].symoff = self.highs[h2].symoff;
        }
        let inst2 = std::mem::take(&mut self.highs[h2].inst);
        if speculative {
            let n1 = self.highs[h1].merge_classes;
            for &i in &inst2 {
                self.vns[i].high = h1;
                self.vns[i].merge_group += n1;
            }
            self.highs[h1].merge_classes += self.highs[h2].merge_classes;
        } else {
            if self.highs[h1].merge_classes != 1 || self.highs[h2].merge_classes != 1 {
                return Err("Making a non-speculative merge after speculative merges have occurred".into());
            }
            for &i in &inst2 {
                self.vns[i].high = h1;
            }
        }
        // std::merge by storage address, stable, the first range first.
        let inst1 = std::mem::take(&mut self.highs[h1].inst);
        let mut merged = Vec::with_capacity(inst1.len() + inst2.len());
        let (mut a, mut b) = (0, 0);
        while a < inst1.len() && b < inst2.len() {
            if self.vns[inst2[b]].addr < self.vns[inst1[a]].addr {
                merged.push(inst2[b]);
                b += 1;
            } else {
                merged.push(inst1[a]);
                a += 1;
            }
        }
        merged.extend_from_slice(&inst1[a..]);
        merged.extend_from_slice(&inst2[b..]);
        self.highs[h1].inst = merged;
        let clean = !self.highs[h1].cover_dirty && !self.highs[h2].cover_dirty;
        if clean {
            let other = self.highs[h2].cover.clone();
            let mut cover = std::mem::take(&mut self.highs[h1].cover);
            cover.merge(self, &other);
            self.highs[h1].cover = cover;
        } else {
            self.highs[h1].cover_dirty = true;
        }
        self.highs[h1].flags_cache.set(None);
        self.highs[h1].type_cache.set(None);
        self.highs[h2].gone = true;
        self.highs[h2].cover = Cover::default();
        Ok(())
    }
}
