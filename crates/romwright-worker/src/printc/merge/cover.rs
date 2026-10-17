//! `cover.cc`: the topological scope of a value, a map from basic block to an
//! interval of the block's ops (ported from the pinned Ghidra 12.1.3
//! decompiler, Apache-2.0).

use super::model::{Func, opc};
use std::collections::BTreeMap;

/// A `CoverBlock` boundary: the special pointers 0, 1, 2 or an op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pt {
    /// Null: the very beginning of the block (or an empty block).
    Zero,
    /// The very end of the block.
    One,
    /// The marker of a function input.
    Two,
    Op(usize),
}

/// `CoverBlock::getUIndex`.
pub fn uindex(f: &Func, p: Pt) -> u32 {
    match p {
        Pt::Zero => 0,
        Pt::One => u32::MAX,
        Pt::Two => 0,
        Pt::Op(o) => {
            let op = &f.ops[o];
            if op.is_marker() {
                if op.code == opc::MULTIEQUAL {
                    return 0;
                } else if op.code == opc::INDIRECT
                    && let Some(t) = op.target {
                        return f.ops[t].order;
                    }
            }
            op.order
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverBlock {
    pub start: Pt,
    pub stop: Pt,
}

impl Default for CoverBlock {
    fn default() -> Self {
        CoverBlock {
            start: Pt::Zero,
            stop: Pt::Zero,
        }
    }
}

impl CoverBlock {
    pub fn empty(&self) -> bool {
        self.start == Pt::Zero && self.stop == Pt::Zero
    }

    pub fn set_all(&mut self) {
        self.start = Pt::Zero;
        self.stop = Pt::One;
    }

    pub fn set_begin(&mut self, begin: Pt) {
        self.start = begin;
        if self.stop == Pt::Zero {
            self.stop = Pt::One;
        }
    }

    pub fn set_end(&mut self, end: Pt) {
        self.stop = end;
    }

    /// `CoverBlock::intersect`: 0 none, 1 boundary, 2 interval.
    pub fn intersect(&self, f: &Func, op2: &CoverBlock) -> i32 {
        if self.empty() || op2.empty() {
            return 0;
        }
        let ustart = uindex(f, self.start);
        let ustop = uindex(f, self.stop);
        let u2start = uindex(f, op2.start);
        let u2stop = uindex(f, op2.stop);
        if ustart <= ustop {
            if u2start <= u2stop {
                if ustop <= u2start || u2stop <= ustart {
                    return if ustart == u2stop || ustop == u2start { 1 } else { 0 };
                }
            } else if ustart >= u2stop && ustop <= u2start {
                return if ustart == u2stop || ustop == u2start { 1 } else { 0 };
            }
        } else if u2start <= u2stop && u2start >= ustop && u2stop <= ustart {
            return if u2start == ustop || u2stop == ustart { 1 } else { 0 };
        }
        2
    }

    pub fn contain(&self, f: &Func, point: Pt) -> bool {
        if self.empty() {
            return false;
        }
        let upoint = uindex(f, point);
        let ustart = uindex(f, self.start);
        let ustop = uindex(f, self.stop);
        if ustart <= ustop {
            upoint >= ustart && upoint <= ustop
        } else {
            upoint <= ustop || upoint >= ustart
        }
    }

    /// 0 not on a boundary, 1 on the tail, 2 on the defining point.
    pub fn boundary(&self, f: &Func, point: Pt) -> i32 {
        if self.empty() {
            return 0;
        }
        let val = uindex(f, point);
        if uindex(f, self.start) == val && self.start != Pt::Zero {
            return 2;
        }
        if uindex(f, self.stop) == val {
            return 1;
        }
        0
    }

    pub fn merge(&mut self, f: &Func, op2: &CoverBlock) {
        if op2.empty() {
            return;
        }
        if self.empty() {
            *self = *op2;
            return;
        }
        let ustart = uindex(f, self.start);
        let u2start = uindex(f, op2.start);
        let internal4 = ustart == 0 && op2.stop == Pt::One;
        let internal1 = internal4 || op2.contain(f, self.start);
        let internal3 = u2start == 0 && self.stop == Pt::One;
        let internal2 = internal3 || self.contain(f, op2.start);
        if internal1 && internal2 && (ustart != u2start || internal3 || internal4) {
            self.set_all();
            return;
        }
        if internal1 {
            self.start = op2.start;
        } else if !internal1 && !internal2 {
            if ustart < u2start {
                self.stop = op2.stop;
            } else {
                self.start = op2.start;
            }
            return;
        }
        if internal3 || op2.contain(f, self.stop) {
            self.stop = op2.stop;
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cover {
    pub blocks: BTreeMap<usize, CoverBlock>,
}

impl Cover {
    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    /// `Cover::intersect(const Cover &)`.
    pub fn intersect(&self, f: &Func, op2: &Cover) -> i32 {
        let mut res = 0;
        let mut a = self.blocks.iter().peekable();
        let mut b = op2.blocks.iter().peekable();
        loop {
            let (Some(&(ka, va)), Some(&(kb, vb))) = (a.peek(), b.peek()) else {
                return res;
            };
            if ka < kb {
                a.next();
            } else if ka > kb {
                b.next();
            } else {
                let new = va.intersect(f, vb);
                if new == 2 {
                    return 2;
                }
                if new == 1 {
                    res = 1;
                }
                a.next();
                b.next();
            }
        }
    }

    pub fn intersect_list(&self, f: &Func, op2: &Cover, level: i32) -> Vec<usize> {
        let mut out = Vec::new();
        let mut a = self.blocks.iter().peekable();
        let mut b = op2.blocks.iter().peekable();
        loop {
            let (Some(&(ka, va)), Some(&(kb, vb))) = (a.peek(), b.peek()) else {
                return out;
            };
            if ka < kb {
                a.next();
            } else if ka > kb {
                b.next();
            } else {
                if va.intersect(f, vb) >= level {
                    out.push(*ka);
                }
                a.next();
                b.next();
            }
        }
    }

    pub fn intersect_by_block(&self, f: &Func, blk: usize, op2: &Cover) -> i32 {
        let (Some(a), Some(b)) = (self.blocks.get(&blk), op2.blocks.get(&blk)) else {
            return 0;
        };
        a.intersect(f, b)
    }

    /// `Cover::contain(op, max)`.
    pub fn contain(&self, f: &Func, op: usize, max: i32) -> bool {
        let Some(block) = f.ops[op].block else {
            return false;
        };
        let Some(cb) = self.blocks.get(&block) else {
            return false;
        };
        if cb.contain(f, Pt::Op(op)) {
            if max == 1 {
                return true;
            }
            if cb.boundary(f, Pt::Op(op)) == 0 {
                return true;
            }
        }
        false
    }

    /// `Cover::containVarnodeDef`.
    pub fn contain_varnode_def(&self, f: &Func, vn: usize) -> i32 {
        let v = &f.vns[vn];
        let (point, blk) = match v.def {
            Some(op) => (Pt::Op(op), f.ops[op].block.unwrap_or(usize::MAX)),
            None => (Pt::Two, 0),
        };
        let Some(cb) = self.blocks.get(&blk) else {
            return 0;
        };
        if cb.contain(f, point) {
            return match cb.boundary(f, point) {
                0 => 1,
                2 => 2,
                _ => 3,
            };
        }
        0
    }

    pub fn merge(&mut self, f: &Func, op2: &Cover) {
        for (blk, cb) in &op2.blocks {
            self.blocks.entry(*blk).or_default().merge(f, cb);
        }
    }

    /// `Cover::rebuild`.
    pub fn rebuild(&mut self, f: &Func, vn: usize) {
        let mut path = vec![vn];
        let mut pos = 0;
        self.add_def_point(f, vn);
        while pos < path.len() {
            let cur = path[pos];
            pos += 1;
            for &op in &f.vns[cur].desc {
                self.add_ref_point(f, op, vn);
                if let Some(out) = f.ops[op].out
                    && f.vns[out].is_implied() {
                        path.push(out);
                    }
            }
        }
    }

    pub fn add_def_point(&mut self, f: &Func, vn: usize) {
        self.blocks.clear();
        let v = &f.vns[vn];
        if let Some(def) = v.def {
            if let Some(b) = f.ops[def].block {
                let block = self.blocks.entry(b).or_default();
                block.set_begin(Pt::Op(def));
                block.set_end(Pt::Op(def));
            }
        } else if v.is_input() {
            let block = self.blocks.entry(0).or_default();
            block.set_begin(Pt::Two);
            block.set_end(Pt::Two);
        }
    }

    fn add_ref_recurse(&mut self, f: &Func, start: usize) {
        let mut stack = vec![start];
        while let Some(bl) = stack.pop() {
            let block = self.blocks.entry(bl).or_default();
            if block.empty() {
                block.set_all();
                for &j in f.blocks[bl].ins.iter().rev() {
                    stack.push(j);
                }
            } else {
                let op = block.stop;
                let ustart = uindex(f, block.start);
                let ustop = uindex(f, op);
                if ustop != u32::MAX && ustop >= ustart {
                    block.set_end(Pt::One);
                }
                if ustop == 0 && block.start == Pt::Zero
                    && let Pt::Op(o) = op
                        && f.ops[o].code == opc::MULTIEQUAL {
                            for &j in f.blocks[bl].ins.iter().rev() {
                                stack.push(j);
                            }
                        }
            }
        }
    }

    pub fn add_ref_point(&mut self, f: &Func, reference: usize, vn: usize) {
        let bl = f.ops[reference].block.expect("ref op in a block");
        let block = self.blocks.entry(bl).or_default();
        if block.empty() {
            block.set_end(Pt::Op(reference));
        } else if block.contain(f, Pt::Op(reference)) {
            if f.ops[reference].code != opc::MULTIEQUAL {
                return;
            }
        } else {
            let op = block.stop;
            let startop = block.start;
            block.set_end(Pt::Op(reference));
            let ustop = uindex(f, block.stop);
            if ustop >= uindex(f, startop) {
                if let Pt::Op(o) = op
                    && f.ops[o].code == opc::MULTIEQUAL && startop == Pt::Zero {
                        for &j in f.blocks[bl].ins.iter() {
                            self.add_ref_recurse(f, j);
                        }
                    }
                return;
            }
        }
        if f.ops[reference].code == opc::MULTIEQUAL {
            for (j, &input) in f.ops[reference].ins.iter().enumerate() {
                if input == vn {
                    self.add_ref_recurse(f, f.blocks[bl].ins[j]);
                }
            }
        } else {
            for &j in f.blocks[bl].ins.iter() {
                self.add_ref_recurse(f, j);
            }
        }
    }
}
