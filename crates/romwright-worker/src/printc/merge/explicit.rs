//! `ActionMarkExplicit` and `ActionMarkImplied` (`coreaction.cc`), ported from
//! the pinned Ghidra 12.1.3 decompiler (Apache-2.0).

use super::model::{Func, Result, opc, pf, vf};

const NEW: u32 = 69;
const INSERT: u32 = 70;

impl Func {
    /// `Varnode::loneDescend`.
    pub fn lone_descend(&self, vn: usize) -> Option<usize> {
        if self.vns[vn].desc.len() == 1 { Some(self.vns[vn].desc[0]) } else { None }
    }

    /// `Varnode::contains`: 0 if `b` lies inside `a`.
    fn vn_contains(&self, a: usize, b: usize) -> i32 {
        let (x, y) = (&self.vns[a], &self.vns[b]);
        if x.addr.space != y.addr.space || self.vn_space_kind(a) == super::model::SPACE_CONSTANT {
            return 3;
        }
        if y.addr.offset < x.addr.offset {
            return -1;
        }
        if y.addr.offset >= x.addr.offset + u64::from(x.size) {
            return 2;
        }
        if y.addr.offset + u64::from(y.size) > x.addr.offset + u64::from(x.size) {
            return 1;
        }
        0
    }

    /// `PcodeOp::compareOrder`.
    fn compare_order(&self, a: usize, b: usize) -> bool {
        if self.ops[a].block == self.ops[b].block {
            self.ops[a].order < self.ops[b].order
        } else {
            self.ops[a].block < self.ops[b].block
        }
    }

    /// `PieceNode::findRoot`.
    fn find_root(&self, mut vn: usize) -> usize {
        while self.vns[vn].flags & vf::PROTO_PARTIAL != 0 || self.vns[vn].is_addr_tied() {
            let mut piece_op: Option<usize> = None;
            for &op in &self.vns[vn].desc {
                if self.ops[op].code != opc::PIECE {
                    continue;
                }
                let slot = self.ops[op].ins.iter().position(|&i| i == vn).unwrap();
                let out = self.ops[op].out.unwrap();
                let mut addr = self.vns[out].addr;
                if self.space(addr.space).big_endian == (slot == 1) {
                    addr.offset += u64::from(self.vns[self.ops[op].ins[1 - slot]].size);
                }
                if addr == self.vns[vn].addr {
                    piece_op = match piece_op {
                        Some(p) => {
                            if self.compare_order(op, p) { Some(op) } else { Some(p) }
                        }
                        None => Some(op),
                    };
                }
            }
            match piece_op {
                None => break,
                Some(p) => vn = self.ops[p].out.unwrap(),
            }
        }
        vn
    }

    /// `ActionMarkExplicit::baseExplicit`.
    fn base_explicit(&self, vn: usize, mut maxref: i32) -> i32 {
        let Some(def) = self.vns[vn].def else { return -1 };
        let d = &self.ops[def];
        if d.is_marker() {
            return -1;
        }
        if d.is_call() {
            if d.code == NEW && d.ins.len() == 1 {
                return -2;
            }
            return -1;
        }
        let high = self.vns[vn].high;
        if high != super::model::NO_HIGH && self.highs[high].inst.len() > 1 {
            return -1;
        }
        let v = &self.vns[vn];
        if v.is_addr_tied() {
            if d.code == opc::SUBPIECE {
                let vin = d.ins[0];
                if self.vns[vin].is_addr_tied()
                    && self.vn_overlap(vn, vin) as u64 == self.vns[d.ins[1]].addr.offset
                {
                    return -1;
                }
            }
            let Some(use_op) = self.lone_descend(vn) else { return -1 };
            let u = &self.ops[use_op];
            if u.code == opc::INT_ZEXT {
                let vnout = u.out.unwrap();
                if !self.vns[vnout].is_addr_tied() || self.vn_contains(vnout, vn) != 0 {
                    return -1;
                }
            } else if u.code == opc::PIECE {
                let root = self.find_root(vn);
                if vn == root {
                    return -1;
                }
                if self.ops[self.vns[root].def.unwrap()].addl & pf::CONCAT_ROOT != 0 {
                    return -1;
                }
            } else {
                return -1;
            }
        } else if v.flags & (vf::MAPPED | vf::PROTO_PARTIAL) != 0
            || (d.code == opc::PIECE && self.vns[d.ins[0]].flags & vf::PROTO_PARTIAL != 0)
        {
            return -1;
        }
        if v.has_no_descend() {
            return -1;
        }
        if d.code == INSERT {
            let store = d.out.and_then(|o| self.lone_descend(o));
            match store {
                Some(s) if self.ops[s].code == opc::STORE => {}
                _ => return -1,
            }
        }
        if d.code == opc::PTRSUB {
            let base = d.ins[0];
            if self.vns[base].is_spacebase() && (self.vns[base].is_constant() || self.vns[base].is_input()) {
                maxref = 1_000_000;
            }
        }
        let mut desccount = 0;
        for &op in &v.desc {
            if self.ops[op].is_marker() {
                return -1;
            }
            desccount += 1;
            if desccount > maxref {
                return -1;
            }
        }
        desccount
    }

    /// `ActionMarkExplicit::multipleInteraction`.
    fn multiple_interaction(&mut self, multlist: &[usize]) -> i32 {
        let mut purge: Vec<usize> = Vec::new();
        for &vn in multlist {
            let op = self.vns[vn].def.unwrap();
            let opcode = self.ops[op].code;
            let bool_out = self.ops[op].flags & pf::BOOLOUTPUT != 0;
            if bool_out || opcode == opc::INT_ZEXT || opcode == opc::INT_SEXT || opcode == opc::PTRADD {
                let maxparam = self.ops[op].ins.len().min(2);
                for j in 0..maxparam {
                    let topvn = self.ops[op].ins[j];
                    if self.vns[topvn].mark {
                        let mut topopc = opc::COPY;
                        if self.vns[topvn].is_written() {
                            let td = self.vns[topvn].def.unwrap();
                            if self.ops[td].flags & pf::BOOLOUTPUT != 0 {
                                continue;
                            }
                            topopc = self.ops[td].code;
                        }
                        if opcode == opc::PTRADD {
                            if topopc == opc::PTRADD {
                                purge.push(topvn);
                            }
                        } else {
                            purge.push(topvn);
                        }
                    }
                }
            }
        }
        for &vn in &purge {
            self.set_explicit(vn);
            self.clear_implied(vn);
            self.vns[vn].mark = false;
        }
        purge.len() as i32
    }

    /// `ActionMarkExplicit::processMultiplier`.
    fn process_multiplier(&mut self, vn: usize, max: i32) {
        struct Elem {
            vn: usize,
            slot: usize,
            slotback: usize,
        }
        let make = |f: &Func, v: usize| -> Elem {
            let (mut slot, mut slotback) = (0, 0);
            if f.vns[v].is_written() {
                let d = &f.ops[f.vns[v].def.unwrap()];
                if d.code == opc::LOAD {
                    slot = 1;
                    slotback = 2;
                } else if d.code == opc::PTRADD {
                    slotback = 1;
                } else if d.code == opc::SEGMENTOP {
                    slot = 2;
                    slotback = 3;
                } else {
                    slotback = d.ins.len();
                }
            }
            Elem { vn: v, slot, slotback }
        };
        let mut stack = vec![make(self, vn)];
        let mut finalcount = 0;
        loop {
            let top = stack.len() - 1;
            let vncur = stack[top].vn;
            let isaterm = self.vns[vncur].is_explicit() || !self.vns[vncur].is_written();
            if isaterm || stack[top].slotback <= stack[top].slot {
                if isaterm && !self.vns[vncur].is_spacebase() {
                    finalcount += 1;
                }
                if finalcount > max {
                    self.set_explicit(vn);
                    self.clear_implied(vn);
                    return;
                }
                stack.pop();
            } else {
                let op = self.vns[vncur].def.unwrap();
                let newvn = self.ops[op].ins[stack[top].slot];
                stack[top].slot += 1;
                if self.vns[newvn].mark {
                    self.set_explicit(vn);
                    self.clear_implied(vn);
                }
                stack.push(make(self, newvn));
            }
            if stack.is_empty() {
                break;
            }
        }
    }

    /// `ActionMarkExplicit::checkNewToConstructor`.
    fn check_new_to_constructor(&mut self, vn: usize) {
        let op = self.vns[vn].def.unwrap();
        let bb = self.ops[op].block;
        let mut firstuse: Option<usize> = None;
        for &cur in &self.vns[vn].desc.clone() {
            if self.ops[cur].block != bb {
                continue;
            }
            match firstuse {
                None => firstuse = Some(cur),
                Some(f) => {
                    if self.ops[cur].order < self.ops[f].order {
                        firstuse = Some(cur);
                    } else if self.ops[cur].code == opc::CALLIND {
                        let ptr = self.ops[cur].ins[0];
                        if self.vns[ptr].is_written() && self.vns[ptr].def == Some(f) {
                            firstuse = Some(cur);
                        }
                    }
                }
            }
        }
        let Some(first) = firstuse else { return };
        let f = &self.ops[first];
        if !f.is_call() || f.out.is_some() || f.ins.len() < 2 || f.ins[1] != vn {
            return;
        }
        self.op_mark_special_print(first);
        self.op_mark_non_printing(op);
    }

    /// `ActionMarkExplicit::apply`.
    pub fn mark_explicit(&mut self) {
        let maxref = self.variant.max_implied_ref.unwrap_or(self.max_implied_ref) as i32;
        let forced: Vec<usize> = self.variant_explicit();
        let mut multlist: Vec<usize> = Vec::new();
        for vn in self.def_order() {
            let mut desccount = self.base_explicit(vn, maxref);
            if desccount >= 0 && forced.contains(&vn) {
                desccount = -1;
            }
            if desccount < 0 {
                self.set_explicit(vn);
                if desccount < -1 {
                    self.check_new_to_constructor(vn);
                }
            } else if desccount > 1 {
                self.vns[vn].mark = true;
                multlist.push(vn);
            }
        }
        self.multiple_interaction(&multlist);
        let maxdup = self.variant.max_term_duplication.unwrap_or(self.max_term_dup) as i32;
        for &vn in &multlist {
            if self.vns[vn].mark {
                self.process_multiplier(vn, maxdup);
            }
        }
        for &vn in &multlist {
            self.vns[vn].mark = false;
        }
    }

    // ---- ActionMarkImplied ----

    fn is_possible_alias_step(&self, vn1: usize, vn2: usize) -> bool {
        for (i, &cur) in [vn1, vn2].iter().enumerate() {
            let other = [vn1, vn2][1 - i];
            if !self.vns[cur].is_written() {
                continue;
            }
            let op = &self.ops[self.vns[cur].def.unwrap()];
            if !matches!(op.code, opc::INT_ADD | opc::PTRSUB | opc::PTRADD | opc::INT_XOR) {
                continue;
            }
            if other != op.ins[0] {
                continue;
            }
            if self.vns[op.ins[1]].is_constant() {
                return false;
            }
        }
        true
    }

    /// `functionalEqualityLevel0`.
    fn feq0(&self, a: usize, b: usize) -> i32 {
        if a == b {
            return 0;
        }
        if self.vns[a].size != self.vns[b].size {
            return -1;
        }
        if self.vns[a].is_constant() {
            if self.vns[b].is_constant() {
                return if self.vns[a].addr.offset == self.vns[b].addr.offset { 0 } else { -1 };
            }
            return -1;
        }
        if self.vns[a].is_free() || self.vns[b].is_free() {
            return -1;
        }
        1
    }

    /// `functionalEqualityLevel`.
    fn feq_level(&self, vn1: usize, vn2: usize, res1: &mut [usize; 2], res2: &mut [usize; 2]) -> i32 {
        let testval = self.feq0(vn1, vn2);
        if testval != 1 {
            return testval;
        }
        if !self.vns[vn1].is_written() || !self.vns[vn2].is_written() {
            return -1;
        }
        let (op1, op2) = (self.vns[vn1].def.unwrap(), self.vns[vn2].def.unwrap());
        let opc1 = self.ops[op1].code;
        if opc1 != self.ops[op2].code {
            return -1;
        }
        let mut num = self.ops[op1].ins.len();
        if num != self.ops[op2].ins.len() {
            return -1;
        }
        if self.ops[op1].is_marker() || self.ops[op2].is_call() {
            return -1;
        }
        if opc1 == opc::LOAD && self.ops[op1].pc != self.ops[op2].pc {
            return -1;
        }
        if num >= 3 {
            if opc1 != opc::PTRADD {
                return -1;
            }
            if self.vns[self.ops[op1].ins[2]].addr.offset != self.vns[self.ops[op2].ins[2]].addr.offset {
                return -1;
            }
            num = 2;
        }
        res1[..num].copy_from_slice(&self.ops[op1].ins[..num]);
        res2[..num].copy_from_slice(&self.ops[op2].ins[..num]);
        let mut testval = self.feq0(res1[0], res2[0]);
        if testval == 0 {
            if num == 1 {
                return 0;
            }
            testval = self.feq0(res1[1], res2[1]);
            if testval == 0 {
                return 0;
            }
            if testval < 0 {
                return -1;
            }
            res1[0] = res1[1];
            res2[0] = res2[1];
            return 1;
        }
        if num == 1 {
            return testval;
        }
        let testval2 = self.feq0(res1[1], res2[1]);
        if testval2 == 0 {
            return testval;
        }
        let unmatchsize = if testval == 1 && testval2 == 1 { 2 } else { -1 };
        if self.ops[op1].flags & 0x4000 == 0 {
            return unmatchsize;
        }
        let comm1 = self.feq0(res1[0], res2[1]);
        let comm2 = self.feq0(res1[1], res2[0]);
        if comm1 == 0 && comm2 == 0 {
            return 0;
        }
        if comm1 < 0 || comm2 < 0 {
            return unmatchsize;
        }
        if comm1 == 0 {
            res1[0] = res1[1];
            return 1;
        }
        if comm2 == 0 {
            res2[0] = res2[1];
            return 1;
        }
        if unmatchsize == 2 {
            return 2;
        }
        res2.swap(0, 1);
        2
    }

    fn functional_equality(&self, a: usize, b: usize) -> bool {
        let (mut r1, mut r2) = ([usize::MAX; 2], [usize::MAX; 2]);
        self.feq_level(a, b, &mut r1, &mut r2) == 0
    }

    /// `ActionMarkImplied::isPossibleAlias`.
    fn is_possible_alias(&self, vn1: usize, vn2: usize, mut depth: i32) -> bool {
        if vn1 == vn2 {
            return true;
        }
        if !self.vns[vn1].is_written() || !self.vns[vn2].is_written() {
            if self.vns[vn1].is_constant() && self.vns[vn2].is_constant() {
                return self.vns[vn1].addr.offset == self.vns[vn2].addr.offset;
            }
            return self.is_possible_alias_step(vn1, vn2);
        }
        if !self.is_possible_alias_step(vn1, vn2) {
            return false;
        }
        let (op1, op2) = (self.vns[vn1].def.unwrap(), self.vns[vn2].def.unwrap());
        let mut opc1 = self.ops[op1].code;
        let mut opc2 = self.ops[op2].code;
        let (mut mult1, mut mult2) = (1u64, 1u64);
        if opc1 == opc::PTRSUB {
            opc1 = opc::INT_ADD;
        } else if opc1 == opc::PTRADD {
            opc1 = opc::INT_ADD;
            mult1 = self.vns[self.ops[op1].ins[2]].addr.offset;
        }
        if opc2 == opc::PTRSUB {
            opc2 = opc::INT_ADD;
        } else if opc2 == opc::PTRADD {
            opc2 = opc::INT_ADD;
            mult2 = self.vns[self.ops[op2].ins[2]].addr.offset;
        }
        if opc1 != opc2 {
            return true;
        }
        if depth == 0 {
            return true;
        }
        depth -= 1;
        let (i1, i2) = (&self.ops[op1].ins, &self.ops[op2].ins);
        match opc1 {
            opc::COPY | opc::INT_ZEXT | opc::INT_SEXT | opc::INT_2COMP | opc::INT_NEGATE => {
                self.is_possible_alias(i1[0], i2[0], depth)
            }
            opc::INT_ADD => {
                let (c1, c2) = (i1[1], i2[1]);
                if self.vns[c1].is_constant() && self.vns[c2].is_constant() {
                    let val1 = (mult1 as i64 as u64).wrapping_mul(self.vns[c1].addr.offset);
                    let val2 = (mult2 as i64 as u64).wrapping_mul(self.vns[c2].addr.offset);
                    if val1 == val2 {
                        return self.is_possible_alias(i1[0], i2[0], depth);
                    }
                    return !self.functional_equality(i1[0], i2[0]);
                }
                if mult1 != mult2 {
                    return true;
                }
                if self.functional_equality(i1[0], i2[0]) {
                    return self.is_possible_alias(i1[1], i2[1], depth);
                }
                if self.functional_equality(i1[1], i2[1]) {
                    return self.is_possible_alias(i1[0], i2[0], depth);
                }
                if self.functional_equality(i1[0], i2[1]) {
                    return self.is_possible_alias(i1[1], i2[0], depth);
                }
                if self.functional_equality(i1[1], i2[0]) {
                    return self.is_possible_alias(i1[0], i2[1], depth);
                }
                true
            }
            _ => true,
        }
    }

    /// `ActionMarkImplied::checkImpliedCover`: true when `vn` may be implied.
    fn check_implied_cover(&mut self, vn: usize) -> bool {
        let op = self.vns[vn].def.unwrap();
        self.update_vn_cover(vn);
        let cover = self.vns[vn].cover.clone();
        if self.ops[op].code == opc::LOAD {
            for si in 0..self.store_ops.len() {
                let storeop = self.store_ops[si];
                if self.ops[storeop].is_dead() {
                    continue;
                }
                if cover.contain(self, storeop, 2) {
                    let s0 = self.vns[self.ops[storeop].ins[0]].addr.offset;
                    let l0 = self.vns[self.ops[op].ins[0]].addr.offset;
                    if s0 == l0 && self.is_possible_alias(self.ops[storeop].ins[1], self.ops[op].ins[1], 2) {
                        return false;
                    }
                }
            }
        }
        if self.ops[op].is_call() || self.ops[op].code == opc::LOAD {
            for &callop in &self.calls {
                if cover.contain(self, callop, 2) {
                    return false;
                }
            }
        }
        let high = self.vns[vn].high;
        for i in 0..self.ops[op].ins.len() {
            let defvn = self.ops[op].ins[i];
            if self.vns[defvn].is_constant() {
                continue;
            }
            if self.inflate_test(defvn, high) {
                return false;
            }
        }
        true
    }

    /// `ActionMarkImplied::apply`.
    pub fn mark_implied_action(&mut self) -> Result<()> {
        self.store_ops = self.alive_ops().into_iter().filter(|&o| self.ops[o].code == opc::STORE).collect();
        for vn in self.loc_order() {
            if self.vns[vn].is_free() || self.vns[vn].is_explicit() || self.vns[vn].is_implied() {
                continue;
            }
            let mut stack: Vec<(usize, usize)> = vec![(vn, 0)];
            while let Some(&(cur, iter)) = stack.last() {
                if iter >= self.vns[cur].desc.len() {
                    if !self.check_implied_cover(cur) {
                        self.set_explicit(cur);
                    } else {
                        self.mark_implied(cur);
                    }
                    stack.pop();
                } else {
                    let top = stack.len() - 1;
                    stack[top].1 += 1;
                    let op = self.vns[cur].desc[iter];
                    if let Some(out) = self.ops[op].out
                        && !self.vns[out].is_explicit() && !self.vns[out].is_implied() {
                            stack.push((out, 0));
                        }
                }
            }
        }
        Ok(())
    }
}
