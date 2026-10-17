//! The for-loop op moves of `romwright_structure.hh` (`romwrightLoopTransform`,
//! `romwrightLoopFinalize`), which are `BlockWhileDo::finalTransform` /
//! `finalizePrinting` (block.cc) and `Funcdata::moveRespectingCover`
//! (funcdata_op.cc) without the structure around them, ported from the pinned
//! Ghidra 12.1.3 decompiler (Apache-2.0).

use super::model::{Func, LoopRec, opc, pf, vf};

#[derive(Clone, Copy, Default)]
struct Cand {
    head: usize,
    tail: usize,
    loop_def: Option<usize>,
    init: Option<usize>,
    iter: Option<usize>,
}

impl Func {
    /// `PcodeOp::isMoveable`.
    pub fn is_moveable(&self, this: usize, point: usize) -> bool {
        if this == point {
            return true;
        }
        let o = &self.ops[this];
        let mut moving_load = false;
        if o.is_special_eval() {
            if o.code == opc::LOAD {
                moving_load = true;
            } else {
                return false;
            }
        }
        if o.block != self.ops[point].block {
            return false;
        }
        let block = o.block.unwrap();
        if let Some(out) = o.out {
            for &read in &self.vns[out].desc {
                if self.ops[read].block != o.block {
                    continue;
                }
                if self.ops[read].order <= self.ops[point].order {
                    return false;
                }
            }
        }
        let mut cross_calls = false;
        if !o.is_special_eval()
            && let Some(out) = o.out
                && !self.vns[out].is_addr_tied() && self.vns[out].flags & vf::PERSIST == 0
                    && o.ins.iter().all(|&i| !self.vns[i].is_addr_tied() && self.vns[i].flags & vf::PERSIST == 0) {
                        cross_calls = true;
                    }
        let tied: Vec<usize> = o.ins.iter().copied().filter(|&i| self.vns[i].is_addr_tied()).collect();
        let list = &self.blocks[block].ops;
        let mut pos = list.iter().position(|&x| x == this).unwrap();
        let point_pos = list.iter().position(|&x| x == point).unwrap();
        loop {
            pos += 1;
            let op = &self.ops[list[pos]];
            if op.is_special_eval() {
                match op.code {
                    opc::LOAD => {
                        if let Some(out) = o.out
                            && self.vns[out].is_addr_tied() {
                                return false;
                            }
                    }
                    opc::STORE => {
                        if moving_load {
                            return false;
                        }
                        if !tied.is_empty() {
                            return false;
                        }
                        if let Some(out) = o.out
                            && self.vns[out].is_addr_tied() {
                                return false;
                            }
                    }
                    opc::INDIRECT | opc::SEGMENTOP | 68 => {}
                    opc::CALL | opc::CALLIND | 69 => {
                        if !cross_calls {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }
            if let Some(out) = op.out {
                if moving_load && self.vns[out].is_addr_tied() {
                    return false;
                }
                for &t in &tied {
                    if self.vn_overlap(t, out) >= 0 || self.vn_overlap(out, t) >= 0 {
                        return false;
                    }
                }
            }
            if pos == point_pos {
                break;
            }
        }
        true
    }

    /// `HighVariable::markExpression`: the marked highs and what the expression calls or loads.
    fn mark_expression(&mut self, root: usize, list: &mut Vec<usize>) -> u32 {
        let h = self.vns[root].high;
        self.highs[h].mark = true;
        list.push(h);
        let mut ret = 0;
        if !self.vns[root].is_written() {
            return ret;
        }
        let op = self.vns[root].def.unwrap();
        if self.ops[op].is_call() {
            ret |= 1;
        }
        if self.ops[op].code == opc::LOAD {
            ret |= 2;
        }
        let mut path: Vec<(usize, usize)> = vec![(op, 0)];
        while let Some(&(cur, slot)) = path.last() {
            if self.ops[cur].ins.len() <= slot {
                path.pop();
                continue;
            }
            let top = path.len() - 1;
            path[top].1 += 1;
            let vn = self.ops[cur].ins[slot];
            if self.vns[vn].is_annotation() {
                continue;
            }
            if self.vns[vn].is_explicit() {
                let h = self.vns[vn].high;
                if self.highs[h].mark {
                    continue;
                }
                self.highs[h].mark = true;
                list.push(h);
                continue;
            }
            if !self.vns[vn].is_written() {
                continue;
            }
            let d = self.vns[vn].def.unwrap();
            if self.ops[d].is_call() {
                ret |= 1;
            }
            if self.ops[d].code == opc::LOAD {
                ret |= 2;
            }
            path.push((d, 0));
        }
        ret
    }

    /// `Funcdata::moveRespectingCover`.
    fn move_respecting_cover(&mut self, op: usize, last_op: usize) -> bool {
        if op == last_op {
            return true;
        }
        if self.ops[op].is_call() {
            return false;
        }
        let mut prev_op = None;
        if self.ops[op].code == opc::CAST {
            let vn = self.ops[op].ins[0];
            if !self.vns[vn].is_explicit() {
                if !self.vns[vn].is_written() {
                    return false;
                }
                let p = self.vns[vn].def.unwrap();
                if self.ops[p].is_call() {
                    return false;
                }
                if self.previous_op(op) != Some(p) {
                    return false;
                }
                prev_op = Some(p);
            }
        }
        let rootvn = match self.ops[op].out {
            Some(o) => o,
            None => return false,
        };
        let mut high_list = Vec::new();
        let type_val = self.mark_expression(rootvn, &mut high_list);
        let mut cur = op;
        while let Some(next) = self.next_op(cur) {
            let code = self.ops[next].code;
            if code != opc::COPY && code != opc::CAST {
                break;
            }
            if rootvn == self.ops[next].ins[0] {
                break;
            }
            let copy_vn = self.ops[next].out.unwrap();
            if self.highs[self.vns[copy_vn].high].mark {
                break;
            }
            if type_val != 0 && self.vns[copy_vn].is_addr_tied() {
                break;
            }
            cur = next;
            if cur == last_op {
                break;
            }
        }
        for h in high_list {
            self.highs[h].mark = false;
        }
        if cur == last_op {
            self.op_uninsert(op);
            self.op_insert_after(op, last_op);
            if let Some(p) = prev_op {
                self.op_uninsert(p);
                self.op_insert_after(p, last_op);
            }
            return true;
        }
        false
    }

    /// `BlockWhileDo::findLoopVariable`.
    fn find_loop_variable(&self, cand: &mut Cand, cbranch: usize, head: usize, tail: usize, last_op: usize) {
        let vn = self.ops[cbranch].ins[1];
        if !self.vns[vn].is_written() {
            return;
        }
        let op = self.vns[vn].def.unwrap();
        let slot = self.out_rev_index(tail, 0);
        if self.ops[op].is_call() || self.ops[op].is_marker() {
            return;
        }
        let mut path: Vec<(usize, usize)> = vec![(op, 0)];
        let mut count: i32 = 0;
        while count >= 0 {
            let (cur_op, ind) = path[count as usize];
            path[count as usize].1 += 1;
            if ind >= self.ops[cur_op].ins.len() {
                count -= 1;
                continue;
            }
            let next_vn = self.ops[cur_op].ins[ind];
            if !self.vns[next_vn].is_written() {
                continue;
            }
            let def_op = self.vns[next_vn].def.unwrap();
            if self.ops[def_op].code == opc::MULTIEQUAL {
                if self.ops[def_op].block != Some(head) {
                    continue;
                }
                let itvn = self.ops[def_op].ins[slot];
                if !self.vns[itvn].is_written() {
                    continue;
                }
                let possible = self.vns[itvn].def.unwrap();
                if self.ops[possible].block == Some(tail) {
                    if self.ops[possible].is_marker() {
                        continue;
                    }
                    if !self.is_moveable(possible, last_op) {
                        continue;
                    }
                    cand.loop_def = Some(def_op);
                    cand.iter = Some(possible);
                    return;
                }
            } else {
                if count == 3 {
                    continue;
                }
                if self.ops[def_op].is_call() || self.ops[def_op].is_marker() {
                    continue;
                }
                count += 1;
                if path.len() <= count as usize {
                    path.push((def_op, 0));
                } else {
                    path[count as usize] = (def_op, 0);
                }
            }
        }
    }

    /// `FlowBlock::getOutRevIndex(i)`.
    fn out_rev_index(&self, block: usize, i: usize) -> usize {
        self.blocks[block].out_rev[i]
    }

    /// `BlockWhileDo::findInitializer`.
    fn find_initializer(&self, cand: &mut Cand, head: usize, mut slot: usize) -> Option<usize> {
        if self.blocks[head].ins.len() != 2 {
            return None;
        }
        slot = 1 - slot;
        let init_vn = self.ops[cand.loop_def?].ins[slot];
        if !self.vns[init_vn].is_written() {
            return None;
        }
        let res = self.vns[init_vn].def.unwrap();
        if self.ops[res].is_marker() {
            return None;
        }
        let initial_block = self.ops[res].block?;
        if initial_block != self.blocks[head].ins[slot] {
            return None;
        }
        let mut last_op = *self.blocks[initial_block].ops.last()?;
        if self.blocks[initial_block].outs.len() != 1 {
            return None;
        }
        if self.ops[last_op].is_branch() {
            last_op = self.previous_op(last_op)?;
        }
        cand.init = Some(res);
        Some(last_op)
    }

    /// `BlockWhileDo::testTerminal`.
    fn test_terminal(&mut self, cand: &Cand, slot: usize) -> Option<usize> {
        let mut vn = self.ops[cand.loop_def?].ins[slot];
        if !self.vns[vn].is_written() {
            return None;
        }
        let final_op = self.vns[vn].def.unwrap();
        let parent_block = self.blocks[self.ops[cand.loop_def?].block?].ins[slot];
        let mut res_op = final_op;
        if self.ops[final_op].code == opc::COPY && self.ops[final_op].not_printed() {
            vn = self.ops[final_op].ins[0];
            if !self.vns[vn].is_written() {
                return None;
            }
            res_op = self.vns[vn].def.unwrap();
            if self.ops[res_op].block != Some(parent_block) {
                return None;
            }
        }
        if !self.vns[vn].is_explicit() {
            return None;
        }
        if self.ops[res_op].not_printed() {
            return None;
        }
        let fb = self.ops[final_op].block?;
        let mut last_op = *self.blocks[fb].ops.last()?;
        if self.ops[last_op].is_branch() {
            last_op = self.previous_op(last_op)?;
        }
        if !self.move_respecting_cover(final_op, last_op) {
            return None;
        }
        Some(res_op)
    }

    /// `BlockWhileDo::testIterateForm`.
    fn test_iterate_form(&self, cand: &Cand) -> bool {
        let target = self.ops[cand.loop_def.unwrap()].out.unwrap();
        let high = self.vns[target].high;
        let mut path: Vec<(usize, usize)> = vec![(cand.iter.unwrap(), 0)];
        while let Some(&(op, slot)) = path.last() {
            if self.ops[op].ins.len() <= slot {
                path.pop();
                continue;
            }
            let top = path.len() - 1;
            path[top].1 += 1;
            let vn = self.ops[op].ins[slot];
            if self.vns[vn].is_annotation() {
                continue;
            }
            if self.vns[vn].high == high {
                return true;
            }
            if self.vns[vn].is_explicit() {
                continue;
            }
            if !self.vns[vn].is_written() {
                continue;
            }
            path.push((self.vns[vn].def.unwrap(), 0));
        }
        false
    }

    /// `romwrightLoopTransform`: the candidates' iterator and initializer move to the ends of their blocks.
    pub fn loop_transform(&mut self) {
        if !self.analyze_loops {
            return;
        }
        let candidates = self.loop_candidates.clone();
        for c in candidates {
            let (head, test, tail) = (c.head, c.test, c.tail);
            let cbranch = match self.blocks[test].ops.last() {
                Some(&o) if self.ops[o].code == opc::CBRANCH => o,
                _ => continue,
            };
            let Some(&last) = self.blocks[tail].ops.last() else { continue };
            let mut last_op = last;
            if self.blocks[tail].outs.len() != 1 || self.blocks[tail].outs[0] != head {
                continue;
            }
            if self.ops[last_op].is_branch() {
                match self.previous_op(last_op) {
                    Some(p) => last_op = p,
                    None => continue,
                }
            }
            let mut cand = Cand { head, tail, ..Cand::default() };
            self.find_loop_variable(&mut cand, cbranch, head, tail, last_op);
            let Some(iter) = cand.iter else { continue };
            if iter != last_op {
                self.op_uninsert(iter);
                self.op_insert_after(iter, last_op);
            }
            let slot = self.out_rev_index(tail, 0);
            if let Some(last) = self.find_initializer(&mut cand, head, slot) {
                let init = cand.init.unwrap();
                if !self.is_moveable(init, last) {
                    cand.init = None;
                } else if init != last {
                    self.op_uninsert(init);
                    self.op_insert_after(init, last);
                }
            }
            self.pending_loops.push(super::model::PendingLoop {
                head,
                tail,
                loop_def: cand.loop_def,
                init: cand.init,
                iter: cand.iter,
            });
        }
    }

    /// `romwrightLoopFinalize`.
    pub fn loop_finalize(&mut self) {
        let pending = std::mem::take(&mut self.pending_loops);
        let mut kept: Vec<LoopRec> = Vec::new();
        for p in pending {
            let mut cand = Cand {
                head: p.head,
                tail: p.tail,
                loop_def: p.loop_def,
                init: p.init,
                iter: p.iter,
            };
            let iter_block = self.ops[cand.iter.unwrap()].block.unwrap();
            let slot = self.out_rev_index(iter_block, 0);
            cand.iter = self.test_terminal(&cand, slot);
            if cand.iter.is_none() {
                continue;
            }
            if !self.test_iterate_form(&cand) {
                continue;
            }
            if cand.init.is_none() {
                let head = self.ops[cand.loop_def.unwrap()].block.unwrap();
                self.find_initializer(&mut cand, head, slot);
            }
            if cand.init.is_some() {
                cand.init = self.test_terminal(&cand, 1 - slot);
            }
            self.op_mark_non_printing(cand.iter.unwrap());
            if let Some(i) = cand.init {
                self.op_mark_non_printing(i);
            }
            kept.push(LoopRec { head: cand.head, tail: cand.tail, init: cand.init, iter: cand.iter });
        }
        for l in &kept {
            self.op_mark_printing(l.iter.unwrap());
            if let Some(i) = l.init {
                self.op_mark_printing(i);
            }
        }
        self.loops = kept;
        let _ = pf::BRANCH;
    }
}
