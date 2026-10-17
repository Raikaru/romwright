//! `merge.cc` (and the HighIntersectTest part of `variable.cc`), ported from
//! the pinned Ghidra 12.1.3 decompiler (Apache-2.0) over the mirror in
//! [`super::model`]. Pieces (`VariablePiece`, `groupWith`) are not modelled:
//! a function that needs them is refused.

use super::cover::{Cover, Pt};
use super::model::{
    AddrSpec, Func, NO_HIGH, Result, SPACE_PROCESSOR, SPACE_SPACEBASE, opc, pf, vf,
};
use super::sortcxx::sort_cxx;

fn err<T>(why: &str) -> Result<T> {
    Err(why.to_string())
}

impl Func {
    // ---- Varnode relations (varnode.cc) ----

    /// `Varnode::characterizeOverlap`: 0 none, 1 partial, 2 same.
    pub fn characterize_overlap(&self, a: usize, b: usize) -> i32 {
        let (x, y) = (&self.vns[a], &self.vns[b]);
        if x.addr.space != y.addr.space {
            return 0;
        }
        if x.addr.offset == y.addr.offset {
            return if x.size == y.size { 2 } else { 1 };
        }
        if x.addr.offset < y.addr.offset {
            let right = x.addr.offset + u64::from(x.size - 1);
            if right < y.addr.offset { 0 } else { 1 }
        } else {
            let right = y.addr.offset + u64::from(y.size - 1);
            if right < x.addr.offset { 0 } else { 1 }
        }
    }

    /// `Varnode::overlap`: where the least significant byte of `a` falls in `b`, or -1.
    pub fn vn_overlap(&self, a: usize, b: usize) -> i64 {
        let (x, y) = (&self.vns[a], &self.vns[b]);
        if x.addr.space != y.addr.space {
            return -1;
        }
        let big = self.space(x.addr.space).big_endian;
        let off = if big { x.addr.offset + u64::from(x.size - 1) } else { x.addr.offset };
        let dist = off.wrapping_sub(y.addr.offset);
        if dist >= u64::from(y.size) {
            return -1;
        }
        if big { i64::from(y.size) - 1 - dist as i64 } else { dist as i64 }
    }

    fn copy_source(&self, mut vn: usize) -> usize {
        loop {
            let v = &self.vns[vn];
            if !v.is_written() {
                return vn;
            }
            let d = &self.ops[v.def.unwrap()];
            if d.code != opc::COPY {
                return vn;
            }
            vn = d.ins[0];
        }
    }

    /// `Varnode::copyShadow`.
    pub fn copy_shadow(&self, this: usize, op2: usize) -> bool {
        if this == op2 {
            return true;
        }
        let mut vn = this;
        while self.vns[vn].is_written() && self.ops[self.vns[vn].def.unwrap()].code == opc::COPY {
            vn = self.ops[self.vns[vn].def.unwrap()].ins[0];
            if vn == op2 {
                return true;
            }
        }
        let mut o2 = op2;
        while self.vns[o2].is_written() && self.ops[self.vns[o2].def.unwrap()].code == opc::COPY {
            o2 = self.ops[self.vns[o2].def.unwrap()].ins[0];
            if vn == o2 {
                return true;
            }
        }
        false
    }

    fn find_subpiece_shadow(&self, this: usize, least_byte: i64, whole: usize, mut recurse: i32) -> bool {
        let mut vn = self.copy_source(this);
        if !self.vns[vn].is_written() {
            if self.vns[vn].is_constant() {
                let w = self.copy_source(whole);
                if !self.vns[w].is_constant() {
                    return false;
                }
                let shift = least_byte * 8;
                let mut off = if shift >= 64 { 0 } else { self.vns[w].addr.offset >> shift };
                let size = self.vns[vn].size;
                if size < 8 {
                    off &= (1u64 << (size * 8)) - 1;
                }
                return off == self.vns[vn].addr.offset;
            }
            return false;
        }
        let def = self.vns[vn].def.unwrap();
        let code = self.ops[def].code;
        if code == opc::SUBPIECE {
            let mut tmp = self.ops[def].ins[0];
            let off = self.vns[self.ops[def].ins[1]].addr.offset as i64;
            if off != least_byte || self.vns[tmp].size != self.vns[whole].size {
                return false;
            }
            if tmp == whole {
                return true;
            }
            while self.vns[tmp].is_written() && self.ops[self.vns[tmp].def.unwrap()].code == opc::COPY {
                tmp = self.ops[self.vns[tmp].def.unwrap()].ins[0];
                if tmp == whole {
                    return true;
                }
            }
        } else if code == opc::MULTIEQUAL {
            recurse += 1;
            if recurse > 1 {
                return false;
            }
            let w = self.copy_source(whole);
            if !self.vns[w].is_written() {
                return false;
            }
            let big = self.vns[w].def.unwrap();
            if self.ops[big].code != opc::MULTIEQUAL {
                return false;
            }
            let small = def;
            if self.ops[big].block != self.ops[small].block {
                return false;
            }
            let _ = &mut vn;
            for i in 0..self.ops[small].ins.len() {
                if !self.find_subpiece_shadow(self.ops[small].ins[i], least_byte, self.ops[big].ins[i], recurse) {
                    return false;
                }
            }
            return true;
        }
        false
    }

    fn find_piece_shadow(&self, this: usize, mut least_byte: i64, piece: usize) -> bool {
        let vn = self.copy_source(this);
        if !self.vns[vn].is_written() {
            return false;
        }
        let def = self.vns[vn].def.unwrap();
        if self.ops[def].code != opc::PIECE {
            return false;
        }
        let mut tmp = self.ops[def].ins[1];
        if least_byte >= i64::from(self.vns[tmp].size) {
            least_byte -= i64::from(self.vns[tmp].size);
            tmp = self.ops[def].ins[0];
        } else if i64::from(self.vns[piece].size) + least_byte > i64::from(self.vns[tmp].size) {
            return false;
        }
        if least_byte == 0 && self.vns[tmp].size == self.vns[piece].size {
            if tmp == piece {
                return true;
            }
            while self.vns[tmp].is_written() && self.ops[self.vns[tmp].def.unwrap()].code == opc::COPY {
                tmp = self.ops[self.vns[tmp].def.unwrap()].ins[0];
                if tmp == piece {
                    return true;
                }
            }
            return false;
        }
        self.find_piece_shadow(tmp, least_byte, piece)
    }

    /// `Varnode::partialCopyShadow`.
    pub fn partial_copy_shadow(&self, this: usize, op2: usize, rel_off: i64) -> bool {
        let (vn, op2, rel_off) = if self.vns[this].size < self.vns[op2].size {
            (this, op2, rel_off)
        } else if self.vns[this].size > self.vns[op2].size {
            (op2, this, -rel_off)
        } else {
            return false;
        };
        if rel_off < 0 || rel_off + i64::from(self.vns[vn].size) > i64::from(self.vns[op2].size) {
            return false;
        }
        let big = self.space(self.vns[this].addr.space).big_endian;
        let least = if big {
            i64::from(self.vns[op2].size - self.vns[vn].size) - rel_off
        } else {
            rel_off
        };
        if self.find_subpiece_shadow(vn, least, op2, 0) {
            return true;
        }
        self.find_piece_shadow(op2, least, vn)
    }

    // ---- HighIntersectTest (variable.cc) ----

    fn purge_high(&self, high: usize) {
        let mut cache = self.cache.borrow_mut();
        let keys: Vec<(usize, usize)> = cache
            .range((high, 0)..=(high, usize::MAX))
            .map(|(k, _)| *k)
            .collect();
        for (a, b) in keys {
            cache.remove(&(a, b));
            cache.remove(&(b, a));
        }
    }

    fn cache_get(&self, a: usize, b: usize) -> Option<bool> {
        self.cache.borrow().get(&(a, b)).copied()
    }

    /// `HighIntersectTest::updateHigh`: true when the cover was clean.
    pub fn update_high_test(&mut self, a: usize) -> bool {
        if !self.highs[a].cover_dirty && !self.highs[a].extend_cover_dirty {
            return true;
        }
        self.update_high_cover(a);
        self.purge_high(a);
        false
    }

    /// `HighIntersectTest::moveIntersectTests`.
    pub fn move_intersect_tests(&self, high1: usize, high2: usize) {
        let mut cache = self.cache.borrow_mut();
        let mut yes = Vec::new();
        let mut no = Vec::new();
        for (&(_, b), &v) in cache.range((high2, 0)..=(high2, usize::MAX)) {
            if b == high1 {
                continue;
            }
            if v {
                yes.push(b);
            } else {
                no.push(b);
            }
        }
        let doomed: Vec<(usize, usize)> = cache
            .range((high2, 0)..=(high2, usize::MAX))
            .map(|(k, _)| *k)
            .collect();
        for (a, b) in doomed {
            cache.remove(&(a, b));
            cache.remove(&(b, a));
        }
        let no_set: std::collections::HashSet<usize> = no.into_iter().collect();
        let stale: Vec<(usize, usize)> = cache
            .range((high1, 0)..=(high1, usize::MAX))
            .filter(|(k, v)| !**v && !no_set.contains(&k.1))
            .map(|(k, _)| *k)
            .collect();
        for (a, b) in stale {
            cache.remove(&(a, b));
            cache.remove(&(b, a));
        }
        for b in yes {
            cache.insert((high1, b), true);
            cache.insert((b, high1), true);
        }
    }

    fn gather_block_varnodes(&mut self, a: usize, blk: usize, cover: &Cover) -> Vec<usize> {
        let inst = self.highs[a].inst.clone();
        let mut res = Vec::new();
        for v in inst {
            self.update_vn_cover(v);
            if self.vns[v].cover.intersect_by_block(self, blk, cover) > 1 {
                res.push(v);
            }
        }
        res
    }

    /// `HighIntersectTest::testBlockIntersection`.
    fn test_block_intersection(&mut self, a: usize, blk: usize, cover: &Cover, rel_off: i32, blist: &[usize]) -> bool {
        let inst = self.highs[a].inst.clone();
        for v in inst {
            self.update_vn_cover(v);
            if self.vns[v].cover.intersect_by_block(self, blk, cover) < 2 {
                continue;
            }
            for &v2 in blist {
                self.update_vn_cover(v2);
                if self.vns[v2].cover.intersect_by_block(self, blk, &self.vns[v].cover) > 1 {
                    if self.vns[v].size == self.vns[v2].size {
                        if !self.copy_shadow(v, v2) {
                            return true;
                        }
                    } else if !self.partial_copy_shadow(v, v2, i64::from(rel_off)) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// `HighIntersectTest::blockIntersection`.
    fn block_intersection(&mut self, a: usize, b: usize, blk: usize) -> bool {
        let a_cover = self.high_cover_of(a).clone();
        let b_cover = self.high_cover_of(b).clone();
        let mut blist = self.gather_block_varnodes(b, blk, &a_cover);
        if self.test_block_intersection(a, blk, &b_cover, 0, &blist) {
            return true;
        }
        if let Some(ap) = self.highs[a].piece {
            let base_off = self.pieces[ap].offset;
            for ip in self.pieces[ap].intersection.clone() {
                let off = self.pieces[ip].offset - base_off;
                let ih = self.pieces[ip].high;
                if self.test_block_intersection(ih, blk, &b_cover, off, &blist) {
                    return true;
                }
            }
        }
        if let Some(bp) = self.highs[b].piece {
            let b_base_off = self.pieces[bp].offset;
            for bq in self.pieces[bp].intersection.clone() {
                let b_off = self.pieces[bq].offset - b_base_off;
                let bqh = self.pieces[bq].high;
                blist = self.gather_block_varnodes(bqh, blk, &a_cover);
                if self.test_block_intersection(a, blk, &b_cover, -b_off, &blist) {
                    return true;
                }
                if let Some(ap) = self.highs[a].piece {
                    let base_off = self.pieces[ap].offset;
                    for ip in self.pieces[ap].intersection.clone() {
                        let off = (self.pieces[ip].offset - base_off) - b_off;
                        if off > 0 && off >= self.pieces[bq].size {
                            continue;
                        }
                        if off < 0 && -off >= self.pieces[ip].size {
                            continue;
                        }
                        let ih = self.pieces[ip].high;
                        if self.test_block_intersection(ih, blk, &b_cover, off, &blist) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn populate_affecting(&self) {
        if self.affect_set.borrow().is_some() {
            return;
        }
        let mut ops: Vec<usize> = self.affecting.iter().map(|a| a.op).collect();
        ops.sort_by_key(|&o| (self.ops[o].block.unwrap_or(usize::MAX), self.ops[o].order));
        let mut block_start = Vec::new();
        let mut last = usize::MAX;
        for (i, &o) in ops.iter().enumerate() {
            let b = self.ops[o].block.unwrap_or(usize::MAX);
            if last == usize::MAX || b > last {
                block_start.push(i);
                last = b;
            }
        }
        *self.affect_set.borrow_mut() = Some(super::model::AffectSet { ops, block_start });
    }

    fn affects_test(&self, op: usize, vn: usize) -> bool {
        if self.ops[op].code == opc::STORE {
            match self.affecting.iter().find(|a| a.op == op) {
                Some(a) => match a.guard {
                    None => true,
                    Some((space, min, max)) => {
                        let v = &self.vns[vn];
                        v.addr.space == space && v.addr.offset >= min && v.addr.offset <= max
                    }
                },
                None => true,
            }
        } else {
            true
        }
    }

    /// `Cover::intersect(const PcodeOpSet &, Varnode *)`.
    fn cover_intersects_ops(&self, cover: &Cover, rep: usize) -> bool {
        self.populate_affecting();
        let set = self.affect_set.borrow();
        let set = set.as_ref().unwrap();
        if set.ops.is_empty() {
            return false;
        }
        let mut set_block = 0usize;
        let mut op_index = set.block_start[set_block];
        let mut set_index = self.ops[set.ops[op_index]].block.unwrap_or(0);
        let first_block = self.ops[set.ops[0]].block.unwrap_or(0);
        let mut iter = cover.blocks.range(first_block..).peekable();
        while let Some(&(&cover_index, cb)) = iter.peek() {
            if cover_index < set_index {
                iter.next();
            } else if cover_index > set_index {
                set_block += 1;
                if set_block >= set.block_start.len() {
                    break;
                }
                op_index = set.block_start[set_block];
                set_index = self.ops[set.ops[op_index]].block.unwrap_or(0);
            } else {
                iter.next();
                let mut op_max = set.ops.len();
                set_block += 1;
                if set_block < set.block_start.len() {
                    op_max = set.block_start[set_block];
                }
                loop {
                    let op = set.ops[op_index];
                    if cb.contain(self, Pt::Op(op)) && cb.boundary(self, Pt::Op(op)) == 0 && self.affects_test(op, rep) {
                        return true;
                    }
                    op_index += 1;
                    if op_index >= op_max {
                        break;
                    }
                }
                if set_block >= set.block_start.len() {
                    break;
                }
            }
        }
        false
    }

    fn test_untied_call_intersection(&mut self, tied: usize, untied: usize) -> bool {
        if self.h_persist(tied) {
            return false;
        }
        let Some(vn) = self.tied_varnode(tied) else {
            self.fail("merge:no-tied-varnode");
            return false;
        };
        if self.vns[vn].flags & vf::NOLOCALALIAS != 0 {
            return false;
        }
        let cover = self.high_cover_of(untied).clone();
        self.cover_intersects_ops(&cover, vn)
    }

    /// `HighIntersectTest::intersection`.
    pub fn intersection(&mut self, a: usize, b: usize) -> bool {
        if a == b {
            return false;
        }
        let ares = self.update_high_test(a);
        let bres = self.update_high_test(b);
        if ares && bres
            && let Some(r) = self.cache_get(a, b) {
                return r;
            }
        let mut res = false;
        let blocks = self.high_cover_of(a).intersect_list(self, self.high_cover_of(b), 2);
        for blk in blocks {
            if self.block_intersection(a, b, blk) {
                res = true;
                break;
            }
        }
        if !res {
            let (a_tied, b_tied) = (self.h_addr_tied(a), self.h_addr_tied(b));
            if a_tied != b_tied {
                res = if a_tied {
                    self.test_untied_call_intersection(a, b)
                } else {
                    self.test_untied_call_intersection(b, a)
                };
            }
        }
        let mut cache = self.cache.borrow_mut();
        cache.insert((a, b), res);
        cache.insert((b, a), res);
        res
    }

    // ---- Merge tests ----

    fn symbol_of(&self, h: usize) -> Option<usize> {
        self.highs[h].symbol
    }

    pub fn merge_test_required(&self, high_out: usize, high_in: usize) -> bool {
        if high_in == high_out {
            return true;
        }
        if self.h_type_lock(high_in)
            && self.h_type_lock(high_out)
            && self.h_type(high_in) != self.h_type(high_out)
        {
            return false;
        }
        if self.h_addr_tied(high_out) && self.h_addr_tied(high_in) {
            let (a, b) = (self.tied_varnode(high_in), self.tied_varnode(high_out));
            if let (Some(a), Some(b)) = (a, b)
                && self.vns[a].addr != self.vns[b].addr {
                    return false;
                }
        }
        if self.h_input(high_in) {
            if self.h_persist(high_out) {
                return false;
            }
            if self.h_addr_tied(high_out) && !self.h_addr_tied(high_in) {
                return false;
            }
        } else if self.h_extra_out(high_in) {
            return false;
        }
        if self.h_input(high_out) {
            if self.h_persist(high_in) {
                return false;
            }
            if self.h_addr_tied(high_in) && !self.h_addr_tied(high_out) {
                return false;
            }
        } else if self.h_extra_out(high_out) {
            return false;
        }
        if self.h_proto_partial(high_in)
            && (self.h_proto_partial(high_out)
                || self.h_input(high_out)
                || self.h_addr_tied(high_out)
                || self.h_persist(high_out))
            {
                return false;
            }
        if self.h_proto_partial(high_out)
            && (self.h_input(high_in) || self.h_addr_tied(high_in) || self.h_persist(high_in))
        {
            return false;
        }
        if let (Some(pi), Some(po)) = (self.highs[high_in].piece, self.highs[high_out].piece) {
            let (gi, go) = (self.pieces[pi].group, self.pieces[po].group);
            if gi == go {
                return false;
            }
            if self.pieces[pi].size != self.groups[gi].size && self.pieces[po].size != self.groups[go].size {
                return false;
            }
        }
        if let (Some(si), Some(so)) = (self.symbol_of(high_in), self.symbol_of(high_out)) {
            if si != so {
                return false;
            }
            if self.highs[high_in].symoff != self.highs[high_out].symoff {
                return false;
            }
        }
        true
    }

    fn input_illegal_not_indirect(&self, h: usize) -> bool {
        match self.input_varnode(h) {
            Some(v) => self.vns[v].is_illegal_input() && self.vns[v].flags & vf::INDIRECTONLY == 0,
            None => false,
        }
    }

    pub fn merge_test_adjacent(&self, high_out: usize, high_in: usize) -> bool {
        if !self.merge_test_required(high_out, high_in) {
            return false;
        }
        if self.h_name_lock(high_in) && self.h_name_lock(high_out) {
            return false;
        }
        if self.h_type(high_out) != self.h_type(high_in) {
            return false;
        }
        if self.h_input(high_out) && self.input_illegal_not_indirect(high_out) {
            return false;
        }
        if self.h_input(high_in) && self.input_illegal_not_indirect(high_in) {
            return false;
        }
        for h in [high_in, high_out] {
            if let Some(s) = self.symbol_of(h)
                && self.symbols[s].isolated {
                    return false;
                }
        }
        if self.highs[high_out].piece.is_some() && self.highs[high_in].piece.is_some() {
            return false;
        }
        true
    }

    pub fn merge_test_speculative(&self, high_out: usize, high_in: usize) -> bool {
        if !self.merge_test_adjacent(high_out, high_in) {
            return false;
        }
        if self.h_persist(high_out) || self.h_persist(high_in) {
            return false;
        }
        if self.h_input(high_out) || self.h_input(high_in) {
            return false;
        }
        if self.h_addr_tied(high_out) || self.h_addr_tied(high_in) {
            return false;
        }
        if self.variant_separates(high_out, high_in) {
            return false;
        }
        true
    }

    fn merge_test_must(&self, vn: usize) -> Result<()> {
        if self.vns[vn].has_cover() && !self.vns[vn].is_implied() {
            return Ok(());
        }
        err("Cannot force merge of range")
    }

    pub fn merge_test_basic(&self, vn: Option<usize>) -> bool {
        let Some(vn) = vn else { return false };
        let v = &self.vns[vn];
        v.has_cover() && !v.is_implied() && v.flags & vf::PROTO_PARTIAL == 0 && !v.is_spacebase()
    }

    /// `Merge::merge`.
    pub fn merge(&mut self, high1: usize, high2: usize, speculative: bool) -> Result<bool> {
        if high1 == high2 {
            return Ok(true);
        }
        if self.intersection(high1, high2) {
            return Ok(false);
        }
        let (a, b) = (self.highs[high1].inst[0], self.highs[high2].inst[0]);
        self.log.push(super::model::Entry::Merge { a, b, speculative });
        self.extra.merges += 1;
        if speculative {
            self.extra.speculative += 1;
        }
        self.merge_high(high1, high2, speculative, true)?;
        self.update_high_cover(high1);
        Ok(true)
    }

    /// `Merge::mergeTest`.
    fn merge_test(&mut self, high: usize, tmplist: &mut Vec<usize>) -> bool {
        if !self.h_has_cover(high) {
            return false;
        }
        for &a in tmplist.iter() {
            if self.intersection(a, high) {
                return false;
            }
        }
        tmplist.push(high);
        true
    }

    // ---- merging ----

    fn compare_high_by_block(&self, a: usize, b: usize) -> bool {
        let first = |c: &Cover| c.blocks.keys().next().copied().unwrap_or(1_000_000);
        let (ca, cb) = (first(self.high_cover_of(a)), first(self.high_cover_of(b)));
        if ca != cb {
            return ca < cb;
        }
        let (v1, v2) = (self.highs[a].inst[0], self.highs[b].inst[0]);
        if self.vns[v1].addr == self.vns[v2].addr {
            let (d1, d2) = (self.vns[v1].def, self.vns[v2].def);
            return match (d1, d2) {
                (None, d2) => d2.is_some(),
                (Some(_), None) => false,
                (Some(d1), Some(d2)) => self.ops[d1].pc < self.ops[d2].pc,
            };
        }
        self.vns[v1].addr < self.vns[v2].addr
    }

    fn merge_linear(&mut self, mut highvec: Vec<usize>) -> Result<()> {
        if highvec.len() <= 1 {
            return Ok(());
        }
        for &h in &highvec {
            self.update_high_test(h);
        }
        {
            let this: &Func = self;
            let mut less = |a: &usize, b: &usize| this.compare_high_by_block(*a, *b);
            sort_cxx(&mut highvec, &mut less)?;
        }
        let mut highstack: Vec<usize> = Vec::new();
        for &high in &highvec {
            let mut merged = false;
            for &out in &highstack.clone() {
                if self.merge_test_speculative(out, high) && self.merge(out, high, true)? {
                    merged = true;
                    break;
                }
            }
            if !merged {
                highstack.push(high);
            }
        }
        Ok(())
    }

    fn merge_range_must(&mut self, loc: &[usize], start: usize, end: usize) -> Result<()> {
        let mut vn = loc[start];
        self.merge_test_must(vn)?;
        let mut high = self.vns[vn].high;
        for &v in &loc[start + 1..end] {
            vn = v;
            if self.vns[vn].high == high {
                continue;
            }
            self.merge_test_must(vn)?;
            let h2 = self.vns[vn].high;
            if !self.merge(high, h2, false)? {
                return err("Forced merge caused intersection");
            }
            high = self.vns[vn].high;
        }
        Ok(())
    }

    /// `Merge::mergeOpcode(CPUI_COPY)`.
    pub fn merge_opcode(&mut self, opcode: u32) -> Result<()> {
        for b in 0..self.blocks.len() {
            let ids = self.blocks[b].ops.clone();
            for op in ids {
                if self.ops[op].code != opcode {
                    continue;
                }
                let vn1 = self.ops[op].out;
                if !self.merge_test_basic(vn1) {
                    continue;
                }
                let vn1 = vn1.unwrap();
                for j in 0..self.ops[op].ins.len() {
                    let vn2 = self.ops[op].ins[j];
                    if !self.merge_test_basic(Some(vn2)) {
                        continue;
                    }
                    let (h1, h2) = (self.vns[vn1].high, self.vns[vn2].high);
                    if self.merge_test_required(h1, h2) && !self.variant_separates(h1, h2) {
                        self.merge(h1, h2, false)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// `Merge::mergeByDatatype` over the whole location set.
    pub fn merge_by_datatype(&mut self) -> Result<()> {
        let loc = self.loc_order();
        let mut highlist: Vec<usize> = Vec::new();
        let mut marked: Vec<usize> = Vec::new();
        for &vn in &loc {
            if self.vns[vn].is_free() {
                continue;
            }
            let high = self.vns[vn].high;
            if high == NO_HIGH || self.highs[high].mark {
                continue;
            }
            if !self.merge_test_basic(Some(vn)) {
                continue;
            }
            self.highs[high].mark = true;
            highlist.push(high);
            marked.push(high);
        }
        for &h in &marked {
            self.highs[h].mark = false;
        }
        while !highlist.is_empty() {
            let first = highlist.remove(0);
            let ct = self.h_type(first);
            let mut highvec = vec![first];
            let mut i = 0;
            while i < highlist.len() {
                if self.h_type(highlist[i]) == ct {
                    highvec.push(highlist.remove(i));
                } else {
                    i += 1;
                }
            }
            self.merge_linear(highvec)?;
        }
        Ok(())
    }

    fn get_slot(&self, op: usize, vn: usize) -> usize {
        self.ops[op].ins.iter().position(|&i| i == vn).expect("input slot")
    }

    fn allocate_copy_trim(&mut self, in_vn: usize, addr: AddrSpec, _trim_op: usize) -> Result<usize> {
        if self.vns[in_vn].is_constant() {
            return err("merge:const-trim");
        }
        let ty = self.vns[in_vn].ty;
        if self.tables.types[ty].needs_resolution {
            return err("merge:union-trim");
        }
        let copy = self.new_copy_op(addr);
        let size = self.vns[in_vn].size;
        let out = self.new_unique(size, in_vn);
        self.op_set_output(copy, out);
        self.op_set_input(copy, in_vn, 0);
        self.copy_trims.push(copy);
        Ok(copy)
    }

    fn snip_reads(&mut self, vn: usize, markedop: &[usize]) -> Result<()> {
        if markedop.is_empty() {
            return Ok(());
        }
        let (bl, pc, afterop) = if self.vns[vn].is_input() {
            (0usize, AddrSpec::BlockStart(0), None)
        } else {
            let def = self.vns[vn].def.unwrap();
            let bl = self.ops[def].block.unwrap();
            let after = if self.ops[def].code == opc::INDIRECT {
                match self.ops[def].target {
                    Some(t) => t,
                    None => return err("merge:indirect-target"),
                }
            } else {
                def
            };
            (bl, AddrSpec::OpAddr(def), Some(after))
        };
        let copyop = self.allocate_copy_trim(vn, pc, markedop[0])?;
        match afterop {
            None => self.op_insert_begin(copyop, bl),
            Some(a) => self.op_insert_after(copyop, a),
        }
        let out = self.ops[copyop].out.unwrap();
        for &op in markedop {
            let slot = self.get_slot(op, vn);
            self.op_set_input(op, out, slot);
        }
        Ok(())
    }

    fn eliminate_intersect(&mut self, vn: usize, blocksort: &[(usize, usize)]) -> Result<()> {
        let mut markedop: Vec<usize> = Vec::new();
        let readers = self.vns[vn].desc.clone();
        for op in readers {
            let mut insertop = false;
            let mut single = Cover::default();
            single.add_def_point(self, vn);
            single.add_ref_point(self, op, vn);
            let blocknums: Vec<usize> = single.blocks.keys().copied().collect();
            'blocks: for blocknum in blocknums {
                // BlockVarnode::findFront
                let Some(mut slot) = blocksort.iter().position(|&(_, idx)| idx == blocknum) else {
                    continue;
                };
                while slot < blocksort.len() {
                    if blocksort[slot].1 != blocknum {
                        break;
                    }
                    let vn2 = blocksort[slot].0;
                    slot += 1;
                    if vn2 == vn {
                        continue;
                    }
                    let boundtype = single.contain_varnode_def(self, vn2);
                    if boundtype == 0 {
                        continue;
                    }
                    let overlaptype = self.characterize_overlap(vn, vn2);
                    if overlaptype == 0 {
                        continue;
                    }
                    if overlaptype == 1 {
                        let off = self.vns[vn].addr.offset as i64 - self.vns[vn2].addr.offset as i64;
                        if self.partial_copy_shadow(vn, vn2, off) {
                            continue;
                        }
                    }
                    if boundtype == 2 {
                        if self.vns[vn2].def.is_none() {
                            if self.vns[vn].def.is_none() {
                                if self.vns[vn].create < self.vns[vn2].create {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        } else if let Some(d) = self.vns[vn].def
                            && self.ops[self.vns[vn2].def.unwrap()].order < self.ops[d].order {
                                continue;
                            }
                    } else if boundtype == 3 {
                        if self.vns[vn2].flags & vf::ADDRFORCE == 0 {
                            continue;
                        }
                        if !self.vns[vn2].is_written() {
                            continue;
                        }
                        let indop = self.vns[vn2].def.unwrap();
                        if self.ops[indop].code != opc::INDIRECT {
                            continue;
                        }
                        if self.ops[indop].target != Some(op) {
                            continue;
                        }
                        if overlaptype != 1 {
                            if self.copy_shadow(vn, self.ops[indop].ins[0]) {
                                continue;
                            }
                        } else {
                            let off = self.vns[vn].addr.offset as i64 - self.vns[vn2].addr.offset as i64;
                            if self.partial_copy_shadow(vn, self.ops[indop].ins[0], off) {
                                continue;
                            }
                        }
                    }
                    insertop = true;
                    break;
                }
                if insertop {
                    break 'blocks;
                }
            }
            if insertop {
                markedop.push(op);
            }
        }
        self.snip_reads(vn, &markedop)
    }

    fn unify_address(&mut self, loc: &[usize], start: usize, end: usize) -> Result<()> {
        let isect: Vec<usize> = loc[start..end]
            .iter()
            .copied()
            .filter(|&v| !self.vns[v].is_free())
            .collect();
        let mut blocksort: Vec<(usize, usize)> = isect
            .iter()
            .map(|&v| {
                let idx = match self.vns[v].def {
                    None => 0,
                    Some(d) => self.ops[d].block.unwrap_or(0),
                };
                (v, idx)
            })
            .collect();
        blocksort.sort_by_key(|&(_, idx)| idx); // stable
        for v in isect {
            self.eliminate_intersect(v, &blocksort)?;
        }
        Ok(())
    }

    /// `Merge::mergeAddrTied`.
    pub fn merge_addr_tied(&mut self) -> Result<()> {
        let loc = self.loc_order();
        let n = loc.len();
        let mut start = 0usize;
        while start < n {
            let space = self.vns[loc[start]].addr.space;
            let kind = self.space(space).kind;
            let mut final_i = start;
            while final_i < n && self.vns[loc[final_i]].addr.space == space {
                final_i += 1;
            }
            if kind != SPACE_PROCESSOR && kind != SPACE_SPACEBASE {
                start = final_i;
                continue;
            }
            while start < final_i {
                let vn = loc[start];
                if self.vns[vn].is_free() {
                    start = self.group_end(&loc, start, true);
                    continue;
                }
                let (flags, bounds) = self.overlap_loc(&loc, start);
                let max = bounds.len() - 1;
                if flags & vf::ADDRTIED != 0 {
                    self.unify_address(&loc, start, bounds[max])?;
                    for i in (0..max).step_by(2) {
                        self.merge_range_must(&loc, bounds[i], bounds[i + 1])?;
                    }
                    if max > 2 {
                        let vn1 = loc[bounds[0]];
                        let mut i = 2;
                        while i < max {
                            let vn2 = loc[bounds[i]];
                            let off = (self.vns[vn2].addr.offset as i64 - self.vns[vn1].addr.offset as i64) as i32;
                            let (h2, h1) = (self.vns[vn2].high, self.vns[vn1].high);
                            self.group_with(h2, off, h1)?;
                            i += 2;
                        }
                    }
                }
                start = bounds[max];
            }
        }
        Ok(())
    }

    /// The index after the varnodes of one (storage, size): the non-free ones only, or all.
    fn group_end(&self, loc: &[usize], start: usize, with_free: bool) -> usize {
        let (addr, size) = (self.vns[loc[start]].addr, self.vns[loc[start]].size);
        let mut i = start;
        while i < loc.len() {
            let v = &self.vns[loc[i]];
            if v.addr != addr || v.size != size || (!with_free && v.is_free()) {
                break;
            }
            i += 1;
        }
        i
    }

    /// `VarnodeBank::overlapLoc`.
    fn overlap_loc(&self, loc: &[usize], start: usize) -> (u32, Vec<usize>) {
        let vn = &self.vns[loc[start]];
        let space = vn.addr.space;
        let off = vn.addr.offset;
        let mut max_off = off + u64::from(vn.size - 1);
        let mut flags = vn.flags;
        let mut bounds = vec![start];
        let mut it = self.group_end(loc, start, false);
        bounds.push(it);
        while it < loc.len() {
            let v = &self.vns[loc[it]];
            if v.addr.space != space || v.addr.offset > max_off {
                break;
            }
            if v.is_free() {
                it = self.group_end(loc, it, true);
                continue;
            }
            let end_off = v.addr.offset + u64::from(v.size - 1);
            if end_off > max_off {
                max_off = end_off;
            }
            flags |= v.flags;
            bounds.push(it);
            it = self.group_end(loc, it, false);
            bounds.push(it);
        }
        bounds.push(it);
        (flags, bounds)
    }

    fn trim_op_output(&mut self, op: usize) -> Result<()> {
        let afterop = if self.ops[op].code == opc::INDIRECT {
            match self.ops[op].target {
                Some(t) => t,
                None => return err("merge:indirect-target"),
            }
        } else {
            op
        };
        let vn = self.ops[op].out.unwrap();
        let ty = self.vns[vn].ty;
        if self.tables.types[ty].needs_resolution {
            return err("merge:union-trim");
        }
        let copyop = self.new_copy_op(AddrSpec::OpAddr(op));
        let uniq = self.new_unique(self.vns[vn].size, vn);
        self.op_set_output(op, uniq);
        self.op_set_output(copyop, vn);
        self.op_set_input(copyop, uniq, 0);
        self.op_insert_after(copyop, afterop);
        Ok(())
    }

    fn trim_op_input(&mut self, op: usize, slot: usize) -> Result<()> {
        let pc = if self.ops[op].code == opc::MULTIEQUAL {
            let bb = self.blocks[self.ops[op].block.unwrap()].ins[slot];
            AddrSpec::BlockStop(bb)
        } else {
            AddrSpec::OpAddr(op)
        };
        let vn = self.ops[op].ins[slot];
        let copyop = self.allocate_copy_trim(vn, pc, op)?;
        let out = self.ops[copyop].out.unwrap();
        self.op_set_input(op, out, slot);
        if self.ops[op].code == opc::MULTIEQUAL {
            let bb = self.blocks[self.ops[op].block.unwrap()].ins[slot];
            self.op_insert_end(copyop, bb);
        } else {
            self.op_insert_before(copyop, op);
        }
        Ok(())
    }

    fn merge_op(&mut self, op: usize) -> Result<()> {
        let max = if self.ops[op].code == opc::INDIRECT { 1 } else { self.ops[op].ins.len() };
        let out = self.ops[op].out.unwrap();
        let in_high = |f: &Func, op: usize, i: usize| f.vns[f.ops[op].ins[i]].high;
        for i in 0..max {
            let high_out = self.vns[out].high;
            let high_in = in_high(self, op, i);
            if !self.merge_test_required(high_out, high_in) {
                self.trim_op_input(op, i)?;
                continue;
            }
            for j in 0..i {
                let hj = in_high(self, op, j);
                let high_in = in_high(self, op, i);
                if !self.merge_test_required(hj, high_in) {
                    self.trim_op_input(op, i)?;
                    break;
                }
            }
        }
        let mut testlist: Vec<usize> = Vec::new();
        let high_out = self.vns[out].high;
        self.merge_test(high_out, &mut testlist);
        let mut i = 0;
        while i < max {
            let h = in_high(self, op, i);
            if !self.merge_test(h, &mut testlist) {
                break;
            }
            i += 1;
        }
        if i != max {
            let mut nexttrim = 0;
            while nexttrim < max {
                self.trim_op_input(op, nexttrim)?;
                testlist.clear();
                let high_out = self.vns[out].high;
                self.merge_test(high_out, &mut testlist);
                i = 0;
                while i < max {
                    let h = in_high(self, op, i);
                    if !self.merge_test(h, &mut testlist) {
                        break;
                    }
                    i += 1;
                }
                if i == max {
                    break;
                }
                nexttrim += 1;
            }
            if nexttrim == max {
                self.trim_op_output(op)?;
            }
        }
        for i in 0..max {
            let out = self.ops[op].out.unwrap();
            let h_out = self.vns[out].high;
            let h_in = in_high(self, op, i);
            if !self.merge_test_required(h_out, h_in) {
                return err("Non-cover related merge restriction violated, despite trims");
            }
            if !self.merge(h_out, h_in, false)? {
                return err("Unable to force merge of op");
            }
        }
        Ok(())
    }

    fn collect_inputs(&self, high: usize, mut op: usize) -> Vec<(usize, usize)> {
        let mut list = Vec::new();
        let group = self.group_of_pub(high);
        loop {
            for (i, &vn) in self.ops[op].ins.iter().enumerate() {
                if self.vns[vn].is_annotation() {
                    continue;
                }
                let th = self.vns[vn].high;
                if th == high || (group.is_some() && self.group_of_pub(th) == group) {
                    list.push((op, i));
                }
            }
            match self.previous_op(op) {
                Some(prev) if self.ops[prev].code == opc::INDIRECT => op = prev,
                _ => break,
            }
        }
        list
    }

    fn snip_output_interference(&mut self, indop: usize) -> Result<bool> {
        let Some(op) = self.ops[indop].target else {
            return err("merge:indirect-target");
        };
        let out = self.ops[indop].out.unwrap();
        let mut correctable = self.collect_inputs(self.vns[out].high, op);
        if correctable.is_empty() {
            return Ok(false);
        }
        correctable.sort_by_key(|&(o, s)| self.vns[self.ops[o].ins[s]].high);
        let mut snipop = None;
        let mut cur_high = NO_HIGH;
        for (insertop, slot) in correctable {
            let vn = self.ops[insertop].ins[slot];
            if self.vns[vn].high != cur_high {
                let s = self.allocate_copy_trim(vn, AddrSpec::OpAddr(insertop), insertop)?;
                self.op_insert_before(s, insertop);
                snipop = Some(s);
                cur_high = self.vns[vn].high;
            }
            let out = self.ops[snipop.unwrap()].out.unwrap();
            self.op_set_input(insertop, out, slot);
        }
        Ok(true)
    }

    fn merge_indirect(&mut self, indop: usize) -> Result<()> {
        let outvn = self.ops[indop].out.unwrap();
        if self.vns[outvn].flags & vf::ADDRFORCE == 0 {
            return self.merge_op(indop);
        }
        let invn0 = self.ops[indop].ins[0];
        let (ho, hi) = (self.vns[outvn].high, self.vns[invn0].high);
        if self.merge_test_required(ho, hi) && self.merge(hi, ho, false)? {
            return Ok(());
        }
        if self.snip_output_interference(indop)? {
            let (ho, hi) = (self.vns[outvn].high, self.vns[invn0].high);
            if self.merge_test_required(ho, hi) && self.merge(hi, ho, false)? {
                return Ok(());
            }
        }
        let newop = self.allocate_copy_trim(invn0, AddrSpec::OpAddr(indop), indop)?;
        let out = self.ops[newop].out.unwrap();
        self.op_set_input(indop, out, 0);
        self.op_insert_before(newop, indop);
        let (ho, hi) = (self.vns[outvn].high, self.vns[self.ops[indop].ins[0]].high);
        if !self.merge_test_required(ho, hi) || !self.merge(hi, ho, false)? {
            return err("Unable to merge address forced indirect");
        }
        Ok(())
    }

    /// `Merge::mergeMarker`.
    pub fn merge_marker(&mut self) -> Result<()> {
        let mut i = 0;
        while i < self.alive.len() {
            let Some(op) = self.alive[i] else {
                i += 1;
                continue;
            };
            i += 1;
            if !self.ops[op].is_marker() || self.ops[op].flags & pf::INDIRECT_CREATION != 0 {
                continue;
            }
            if self.ops[op].code == opc::INDIRECT {
                self.merge_indirect(op)?;
            } else {
                self.merge_op(op)?;
            }
        }
        Ok(())
    }

    /// `Merge::mergeAdjacent`.
    pub fn merge_adjacent(&mut self) -> Result<()> {
        for op in self.alive_ops() {
            if self.ops[op].is_call() {
                continue;
            }
            let vn1 = self.ops[op].out;
            if !self.merge_test_basic(vn1) {
                continue;
            }
            let vn1 = vn1.unwrap();
            for i in 0..self.ops[op].ins.len() {
                // `ct != op->inputTypeLocal(i)` as a precomputed bit
                if self.ops[op].same_local.get(i / 32).is_none_or(|w| w & (1 << (i % 32)) == 0) {
                    continue;
                }
                let vn2 = self.ops[op].ins[i];
                if !self.merge_test_basic(Some(vn2)) {
                    continue;
                }
                if self.vns[vn1].size != self.vns[vn2].size {
                    continue;
                }
                if self.vns[vn2].def.is_none() && !self.vns[vn2].is_input() {
                    continue;
                }
                let (h_out, h_in) = (self.vns[vn1].high, self.vns[vn2].high);
                if !self.merge_test_adjacent(h_out, h_in) || self.variant_separates(h_out, h_in) {
                    continue;
                }
                if !self.intersection(h_in, h_out) {
                    self.merge(h_out, h_in, true)?;
                }
            }
        }
        Ok(())
    }

    // ---- shadows and copies ----

    fn find_single_copy(&self, high: usize) -> Vec<usize> {
        let mut list = Vec::new();
        for &vn in &self.highs[high].inst {
            if !self.vns[vn].is_written() {
                continue;
            }
            let op = self.vns[vn].def.unwrap();
            if self.ops[op].code != opc::COPY {
                continue;
            }
            if self.vns[self.ops[op].ins[0]].high == high {
                continue;
            }
            list.push(vn);
        }
        list
    }

    /// `Merge::hideShadows`.
    pub fn hide_shadows(&mut self, high: usize) -> bool {
        let mut singlelist: Vec<Option<usize>> = self.find_single_copy(high).into_iter().map(Some).collect();
        if singlelist.len() <= 1 {
            return false;
        }
        let mut res = false;
        // `singlelist` is rewritten at `j > i` inside the loop, so it cannot be iterated.
        #[allow(clippy::needless_range_loop)]
        for i in 0..singlelist.len() - 1 {
            let Some(vn1) = singlelist[i] else { continue };
            for j in i + 1..singlelist.len() {
                let Some(vn2) = singlelist[j] else { continue };
                if !self.copy_shadow(vn1, vn2) {
                    continue;
                }
                self.update_vn_cover(vn1);
                self.update_vn_cover(vn2);
                let c2 = self.vns[vn2].cover.clone();
                let c1 = self.vns[vn1].cover.clone();
                if c2.contain_varnode_def(self, vn1) == 1 {
                    let d = self.vns[vn1].def.unwrap();
                    self.op_set_input(d, vn2, 0);
                    res = true;
                    break;
                } else if c1.contain_varnode_def(self, vn2) == 1 {
                    let d = self.vns[vn2].def.unwrap();
                    self.op_set_input(d, vn1, 0);
                    singlelist[j] = None;
                    res = true;
                }
            }
        }
        res
    }

    fn check_copy_pair(&mut self, high: usize, dom_op: usize, sub_op: usize) -> bool {
        let dom_block = self.ops[dom_op].block.unwrap();
        let sub_block = self.ops[sub_op].block.unwrap();
        if !self.dominates(dom_block, sub_block) {
            return false;
        }
        let mut range = Cover::default();
        range.add_def_point(self, self.ops[dom_op].out.unwrap());
        range.add_ref_point(self, sub_op, self.ops[sub_op].ins[0]);
        let in_vn = self.ops[dom_op].ins[0];
        for &vn in &self.highs[high].inst {
            if !self.vns[vn].is_written() {
                continue;
            }
            let op = self.vns[vn].def.unwrap();
            if self.ops[op].code == opc::COPY && self.ops[op].ins[0] == in_vn {
                continue;
            }
            if range.contain(self, op, 1) {
                return false;
            }
        }
        true
    }

    /// `FlowBlock::dominates`.
    pub fn dominates(&self, this: usize, sub: usize) -> bool {
        let mut sub = Some(sub);
        while let Some(s) = sub {
            if this > s {
                break;
            }
            if s == this {
                return true;
            }
            sub = self.blocks[s].idom;
        }
        false
    }

    fn find_common_block(&self, set: &[usize]) -> usize {
        let mut marked = std::collections::HashSet::new();
        let mut res = set[0];
        let mut best = res;
        let mut bl = Some(res);
        while let Some(b) = bl {
            marked.insert(b);
            bl = self.blocks[b].idom;
        }
        for &s in &set[1..] {
            if best == 0 {
                break;
            }
            let mut b = s;
            while !marked.contains(&b) {
                marked.insert(b);
                match self.blocks[b].idom {
                    Some(n) => b = n,
                    None => break,
                }
            }
            if b < best {
                res = b;
                best = b;
            }
        }
        res
    }

    fn build_dominant_copy(&mut self, high: usize, copy: &[usize], pos: usize, size: usize) -> Result<()> {
        let block_set: Vec<usize> = (0..size).map(|i| self.ops[copy[pos + i]].block.unwrap()).collect();
        let dom_bl = self.find_common_block(&block_set);
        let mut dom_copy = copy[pos];
        let root_vn = self.ops[dom_copy].ins[0];
        let mut dom_vn = self.ops[dom_copy].out.unwrap();
        let dom_copy_is_new;
        if Some(dom_bl) == self.ops[dom_copy].block {
            dom_copy_is_new = false;
        } else {
            dom_copy_is_new = true;
            if self.tables.types[self.vns[root_vn].ty].needs_resolution {
                return err("merge:union-trim");
            }
            dom_copy = self.new_copy_op(AddrSpec::BlockStop(dom_bl));
            dom_vn = self.new_unique(self.vns[root_vn].size, root_vn);
            self.op_set_output(dom_copy, dom_vn);
            self.op_set_input(dom_copy, root_vn, 0);
            self.op_insert_end(dom_copy, dom_bl);
        }
        let mut b_cover = Cover::default();
        for i in 0..self.highs[high].inst.len() {
            let vn = self.highs[high].inst[i];
            if self.vns[vn].is_written() {
                let op = self.vns[vn].def.unwrap();
                if self.ops[op].code == opc::COPY && self.copy_shadow(self.ops[op].ins[0], root_vn) {
                    continue;
                }
            }
            self.update_vn_cover(vn);
            let c = self.vns[vn].cover.clone();
            b_cover.merge(self, &c);
        }
        let mut count = size as i32;
        let mut marks: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for i in 0..size {
            let op = copy[pos + i];
            if op == dom_copy {
                continue;
            }
            let out_vn = self.ops[op].out.unwrap();
            let mut a_cover = Cover::default();
            a_cover.add_def_point(self, dom_vn);
            for &r in &self.vns[out_vn].desc.clone() {
                a_cover.add_ref_point(self, r, out_vn);
            }
            if b_cover.intersect(self, &a_cover) > 1 {
                count -= 1;
                marks.insert(op);
            }
        }
        if count <= 1 {
            for i in 0..size {
                marks.insert(copy[pos + i]);
            }
            count = 0;
            if dom_copy_is_new {
                self.op_destroy(dom_copy);
            }
        }
        for i in 0..size {
            let op = copy[pos + i];
            if marks.contains(&op) {
                continue;
            }
            let out_vn = self.ops[op].out.unwrap();
            if out_vn != dom_vn {
                self.high_remove(out_vn);
                self.total_replace(out_vn, dom_vn);
                self.op_destroy(op);
            }
        }
        if count > 0 && dom_copy_is_new {
            let (h, d) = (high, self.vns[dom_vn].high);
            self.log.push(super::model::Entry::Merge {
                a: self.highs[h].inst[0],
                b: self.highs[d].inst[0],
                speculative: true,
            });
            self.merge_high(h, d, true, false)?;
        }
        Ok(())
    }

    fn find_all_into_copies(&self, high: usize, filter_temps: bool) -> Vec<usize> {
        let mut copy_ins = Vec::new();
        for &vn in &self.highs[high].inst {
            if !self.vns[vn].is_written() {
                continue;
            }
            let op = self.vns[vn].def.unwrap();
            if self.ops[op].code != opc::COPY {
                continue;
            }
            if self.vns[self.ops[op].ins[0]].high == high {
                continue;
            }
            if filter_temps && self.vn_space_kind(self.ops[op].out.unwrap()) != super::model::SPACE_INTERNAL {
                continue;
            }
            copy_ins.push(op);
        }
        copy_ins.sort_by_key(|&op| {
            let in_vn = self.ops[op].ins[0];
            (self.vns[in_vn].create, self.ops[op].block.unwrap_or(0), self.ops[op].order)
        });
        copy_ins
    }

    fn process_high_dominant_copy(&mut self, high: usize) -> Result<()> {
        let copy_ins = self.find_all_into_copies(high, true);
        if copy_ins.len() < 2 {
            return Ok(());
        }
        let mut pos = 0;
        while pos < copy_ins.len() {
            let in_vn = self.ops[copy_ins[pos]].ins[0];
            let mut sz = 1;
            while pos + sz < copy_ins.len() {
                if self.ops[copy_ins[pos + sz]].ins[0] != in_vn {
                    break;
                }
                sz += 1;
            }
            if sz > 1 {
                self.build_dominant_copy(high, &copy_ins, pos, sz)?;
            }
            pos += sz;
        }
        Ok(())
    }

    fn mark_redundant_copies(&mut self, high: usize, copy: &[usize], pos: usize, size: usize) {
        for i in (1..size).rev() {
            let sub_op = copy[pos + i];
            if self.ops[sub_op].is_dead() {
                continue;
            }
            for j in (0..i).rev() {
                let dom_op = copy[pos + j];
                if self.ops[dom_op].is_dead() {
                    continue;
                }
                if self.check_copy_pair(high, dom_op, sub_op) {
                    self.op_mark_non_printing(sub_op);
                    break;
                }
            }
        }
    }

    fn process_high_redundant_copy(&mut self, high: usize) {
        let copy_ins = self.find_all_into_copies(high, false);
        if copy_ins.len() < 2 {
            return;
        }
        let mut pos = 0;
        while pos < copy_ins.len() {
            let in_vn = self.ops[copy_ins[pos]].ins[0];
            let mut sz = 1;
            while pos + sz < copy_ins.len() {
                if self.ops[copy_ins[pos + sz]].ins[0] != in_vn {
                    break;
                }
                sz += 1;
            }
            if sz > 1 {
                self.mark_redundant_copies(high, &copy_ins, pos, sz);
            }
            pos += sz;
        }
    }

    /// `Merge::processCopyTrims`.
    pub fn process_copy_trims(&mut self) -> Result<()> {
        let trims = std::mem::take(&mut self.copy_trims);
        let mut multi: Vec<usize> = Vec::new();
        for &c in &trims {
            let out = self.ops[c].out.unwrap();
            let high = self.vns[out].high;
            if !self.highs[high].copy_in1 {
                multi.push(high);
                self.highs[high].copy_in1 = true;
            } else {
                self.highs[high].copy_in2 = true;
            }
        }
        for high in multi {
            if self.highs[high].copy_in2 {
                self.process_high_dominant_copy(high)?;
            }
            self.highs[high].copy_in1 = false;
            self.highs[high].copy_in2 = false;
        }
        Ok(())
    }

    fn shadowed_varnode(&mut self, vn: usize) -> bool {
        let high = self.vns[vn].high;
        self.update_vn_cover(vn);
        let c = self.vns[vn].cover.clone();
        for i in 0..self.highs[high].inst.len() {
            let other = self.highs[high].inst[i];
            if other == vn {
                continue;
            }
            self.update_vn_cover(other);
            if c.intersect(self, &self.vns[other].cover) == 2 {
                return true;
            }
        }
        false
    }

    /// `Merge::markInternalCopies`.
    pub fn mark_internal_copies(&mut self) {
        let mut multi: Vec<usize> = Vec::new();
        for op in self.alive_ops() {
            match self.ops[op].code {
                opc::COPY => {
                    let v1 = self.ops[op].out.unwrap();
                    let h1 = self.vns[v1].high;
                    if h1 == self.vns[self.ops[op].ins[0]].high {
                        self.op_mark_non_printing(op);
                    } else {
                        if !self.highs[h1].copy_in1 {
                            self.highs[h1].copy_in1 = true;
                            multi.push(h1);
                        } else {
                            self.highs[h1].copy_in2 = true;
                        }
                        if self.vns[v1].has_no_descend() && self.shadowed_varnode(v1) {
                            self.op_mark_non_printing(op);
                        }
                    }
                }
                opc::PIECE => {
                    let v1 = self.ops[op].out.unwrap();
                    let (v2, v3) = (self.ops[op].ins[0], self.ops[op].ins[1]);
                    let (Some(p1), Some(p2), Some(p3)) = (
                        self.highs[self.vns[v1].high].piece,
                        self.highs[self.vns[v2].high].piece,
                        self.highs[self.vns[v3].high].piece,
                    ) else {
                        continue;
                    };
                    let g = self.pieces[p1].group;
                    if g != self.pieces[p2].group || g != self.pieces[p3].group {
                        continue;
                    }
                    let (o1, o2, o3) = (self.pieces[p1].offset, self.pieces[p2].offset, self.pieces[p3].offset);
                    if self.space(self.vns[v1].addr.space).big_endian {
                        if o2 != o1 || o3 != o1 + self.vns[v2].size as i32 {
                            continue;
                        }
                    } else if o3 != o1 || o2 != o1 + self.vns[v3].size as i32 {
                        continue;
                    }
                    self.op_mark_non_printing(op);
                    for v in [v2, v3] {
                        if self.vns[v].is_implied() {
                            self.clear_implied(v);
                            self.set_explicit(v);
                        }
                    }
                }
                opc::SUBPIECE => {
                    let v1 = self.ops[op].out.unwrap();
                    let v2 = self.ops[op].ins[0];
                    let (Some(p1), Some(p2)) =
                        (self.highs[self.vns[v1].high].piece, self.highs[self.vns[v2].high].piece)
                    else {
                        continue;
                    };
                    if self.pieces[p1].group != self.pieces[p2].group {
                        continue;
                    }
                    let val = self.vns[self.ops[op].ins[1]].addr.offset as i32;
                    let (o1, o2) = (self.pieces[p1].offset, self.pieces[p2].offset);
                    if self.space(self.vns[v1].addr.space).big_endian {
                        if o2 + (self.vns[v2].size as i32 - self.vns[v1].size as i32 - val) != o1 {
                            continue;
                        }
                    } else if o2 + val != o1 {
                        continue;
                    }
                    self.op_mark_non_printing(op);
                    if self.vns[v2].is_implied() {
                        self.clear_implied(v2);
                        self.set_explicit(v2);
                    }
                }
                _ => {}
            }
        }
        for h in multi {
            if self.highs[h].copy_in2 {
                self.process_high_redundant_copy(h);
            }
            self.highs[h].copy_in1 = false;
            self.highs[h].copy_in2 = false;
        }
    }

    /// `Funcdata::checkIndirectUse`.
    fn check_indirect_use(&self, vn: usize) -> bool {
        let mut list = vec![vn];
        let mut seen = std::collections::HashSet::new();
        seen.insert(vn);
        let mut i = 0;
        while i < list.len() {
            let cur = list[i];
            i += 1;
            for &op in &self.vns[cur].desc {
                let code = self.ops[op].code;
                if code == opc::INDIRECT {
                    if self.ops[op].flags & pf::INDIRECT_STORE != 0 {
                        let out = self.ops[op].out.unwrap();
                        if seen.insert(out) {
                            list.push(out);
                        }
                    }
                } else if code == opc::MULTIEQUAL {
                    let out = self.ops[op].out.unwrap();
                    if seen.insert(out) {
                        list.push(out);
                    }
                } else {
                    return false;
                }
            }
        }
        true
    }

    /// `Funcdata::markIndirectOnly`.
    pub fn mark_indirect_only(&mut self) {
        for vn in self.def_order() {
            if !self.vns[vn].is_input() || !self.vns[vn].is_illegal_input() {
                continue;
            }
            if self.check_indirect_use(vn) {
                self.log.push(super::model::Entry::IndirectOnly(vn));
                self.vn_set_flags(vn, vf::INDIRECTONLY);
            }
        }
    }

    /// `ActionHideShadow`.
    pub fn hide_shadow_action(&mut self) {
        let order = self.def_order();
        let mut marked = Vec::new();
        for &vn in &order {
            let high = self.vns[vn].high;
            if self.highs[high].mark {
                continue;
            }
            self.hide_shadows(high);
            self.highs[high].mark = true;
            marked.push(high);
        }
        for h in marked {
            self.highs[h].mark = false;
        }
    }

    /// `Merge::inflateTest`.
    pub fn inflate_test(&mut self, a: usize, high: usize) -> bool {
        let ahigh = self.vns[a].high;
        self.update_high_test(high);
        let high_cover = self.highs[high].cover.clone();
        let inst = self.highs[ahigh].inst.clone();
        for b in inst {
            if self.copy_shadow(b, a) {
                continue;
            }
            self.update_vn_cover(b);
            if self.vns[b].cover.intersect(self, &high_cover) == 2 {
                return true;
            }
        }
        if let Some(piece) = self.highs[ahigh].piece {
            self.piece_update_intersections(piece);
            let base = self.pieces[piece].offset;
            for other in self.pieces[piece].intersection.clone() {
                let other_high = self.pieces[other].high;
                let off = self.pieces[other].offset - base;
                for b in self.highs[other_high].inst.clone() {
                    if self.partial_copy_shadow(b, a, i64::from(off)) {
                        continue;
                    }
                    self.update_vn_cover(b);
                    if self.vns[b].cover.intersect(self, &high_cover) == 2 {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn group_of_pub(&self, h: usize) -> Option<usize> {
        self.highs[h].piece.map(|p| self.pieces[p].group)
    }
}
