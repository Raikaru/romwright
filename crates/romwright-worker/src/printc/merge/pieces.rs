//! `VariableGroup` / `VariablePiece` (variable.cc), `Merge::groupPartials`,
//! `Merge::groupPartialRoot` and `PieceNode::gatherPieces` (op.cc), ported
//! from the pinned Ghidra 12.1.3 decompiler (Apache-2.0).

use super::cover::Cover;
use super::model::{Entry, Func, Group, Piece, Result, pf, vf};

fn err<T>(why: &str) -> Result<T> {
    Err(why.to_string())
}

/// `PieceNode`: one edge of a CONCAT tree.
#[derive(Clone, Copy)]
struct PieceNode {
    op: usize,
    slot: usize,
    type_offset: i32,
}

impl Func {
    pub fn high_cover_of(&self, h: usize) -> &Cover {
        match self.highs[h].piece {
            Some(p) => &self.pieces[p].cover,
            None => &self.highs[h].cover,
        }
    }

    fn group_of(&self, h: usize) -> Option<usize> {
        self.highs[h].piece.map(|p| self.pieces[p].group)
    }

    // ---- VariableGroup ----

    fn group_add_piece(&mut self, group: usize, piece: usize) -> Result<()> {
        let key = (self.pieces[piece].offset, self.pieces[piece].size);
        let existing = self.groups[group].pieces.clone();
        let mut at = existing.len();
        for (i, &q) in existing.iter().enumerate() {
            let k = (self.pieces[q].offset, self.pieces[q].size);
            if k == key {
                return err("Duplicate VariablePiece");
            }
            if k > key {
                at = i;
                break;
            }
        }
        self.pieces[piece].group = group;
        self.groups[group].pieces.insert(at, piece);
        let max = key.0 + key.1;
        if max > self.groups[group].size {
            self.groups[group].size = max;
        }
        Ok(())
    }

    fn group_remove_piece(&mut self, group: usize, piece: usize) {
        self.groups[group].pieces.retain(|&p| p != piece);
    }

    pub fn group_adjust_offsets(&mut self, group: usize, amt: i32) {
        for p in self.groups[group].pieces.clone() {
            self.pieces[p].offset += amt;
        }
        self.groups[group].size += amt;
    }

    // ---- VariablePiece ----

    fn new_piece(&mut self, high: usize, offset: i32, grp: Option<usize>) -> Result<usize> {
        let size = self.vns[self.highs[high].inst[0]].size as i32;
        let group = match grp {
            Some(g) => self.group_of(g).ok_or("merge:group-without-piece")?,
            None => {
                self.groups.push(Group::default());
                self.groups.len() - 1
            }
        };
        let id = self.pieces.len();
        self.pieces.push(Piece { high, group, offset, size, ..Piece::default() });
        self.group_add_piece(group, id)?;
        Ok(id)
    }

    /// `VariablePiece::markIntersectionDirty`.
    pub fn piece_mark_intersection_dirty(&mut self, piece: usize) {
        let group = self.pieces[piece].group;
        for q in self.groups[group].pieces.clone() {
            let h = self.pieces[q].high;
            self.highs[h].intersect_dirty = true;
            self.highs[h].extend_cover_dirty = true;
        }
    }

    /// `VariablePiece::markExtendCoverDirty`.
    pub fn piece_mark_extend_cover_dirty(&mut self, piece: usize) {
        let h = self.pieces[piece].high;
        if self.highs[h].intersect_dirty {
            return;
        }
        for q in self.pieces[piece].intersection.clone() {
            let qh = self.pieces[q].high;
            self.highs[qh].extend_cover_dirty = true;
        }
        self.highs[h].extend_cover_dirty = true;
    }

    /// `~VariablePiece`.
    fn delete_piece(&mut self, piece: usize) {
        let group = self.pieces[piece].group;
        self.group_remove_piece(group, piece);
        self.pieces[piece].gone = true;
        if self.groups[group].pieces.is_empty() {
            self.groups[group].gone = true;
        } else {
            let any = self.groups[group].pieces[0];
            self.piece_mark_intersection_dirty(any);
        }
    }

    /// `VariablePiece::updateIntersections`.
    pub fn piece_update_intersections(&mut self, piece: usize) {
        let h = self.pieces[piece].high;
        if !self.highs[h].intersect_dirty {
            return;
        }
        let (offset, size) = (self.pieces[piece].offset, self.pieces[piece].size);
        let end = offset + size;
        let mut list = Vec::new();
        for &q in &self.groups[self.pieces[piece].group].pieces {
            if q == piece {
                continue;
            }
            let o = &self.pieces[q];
            if end <= o.offset {
                continue;
            }
            if offset >= o.offset + o.size {
                continue;
            }
            list.push(q);
        }
        self.pieces[piece].intersection = list;
        self.highs[h].intersect_dirty = false;
    }

    /// `VariablePiece::updateCover`.
    fn piece_update_cover(&mut self, piece: usize) {
        let h = self.pieces[piece].high;
        if !self.highs[h].cover_dirty && !self.highs[h].extend_cover_dirty {
            return;
        }
        self.update_internal_cover(h);
        let mut cover = self.highs[h].cover.clone();
        for q in self.pieces[piece].intersection.clone() {
            let qh = self.pieces[q].high;
            self.update_internal_cover(qh);
            let other = self.highs[qh].cover.clone();
            cover.merge(self, &other);
        }
        self.pieces[piece].cover = cover;
        self.highs[h].extend_cover_dirty = false;
    }

    /// `HighVariable::updateCover`.
    pub fn update_high_cover(&mut self, h: usize) {
        match self.highs[h].piece {
            None => self.update_internal_cover(h),
            Some(p) => {
                self.piece_update_intersections(p);
                self.piece_update_cover(p);
            }
        }
    }

    fn piece_transfer_group(&mut self, piece: usize, new_group: usize) -> Result<()> {
        let old = self.pieces[piece].group;
        self.group_remove_piece(old, piece);
        if self.groups[old].pieces.is_empty() {
            self.groups[old].gone = true;
        }
        self.group_add_piece(new_group, piece)
    }

    /// `VariablePiece::mergeGroups`: the pairs of highs that must be merged.
    fn piece_merge_groups(&mut self, piece: usize, op2: usize, pairs: &mut Vec<usize>) -> Result<()> {
        let group = self.pieces[piece].group;
        let group2 = self.pieces[op2].group;
        let diff = self.pieces[piece].offset - self.pieces[op2].offset;
        if diff > 0 {
            self.group_adjust_offsets(group2, diff);
        } else if diff < 0 {
            self.group_adjust_offsets(group, -diff);
        }
        for q in self.groups[group2].pieces.clone() {
            let key = (self.pieces[q].offset, self.pieces[q].size);
            let matched = self.groups[group]
                .pieces
                .iter()
                .copied()
                .find(|&m| (self.pieces[m].offset, self.pieces[m].size) == key);
            if let Some(m) = matched {
                pairs.push(self.pieces[m].high);
                pairs.push(self.pieces[q].high);
                let qh = self.pieces[q].high;
                self.highs[qh].piece = None;
                self.delete_piece(q);
            } else {
                self.piece_transfer_group(q, group)?;
            }
        }
        Ok(())
    }

    /// `HighVariable::groupWith`.
    pub fn group_with(&mut self, this: usize, off: i32, hi2: usize) -> Result<()> {
        self.log.push(Entry::GroupWith {
            a: self.highs[this].inst[0],
            b: self.highs[hi2].inst[0],
            off,
        });
        let (p1, p2) = (self.highs[this].piece, self.highs[hi2].piece);
        match (p1, p2) {
            (None, None) => {
                let np2 = self.new_piece(hi2, 0, None)?;
                self.highs[hi2].piece = Some(np2);
                let np1 = self.new_piece(this, off, Some(hi2))?;
                self.highs[this].piece = Some(np1);
                self.piece_mark_intersection_dirty(np2);
            }
            (None, Some(q)) => {
                if !self.highs[hi2].intersect_dirty {
                    self.piece_mark_intersection_dirty(q);
                }
                self.highs[this].intersect_dirty = true;
                self.highs[this].extend_cover_dirty = true;
                let off = off + self.pieces[q].offset;
                let np = self.new_piece(this, off, Some(hi2))?;
                self.highs[this].piece = Some(np);
            }
            (Some(p), None) => {
                let mut hi2_off = self.pieces[p].offset - off;
                if hi2_off < 0 {
                    let g = self.pieces[p].group;
                    self.group_adjust_offsets(g, -hi2_off);
                    hi2_off = 0;
                }
                if !self.highs[this].intersect_dirty {
                    self.piece_mark_intersection_dirty(p);
                }
                self.highs[hi2].intersect_dirty = true;
                self.highs[hi2].extend_cover_dirty = true;
                let np = self.new_piece(hi2, hi2_off, Some(this))?;
                self.highs[hi2].piece = Some(np);
            }
            (Some(p), Some(q)) => {
                let off_diff = self.pieces[q].offset + off - self.pieces[p].offset;
                if off_diff != 0 {
                    let g = self.pieces[p].group;
                    self.group_adjust_offsets(g, off_diff);
                }
                let (g2, g1) = (self.pieces[q].group, self.pieces[p].group);
                // VariableGroup::combineGroups
                for r in self.groups[g1].pieces.clone() {
                    self.piece_transfer_group(r, g2)?;
                }
                self.piece_mark_intersection_dirty(q);
            }
        }
        Ok(())
    }

    /// `HighVariable::merge` (with the cache of `Merge::merge` when `use_cache`), pieces included.
    pub fn merge_high(&mut self, h1: usize, h2: usize, speculative: bool, use_cache: bool) -> Result<()> {
        if h1 == h2 {
            return Ok(());
        }
        if use_cache {
            self.move_intersect_tests(h1, h2);
        }
        let (p1, p2) = (self.highs[h1].piece, self.highs[h2].piece);
        match (p1, p2) {
            (None, None) => return self.merge_high_internal(h1, h2, speculative),
            (Some(p), None) => {
                self.piece_mark_extend_cover_dirty(p);
                return self.merge_high_internal(h1, h2, speculative);
            }
            (None, Some(q)) => {
                // transferPiece
                self.highs[h1].piece = Some(q);
                self.highs[h2].piece = None;
                self.pieces[q].high = h1;
                self.highs[h1].intersect_dirty |= self.highs[h2].intersect_dirty;
                self.highs[h1].extend_cover_dirty |= self.highs[h2].extend_cover_dirty;
                self.highs[h2].intersect_dirty = false;
                self.highs[h2].extend_cover_dirty = false;
                self.piece_mark_extend_cover_dirty(q);
                return self.merge_high_internal(h1, h2, speculative);
            }
            (Some(p), Some(q)) => {
                if speculative {
                    return err("Trying speculatively merge variables in separate groups");
                }
                let mut pairs = Vec::new();
                self.piece_merge_groups(p, q, &mut pairs)?;
                for pair in pairs.chunks(2) {
                    let (high1, high2) = (pair[0], pair[1]);
                    if use_cache {
                        self.move_intersect_tests(high1, high2);
                    }
                    self.merge_high_internal(high1, high2, speculative)?;
                }
                self.piece_mark_intersection_dirty(p);
            }
        }
        Ok(())
    }

    // ---- PieceNode ----

    fn piece_is_leaf(&self, root: usize, vn: usize, rel_offset: i32) -> bool {
        if self.vns[vn].flags & vf::MAPPED != 0 && self.vns[root].entry != self.vns[vn].entry {
            return true;
        }
        if !self.vns[vn].is_written() {
            return true;
        }
        let def = self.vns[vn].def.unwrap();
        if self.ops[def].code != super::model::opc::PIECE {
            return true;
        }
        if self.lone_descend(vn).is_none() {
            return true;
        }
        if self.vns[vn].is_addr_tied() {
            let mut addr = self.vns[root].addr;
            addr.offset = addr.offset.wrapping_add(rel_offset as i64 as u64);
            if self.vns[vn].addr != addr {
                return true;
            }
        }
        false
    }

    fn gather_pieces(&self, out: &mut Vec<PieceNode>, root: usize, op: usize, base: i32, root_offset: i32) {
        for i in 0..2usize {
            let vn = self.ops[op].ins[i];
            let big = self.space(self.vns[root].addr.space).big_endian;
            let offset = if big == (i == 1) {
                base + self.vns[self.ops[op].ins[1 - i]].size as i32
            } else {
                base
            };
            let leaf = self.piece_is_leaf(root, vn, offset - root_offset);
            out.push(PieceNode { op, slot: i, type_offset: offset });
            if !leaf {
                self.gather_pieces(out, root, self.vns[vn].def.unwrap(), offset, root_offset);
            }
        }
    }

    /// `Merge::groupPartialRoot`.
    fn group_partial_root(&mut self, vn: usize) -> Result<()> {
        let high = self.vns[vn].high;
        if self.highs[high].inst.len() != 1 {
            return Ok(());
        }
        let base_offset = if self.vns[vn].entry.is_some() { self.vns[vn].entry_offset } else { 0 };
        let mut pieces = Vec::new();
        self.gather_pieces(&mut pieces, vn, self.vns[vn].def.unwrap(), base_offset, base_offset);
        let mut throw_out = false;
        for p in &pieces {
            let node_vn = self.ops[p.op].ins[p.slot];
            if self.vns[node_vn].flags & vf::PROTO_PARTIAL == 0 || self.highs[self.vns[node_vn].high].inst.len() != 1 {
                throw_out = true;
                break;
            }
        }
        if throw_out {
            for p in &pieces {
                let node_vn = self.ops[p.op].ins[p.slot];
                self.log.push(Entry::ClearProtoPartial(node_vn));
                self.vn_clear_flags(node_vn, vf::PROTO_PARTIAL);
            }
        } else {
            for p in &pieces {
                let node_vn = self.ops[p.op].ins[p.slot];
                let h = self.vns[node_vn].high;
                self.group_with(h, p.type_offset - base_offset, high)?;
            }
        }
        Ok(())
    }

    /// `Merge::groupPartials`.
    pub fn group_partials(&mut self) -> Result<()> {
        for i in 0..self.proto_partial.len() {
            let op = self.proto_partial[i];
            if self.ops[op].is_dead() || self.ops[op].addl & pf::CONCAT_ROOT == 0 {
                continue;
            }
            let out = self.ops[op].out.unwrap();
            self.group_partial_root(out)?;
        }
        Ok(())
    }
}
