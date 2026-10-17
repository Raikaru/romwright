//! The structuring rules of `CollapseStructure` (blockaction.cc) and the
//! switch recovery of `BlockGraph::newBlockSwitch` / `BlockSwitch::grabCaseBasic`.

use super::loops::Collapse;
use super::*;

impl Graph {
    fn add_case(&mut self, sw: usize, switchbl: usize, bl: usize, gt: u32) -> Res<()> {
        let leaf = self.front_leaf(bl).ok_or("switch case without a leaf")?;
        let basicbl = self.b[leaf].basic;
        let inindex = self.orig_ins[basicbl]
            .iter()
            .position(|e| e.point == switchbl)
            .ok_or("Case block has become detached from switch")?;
        let outindex = self.orig_ins[basicbl][inindex].rev;
        let isexit = if gt != 0 { false } else { self.size_out(bl) == 1 };
        self.b[sw].cases.push(CaseOrder {
            block: bl,
            label: 0,
            depth: 0,
            chain: -1,
            outindex,
            gototype: gt,
            isexit,
        });
        Ok(())
    }

    fn grab_case_basic(&mut self, sw: usize, switchbl: usize, cs: &[usize]) -> Res<()> {
        let mut casemap = vec![-1i32; self.orig_outs[switchbl].len()];
        self.b[sw].cases.clear();
        for (i, &casebl) in cs.iter().enumerate().skip(1) {
            self.add_case(sw, switchbl, casebl, 0)?;
            let outindex = self.b[sw].cases[i - 1].outindex;
            casemap[outindex] = (i - 1) as i32;
        }
        for i in 0..self.b[sw].cases.len() {
            let casebl = self.b[sw].cases[i].block;
            if self.b[casebl].kind == kind::GOTO {
                let targetbl = self.b[casebl].goto_target.ok_or("goto without target")?;
                let leaf = self.front_leaf(targetbl).ok_or("goto target without leaf")?;
                let basicbl = self.b[leaf].basic;
                let Some(inindex) = self.orig_ins[basicbl].iter().position(|e| e.point == switchbl) else {
                    continue;
                };
                let rev = self.orig_ins[basicbl][inindex].rev;
                self.b[sw].cases[i].chain = casemap[rev];
            }
        }
        if self.b[cs[0]].kind == kind::MULTIGOTO {
            for target in self.b[cs[0]].gotoedges.clone() {
                self.add_case(sw, switchbl, target, F_GOTO_GOTO)?;
            }
        }
        Ok(())
    }

    fn new_block_switch(&mut self, cs: &[usize], has_exit: bool) -> Res<()> {
        let rootbl = cs[0];
        let leaf = self
            .exit_leaf(rootbl)
            .filter(|&l| self.b[l].kind == kind::COPY)
            .ok_or("Could not get switch leaf")?;
        let switchbl = self.b[leaf].basic;
        let ret = self.new_block(kind::SWITCH);
        self.b[ret].switch_basic = switchbl;
        self.grab_case_basic(ret, switchbl, cs)?;
        self.identify_internal(ret, cs);
        let root = self.root;
        self.add_block(root, ret);
        if has_exit {
            self.force_output_num(ret, 1);
        }
        self.b[ret].flags &= !F_SWITCH_OUT;
        Ok(())
    }
}

impl Collapse<'_> {
    fn rule_block_cat(&mut self, bl: usize) -> Res<bool> {
        let g = &mut *self.g;
        if g.size_out(bl) != 1 || g.is_switch_out(bl) {
            return Ok(false);
        }
        if g.size_in(bl) == 1 && g.size_out(g.get_in(bl, 0)) == 1 {
            return Ok(false);
        }
        let mut outblock = g.get_out(bl, 0);
        if outblock == bl || g.size_in(outblock) != 1 || !g.is_decision_out(bl, 0) || g.is_switch_out(outblock) {
            return Ok(false);
        }
        let mut nodes = vec![bl, outblock];
        while g.size_out(outblock) == 1 {
            let outbl2 = g.get_out(outblock, 0);
            if outbl2 == bl || g.size_in(outbl2) != 1 || !g.is_decision_out(outblock, 0) || g.is_switch_out(outbl2) {
                break;
            }
            outblock = outbl2;
            nodes.push(outblock);
        }
        g.new_block_list(&nodes)?;
        Ok(true)
    }

    fn rule_block_or(&mut self, bl: usize) -> Res<bool> {
        let g = &mut *self.g;
        if g.size_out(bl) != 2 || g.is_goto_out(bl, 0) || g.is_goto_out(bl, 1) || g.is_switch_out(bl) {
            return Ok(false);
        }
        for i in 0..2 {
            let orblock = g.get_out(bl, i);
            if orblock == bl || g.size_in(orblock) != 1 || g.size_out(orblock) != 2 {
                continue;
            }
            if g.b[orblock].flags & F_INTERIOR_GOTOIN != 0 || g.is_switch_out(orblock) {
                continue;
            }
            if g.is_back_edge_out(bl, i) || g.is_complex(orblock) {
                continue;
            }
            let clauseblock = g.get_out(bl, 1 - i);
            if clauseblock == bl || clauseblock == orblock {
                continue;
            }
            let Some(j) = (0..2).find(|&j| g.get_out(orblock, j) == clauseblock) else {
                continue;
            };
            if g.get_out(orblock, 1 - j) == bl {
                continue;
            }
            if i == 1 {
                g.negate_condition(bl, true);
            }
            if j == 0 {
                g.negate_condition(orblock, true);
            }
            g.new_block_condition(bl, orblock)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn rule_block_proper_if(&mut self, bl: usize) -> Res<bool> {
        let g = &mut *self.g;
        if g.size_out(bl) != 2 || g.is_switch_out(bl) {
            return Ok(false);
        }
        if g.get_out(bl, 0) == bl || g.get_out(bl, 1) == bl || g.is_goto_out(bl, 0) || g.is_goto_out(bl, 1) {
            return Ok(false);
        }
        for i in 0..2 {
            let clauseblock = g.get_out(bl, i);
            if g.size_in(clauseblock) != 1 || g.size_out(clauseblock) != 1 || g.is_switch_out(clauseblock) {
                continue;
            }
            if !g.is_decision_out(bl, i) || g.is_goto_out(clauseblock, 0) {
                continue;
            }
            let outblock = g.get_out(clauseblock, 0);
            if outblock != g.get_out(bl, 1 - i) {
                continue;
            }
            if i == 0 {
                g.negate_condition(bl, true);
            }
            let ret = g.new_block_group(kind::IF, &[bl, clauseblock], Some(1));
            let _ = ret;
            return Ok(true);
        }
        Ok(false)
    }

    fn rule_block_if_else(&mut self, bl: usize) -> Res<bool> {
        let g = &mut *self.g;
        if g.size_out(bl) != 2 || g.is_switch_out(bl) || !g.is_decision_out(bl, 0) || !g.is_decision_out(bl, 1) {
            return Ok(false);
        }
        let tc = g.get_out(bl, 1);
        let fc = g.get_out(bl, 0);
        if g.size_in(tc) != 1 || g.size_in(fc) != 1 || g.size_out(tc) != 1 || g.size_out(fc) != 1 {
            return Ok(false);
        }
        let outblock = g.get_out(tc, 0);
        if outblock == bl || outblock != g.get_out(fc, 0) {
            return Ok(false);
        }
        if g.is_switch_out(tc) || g.is_switch_out(fc) || g.is_goto_out(tc, 0) || g.is_goto_out(fc, 0) {
            return Ok(false);
        }
        g.new_block_group(kind::IF, &[bl, tc, fc], Some(1));
        Ok(true)
    }

    fn rule_block_goto(&mut self, bl: usize) -> Res<bool> {
        let g = &mut *self.g;
        let sizeout = g.size_out(bl);
        for i in 0..sizeout {
            if g.is_goto_out(bl, i) {
                if g.is_switch_out(bl) {
                    g.new_block_multi_goto(bl, i);
                    return Ok(true);
                }
                if sizeout == 2 {
                    if !g.is_goto_out(bl, 1) {
                        g.negate_condition(bl, true);
                    }
                    g.new_block_if_goto(bl)?;
                    return Ok(true);
                }
                if sizeout == 1 {
                    g.new_block_goto(bl);
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn rule_block_if_no_exit(&mut self, bl: usize) -> Res<bool> {
        let g = &mut *self.g;
        if g.size_out(bl) != 2 || g.is_switch_out(bl) {
            return Ok(false);
        }
        if g.get_out(bl, 0) == bl || g.get_out(bl, 1) == bl || g.is_goto_out(bl, 0) || g.is_goto_out(bl, 1) {
            return Ok(false);
        }
        for i in 0..2 {
            let clauseblock = g.get_out(bl, i);
            if g.size_in(clauseblock) != 1 || g.size_out(clauseblock) != 0 || g.is_switch_out(clauseblock) {
                continue;
            }
            if !g.is_decision_out(bl, i) {
                continue;
            }
            if i == 0 {
                g.negate_condition(bl, true);
            }
            g.new_block_group(kind::IF, &[bl, clauseblock], Some(1));
            return Ok(true);
        }
        Ok(false)
    }

    fn rule_block_while_do(&mut self, bl: usize) -> Res<bool> {
        let g = &mut *self.g;
        if g.size_out(bl) != 2 || g.is_switch_out(bl) {
            return Ok(false);
        }
        if g.get_out(bl, 0) == bl || g.get_out(bl, 1) == bl || g.b[bl].flags & F_INTERIOR_GOTOIN != 0 {
            return Ok(false);
        }
        if g.is_goto_out(bl, 0) || g.is_goto_out(bl, 1) {
            return Ok(false);
        }
        for i in 0..2 {
            let clauseblock = g.get_out(bl, i);
            if g.size_in(clauseblock) != 1 || g.size_out(clauseblock) != 1 || g.is_switch_out(clauseblock) {
                continue;
            }
            if g.get_out(clauseblock, 0) != bl {
                continue;
            }
            let overflow = g.is_complex(bl);
            if (i == 0) != overflow {
                g.negate_condition(bl, true);
            }
            let ret = g.new_block_group(kind::WHILE_DO, &[bl, clauseblock], Some(1));
            if overflow {
                g.b[ret].flags |= F_WHILEDO_OVERFLOW;
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn rule_block_do_while(&mut self, bl: usize) -> Res<bool> {
        let g = &mut *self.g;
        if g.size_out(bl) != 2 || g.is_switch_out(bl) || g.is_goto_out(bl, 0) || g.is_goto_out(bl, 1) {
            return Ok(false);
        }
        for i in 0..2 {
            if g.get_out(bl, i) != bl {
                continue;
            }
            if i == 0 {
                g.negate_condition(bl, true);
            }
            g.new_block_group(kind::DO_WHILE, &[bl], Some(1));
            return Ok(true);
        }
        Ok(false)
    }

    fn rule_block_inf_loop(&mut self, bl: usize) -> Res<bool> {
        let g = &mut *self.g;
        if g.size_out(bl) != 1 || g.is_goto_out(bl, 0) || g.get_out(bl, 0) != bl {
            return Ok(false);
        }
        g.new_block_group(kind::INFINITE_LOOP, &[bl], None);
        Ok(true)
    }

    fn check_switch_skips(&mut self, switchbl: usize, exitblock: Option<usize>) -> bool {
        let g = &mut *self.g;
        let Some(exitblock) = exitblock else { return true };
        let sizeout = g.size_out(switchbl);
        let mut defaultnottoexit = false;
        let mut anyskiptoexit = false;
        for edgenum in 0..sizeout {
            if g.get_out(switchbl, edgenum) == exitblock {
                if !g.is_default_branch(switchbl, edgenum) {
                    anyskiptoexit = true;
                }
            } else if g.is_default_branch(switchbl, edgenum) {
                defaultnottoexit = true;
            }
        }
        if !anyskiptoexit {
            return true;
        }
        if !defaultnottoexit && g.b[switchbl].kind == kind::MULTIGOTO && g.b[switchbl].default_goto {
            defaultnottoexit = true;
        }
        if !defaultnottoexit {
            return true;
        }
        for edgenum in 0..sizeout {
            if g.get_out(switchbl, edgenum) == exitblock && !g.is_default_branch(switchbl, edgenum) {
                g.set_goto_branch(switchbl, edgenum);
            }
        }
        false
    }

    fn rule_block_switch(&mut self, bl: usize) -> Res<bool> {
        if !self.g.is_switch_out(bl) {
            return Ok(false);
        }
        let mut exitblock: Option<usize> = None;
        let sizeout = self.g.size_out(bl);
        {
            let g = &*self.g;
            for i in 0..sizeout {
                let curbl = g.get_out(bl, i);
                if curbl == bl || g.size_out(curbl) > 1 || g.size_in(curbl) > 1 {
                    exitblock = Some(curbl);
                    break;
                }
            }
            match exitblock {
                None => {
                    for i in 0..sizeout {
                        let curbl = g.get_out(bl, i);
                        if g.is_goto_in(curbl, 0) || g.is_switch_out(curbl) {
                            return Ok(false);
                        }
                        if g.size_out(curbl) == 1 {
                            if g.is_goto_out(curbl, 0) {
                                return Ok(false);
                            }
                            match exitblock {
                                Some(e) => {
                                    if e != g.get_out(curbl, 0) {
                                        return Ok(false);
                                    }
                                }
                                None => exitblock = Some(g.get_out(curbl, 0)),
                            }
                        }
                    }
                }
                Some(exit) => {
                    for i in 0..g.size_in(exit) {
                        if g.is_goto_in(exit, i) {
                            return Ok(false);
                        }
                    }
                    for i in 0..g.size_out(exit) {
                        if g.is_goto_out(exit, i) {
                            return Ok(false);
                        }
                    }
                    for i in 0..sizeout {
                        let curbl = g.get_out(bl, i);
                        if curbl == exit {
                            continue;
                        }
                        if g.size_in(curbl) > 1 || g.is_goto_in(curbl, 0) || g.size_out(curbl) > 1 {
                            return Ok(false);
                        }
                        if g.size_out(curbl) == 1
                            && (g.is_goto_out(curbl, 0) || g.get_out(curbl, 0) != exit) {
                                return Ok(false);
                            }
                        if g.is_switch_out(curbl) {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        if !self.check_switch_skips(bl, exitblock) {
            return Ok(true);
        }
        let mut cases = vec![bl];
        for i in 0..sizeout {
            let curbl = self.g.get_out(bl, i);
            if Some(curbl) == exitblock {
                continue;
            }
            cases.push(curbl);
        }
        self.g.new_block_switch(&cases, exitblock.is_some())?;
        Ok(true)
    }

    fn rule_case_fallthru(&mut self, bl: usize) -> bool {
        let g = &mut *self.g;
        if !g.is_switch_out(bl) {
            return false;
        }
        let sizeout = g.size_out(bl);
        let mut nonfallthru = 0;
        let mut fallthru = Vec::new();
        for i in 0..sizeout {
            let curbl = g.get_out(bl, i);
            if curbl == bl {
                return false;
            }
            if g.size_in(curbl) > 2 || g.size_out(curbl) > 1 {
                nonfallthru += 1;
            } else if g.size_out(curbl) == 1 {
                let target = g.get_out(curbl, 0);
                if g.size_in(target) == 2 && g.size_out(target) <= 1 {
                    let inslot = g.b[curbl].outs[0].rev;
                    if g.get_in(target, 1 - inslot) == bl {
                        fallthru.push(curbl);
                    }
                }
            }
            if nonfallthru > 1 {
                return false;
            }
        }
        if fallthru.is_empty() {
            return false;
        }
        for curbl in fallthru {
            g.set_goto_branch(curbl, 0);
        }
        true
    }

    pub(super) fn collapse_internal(&mut self, mut targetbl: Option<usize>) -> Res<usize> {
        let mut passes = 0usize;
        loop {
            passes += 1;
            if passes > 4 * self.g.b.len() + 64 {
                return Err("block structuring did not converge".into());
            }
            let mut isolated_count;
            let mut rounds = 0usize;
            loop {
                rounds += 1;
                if rounds > 4 * self.g.b.len() + 64 {
                    return Err("block structuring did not converge".into());
                }
                let mut change = false;
                let mut index = 0;
                isolated_count = 0;
                while index < self.g.b[self.g.root].list.len() {
                    let bl = match targetbl.take() {
                        None => {
                            let bl = self.g.b[self.g.root].list[index];
                            index += 1;
                            bl
                        }
                        Some(t) => {
                            change = true;
                            index = self.g.b[self.g.root].list.len();
                            t
                        }
                    };
                    if self.g.size_in(bl) == 0 && self.g.size_out(bl) == 0 {
                        isolated_count += 1;
                        continue;
                    }
                    if self.rule_block_goto(bl)?
                        || self.rule_block_cat(bl)?
                        || self.rule_block_proper_if(bl)?
                        || self.rule_block_if_else(bl)?
                        || self.rule_block_while_do(bl)?
                        || self.rule_block_do_while(bl)?
                        || self.rule_block_inf_loop(bl)?
                        || self.rule_block_switch(bl)?
                    {
                        change = true;
                    }
                }
                if !change {
                    break;
                }
            }
            let mut fullchange = false;
            let size = self.g.b[self.g.root].list.len();
            for index in 0..size {
                let bl = self.g.b[self.g.root].list[index];
                if self.rule_block_if_no_exit(bl)? {
                    fullchange = true;
                    break;
                }
                if self.rule_case_fallthru(bl) {
                    fullchange = true;
                    break;
                }
            }
            if !fullchange {
                return Ok(isolated_count);
            }
        }
    }

    pub(super) fn collapse_conditions(&mut self) -> Res<()> {
        loop {
            let mut change = false;
            let mut i = 0;
            while i < self.g.b[self.g.root].list.len() {
                let bl = self.g.b[self.g.root].list[i];
                if self.rule_block_or(bl)? {
                    change = true;
                }
                i += 1;
            }
            if !change {
                return Ok(());
            }
        }
    }
}
