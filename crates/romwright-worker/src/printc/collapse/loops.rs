//! `LoopBody`, `TraceDAG` and the driver of `CollapseStructure`
//! (blockaction.cc): which edge becomes an unstructured `goto` when no rule
//! applies.

use super::*;

/// An edge named by its end blocks, followed through collapsing
/// (`FloatingEdge`).
pub(super) type Floating = (usize, usize);

impl Graph {
    pub(super) fn current_edge(&self, edge: &mut Floating) -> Option<(usize, usize)> {
        let root = self.root;
        while self.b[edge.0].parent != Some(root) {
            edge.0 = self.b[edge.0].parent?;
        }
        while self.b[edge.1].parent != Some(root) {
            edge.1 = self.b[edge.1].parent?;
        }
        let outedge = self.out_index(edge.0, edge.1)?;
        Some((edge.0, outedge))
    }

    fn clear_marks(&mut self, body: &[usize]) {
        for &b in body {
            self.clear_mark(b);
        }
    }
}

pub(super) struct Collapse<'g> {
    pub g: &'g mut Graph,
    loopbody: Vec<LoopBody>,
    order: Vec<usize>,
    pos: usize,
    likelygoto: Vec<Floating>,
    likelyiter: usize,
    likelylistfull: bool,
    finaltrace: bool,
}

impl LoopBody {
    fn new(head: usize) -> Self {
        LoopBody {
            head: Some(head),
            tails: Vec::new(),
            depth: 0,
            uniquecount: 0,
            exitblock: None,
            immed_container: None,
            exitedges: Vec::new(),
        }
    }
}

impl<'g> Collapse<'g> {
    pub fn new(g: &'g mut Graph) -> Self {
        Collapse {
            g,
            loopbody: Vec::new(),
            order: Vec::new(),
            pos: 0,
            likelygoto: Vec::new(),
            likelyiter: 0,
            likelylistfull: false,
            finaltrace: false,
        }
    }

    // ---- LoopBody ----------------------------------------------------------

    fn extend_to_container(&mut self, li: usize, container: usize, body: &mut Vec<usize>) {
        let chead = self.loopbody[container].head.expect("container head");
        let ctails = self.loopbody[container].tails.clone();
        let head = self.loopbody[li].head.expect("head");
        let mut i = 0;
        if !self.g.is_mark(chead) {
            self.g.set_mark(chead);
            body.push(chead);
            i = 1;
        }
        for tail in ctails {
            if !self.g.is_mark(tail) {
                self.g.set_mark(tail);
                body.push(tail);
            }
        }
        if head != chead {
            let sizein = self.g.size_in(head);
            for k in 0..sizein {
                if self.g.is_goto_in(head, k) {
                    continue;
                }
                let bl = self.g.get_in(head, k);
                if self.g.is_mark(bl) {
                    continue;
                }
                self.g.set_mark(bl);
                body.push(bl);
            }
        }
        while i < body.len() {
            let cur = body[i];
            i += 1;
            for k in 0..self.g.size_in(cur) {
                if self.g.is_goto_in(cur, k) {
                    continue;
                }
                let bl = self.g.get_in(cur, k);
                if self.g.is_mark(bl) {
                    continue;
                }
                self.g.set_mark(bl);
                body.push(bl);
            }
        }
    }

    /// `LoopBody::update`
    fn update(&mut self, li: usize) -> Option<usize> {
        let root = self.g.root;
        let mut head = self.loopbody[li].head.expect("head");
        while self.g.b[head].parent != Some(root) {
            head = self.g.b[head].parent.expect("parent");
        }
        self.loopbody[li].head = Some(head);
        for i in 0..self.loopbody[li].tails.len() {
            let mut bottom = self.loopbody[li].tails[i];
            while self.g.b[bottom].parent != Some(root) {
                bottom = self.g.b[bottom].parent.expect("parent");
            }
            self.loopbody[li].tails[i] = bottom;
            if bottom != head {
                return Some(bottom);
            }
        }
        for i in (0..self.g.size_out(head)).rev() {
            if self.g.get_out(head, i) == head {
                return Some(head);
            }
        }
        None
    }

    fn find_base(&mut self, li: usize, body: &mut Vec<usize>) {
        let head = self.loopbody[li].head.expect("head");
        self.g.set_mark(head);
        body.push(head);
        for tail in self.loopbody[li].tails.clone() {
            if !self.g.is_mark(tail) {
                self.g.set_mark(tail);
                body.push(tail);
            }
        }
        self.loopbody[li].uniquecount = body.len();
        let mut i = 1;
        while i < body.len() {
            let cur = body[i];
            i += 1;
            for k in 0..self.g.size_in(cur) {
                if self.g.is_goto_in(cur, k) {
                    continue;
                }
                let bl = self.g.get_in(cur, k);
                if self.g.is_mark(bl) {
                    continue;
                }
                self.g.set_mark(bl);
                body.push(bl);
            }
        }
    }

    fn extend(&mut self, li: usize, body: &mut Vec<usize>) {
        let exitblock = self.loopbody[li].exitblock;
        let mut trial = Vec::new();
        let mut i = 0;
        while i < body.len() {
            let bl = body[i];
            i += 1;
            for j in 0..self.g.size_out(bl) {
                if self.g.is_goto_out(bl, j) {
                    continue;
                }
                let curbl = self.g.get_out(bl, j);
                if self.g.is_mark(curbl) {
                    continue;
                }
                if Some(curbl) == exitblock {
                    continue;
                }
                let mut count = self.g.b[curbl].visit;
                if count == 0 {
                    trial.push(curbl);
                }
                count += 1;
                self.g.b[curbl].visit = count;
                if count as usize == self.g.size_in(curbl) {
                    self.g.set_mark(curbl);
                    body.push(curbl);
                }
            }
        }
        for t in trial {
            self.g.b[t].visit = 0;
        }
    }

    fn find_exit(&mut self, li: usize, body: &[usize]) {
        let mut trialexit = Vec::new();
        let container = self.loopbody[li].immed_container;
        let tails = self.loopbody[li].tails.clone();
        for &tail in &tails {
            for i in 0..self.g.size_out(tail) {
                if self.g.is_goto_out(tail, i) {
                    continue;
                }
                let curbl = self.g.get_out(tail, i);
                if !self.g.is_mark(curbl) {
                    if container.is_none() {
                        self.loopbody[li].exitblock = Some(curbl);
                        return;
                    }
                    trialexit.push(curbl);
                }
            }
        }
        let unique = self.loopbody[li].uniquecount;
        for (i, &bl) in body.iter().enumerate() {
            if i > 0 && i < unique {
                continue;
            }
            for j in 0..self.g.size_out(bl) {
                if self.g.is_goto_out(bl, j) {
                    continue;
                }
                let curbl = self.g.get_out(bl, j);
                if !self.g.is_mark(curbl) {
                    if container.is_none() {
                        self.loopbody[li].exitblock = Some(curbl);
                        return;
                    }
                    trialexit.push(curbl);
                }
            }
        }
        self.loopbody[li].exitblock = None;
        if trialexit.is_empty() {
            return;
        }
        if let Some(container) = container {
            let mut extension = Vec::new();
            self.extend_to_container(li, container, &mut extension);
            for bl in trialexit {
                if self.g.is_mark(bl) {
                    self.loopbody[li].exitblock = Some(bl);
                    break;
                }
            }
            self.g.clear_marks(&extension);
        }
    }

    fn order_tails(&mut self, li: usize) {
        let lb = &self.loopbody[li];
        if lb.tails.len() <= 1 {
            return;
        }
        let Some(exitblock) = lb.exitblock else { return };
        let mut prefindex = 0;
        while prefindex < lb.tails.len() {
            let trial = lb.tails[prefindex];
            if (0..self.g.size_out(trial)).any(|j| self.g.get_out(trial, j) == exitblock) {
                break;
            }
            prefindex += 1;
        }
        if prefindex >= lb.tails.len() || prefindex == 0 {
            return;
        }
        self.loopbody[li].tails.swap(0, prefindex);
    }

    fn label_exit_edges(&mut self, li: usize, body: &[usize]) {
        let head = self.loopbody[li].head;
        let exitblock = self.loopbody[li].exitblock;
        let unique = self.loopbody[li].uniquecount;
        let tails = self.loopbody[li].tails.clone();
        let mut toexitblock = Vec::new();
        let mut exitedges: Vec<Floating> = Vec::new();
        let scan = |g: &Graph, cur: usize, exitedges: &mut Vec<Floating>, toexit: &mut Vec<usize>| {
            for k in 0..g.size_out(cur) {
                if g.is_goto_out(cur, k) {
                    continue;
                }
                let bl = g.get_out(cur, k);
                if Some(bl) == exitblock {
                    toexit.push(cur);
                    continue;
                }
                if !g.is_mark(bl) {
                    exitedges.push((cur, bl));
                }
            }
        };
        for &cur in body.iter().skip(unique) {
            scan(self.g, cur, &mut exitedges, &mut toexitblock);
        }
        if let Some(head) = head {
            scan(self.g, head, &mut exitedges, &mut toexitblock);
        }
        for &cur in tails.iter().rev() {
            if Some(cur) == head {
                continue;
            }
            scan(self.g, cur, &mut exitedges, &mut toexitblock);
        }
        for bl in toexitblock {
            exitedges.push((bl, exitblock.expect("exit block")));
        }
        self.loopbody[li].exitedges = exitedges;
    }

    fn find_loop(&self, looptop: usize, looporder: &[usize]) -> Option<usize> {
        let (mut min, mut max) = (0i64, looporder.len() as i64 - 1);
        let target = self.g.b[looptop].index;
        while min <= max {
            let mid = ((min + max) / 2) as usize;
            let head = self.loopbody[looporder[mid]].head?;
            let idx = self.g.b[head].index;
            if idx == target {
                return Some(looporder[mid]);
            }
            if idx < target {
                min = mid as i64 + 1;
            } else {
                max = mid as i64 - 1;
            }
        }
        None
    }

    fn label_containments(&mut self, li: usize, body: &[usize], looporder: &[usize]) {
        let head = self.loopbody[li].head;
        let mut containlist = Vec::new();
        for &cur in body {
            if Some(cur) != head
                && let Some(sub) = self.find_loop(cur, looporder) {
                    containlist.push(sub);
                    self.loopbody[sub].depth += 1;
                }
        }
        let depth = self.loopbody[li].depth;
        for lb in containlist {
            let ic = self.loopbody[lb].immed_container;
            if ic.is_none() || self.loopbody[ic.expect("ic")].depth < depth {
                self.loopbody[lb].immed_container = Some(li);
            }
        }
    }

    fn emit_likely_edges(&mut self, li: usize) {
        let root = self.g.root;
        let climb = |g: &Graph, mut b: usize| {
            while g.b[b].parent != Some(root) {
                b = g.b[b].parent.expect("parent");
            }
            b
        };
        let head = climb(self.g, self.loopbody[li].head.expect("head"));
        self.loopbody[li].head = Some(head);
        if let Some(e) = self.loopbody[li].exitblock {
            self.loopbody[li].exitblock = Some(climb(self.g, e));
        }
        for i in 0..self.loopbody[li].tails.len() {
            let tail = climb(self.g, self.loopbody[li].tails[i]);
            self.loopbody[li].tails[i] = tail;
            if Some(tail) == self.loopbody[li].exitblock {
                self.loopbody[li].exitblock = None;
            }
        }
        let exitblock = self.loopbody[li].exitblock;
        let mut exitedges = self.loopbody[li].exitedges.clone();
        let total = exitedges.len();
        let mut hold: Option<(usize, usize)> = None;
        let mut idx = 0;
        while idx < total {
            let cur = self.g.current_edge(&mut exitedges[idx]);
            idx += 1;
            let Some((inbl, outedge)) = cur else { continue };
            let outbl = self.g.get_out(inbl, outedge);
            if idx == total && Some(outbl) == exitblock {
                hold = Some((inbl, outbl));
                break;
            }
            self.likelygoto.push((inbl, outbl));
        }
        self.loopbody[li].exitedges = exitedges;
        let tails = self.loopbody[li].tails.clone();
        for i in (0..tails.len()).rev() {
            if let (Some(h), 0) = (hold, i) {
                self.likelygoto.push(h);
            }
            let tail = tails[i];
            for j in 0..self.g.size_out(tail) {
                if self.g.get_out(tail, j) == head {
                    self.likelygoto.push((tail, head));
                }
            }
        }
    }

    fn clear_exit_marks(&mut self, li: usize) {
        let mut edges = self.loopbody[li].exitedges.clone();
        for e in edges.iter_mut() {
            if let Some((inloop, outedge)) = self.g.current_edge(e) {
                let t = self.g.b[inloop].outs[outedge];
                self.g.b[inloop].outs[outedge].label &= !E_LOOP_EXIT;
                self.g.b[t.point].ins[t.rev].label &= !E_LOOP_EXIT;
            }
        }
        self.loopbody[li].exitedges = edges;
    }

    // ---- CollapseStructure -------------------------------------------------

    fn only_reachable_from_root(&mut self, root: usize, body: &mut Vec<usize>) {
        let mut trial = Vec::new();
        let mut i = 0;
        self.g.set_mark(root);
        body.push(root);
        while i < body.len() {
            let bl = body[i];
            i += 1;
            for j in 0..self.g.size_out(bl) {
                let curbl = self.g.get_out(bl, j);
                if self.g.is_mark(curbl) {
                    continue;
                }
                let mut count = self.g.b[curbl].visit;
                if count == 0 {
                    trial.push(curbl);
                }
                count += 1;
                self.g.b[curbl].visit = count;
                if count as usize == self.g.size_in(curbl) {
                    self.g.set_mark(curbl);
                    body.push(curbl);
                }
            }
        }
        for t in trial {
            self.g.b[t].visit = 0;
        }
    }

    fn mark_exits_as_gotos(&mut self, body: &[usize]) -> usize {
        let mut changecount = 0;
        for &bl in body {
            for j in 0..self.g.size_out(bl) {
                let curbl = self.g.get_out(bl, j);
                if !self.g.is_mark(curbl) {
                    self.g.set_goto_branch(bl, j);
                    changecount += 1;
                }
            }
        }
        changecount
    }

    fn clip_extra_roots(&mut self) -> bool {
        let size = self.g.b[self.g.root].list.len();
        for i in 1..size {
            let bl = self.g.b[self.g.root].list[i];
            if self.g.size_in(bl) != 0 {
                continue;
            }
            let mut body = Vec::new();
            self.only_reachable_from_root(bl, &mut body);
            let count = self.mark_exits_as_gotos(&body);
            self.g.clear_marks(&body);
            if count != 0 {
                return true;
            }
        }
        false
    }

    fn label_loops(&mut self) -> Vec<usize> {
        let mut looporder = Vec::new();
        let list = self.g.b[self.g.root].list.clone();
        for bl in list {
            for j in 0..self.g.size_in(bl) {
                if self.g.is_back_edge_in(bl, j) {
                    let loopbottom = self.g.get_in(bl, j);
                    let mut lb = LoopBody::new(bl);
                    lb.tails.push(loopbottom);
                    self.loopbody.push(lb);
                    looporder.push(self.loopbody.len() - 1);
                }
            }
        }
        let g = &*self.g;
        let lbs = &self.loopbody;
        sorted_by(&mut looporder, |&a, &b| {
            let ai = g.b[lbs[a].head.expect("head")].index;
            let bi = g.b[lbs[b].head.expect("head")].index;
            if ai != bi {
                return ai < bi;
            }
            g.b[lbs[a].tails[0]].index < g.b[lbs[b].tails[0]].index
        });
        looporder
    }

    pub fn order_loop_bodies(&mut self) {
        let mut looporder = self.label_loops();
        self.order = (0..self.loopbody.len()).collect();
        if !self.loopbody.is_empty() {
            let oldsize = looporder.len();
            // mergeIdenticalHeads
            let mut i = 0;
            let mut cur = looporder[0];
            for j in 1..looporder.len() {
                let next = looporder[j];
                if self.loopbody[next].head == self.loopbody[cur].head {
                    let t = self.loopbody[next].tails[0];
                    self.loopbody[cur].tails.push(t);
                    self.loopbody[next].head = None;
                } else {
                    i += 1;
                    looporder[i] = next;
                    cur = next;
                }
            }
            looporder.truncate(i + 1);
            if oldsize != looporder.len() {
                let lbs = &self.loopbody;
                self.order.retain(|&l| lbs[l].head.is_some());
            }
            let order = self.order.clone();
            for &li in &order {
                let mut body = Vec::new();
                self.find_base(li, &mut body);
                self.label_containments(li, &body, &looporder);
                self.g.clear_marks(&body);
            }
            let lbs = &self.loopbody;
            self.order.sort_by(|&a, &b| lbs[b].depth.cmp(&lbs[a].depth));
            let order = self.order.clone();
            for &li in &order {
                let mut body = Vec::new();
                self.find_base(li, &mut body);
                self.find_exit(li, &body);
                self.order_tails(li);
                self.extend(li, &mut body);
                self.label_exit_edges(li, &body);
                self.g.clear_marks(&body);
            }
        }
        self.likelylistfull = false;
        self.pos = 0;
    }

    fn update_loop_body(&mut self) -> Res<bool> {
        if self.finaltrace {
            return Ok(false);
        }
        let mut loopbottom: Option<usize> = None;
        let mut looptop: Option<usize> = None;
        while self.pos < self.order.len() {
            let li = self.order[self.pos];
            loopbottom = self.update(li);
            if let Some(bottom) = loopbottom {
                looptop = self.loopbody[li].head;
                if Some(bottom) == looptop {
                    self.likelygoto.clear();
                    self.likelygoto.push((bottom, bottom));
                    self.likelyiter = 0;
                    self.likelylistfull = true;
                    return Ok(true);
                }
                if !self.likelylistfull || self.likelyiter != self.likelygoto.len() {
                    break;
                }
            }
            self.pos += 1;
            self.likelylistfull = false;
            loopbottom = None;
        }
        if self.likelylistfull && self.likelyiter != self.likelygoto.len() {
            return Ok(true);
        }
        self.likelygoto.clear();
        let mut tracer = TraceDag::new(self.g);
        if let Some(bottom) = loopbottom {
            tracer.roots.push(looptop.expect("loop top"));
            tracer.finishblock = Some(bottom);
            let li = self.order[self.pos];
            // setExitMarks
            let mut edges = self.loopbody[li].exitedges.clone();
            for e in edges.iter_mut() {
                if let Some((inloop, outedge)) = tracer.g.current_edge(e) {
                    tracer.g.set_out_edge_flag(inloop, outedge, E_LOOP_EXIT);
                }
            }
            self.loopbody[li].exitedges = edges;
        } else {
            let list = tracer.g.b[tracer.g.root].list.clone();
            for bl in list {
                if tracer.g.size_in(bl) == 0 {
                    tracer.roots.push(bl);
                }
            }
        }
        tracer.initialize();
        tracer.push_branches();
        let mut found = std::mem::take(&mut tracer.likelygoto);
        drop(tracer);
        self.likelygoto.append(&mut found);
        self.likelylistfull = true;
        if loopbottom.is_some() {
            let li = self.order[self.pos];
            self.emit_likely_edges(li);
            self.clear_exit_marks(li);
        } else if self.likelygoto.is_empty() {
            self.finaltrace = true;
            return Ok(false);
        }
        self.likelyiter = 0;
        Ok(true)
    }

    fn select_goto(&mut self) -> Res<Option<usize>> {
        while self.update_loop_body()? {
            while self.likelyiter < self.likelygoto.len() {
                let mut edge = self.likelygoto[self.likelyiter];
                let cur = self.g.current_edge(&mut edge);
                self.likelygoto[self.likelyiter] = edge;
                self.likelyiter += 1;
                if let Some((startbl, outedge)) = cur {
                    self.g.set_goto_branch(startbl, outedge);
                    return Ok(Some(startbl));
                }
            }
        }
        if !self.clip_extra_roots() {
            return Err("Could not finish collapsing block structure".into());
        }
        Ok(None)
    }

    pub fn collapse_all(&mut self) -> Res<()> {
        self.finaltrace = false;
        for b in 0..self.g.b.len() {
            self.g.b[b].visit = 0;
        }
        self.order_loop_bodies();
        self.collapse_conditions()?;
        let mut isolated = self.collapse_internal(None)?;
        // Each pass marks one more edge a goto: more passes than edges is a loop.
        let mut budget = self.g.b.iter().map(|b| b.outs.len()).sum::<usize>() + self.g.b.len() + 16;
        while isolated < self.g.b[self.g.root].list.len() {
            if budget == 0 {
                return Err("block structuring did not converge".into());
            }
            budget -= 1;
            let target = self.select_goto()?;
            isolated = self.collapse_internal(target)?;
        }
        Ok(())
    }
}

// ---- TraceDAG --------------------------------------------------------------

struct TraceDag<'g> {
    g: &'g mut Graph,
    bps: Vec<BranchPoint>,
    traces: Vec<BlockTrace>,
    active: Vec<usize>,
    roots: Vec<usize>,
    finishblock: Option<usize>,
    likelygoto: Vec<Floating>,
    current: usize,
    missed: usize,
}

impl<'g> TraceDag<'g> {
    fn new(g: &'g mut Graph) -> Self {
        TraceDag {
            g,
            bps: Vec::new(),
            traces: Vec::new(),
            active: Vec::new(),
            roots: Vec::new(),
            finishblock: None,
            likelygoto: Vec::new(),
            current: 0,
            missed: 0,
        }
    }

    fn new_trace(&mut self, bp: usize, pathout: i32, edge: usize) -> usize {
        let bottom = self.bps[bp].top.expect("branch point block");
        let dest = self.g.get_out(bottom, edge);
        self.traces.push(BlockTrace {
            flags: 0,
            top: bp,
            pathout,
            bottom: Some(bottom),
            destnode: Some(dest),
            edgelump: 1,
            derivedbp: None,
        });
        self.traces.len() - 1
    }

    fn create_traces(&mut self, bp: usize) {
        let top = self.bps[bp].top.expect("top");
        for i in 0..self.g.size_out(top) {
            if !self.g.is_loop_dag_out(top, i) {
                continue;
            }
            let po = self.bps[bp].paths.len() as i32;
            let t = self.new_trace(bp, po, i);
            self.bps[bp].paths.push(t);
        }
    }

    fn new_branch_from(&mut self, parenttrace: usize) -> usize {
        let parent = self.traces[parenttrace].top;
        let bp = BranchPoint {
            parent: Some(parent),
            depth: self.bps[parent].depth + 1,
            pathout: self.traces[parenttrace].pathout,
            top: self.traces[parenttrace].destnode,
            paths: Vec::new(),
        };
        self.bps.push(bp);
        let id = self.bps.len() - 1;
        self.create_traces(id);
        id
    }

    fn position(&self, trace: usize) -> usize {
        self.active.iter().position(|&t| t == trace).expect("active trace")
    }

    fn insert_active(&mut self, trace: usize) {
        self.active.push(trace);
        self.traces[trace].flags |= BT_ACTIVE;
    }

    fn remove_active(&mut self, trace: usize) {
        let p = self.position(trace);
        self.active.remove(p);
        self.traces[trace].flags &= !BT_ACTIVE;
    }

    fn is_terminal(&self, trace: usize) -> bool {
        self.traces[trace].flags & BT_TERMINAL != 0
    }

    fn remove_trace(&mut self, trace: usize) {
        let (bottom, dest, lump) = {
            let t = &self.traces[trace];
            (t.bottom, t.destnode, t.edgelump)
        };
        self.likelygoto.push((bottom.expect("bottom"), dest.expect("dest")));
        let d = dest.expect("dest");
        self.g.b[d].visit += lump;
        let parentbp = self.traces[trace].top;
        if bottom != self.bps[parentbp].top {
            let t = &mut self.traces[trace];
            t.flags |= BT_TERMINAL;
            t.bottom = None;
            t.destnode = None;
            t.edgelump = 0;
            return;
        }
        self.remove_active(trace);
        let size = self.bps[parentbp].paths.len();
        let po = self.traces[trace].pathout as usize;
        for i in (po + 1)..size {
            let moved = self.bps[parentbp].paths[i];
            self.traces[moved].pathout -= 1;
            if let Some(d) = self.traces[moved].derivedbp {
                self.bps[d].pathout -= 1;
            }
            self.bps[parentbp].paths[i - 1] = moved;
        }
        self.bps[parentbp].paths.pop();
    }

    fn process_exit_conflict(&self, scores: &mut [BadEdgeScore]) {
        // `scores` is one group of traces going to the same exit block.
        let n = scores.len();
        let mut start = 0;
        while start < n {
            let startbp = self.traces[scores[start].trace].top;
            if start + 1 < n {
                // markPath
                let mut bps_mark = Vec::new();
                let mut cur = Some(startbp);
                while let Some(c) = cur {
                    bps_mark.push(c);
                    cur = self.bps[c].parent;
                }
                let on_path: HashSet<usize> = bps_mark.into_iter().collect();
                for it in (start + 1)..n {
                    let itbp = self.traces[scores[it].trace].top;
                    if startbp == itbp {
                        scores[start].siblingedge += 1;
                        scores[it].siblingedge += 1;
                    }
                    // distance(), with the path marks held in `on_path`
                    let mut cur = Some(itbp);
                    let mut dist = self.bps[startbp].depth + self.bps[itbp].depth + 1;
                    while let Some(c) = cur {
                        if on_path.contains(&c) {
                            dist = (self.bps[startbp].depth - self.bps[c].depth)
                                + (self.bps[itbp].depth - self.bps[c].depth);
                            break;
                        }
                        cur = self.bps[c].parent;
                    }
                    if scores[start].distance == -1 || scores[start].distance > dist {
                        scores[start].distance = dist;
                    }
                    if scores[it].distance == -1 || scores[it].distance > dist {
                        scores[it].distance = dist;
                    }
                }
            }
            start += 1;
        }
    }

    fn compare_final(&self, a: &BadEdgeScore, b: &BadEdgeScore) -> bool {
        // true if `a` is LESS likely to be the bad edge than `b`
        if a.siblingedge != b.siblingedge {
            return b.siblingedge < a.siblingedge;
        }
        if a.terminal != b.terminal {
            return a.terminal < b.terminal;
        }
        if a.distance != b.distance {
            return a.distance < b.distance;
        }
        self.bps[self.traces[a.trace].top].depth < self.bps[self.traces[b.trace].top].depth
    }

    fn select_bad_edge(&mut self) -> usize {
        let mut list: Vec<BadEdgeScore> = Vec::new();
        for &t in &self.active {
            if self.is_terminal(t) {
                continue;
            }
            let tr = &self.traces[t];
            if self.bps[tr.top].top.is_none() && tr.bottom.is_none() {
                continue;
            }
            let dest = tr.destnode.expect("dest");
            list.push(BadEdgeScore {
                trace: t,
                exitproto: dest,
                distance: -1,
                siblingedge: 0,
                terminal: if self.g.size_out(dest) == 0 { 1 } else { 0 },
            });
        }
        {
            let g = &*self.g;
            let traces = &self.traces;
            let bps = &self.bps;
            list.sort_by(|a, b| {
                let key = |s: &BadEdgeScore| {
                    (
                        g.b[s.exitproto].index,
                        bps[traces[s.trace].top].top.map(|t| g.b[t].index).unwrap_or(-1),
                        traces[s.trace].pathout,
                    )
                };
                key(a).cmp(&key(b))
            });
        }
        let mut start = 0;
        while start < list.len() {
            let mut end = start + 1;
            while end < list.len() && list[end].exitproto == list[start].exitproto {
                end += 1;
            }
            if end - start > 1 {
                let mut group = list[start..end].to_vec();
                self.process_exit_conflict(&mut group);
                list[start..end].clone_from_slice(&group);
            }
            start = end;
        }
        let mut max = 0;
        for i in 1..list.len() {
            if self.compare_final(&list[max], &list[i]) {
                max = i;
            }
        }
        list[max].trace
    }

    fn check_open(&self, trace: usize) -> bool {
        if self.is_terminal(trace) {
            return false;
        }
        let t = &self.traces[trace];
        let mut isroot = false;
        if self.bps[t.top].depth == 0 {
            if t.bottom.is_none() {
                return true;
            }
            isroot = true;
        }
        let bl = t.destnode.expect("dest");
        if Some(bl) == self.finishblock && !isroot {
            return false;
        }
        let ignore = t.edgelump + self.g.b[bl].visit;
        let mut count = 0;
        for i in 0..self.g.size_in(bl) {
            if self.g.is_loop_dag_in(bl, i) {
                count += 1;
                if count > ignore {
                    return false;
                }
            }
        }
        true
    }

    /// Returns the position (in the active list) of the first new trace, or
    /// of the parent when there is nothing to open.
    fn open_branch(&mut self, parent: usize) -> usize {
        let nb = self.new_branch_from(parent);
        self.traces[parent].derivedbp = Some(nb);
        if self.bps[nb].paths.is_empty() {
            self.bps.pop();
            self.traces[parent].derivedbp = None;
            let t = &mut self.traces[parent];
            t.flags |= BT_TERMINAL;
            t.bottom = None;
            t.destnode = None;
            t.edgelump = 0;
            return self.position(parent);
        }
        self.remove_active(parent);
        for p in self.bps[nb].paths.clone() {
            self.insert_active(p);
        }
        self.position(self.bps[nb].paths[0])
    }

    fn check_retirement(&self, trace: usize) -> Option<Option<usize>> {
        if self.traces[trace].pathout != 0 {
            return None;
        }
        let bp = self.traces[trace].top;
        if self.bps[bp].depth == 0 {
            for &p in &self.bps[bp].paths {
                if self.traces[p].flags & BT_ACTIVE == 0 || !self.is_terminal(p) {
                    return None;
                }
            }
            return Some(None);
        }
        let mut outblock: Option<usize> = None;
        for &p in &self.bps[bp].paths {
            if self.traces[p].flags & BT_ACTIVE == 0 {
                return None;
            }
            if self.is_terminal(p) {
                continue;
            }
            let dest = self.traces[p].destnode;
            if outblock == dest {
                continue;
            }
            if outblock.is_some() {
                return None;
            }
            outblock = dest;
        }
        Some(outblock)
    }

    fn retire_branch(&mut self, bp: usize, exitblock: Option<usize>) -> usize {
        let mut edgeout_bl: Option<usize> = None;
        let mut edgelump_sum = 0;
        for p in self.bps[bp].paths.clone() {
            if !self.is_terminal(p) {
                edgelump_sum += self.traces[p].edgelump;
                if edgeout_bl.is_none() {
                    edgeout_bl = self.traces[p].bottom;
                }
            }
            self.remove_active(p);
        }
        if self.bps[bp].depth == 0 {
            return 0;
        }
        if let Some(parent) = self.bps[bp].parent {
            let parenttrace = self.bps[parent].paths[self.bps[bp].pathout as usize];
            self.traces[parenttrace].derivedbp = None;
            if edgeout_bl.is_none() {
                let t = &mut self.traces[parenttrace];
                t.flags |= BT_TERMINAL;
                t.bottom = None;
                t.destnode = None;
                t.edgelump = 0;
            } else {
                let t = &mut self.traces[parenttrace];
                t.bottom = edgeout_bl;
                t.destnode = exitblock;
                t.edgelump = edgelump_sum;
            }
            self.insert_active(parenttrace);
            return self.position(parenttrace);
        }
        0
    }

    fn initialize(&mut self) {
        self.bps.push(BranchPoint {
            parent: None,
            depth: 0,
            pathout: -1,
            top: None,
            paths: Vec::new(),
        });
        for &root in &self.roots.clone() {
            let po = self.bps[0].paths.len() as i32;
            self.traces.push(BlockTrace {
                flags: 0,
                top: 0,
                pathout: po,
                bottom: None,
                destnode: Some(root),
                edgelump: 1,
                derivedbp: None,
            });
            let t = self.traces.len() - 1;
            self.bps[0].paths.push(t);
            self.insert_active(t);
        }
    }

    fn push_branches(&mut self) {
        self.current = 0;
        self.missed = 0;
        let mut steps = 0usize;
        while !self.active.is_empty() {
            steps += 1;
            if steps > 50_000_000 {
                break;
            }
            if self.current >= self.active.len() {
                self.current = 0;
            }
            let curtrace = self.active[self.current];
            if self.missed >= self.active.len() {
                let bad = self.select_bad_edge();
                self.remove_trace(bad);
                self.current = 0;
                self.missed = 0;
            } else if let Some(exitblock) = self.check_retirement(curtrace) {
                let bp = self.traces[curtrace].top;
                self.current = self.retire_branch(bp, exitblock);
                self.missed = 0;
            } else if self.check_open(curtrace) {
                self.current = self.open_branch(curtrace);
                self.missed = 0;
            } else {
                self.missed += 1;
                self.current += 1;
            }
        }
        // clearVisitCount
        for (_, bottom) in self.likelygoto.clone() {
            self.g.b[bottom].visit = 0;
        }
    }
}
