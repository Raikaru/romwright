//! `ActionFinalStructure` (block ordering, switch case order, `break`,
//! unstructured-target and label marking) and the conversion of the finished
//! hierarchy into the [`Node`] tree the printer reads.

use super::loops::Collapse;
use super::*;

/// The finished tree.
pub struct FinalTree {
    pub body: Vec<Node>,
}

/// Runs `work`, turning a panic in the structurer (an edge case of a graph
/// shape it was not written for) into the error of that one function.
fn guarded<T>(work: impl FnOnce() -> Res<T>) -> Res<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
        .unwrap_or_else(|_| Err("the structurer panicked on this graph".to_string()))
}

/// Builds the structured tree of an exported graph.
pub fn build(cfg: &mut Cfg) -> Res<FinalTree> {
    guarded(|| build_unguarded(cfg))
}

fn build_unguarded(cfg: &mut Cfg) -> Res<FinalTree> {
    let mut g = Graph::new(cfg);
    Collapse::new(&mut g).collapse_all()?;
    g.prefer_complement(&cfg.prefer);
    g.finalize();
    let mut body = g.nodes(cfg);
    take_loop_ops(&mut body);
    Ok(FinalTree { body })
}

/// A `for` loop prints its initializer and iterator in its header: take the
/// two statements out of the blocks that hold them, for every loop the
/// structure printed that way. The decompiler exports them as ordinary
/// statements, so a loop its structure did not make a `while` keeps them.
pub fn take_loop_ops(body: &mut [Node]) {
    fn collect(node: &Node, ops: &mut HashSet<u64>) {
        if let Detail::WhileDo {
            initialize, iterate, ..
        } = &node.detail
        {
            ops.extend(initialize.iter().chain(iterate.iter()).map(|(op, ..)| *op));
        }
        for child in &node.children {
            collect(child, ops);
        }
        if let Detail::Switch { cases } = &node.detail {
            for case in cases {
                if let CaseBody::Block(block) = &case.body {
                    collect(block, ops);
                }
            }
        }
    }
    fn remove(node: &mut Node, ops: &HashSet<u64>) {
        if let Detail::Basic(basic) = &mut node.detail {
            let before = basic.statements.len();
            basic
                .statements
                .retain(|statement| statement.is_branch || !ops.contains(&statement.op));
            if basic.statements.len() != before {
                basic.holds_loop_op = true;
            }
        }
        for child in &mut node.children {
            remove(child, ops);
        }
        if let Detail::Switch { cases } = &mut node.detail {
            for case in cases {
                if let CaseBody::Block(block) = &mut case.body {
                    remove(block, ops);
                }
            }
        }
    }
    let mut ops = HashSet::new();
    for node in body.iter() {
        collect(node, &mut ops);
    }
    if ops.is_empty() {
        return;
    }
    for node in body.iter_mut() {
        remove(node, &ops);
    }
}

/// What `ActionBlockStructure` learns from structuring the graph as it is.
pub struct Analysis {
    /// The blocks whose `CBRANCH` the structure negates (net): Ghidra flips
    /// them in the p-code (`BlockBasic::negateCondition`), where
    /// `RuleCondNegate` and the boolean rules turn the flip into the
    /// comparison's complement.
    pub flips: Vec<usize>,
    /// For each return block with several in-edges: the in-edge slots whose
    /// predecessor sits under a structured `goto` to it, in the order
    /// `ActionReturnSplit` splits them (highest slot first).
    pub returns: Vec<(usize, Vec<usize>)>,
    /// For each `if`/`else` in `ActionPreferComplement`'s order, the
    /// condition blocks a complemented test would change in place.
    pub splits: Vec<Split>,
    /// The loops `BlockWhileDo::finalTransform` looks at, inner loops first:
    /// the loop's head block, the block holding its `CBRANCH` and its tail.
    pub loops: Vec<(usize, usize, usize)>,
}

/// `FlowBlock::getSplitPoint`: the basic blocks whose `CBRANCH` decides an
/// `if` (through `&&`/`||` and lists), as `BlockIf::preferComplement` tests them.
#[derive(Clone, Debug)]
pub enum Split {
    None,
    Leaf(usize),
    Cond(usize, Box<Split>, Box<Split>),
}

/// Structures a graph for the decompiler's pipeline.
pub fn analyze(cfg: &Cfg) -> Res<Analysis> {
    guarded(|| analyze_unguarded(cfg))
}

fn analyze_unguarded(cfg: &Cfg) -> Res<Analysis> {
    let mut g = Graph::new(cfg);
    Collapse::new(&mut g).collapse_all()?;
    let flips = (0..cfg.blocks.len())
        .filter(|&b| g.negated[b] != cfg.blocks[b].flipped)
        .collect();
    let mut returns = Vec::new();
    for (parent, block) in cfg.blocks.iter().enumerate() {
        if block.last == Last::Return && block.ins.len() > 1 {
            returns.push((parent, g.return_split_slots(parent)));
        }
    }
    let splits = g
        .if_elses()
        .into_iter()
        .map(|b| g.split_point(g.b[b].list[0]))
        .collect();
    let mut loops = Vec::new();
    g.for_loop_candidates(g.root, &mut loops);
    Ok(Analysis {
        flips,
        returns,
        splits,
        loops,
    })
}

impl Graph {
    /// `BlockWhileDo::finalTransform`'s walk: children first, then the loop
    /// itself when it is not in overflow syntax and has a test and a body that
    /// ends in an op.
    fn for_loop_candidates(&self, b: usize, out: &mut Vec<(usize, usize, usize)>) {
        for &child in &self.b[b].list {
            self.for_loop_candidates(child, out);
        }
        let blk = &self.b[b];
        if blk.kind != kind::WHILE_DO || blk.flags & F_WHILEDO_OVERFLOW != 0 || blk.list.len() != 2 {
            return;
        }
        let head = self.front_leaf(b).map(|l| self.b[l].basic);
        let test = self.last_basic(blk.list[0]);
        let tail = self.last_basic(blk.list[1]);
        if let (Some(head), Some(test), Some(tail)) = (head, test, tail)
            && self.last[test] == Last::Cbranch
        {
            out.push((head, test, tail));
        }
    }

    /// The `if`/`else` blocks in the order `ActionPreferComplement` visits
    /// them: the hierarchy breadth first.
    fn if_elses(&self) -> Vec<usize> {
        let mut queue = vec![self.root];
        let mut found = Vec::new();
        let mut pos = 0;
        while pos < queue.len() {
            let cur = queue[pos];
            pos += 1;
            for &child in &self.b[cur].list {
                if self.b[child].kind != kind::COPY {
                    queue.push(child);
                }
            }
            if self.b[cur].kind == kind::IF && self.b[cur].list.len() == 3 {
                found.push(cur);
            }
        }
        found
    }

    fn split_point(&self, b: usize) -> Split {
        let blk = &self.b[b];
        match blk.kind {
            kind::COPY if self.orig_outs[blk.basic].len() == 2 => Split::Leaf(blk.basic),
            kind::LIST => blk.list.last().map_or(Split::None, |&l| self.split_point(l)),
            kind::CONDITION => Split::Cond(
                b,
                Box::new(self.split_point(blk.list[0])),
                Box::new(self.split_point(blk.list[1])),
            ),
            _ => Split::None,
        }
    }

    /// `flipInPlaceExecute` of a split: the decompiler changed the test's
    /// p-code in place, so its edges and the `&&`/`||` swap and the printed
    /// statements (which already show the changed test) keep their polarity.
    fn execute_split(&mut self, split: &Split) {
        match split {
            Split::None => {}
            Split::Leaf(basic) => {
                self.fall[*basic] = !self.fall[*basic];
                self.negated[*basic] = !self.negated[*basic];
            }
            Split::Cond(b, left, right) => {
                self.b[*b].and = !self.b[*b].and;
                self.execute_split(left);
                self.execute_split(right);
            }
        }
    }

    /// `BlockIf::preferComplement` for the `if`/`else` blocks (by position in
    /// [`Graph::if_elses`]) the decompiler flipped: the arms swap.
    fn prefer_complement(&mut self, flipped: &[usize]) {
        let ifs = self.if_elses();
        for &i in flipped {
            if let Some(&b) = ifs.get(i) {
                let split = self.split_point(self.b[b].list[0]);
                self.execute_split(&split);
                self.b[b].list.swap(1, 2);
            }
        }
    }

    fn return_split_slots(&self, parent: usize) -> Vec<usize> {
        let gotoblocks = self.gather_return_gotos(parent);
        let mut slots = Vec::new();
        if gotoblocks.is_empty() {
            return slots;
        }
        let insize = self.orig_ins[parent].len();
        let mut splitcount = 0;
        for i in (0..insize).rev() {
            let mut bl = Some(self.orig_ins[parent][i].point);
            while let Some(x) = bl {
                if gotoblocks.contains(&x) {
                    slots.push(i);
                    splitcount += 1;
                    break;
                }
                bl = self.b[x].parent;
            }
        }
        if insize == splitcount {
            slots.pop();
        }
        slots
    }

    fn gather_return_gotos(&self, parent: usize) -> HashSet<usize> {
        let mut marked = HashSet::new();
        for e in &self.orig_ins[parent] {
            let mut bl = Some(e.point);
            while let Some(x) = bl {
                if !marked.contains(&x) {
                    let ret = match self.b[x].kind {
                        kind::GOTO if self.goto_prints(x) => self.b[x].goto_target,
                        kind::IF => self.b[x].goto_target,
                        _ => None,
                    };
                    if let Some(r) = ret
                        && self.front_leaf(r).map(|l| self.b[l].basic) == Some(parent)
                    {
                        marked.insert(x);
                    }
                }
                bl = self.b[x].parent;
            }
        }
        marked
    }

    /// `orderBlocks`, `finalizePrinting`, `scopeBreak`, `markUnstructured`
    /// and `markLabelBumpUp`, in `ActionFinalStructure`'s order.
    fn finalize(&mut self) {
        let root = self.root;
        // orderBlocks: entry first, returns last, otherwise by index.
        if self.b[root].list.len() != 1 {
            let mut list = std::mem::take(&mut self.b[root].list);
            {
                let g = &*self;
                sorted_by(&mut list, |&a, &b| g.final_order_less(a, b));
            }
            self.b[root].list = list;
        }
        self.finalize_switches(root);
        self.scope_break(root, -1, -1);
        self.mark_unstructured(root);
        self.mark_label_bump_up(root, false);
    }

    fn final_order_less(&self, bl1: usize, bl2: usize) -> bool {
        if self.b[bl1].index == 0 {
            return true;
        }
        if self.b[bl2].index == 0 {
            return false;
        }
        let k1 = self.last_kind(bl1);
        let k2 = self.last_kind(bl2);
        if k1 != Last::None {
            if k2 != Last::None {
                if k1 == Last::Return && k2 != Last::Return {
                    return false;
                }
                if k1 != Last::Return && k2 == Last::Return {
                    return true;
                }
            }
            if k1 == Last::Return {
                return false;
            }
        } else if k2 != Last::None && k2 == Last::Return {
            return true;
        }
        self.b[bl1].index < self.b[bl2].index
    }

    fn finalize_switches(&mut self, b: usize) {
        for child in self.b[b].list.clone() {
            self.finalize_switches(child);
        }
        if self.b[b].kind != kind::SWITCH {
            return;
        }
        let sw = self.b[b].switch_basic;
        let mut cases = std::mem::take(&mut self.b[b].cases);
        for i in 0..cases.len() {
            let mut j = cases[i].chain;
            while j != -1 {
                if cases[j as usize].depth != 0 {
                    break;
                }
                cases[j as usize].depth = -1;
                j = cases[j as usize].chain;
            }
        }
        for i in 0..cases.len() {
            let labels = self.switch_edges[sw]
                .get(cases[i].outindex)
                .and_then(|e| e.as_ref())
                .map(|e| e.labels.clone())
                .unwrap_or_default();
            if let Some(&first) = labels.first() {
                if cases[i].depth == 0 {
                    cases[i].label = first;
                    let mut j = cases[i].chain;
                    let mut depthcount = 1;
                    let label = cases[i].label;
                    while j != -1 {
                        if cases[j as usize].depth > 0 {
                            break;
                        }
                        cases[j as usize].depth = depthcount;
                        depthcount += 1;
                        cases[j as usize].label = label;
                        j = cases[j as usize].chain;
                    }
                }
            } else {
                cases[i].label = 0;
            }
        }
        cases.sort_by(|a, b| a.label.cmp(&b.label).then(a.depth.cmp(&b.depth)));
        self.b[b].cases = cases;
    }

    fn scope_break(&mut self, b: usize, curexit: i64, curloopexit: i64) {
        let list = self.b[b].list.clone();
        match self.b[b].kind {
            kind::COPY => {}
            kind::GOTO => {
                let target = self.b[b].goto_target.expect("goto target");
                let tindex = self.b[target].index;
                self.scope_break(list[0], tindex, curloopexit);
                if curloopexit == tindex {
                    self.b[b].goto_type = F_BREAK_GOTO;
                }
            }
            kind::MULTIGOTO => self.scope_break(list[0], -1, curloopexit),
            kind::CONDITION => {
                self.scope_break(list[0], -1, curloopexit);
                self.scope_break(list[1], -1, curloopexit);
            }
            kind::IF => {
                self.scope_break(list[0], -1, curloopexit);
                for &c in list.iter().skip(1) {
                    self.scope_break(c, curexit, curloopexit);
                }
                if let Some(t) = self.b[b].goto_target
                    && self.b[t].index == curloopexit
                {
                    self.b[b].goto_type = F_BREAK_GOTO;
                }
            }
            kind::WHILE_DO => {
                self.scope_break(list[0], -1, curexit);
                let idx = self.b[list[0]].index;
                self.scope_break(list[1], idx, curexit);
            }
            kind::DO_WHILE => self.scope_break(list[0], -1, curexit),
            kind::INFINITE_LOOP => {
                let idx = self.b[list[0]].index;
                self.scope_break(list[0], idx, curexit);
            }
            kind::SWITCH => {
                self.scope_break(list[0], -1, curexit);
                for i in 0..self.b[b].cases.len() {
                    let bl = self.b[b].cases[i].block;
                    if self.b[b].cases[i].gototype != 0 {
                        if self.b[bl].index == curexit {
                            self.b[b].cases[i].gototype = F_BREAK_GOTO;
                        }
                    } else {
                        self.scope_break(bl, curexit, curexit);
                    }
                }
            }
            _ => {
                for i in 0..list.len() {
                    let ind = if i + 1 < list.len() {
                        self.b[list[i + 1]].index
                    } else {
                        curexit
                    };
                    self.scope_break(list[i], ind, curloopexit);
                }
            }
        }
    }

    fn mark_unstructured(&mut self, b: usize) {
        if self.b[b].kind == kind::COPY {
            return;
        }
        for c in self.b[b].list.clone() {
            self.mark_unstructured(c);
        }
        match self.b[b].kind {
            kind::GOTO => {
                if self.b[b].goto_type == F_GOTO_GOTO && self.goto_prints(b) {
                    let t = self.b[b].goto_target.expect("goto target");
                    self.mark_copy_block(t, F_UNSTRUCTURED_TARG);
                }
            }
            kind::IF => {
                if let Some(t) = self.b[b].goto_target
                    && self.b[b].goto_type == F_GOTO_GOTO
                {
                    self.mark_copy_block(t, F_UNSTRUCTURED_TARG);
                }
            }
            kind::SWITCH => {
                for i in 0..self.b[b].cases.len() {
                    if self.b[b].cases[i].gototype == F_GOTO_GOTO {
                        let bl = self.b[b].cases[i].block;
                        self.mark_copy_block(bl, F_UNSTRUCTURED_TARG);
                    }
                }
            }
            _ => {}
        }
    }

    fn mark_label_bump_up(&mut self, b: usize, bump: bool) {
        let loopish = matches!(self.b[b].kind, kind::WHILE_DO | kind::DO_WHILE | kind::INFINITE_LOOP);
        let effective = bump || loopish;
        if effective {
            self.b[b].flags |= F_LABEL_BUMPUP;
        }
        let list = self.b[b].list.clone();
        for (i, &c) in list.iter().enumerate() {
            self.mark_label_bump_up(c, effective && i == 0);
        }
        if loopish && !bump {
            self.b[b].flags &= !F_LABEL_BUMPUP;
        }
    }

    // ---- Node conversion ---------------------------------------------------

    fn front_basic(&self, b: usize) -> i64 {
        match self.front_leaf(b) {
            Some(leaf) => self.b[leaf].basic as i64,
            None => -1,
        }
    }

    fn goto_target_of(&self, b: usize) -> GotoTarget {
        GotoTarget {
            block: self.front_basic(b),
            label: self
                .front_leaf(b)
                .map(|l| self.labels[self.b[l].basic].clone())
                .unwrap_or_default(),
        }
    }

    fn nodes(&mut self, cfg: &mut Cfg) -> Vec<Node> {
        let root = self.root;
        let list = self.b[root].list.clone();
        list.into_iter().map(|b| self.node(b, cfg)).collect()
    }

    fn node(&mut self, b: usize, cfg: &mut Cfg) -> Node {
        let leaf = if self.b[b].flags & F_LABEL_BUMPUP != 0 { None } else { self.front_leaf(b) };
        let label = leaf
            .filter(|&l| self.b[l].flags & F_UNSTRUCTURED_TARG != 0 && self.b[l].kind == kind::COPY)
            .map(|l| self.labels[self.b[l].basic].clone());
        let mut node = Node {
            kind: self.b[b].kind,
            index: self.b[b].index,
            last_op: self.last_op_time(b),
            label,
            children: Vec::new(),
            detail: Detail::None,
        };
        if self.b[b].kind == kind::COPY {
            let basic = self.b[b].basic;
            let mut data = cfg.blocks[basic].basic.take().expect("basic block placed once");
            if self.negated[basic] {
                negate_basic(&mut data, self.last_time[basic]);
            }
            node.children.push(Node {
                kind: kind::BASIC,
                index: basic as i64,
                last_op: self.last_time[basic],
                label: None,
                children: Vec::new(),
                detail: Detail::Basic(data),
            });
            node.detail = Detail::Copy {
                label: self.labels[basic].clone(),
            };
            return node;
        }
        let list = self.b[b].list.clone();
        node.children = list.iter().map(|&c| self.node(c, cfg)).collect();
        node.detail = match self.b[b].kind {
            kind::GOTO => Detail::Goto {
                prints: self.goto_prints(b),
                goto_kind: self.b[b].goto_type as u64,
                target: self.b[b].goto_target.map(|t| self.goto_target_of(t)),
            },
            kind::LIST => Detail::List {
                flow_breaks: (0..list.len().saturating_sub(1))
                    .map(|i| self.next_in_flow(list[i]) != Some(list[i + 1]))
                    .collect(),
            },
            kind::CONDITION => Detail::Condition { and: self.b[b].and },
            kind::IF => Detail::If {
                goto_kind: self.b[b].goto_type as u64,
                target: self.b[b].goto_target.map(|t| self.goto_target_of(t)),
            },
            kind::WHILE_DO => {
                let head = self.front_leaf(b).map(|l| self.b[l].basic);
                let tail = list.get(1).and_then(|&body| self.last_basic(body));
                let overflow = self.b[b].flags & F_WHILEDO_OVERFLOW != 0;
                let record = cfg
                    .loops
                    .iter()
                    .find(|r| !overflow && Some(r.head) == head && Some(r.tail) == tail);
                Detail::WhileDo {
                    overflow: self.b[b].flags & F_WHILEDO_OVERFLOW != 0,
                    initialize: record.and_then(|r| r.initialize.clone()),
                    iterate: record.and_then(|r| r.iterate.clone()),
                }
            }
            kind::SWITCH => {
                let sw = self.b[b].switch_basic;
                let cases = self.b[b].cases.clone();
                Detail::Switch {
                    cases: cases
                        .iter()
                        .map(|c| {
                            let fragment = self.switch_edges[sw]
                                .get(c.outindex)
                                .and_then(|e| e.as_ref())
                                .map(|e| e.fragment.clone())
                                .unwrap_or_default();
                            let body = if c.gototype != 0 {
                                CaseBody::Goto {
                                    goto_kind: c.gototype as u64,
                                    target: Some(self.goto_target_of(c.block)),
                                }
                            } else {
                                CaseBody::Child(list.iter().position(|&x| x == c.block).unwrap_or(0))
                            };
                            Case {
                                labels: vec![fragment],
                                exit: c.isexit,
                                body,
                            }
                        })
                        .collect(),
                }
            }
            _ => Detail::None,
        };
        node
    }
}

/// `BlockBasic::negateCondition`'s effect on what prints: the block takes
/// PrintC's negated rendering and swaps its out-edges.
fn negate_basic(basic: &mut Basic, last_op: Option<u64>) {
    let (Some(negated), Some(branch)) = (&mut basic.negated, &mut basic.branch) else {
        return;
    };
    if basic.successors.len() != 2 {
        return;
    }
    std::mem::swap(negated, branch);
    for statement in &mut basic.statements {
        if statement.is_branch && Some(statement.op) == last_op {
            statement.expression = branch.clone();
            statement.effect.flip = !statement.effect.flip;
        }
    }
    basic.successors.swap(0, 1);
}

/// A compact description of a tree for comparing two structurings of one
/// graph: block kinds and indices, labels, gotos, switch cases and the
/// branch facts each leaf prints from.
pub fn shape(node: &Node) -> String {
    let mut out = String::new();
    describe(node, &mut out);
    out
}

fn describe(node: &Node, out: &mut String) {
    use std::fmt::Write;
    let _ = write!(out, "({}#{}@{:?}", node.kind, node.index, node.last_op);
    if let Some(label) = &node.label {
        let _ = write!(out, " label{:x}", fragment_hash(label));
    }
    match &node.detail {
        Detail::None => {}
        Detail::Basic(basic) => {
            let _ = write!(
                out,
                " succ{:?} stmts{} branch{} neg{}",
                basic.successors,
                basic.statements.len(),
                basic.branch.is_some(),
                basic.negated.is_some()
            );
            for statement in &basic.statements {
                let _ = write!(out, " s{}:{}", statement.op, statement.effect.flip as u8);
            }
        }
        Detail::Copy { .. } => {}
        Detail::Goto {
            prints,
            goto_kind,
            target,
        } => {
            let _ = write!(
                out,
                " goto{} k{} ->{:?}",
                *prints as u8,
                goto_kind,
                target.as_ref().map(|t| t.block)
            );
        }
        Detail::List { flow_breaks } => {
            let _ = write!(out, " breaks{flow_breaks:?}");
        }
        Detail::Condition { and } => {
            let _ = write!(out, " and{}", *and as u8);
        }
        Detail::If { goto_kind, target } => {
            let _ = write!(out, " k{} ->{:?}", goto_kind, target.as_ref().map(|t| t.block));
        }
        Detail::WhileDo {
            overflow,
            initialize,
            iterate,
        } => {
            let _ = write!(
                out,
                " overflow{} init{:?} iter{:?}",
                *overflow as u8,
                initialize.as_ref().map(|i| i.0),
                iterate.as_ref().map(|i| i.0)
            );
        }
        Detail::Switch { cases } => {
            for case in cases {
                let _ = write!(out, " case[{:x} exit{}", case.labels.iter().map(fragment_hash).fold(0u64, |a, h| a ^ h), case.exit as u8);
                match &case.body {
                    CaseBody::Goto { goto_kind, target } => {
                        let _ = write!(out, " goto k{} ->{:?}", goto_kind, target.as_ref().map(|t| t.block));
                    }
                    CaseBody::Child(i) => {
                        let _ = write!(out, " child{i}");
                    }
                    CaseBody::Block(_) => out.push_str(" block"),
                }
                out.push(']');
            }
        }
    }
    for child in &node.children {
        out.push(' ');
        describe(child, out);
    }
    out.push(')');
}

fn fragment_hash(fragment: &Fragment) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format!("{:?}", fragment).hash(&mut hasher);
    hasher.finish()
}
