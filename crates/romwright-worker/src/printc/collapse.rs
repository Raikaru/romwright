//! Block structuring in Rust: a port of Ghidra's `CollapseStructure`
//! (`blockaction.cc`) over the `BlockGraph` machinery of `block.cc`, run on the
//! unstructured control-flow graph the decompiler exports (docs/printer-ir.md,
//! "Unstructured handoff"). The result is the hierarchical block tree
//! `ActionBlockStructure` + `ActionFinalStructure` would have built, as the
//! [`Node`] tree the printer and the structure models consume.
//!
//! Porting Ghidra's Apache-2.0 code is the point of the module, so the
//! algorithm (edge bookkeeping, the loop and DAG traces that pick unstructured
//! edges, the rules and their order, switch recovery, final ordering, `break`
//! and label marking) follows it step for step; the comparison against the tree
//! the C++ built from the same graph (`ROMWRIGHT_STRUCTURE=verify`) is what
//! keeps that true.

use std::collections::HashSet;

use super::ir::{Basic, Case, CaseBody, Detail, Fragment, GotoTarget, Node, Source, kind};

// FlowBlock::block_flags
const F_GOTO_GOTO: u32 = 1;
const F_BREAK_GOTO: u32 = 2;
const F_SWITCH_OUT: u32 = 0x10;
const F_UNSTRUCTURED_TARG: u32 = 0x20;
const F_MARK: u32 = 0x80;
const F_INTERIOR_GOTOOUT: u32 = 0x400;
const F_INTERIOR_GOTOIN: u32 = 0x800;
const F_LABEL_BUMPUP: u32 = 0x1000;
const F_WHILEDO_OVERFLOW: u32 = 0x8000;
const F_FLIP_PATH: u32 = 0x10000;
/// The basic-block flags the structurer reads.
pub const BASIC_FLAG_MASK: u32 = F_SWITCH_OUT | F_UNSTRUCTURED_TARG | F_INTERIOR_GOTOOUT | F_INTERIOR_GOTOIN;

// FlowBlock::edge_flags
const E_GOTO: u32 = 1;
const E_LOOP: u32 = 2;
/// `f_defaultswitch_edge`
pub const E_DEFAULT: u32 = 4;
const E_IRREDUCIBLE: u32 = 8;
const E_BACK: u32 = 0x80;
const E_LOOP_EXIT: u32 = 0x100;

/// The kind of a basic block's last op, as far as structuring reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Last {
    None,
    Return,
    Cbranch,
    Other,
}

/// One edge of the exported graph: the block at the other end, the slot the
/// edge has in that block's opposite list, and its `FlowBlock::edge_flags`.
#[derive(Clone, Copy, Debug)]
pub struct CfgEdge {
    pub block: usize,
    pub rev: usize,
    pub label: u32,
}

/// What a `case` of a switch prints for one out-edge of its block: the
/// labels of the jump table entries that reach the target, and the
/// `emitSwitchCase` fragment (the `default:` line or the `case` lines).
#[derive(Clone, Debug, Default)]
pub struct SwitchEdge {
    pub labels: Vec<u64>,
    pub fragment: Fragment,
}

#[derive(Clone, Debug)]
pub struct CfgBlock {
    pub ins: Vec<CfgEdge>,
    pub outs: Vec<CfgEdge>,
    pub flags: u32,
    pub last: Last,
    pub last_time: Option<u64>,
    pub fallthru_true: bool,
    /// `BlockBasic::isComplex`
    pub complex: bool,
    /// The exported statements print the condition the other way round from
    /// the graph's edges (stock structuring negated it after the graph was
    /// taken): the block starts negated.
    pub flipped: bool,
    /// `PrintC::emitLabel` of the block
    pub label: Fragment,
    /// Per out-edge slot, for a switch block.
    pub switch_edges: Vec<Option<SwitchEdge>>,
    pub basic: Option<Basic>,
}

/// A loop of the basic-block graph the exporter found a for-loop initializer
/// and iterator for: the head block, the block holding the loop test and the
/// tail that flows back to the head.
#[derive(Clone, Debug)]
pub struct LoopRecord {
    pub head: usize,
    pub tail: usize,
    pub initialize: Option<(u64, Fragment, Source)>,
    pub iterate: Option<(u64, Fragment, Source)>,
}

#[derive(Clone, Debug, Default)]
pub struct Cfg {
    pub blocks: Vec<CfgBlock>,
    pub loops: Vec<LoopRecord>,
    /// The `if`/`else` blocks (by position in `ActionPreferComplement`'s
    /// order) the decompiler complemented in place.
    pub prefer: Vec<usize>,
}

#[derive(Clone, Copy, Debug)]
struct Edge {
    point: usize,
    label: u32,
    rev: usize,
}

#[derive(Clone, Debug, Default)]
struct CaseOrder {
    block: usize,
    label: u64,
    depth: i32,
    chain: i32,
    outindex: usize,
    gototype: u32,
    isexit: bool,
}

#[derive(Clone, Debug)]
struct Blk {
    kind: u64,
    flags: u32,
    index: i64,
    ins: Vec<Edge>,
    outs: Vec<Edge>,
    parent: Option<usize>,
    list: Vec<usize>,
    visit: i32,
    /// COPY: the basic block copied.
    basic: usize,
    goto_target: Option<usize>,
    goto_type: u32,
    gotoedges: Vec<usize>,
    default_goto: bool,
    and: bool,
    cases: Vec<CaseOrder>,
    /// SWITCH: the basic block with the jump table.
    switch_basic: usize,
}

impl Blk {
    fn new(kind: u64) -> Self {
        Blk {
            kind,
            flags: 0,
            index: 0,
            ins: Vec::new(),
            outs: Vec::new(),
            parent: None,
            list: Vec::new(),
            visit: 0,
            basic: usize::MAX,
            goto_target: None,
            goto_type: F_GOTO_GOTO,
            gotoedges: Vec::new(),
            default_goto: false,
            and: false,
            cases: Vec::new(),
            switch_basic: usize::MAX,
        }
    }
}

type Res<T> = Result<T, String>;

/// A loop's nesting and exit record (`LoopBody`).
#[derive(Clone, Debug)]
struct LoopBody {
    head: Option<usize>,
    tails: Vec<usize>,
    depth: i32,
    uniquecount: usize,
    exitblock: Option<usize>,
    immed_container: Option<usize>,
    exitedges: Vec<(usize, usize)>,
}

struct BranchPoint {
    parent: Option<usize>,
    depth: i32,
    pathout: i32,
    top: Option<usize>,
    paths: Vec<usize>,
}

const BT_ACTIVE: u32 = 1;
const BT_TERMINAL: u32 = 2;

struct BlockTrace {
    flags: u32,
    top: usize,
    pathout: i32,
    bottom: Option<usize>,
    destnode: Option<usize>,
    edgelump: i32,
    derivedbp: Option<usize>,
}

#[derive(Clone)]
struct BadEdgeScore {
    trace: usize,
    distance: i32,
    terminal: i32,
    siblingedge: i32,
    exitproto: usize,
}

/// The graph under structuring, with every block ever made.
pub struct Graph {
    b: Vec<Blk>,
    root: usize,
    /// Original basic-block edges, for the switch bookkeeping that reads them.
    orig_ins: Vec<Vec<Edge>>,
    orig_outs: Vec<Vec<Edge>>,
    last: Vec<Last>,
    last_time: Vec<Option<u64>>,
    fall: Vec<bool>,
    /// Parity of `BlockBasic::negateCondition` calls.
    negated: Vec<bool>,
    complex: Vec<bool>,
    switch_edges: Vec<Vec<Option<SwitchEdge>>>,
    labels: Vec<Fragment>,
}

fn sorted_by<T, F: FnMut(&T, &T) -> bool>(v: &mut [T], mut less: F) {
    v.sort_by(|a, b| {
        if less(a, b) {
            std::cmp::Ordering::Less
        } else if less(b, a) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
}

impl Graph {
    /// `BlockGraph::buildCopy` over the exported basic blocks.
    pub fn new(cfg: &Cfg) -> Self {
        let n = cfg.blocks.len();
        let mut g = Graph {
            b: Vec::with_capacity(n * 3),
            root: n,
            orig_ins: Vec::with_capacity(n),
            orig_outs: Vec::with_capacity(n),
            last: Vec::with_capacity(n),
            last_time: Vec::with_capacity(n),
            fall: Vec::with_capacity(n),
            negated: cfg.blocks.iter().map(|b| b.flipped).collect(),
            complex: Vec::with_capacity(n),
            switch_edges: Vec::with_capacity(n),
            labels: Vec::with_capacity(n),
        };
        for (i, block) in cfg.blocks.iter().enumerate() {
            let mut copy = Blk::new(kind::COPY);
            copy.index = i as i64;
            copy.basic = i;
            copy.flags = block.flags & BASIC_FLAG_MASK;
            copy.parent = Some(n);
            let edges = |list: &[CfgEdge]| {
                list.iter()
                    .map(|e| Edge {
                        point: e.block,
                        label: e.label,
                        rev: e.rev,
                    })
                    .collect::<Vec<_>>()
            };
            copy.ins = edges(&block.ins);
            copy.outs = edges(&block.outs);
            if copy.outs.len() > 2 {
                copy.flags |= F_SWITCH_OUT;
            }
            g.orig_ins.push(copy.ins.clone());
            g.orig_outs.push(copy.outs.clone());
            g.last.push(block.last);
            g.last_time.push(block.last_time);
            g.fall.push(block.fallthru_true);
            g.complex.push(block.complex);
            g.switch_edges.push(block.switch_edges.clone());
            g.labels.push(block.label.clone());
            g.b.push(copy);
        }
        let mut root = Blk::new(kind::GRAPH);
        root.list = (0..n).collect();
        root.index = 0;
        g.b.push(root);
        g
    }

    // ---- edge bookkeeping (FlowBlock) -------------------------------------

    fn size_in(&self, b: usize) -> usize {
        self.b[b].ins.len()
    }

    fn size_out(&self, b: usize) -> usize {
        self.b[b].outs.len()
    }

    fn get_in(&self, b: usize, i: usize) -> usize {
        self.b[b].ins[i].point
    }

    fn get_out(&self, b: usize, i: usize) -> usize {
        self.b[b].outs[i].point
    }

    fn out_index(&self, b: usize, target: usize) -> Option<usize> {
        self.b[b].outs.iter().position(|e| e.point == target)
    }

    fn add_in_edge(&mut self, b: usize, src: usize, label: u32) {
        let ourrev = self.b[src].outs.len();
        let brev = self.b[b].ins.len();
        self.b[b].ins.push(Edge {
            point: src,
            label,
            rev: ourrev,
        });
        self.b[src].outs.push(Edge {
            point: b,
            label,
            rev: brev,
        });
    }

    fn half_delete_in_edge(&mut self, b: usize, slot: usize) {
        let mut slot = slot;
        while slot + 1 < self.b[b].ins.len() {
            let edge = self.b[b].ins[slot + 1];
            self.b[b].ins[slot] = edge;
            self.b[edge.point].outs[edge.rev].rev -= 1;
            slot += 1;
        }
        self.b[b].ins.pop();
    }

    fn half_delete_out_edge(&mut self, b: usize, slot: usize) {
        let mut slot = slot;
        while slot + 1 < self.b[b].outs.len() {
            let edge = self.b[b].outs[slot + 1];
            self.b[b].outs[slot] = edge;
            self.b[edge.point].ins[edge.rev].rev -= 1;
            slot += 1;
        }
        self.b[b].outs.pop();
    }

    fn remove_in_edge(&mut self, b: usize, slot: usize) {
        let src = self.b[b].ins[slot].point;
        let rev = self.b[b].ins[slot].rev;
        self.half_delete_in_edge(b, slot);
        self.half_delete_out_edge(src, rev);
    }

    fn replace_in_edge(&mut self, b: usize, num: usize, nb: usize) {
        let oldb = self.b[b].ins[num].point;
        let oldrev = self.b[b].ins[num].rev;
        self.half_delete_out_edge(oldb, oldrev);
        let label = self.b[b].ins[num].label;
        self.b[b].ins[num].point = nb;
        self.b[b].ins[num].rev = self.b[nb].outs.len();
        self.b[nb].outs.push(Edge {
            point: b,
            label,
            rev: num,
        });
    }

    fn replace_out_edge(&mut self, b: usize, num: usize, nb: usize) {
        let oldb = self.b[b].outs[num].point;
        let oldrev = self.b[b].outs[num].rev;
        self.half_delete_in_edge(oldb, oldrev);
        let label = self.b[b].outs[num].label;
        self.b[b].outs[num].point = nb;
        self.b[b].outs[num].rev = self.b[nb].ins.len();
        self.b[nb].ins.push(Edge {
            point: b,
            label,
            rev: num,
        });
    }

    fn swap_edges(&mut self, b: usize) {
        self.b[b].outs.swap(0, 1);
        for slot in 0..2 {
            let e = self.b[b].outs[slot];
            self.b[e.point].ins[e.rev].rev = slot;
        }
        self.b[b].flags ^= F_FLIP_PATH;
    }

    fn set_out_edge_flag(&mut self, b: usize, i: usize, lab: u32) {
        let e = self.b[b].outs[i];
        self.b[b].outs[i].label |= lab;
        self.b[e.point].ins[e.rev].label |= lab;
    }

    fn set_goto_branch(&mut self, b: usize, i: usize) {
        self.set_out_edge_flag(b, i, E_GOTO);
        self.b[b].flags |= F_INTERIOR_GOTOOUT;
        let t = self.b[b].outs[i].point;
        self.b[t].flags |= F_INTERIOR_GOTOIN;
    }

    fn is_goto_out(&self, b: usize, i: usize) -> bool {
        self.b[b].outs[i].label & (E_IRREDUCIBLE | E_GOTO) != 0
    }

    fn is_goto_in(&self, b: usize, i: usize) -> bool {
        self.b[b].ins[i].label & (E_IRREDUCIBLE | E_GOTO) != 0
    }

    fn is_decision_out(&self, b: usize, i: usize) -> bool {
        self.b[b].outs[i].label & (E_IRREDUCIBLE | E_BACK | E_GOTO) == 0
    }

    fn is_loop_dag_out(&self, b: usize, i: usize) -> bool {
        self.b[b].outs[i].label & (E_IRREDUCIBLE | E_BACK | E_LOOP_EXIT | E_GOTO) == 0
    }

    fn is_loop_dag_in(&self, b: usize, i: usize) -> bool {
        self.b[b].ins[i].label & (E_IRREDUCIBLE | E_BACK | E_LOOP_EXIT | E_GOTO) == 0
    }

    fn is_back_edge_in(&self, b: usize, i: usize) -> bool {
        self.b[b].ins[i].label & E_BACK != 0
    }

    fn is_back_edge_out(&self, b: usize, i: usize) -> bool {
        self.b[b].outs[i].label & E_BACK != 0
    }

    fn is_default_branch(&self, b: usize, i: usize) -> bool {
        self.b[b].outs[i].label & E_DEFAULT != 0
    }

    fn is_switch_out(&self, b: usize) -> bool {
        self.b[b].flags & F_SWITCH_OUT != 0
    }

    fn is_mark(&self, b: usize) -> bool {
        self.b[b].flags & F_MARK != 0
    }

    fn set_mark(&mut self, b: usize) {
        self.b[b].flags |= F_MARK;
    }

    fn clear_mark(&mut self, b: usize) {
        self.b[b].flags &= !F_MARK;
    }

    fn eliminate_in_dups(&mut self, b: usize, bl: usize) {
        let mut indval: Option<usize> = None;
        let mut i = 0;
        while i < self.b[b].ins.len() {
            if self.b[b].ins[i].point == bl {
                match indval {
                    None => {
                        indval = Some(i);
                        i += 1;
                    }
                    Some(keep) => {
                        let label = self.b[b].ins[i].label;
                        self.b[b].ins[keep].label |= label;
                        let rev = self.b[b].ins[i].rev;
                        self.half_delete_in_edge(b, i);
                        self.half_delete_out_edge(bl, rev);
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    fn eliminate_out_dups(&mut self, b: usize, bl: usize) {
        let mut indval: Option<usize> = None;
        let mut i = 0;
        while i < self.b[b].outs.len() {
            if self.b[b].outs[i].point == bl {
                match indval {
                    None => {
                        indval = Some(i);
                        i += 1;
                    }
                    Some(keep) => {
                        let label = self.b[b].outs[i].label;
                        self.b[b].outs[keep].label |= label;
                        let rev = self.b[b].outs[i].rev;
                        self.half_delete_out_edge(b, i);
                        self.half_delete_in_edge(bl, rev);
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    fn dups(list: &[Edge]) -> Vec<usize> {
        let mut seen = HashSet::new();
        let mut dups = Vec::new();
        let mut reported = HashSet::new();
        for e in list {
            if !seen.insert(e.point) && reported.insert(e.point) {
                dups.push(e.point);
            }
        }
        dups
    }

    fn dedup(&mut self, b: usize) {
        for d in Self::dups(&self.b[b].ins.clone()) {
            self.eliminate_in_dups(b, d);
        }
        for d in Self::dups(&self.b[b].outs.clone()) {
            self.eliminate_out_dups(b, d);
        }
    }

    // ---- BlockGraph --------------------------------------------------------

    fn add_block(&mut self, ident: usize, bl: usize) {
        let min = self.b[bl].index;
        if self.b[ident].list.is_empty() || min < self.b[ident].index {
            self.b[ident].index = min;
        }
        self.b[bl].parent = Some(ident);
        self.b[ident].list.push(bl);
    }

    fn force_output_num(&mut self, b: usize, n: usize) {
        while self.size_out(b) < n {
            self.add_in_edge(b, b, E_LOOP | E_BACK);
        }
    }

    fn self_identify(&mut self, ident: usize) {
        if self.b[ident].list.is_empty() {
            return;
        }
        let members = self.b[ident].list.clone();
        for mybl in members {
            let mut i = 0;
            while i < self.b[mybl].ins.len() {
                let otherbl = self.b[mybl].ins[i].point;
                if self.b[otherbl].parent == Some(ident) {
                    i += 1;
                } else {
                    for j in 0..self.b[otherbl].outs.len() {
                        if self.b[otherbl].outs[j].point == mybl {
                            self.replace_out_edge(otherbl, j, ident);
                        }
                    }
                }
            }
            i = 0;
            while i < self.b[mybl].outs.len() {
                let otherbl = self.b[mybl].outs[i].point;
                if self.b[otherbl].parent == Some(ident) {
                    i += 1;
                } else {
                    for j in 0..self.b[otherbl].ins.len() {
                        if self.b[otherbl].ins[j].point == mybl {
                            self.replace_in_edge(otherbl, j, ident);
                        }
                    }
                    if self.is_switch_out(mybl) {
                        self.b[ident].flags |= F_SWITCH_OUT;
                    }
                }
            }
        }
        self.dedup(ident);
    }

    fn identify_internal(&mut self, ident: usize, nodes: &[usize]) {
        let graph = self.root;
        for &n in nodes {
            self.set_mark(n);
            self.add_block(ident, n);
            let inherited = self.b[n].flags & (F_INTERIOR_GOTOOUT | F_INTERIOR_GOTOIN);
            self.b[ident].flags |= inherited;
        }
        let list = std::mem::take(&mut self.b[graph].list);
        let mut kept = Vec::with_capacity(list.len());
        for n in list {
            if self.is_mark(n) {
                self.clear_mark(n);
            } else {
                kept.push(n);
            }
        }
        self.b[graph].list = kept;
        self.self_identify(ident);
    }

    fn remove_edge(&mut self, begin: usize, end: usize) {
        if let Some(i) = self.b[end].ins.iter().position(|e| e.point == begin) {
            self.remove_in_edge(end, i);
        }
    }

    fn force_false_edge(&mut self, b: usize, out0: usize) -> Res<()> {
        if self.size_out(b) != 2 {
            return Err("Can only preserve binary condition".into());
        }
        let out0 = if self.b[out0].parent == Some(b) { b } else { out0 };
        if self.b[b].outs[0].point != out0 {
            self.swap_edges(b);
        }
        if self.b[b].outs[0].point != out0 {
            return Err("Unable to preserve condition".into());
        }
        Ok(())
    }

    fn new_block(&mut self, kind: u64) -> usize {
        self.b.push(Blk::new(kind));
        self.b.len() - 1
    }

    fn new_block_goto(&mut self, bl: usize) {
        let ret = self.new_block(kind::GOTO);
        self.b[ret].goto_target = Some(self.get_out(bl, 0));
        self.identify_internal(ret, &[bl]);
        let root = self.root;
        self.add_block(root, ret);
        self.force_output_num(ret, 1);
        let out = self.get_out(ret, 0);
        self.remove_edge(ret, out);
    }

    fn new_block_multi_goto(&mut self, bl: usize, outedge: usize) {
        let targetbl = self.get_out(bl, outedge);
        let isdefaultedge = self.is_default_branch(bl, outedge);
        if self.b[bl].kind == kind::MULTIGOTO {
            self.b[bl].gotoedges.push(targetbl);
            self.remove_edge(bl, targetbl);
            if isdefaultedge {
                self.b[bl].default_goto = true;
            }
        } else {
            let ret = self.new_block(kind::MULTIGOTO);
            let orig_size_out = self.size_out(bl);
            self.identify_internal(ret, &[bl]);
            let root = self.root;
            self.add_block(root, ret);
            self.b[ret].gotoedges.push(targetbl);
            if targetbl != bl {
                if self.size_out(ret) != orig_size_out {
                    let n = self.size_out(ret) + 1;
                    self.force_output_num(ret, n);
                }
                self.remove_edge(ret, targetbl);
            }
            if isdefaultedge {
                self.b[ret].default_goto = true;
            }
        }
    }

    fn new_block_list(&mut self, nodes: &[usize]) -> Res<()> {
        let last = *nodes.last().expect("list nodes");
        let outforce = self.size_out(last);
        let out0 = if outforce == 2 { Some(self.get_out(last, 0)) } else { None };
        let ret = self.new_block(kind::LIST);
        self.identify_internal(ret, nodes);
        let root = self.root;
        self.add_block(root, ret);
        self.force_output_num(ret, outforce);
        if self.size_out(ret) == 2 {
            self.force_false_edge(ret, out0.unwrap_or(usize::MAX))?;
        }
        Ok(())
    }

    fn new_block_condition(&mut self, b1: usize, b2: usize) -> Res<()> {
        let out0 = self.get_out(b2, 0);
        let or = self.b[b1].outs[0].point == b2;
        let ret = self.new_block(kind::CONDITION);
        self.b[ret].and = !or;
        self.identify_internal(ret, &[b1, b2]);
        let root = self.root;
        self.add_block(root, ret);
        self.force_output_num(ret, 2);
        self.force_false_edge(ret, out0)
    }

    fn new_block_if_goto(&mut self, cond: usize) -> Res<()> {
        if !self.is_goto_out(cond, 1) {
            return Err("Building ifgoto where true branch is not the goto".into());
        }
        let out0 = self.get_out(cond, 0);
        let ret = self.new_block(kind::IF);
        self.b[ret].goto_target = Some(self.get_out(cond, 1));
        self.identify_internal(ret, &[cond]);
        let root = self.root;
        self.add_block(root, ret);
        self.force_output_num(ret, 2);
        self.force_false_edge(ret, out0)?;
        let t = self.get_out(ret, 1);
        self.remove_edge(ret, t);
        Ok(())
    }

    fn new_block_group(&mut self, kind: u64, nodes: &[usize], outputs: Option<usize>) -> usize {
        let ret = self.new_block(kind);
        self.identify_internal(ret, nodes);
        let root = self.root;
        self.add_block(root, ret);
        if let Some(n) = outputs {
            self.force_output_num(ret, n);
        }
        ret
    }

    // ---- block queries -----------------------------------------------------

    fn front_leaf(&self, mut b: usize) -> Option<usize> {
        while self.b[b].kind != kind::COPY {
            b = *self.b[b].list.first()?;
        }
        Some(b)
    }

    fn exit_leaf(&self, b: usize) -> Option<usize> {
        let blk = &self.b[b];
        match blk.kind {
            kind::COPY => Some(b),
            kind::GOTO | kind::MULTIGOTO => self.exit_leaf(*blk.list.first()?),
            kind::LIST => self.exit_leaf(*blk.list.last()?),
            kind::IF if blk.list.len() == 1 => self.exit_leaf(blk.list[0]),
            _ => None,
        }
    }

    /// `FlowBlock::lastOp` (the basic block and whether it is a CBRANCH/RETURN).
    fn last_basic(&self, b: usize) -> Option<usize> {
        let blk = &self.b[b];
        match blk.kind {
            kind::COPY => Some(blk.basic),
            kind::GOTO | kind::MULTIGOTO => self.last_basic(*blk.list.first()?),
            kind::LIST => self.last_basic(*blk.list.last()?),
            kind::CONDITION => self.last_basic(*blk.list.get(1)?),
            kind::IF if blk.list.len() == 1 => self.last_basic(blk.list[0]),
            _ => None,
        }
    }

    fn last_kind(&self, b: usize) -> Last {
        match self.last_basic(b) {
            Some(basic) => self.last[basic],
            None => Last::None,
        }
    }

    fn last_op_time(&self, b: usize) -> Option<u64> {
        self.last_basic(b).and_then(|basic| self.last_time[basic])
    }

    fn is_complex(&self, b: usize) -> bool {
        let blk = &self.b[b];
        match blk.kind {
            kind::COPY => self.complex[blk.basic],
            kind::CONDITION => blk.list.first().map(|&c| self.is_complex(c)).unwrap_or(true),
            _ => true,
        }
    }

    /// `FlowBlock::nextInFlow`
    fn next_in_flow(&self, b: usize) -> Option<usize> {
        match self.size_out(b) {
            1 => Some(self.get_out(b, 0)),
            2 => {
                let basic = self.last_basic(b)?;
                if self.last[basic] != Last::Cbranch {
                    return None;
                }
                Some(if self.fall[basic] { self.get_out(b, 1) } else { self.get_out(b, 0) })
            }
            _ => None,
        }
    }

    /// `FlowBlock::negateCondition`
    fn negate_condition(&mut self, b: usize, top: bool) -> bool {
        match self.b[b].kind {
            kind::COPY => {
                let basic = self.b[b].basic;
                self.fall[basic] = !self.fall[basic];
                self.negated[basic] = !self.negated[basic];
                if top {
                    self.swap_edges(b);
                }
                true
            }
            kind::LIST => {
                let last = *self.b[b].list.last().expect("list");
                let res = self.negate_condition(last, false);
                if top {
                    self.swap_edges(b);
                }
                res
            }
            kind::CONDITION => {
                let (c0, c1) = (self.b[b].list[0], self.b[b].list[1]);
                let r1 = self.negate_condition(c0, false);
                let r2 = self.negate_condition(c1, false);
                self.b[b].and = !self.b[b].and;
                if top {
                    self.swap_edges(b);
                }
                r1 || r2
            }
            _ => {
                if top {
                    self.swap_edges(b);
                }
                false
            }
        }
    }

    fn mark_copy_block(&mut self, bl: usize, fl: u32) {
        if let Some(leaf) = self.front_leaf(bl) {
            self.b[leaf].flags |= fl;
        }
    }

    /// `BlockGraph::nextFlowAfter` and its overrides: the front leaf of the
    /// block that executes after child `bl` of `this`.
    fn next_flow_after(&self, this: usize, bl: usize) -> Option<usize> {
        let blk = &self.b[this];
        match blk.kind {
            kind::GOTO => self.front_leaf(blk.goto_target?),
            kind::MULTIGOTO | kind::CONDITION | kind::DO_WHILE => None,
            kind::IF => {
                if blk.list.first() == Some(&bl) {
                    return None;
                }
                let parent = blk.parent?;
                self.next_flow_after(parent, this)
            }
            kind::WHILE_DO => {
                if blk.list.first() == Some(&bl) {
                    return None;
                }
                self.front_leaf(blk.list[0])
            }
            kind::INFINITE_LOOP => self.front_leaf(blk.list[0]),
            kind::SWITCH => {
                if blk.list.first() == Some(&bl) {
                    return None;
                }
                if self.b[bl].kind != kind::GOTO {
                    return None;
                }
                let i = blk.cases.iter().position(|c| c.block == bl)?;
                if i + 1 < blk.cases.len() {
                    return self.front_leaf(blk.cases[i + 1].block);
                }
                let parent = blk.parent?;
                self.next_flow_after(parent, this)
            }
            _ => {
                let pos = blk.list.iter().position(|&c| c == bl)?;
                if pos + 1 >= blk.list.len() {
                    let parent = blk.parent?;
                    return self.next_flow_after(parent, this);
                }
                self.front_leaf(blk.list[pos + 1])
            }
        }
    }

    fn goto_prints(&self, b: usize) -> bool {
        let blk = &self.b[b];
        let Some(parent) = blk.parent else { return false };
        let nextbl = self.next_flow_after(parent, b);
        let gotobl = blk.goto_target.and_then(|t| self.front_leaf(t));
        gotobl != nextbl
    }

    // ---- loop and DAG analysis ---------------------------------------------
}

mod loops;
mod rules;
mod finish;

pub use finish::{Analysis, FinalTree, Split, analyze, build, shape, take_loop_ops};


#[cfg(test)]
mod tests;
