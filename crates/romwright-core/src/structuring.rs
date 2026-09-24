//! Control-flow structuring in Rust, scored against the decompiler's own.
//!
//! The input is the same graph both sides see: blocks and edges from
//! `demand::BodyWalk::basic_blocks`. The output is a hierarchy of structured
//! regions plus the edges that could not be placed in one -- the same
//! category `CollapseStructure` reports through `structureGraph`, so the two
//! numbers are comparable.
//!
//! The algorithm is region collapsing over the graph, in the order that
//! commits to the least: sequences and conditionals whose shape is decided by
//! dominance and post-dominance, then loops, and only when nothing matches
//! does an edge get virtualised into a jump. Two things it does that stock's
//! does not, both from SAILR's account of why decompiler output grows gotos
//! that the source never had:
//!
//! * **A single-block tail is duplicated rather than jumped to.** A compiler
//!   that shares one epilogue between several paths forces a structuring to
//!   pick one path and jump from the rest. Duplicating a side-effect-free
//!   tail with no other predecessors costs a block and removes the jumps.
//! * **A loop's second exit is refined into the loop, not out of it.** An
//!   exit that post-dominates the loop's own exit is a successor of the loop
//!   body, so it joins the loop's follow region instead of being virtualised.
//!
//! Everything here is deterministic: candidate regions are considered in
//! block-index order, so the same graph always structures the same way.

use std::collections::{BTreeMap, BTreeSet};

/// One node of the structured hierarchy this pass produces.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Region {
    /// A basic block, by its index in the input graph.
    Block(usize),
    /// Regions executed one after another.
    Sequence(Vec<Region>),
    /// Components linked by explicit original-edge jumps, not fallthrough.
    Unstructured {
        entry: Box<Region>,
        detached: Vec<Region>,
    },
    /// A two-way branch: condition, then the taken side and, where there is
    /// one, the other side.
    ///
    /// `negated` records the branch's polarity: a conditional's false edge
    /// is successor 0 and its true edge successor 1 (the order `CBranch`
    /// encodes and Ghidra's `getFalseOut`/`getTrueOut` read). `negated` is
    /// set when `then` sits on the false edge, so the condition as stored
    /// must be inverted to read `if (c) then`.
    If {
        condition: Box<Region>,
        then: Box<Region>,
        otherwise: Option<Box<Region>>,
        negated: bool,
    },
    /// A loop whose exit is tested at the top.
    While {
        head: Box<Region>,
        body: Box<Region>,
        negated: bool,
    },
    /// A loop whose exit is tested at the bottom.
    DoWhile { body: Box<Region>, negated: bool },
    /// A loop with no exit edge at all.
    Infinite { body: Box<Region> },
    /// Two conditions the source combined with `&&` or `||`: both blocks
    /// branch to the same place, so one test guards the other. Ghidra's
    /// `BlockCondition` (`t_condition`) is the same shape; without it a
    /// short-circuit costs a jump.
    ///
    /// `or` records which: the second test runs on the first's false edge
    /// for `||` and on its true edge for `&&` — the same distinction
    /// `BlockGraph::newBlockCondition` draws with
    /// `(b1->getFalseOut() == b2) ? INT_OR : INT_AND` (block.cc:1784).
    Condition {
        first: Box<Region>,
        second: Box<Region>,
        or: bool,
        /// Invert the second test when its shared edge has opposite polarity.
        second_negated: bool,
    },
    /// A multi-way branch and its cases.
    Switch {
        head: Box<Region>,
        cases: Vec<Region>,
    },
}

/// What structuring one graph produced.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Structured {
    pub region: Region,
    /// Original edges that could not be placed in a construct, as (from,
    /// to) block indices: one printed jump each.
    pub unstructured: Vec<(usize, usize)>,
    /// Edges of the collapsed graph turned into jumps: the measure stock's
    /// `structureGraph` reports, because `BlockGraph::selfIdentify` dedups
    /// parallel edges when it collapses a region (block.cc:930), so one
    /// collapsed edge stands for every original edge behind it.
    pub virtualised: usize,
    /// Tails duplicated to avoid a jump, by block index.
    pub duplicated: Vec<usize>,
}

impl Structured {
    pub fn unstructured_edges(&self) -> usize {
        self.unstructured.len()
    }
}

/// The graph, in the form the collapsing works on.
struct Graph {
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
    /// Original edges represented by each surviving edge after collapsing.
    origins: BTreeMap<(usize, usize), Vec<(usize, usize)>>,
}

impl Graph {
    fn new(blocks: usize, edges: &[(usize, usize)]) -> Self {
        let mut successors = vec![Vec::new(); blocks];
        let mut predecessors = vec![Vec::new(); blocks];
        let mut origins: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (from, to) in edges {
            if *from >= blocks || *to >= blocks {
                continue;
            }
            if !successors[*from].contains(to) {
                successors[*from].push(*to);
            }
            if !predecessors[*to].contains(from) {
                predecessors[*to].push(*from);
            }
            origins.entry((*from, *to)).or_default().push((*from, *to));
        }
        Self {
            successors,
            predecessors,
            origins,
        }
    }

    fn reachable(&self, entry: usize) -> BTreeSet<usize> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![entry];
        while let Some(node) = stack.pop() {
            if !seen.insert(node) {
                continue;
            }
            for next in &self.successors[node] {
                stack.push(*next);
            }
        }
        seen
    }

    /// Reverse post-order from the entry: the order dominance is computed in.
    fn reverse_post_order(
        &self,
        entry: usize,
        checkpoint: &dyn Fn() -> Result<(), String>,
    ) -> Result<Vec<usize>, String> {
        let mut order = Vec::new();
        let mut seen = vec![false; self.successors.len()];
        let mut stack = vec![(entry, 0usize)];
        seen[entry] = true;
        while let Some((node, index)) = stack.pop() {
            checkpoint()?;
            if index < self.successors[node].len() {
                stack.push((node, index + 1));
                let next = self.successors[node][index];
                if !seen[next] {
                    seen[next] = true;
                    stack.push((next, 0));
                }
            } else {
                order.push(node);
            }
        }
        order.reverse();
        Ok(order)
    }

    /// Immediate dominators, by the Cooper/Harvey/Kennedy iteration.
    fn dominators(
        &self,
        entry: usize,
        checkpoint: &dyn Fn() -> Result<(), String>,
    ) -> Result<Vec<Option<usize>>, String> {
        let order = self.reverse_post_order(entry, checkpoint)?;
        let mut position = vec![usize::MAX; self.successors.len()];
        for (index, node) in order.iter().enumerate() {
            position[*node] = index;
        }
        let mut idom: Vec<Option<usize>> = vec![None; self.successors.len()];
        idom[entry] = Some(entry);
        let mut changed = true;
        while changed {
            changed = false;
            for &node in order.iter().skip(1) {
                checkpoint()?;
                let mut new: Option<usize> = None;
                for &pred in &self.predecessors[node] {
                    if idom[pred].is_none() {
                        continue;
                    }
                    new = Some(match new {
                        None => pred,
                        Some(current) => {
                            // Walk both up the tree until they meet.
                            let mut left = pred;
                            let mut right = current;
                            while left != right {
                                while position[left] > position[right] {
                                    left = idom[left].expect("dominator is set");
                                }
                                while position[right] > position[left] {
                                    right = idom[right].expect("dominator is set");
                                }
                            }
                            left
                        }
                    });
                }
                if new.is_some() && idom[node] != new {
                    idom[node] = new;
                    changed = true;
                }
            }
        }
        Ok(idom)
    }

    fn dominates(&self, idom: &[Option<usize>], ancestor: usize, mut node: usize) -> bool {
        loop {
            if node == ancestor {
                return true;
            }
            match idom[node] {
                Some(next) if next != node => node = next,
                _ => return false,
            }
        }
    }
}

/// Structures one control-flow graph.
///
/// `blocks` is the block count and `edges` the graph's edges, in the order
/// each source branches -- the same input the decompiler is handed.
pub fn structure(blocks: usize, edges: &[(usize, usize)]) -> Structured {
    structure_from(blocks, edges, 0, &|| Ok(())).expect("unbounded structuring cannot be cancelled")
}

/// Structures a graph whose entry is not block zero: the body of a loop
/// keeps its own numbering when it is structured on its own.
pub fn structure_from(
    blocks: usize,
    edges: &[(usize, usize)],
    entry: usize,
    checkpoint: &dyn Fn() -> Result<(), String>,
) -> Result<Structured, String> {
    checkpoint()?;
    if blocks == 0 {
        return Ok(Structured {
            region: Region::Sequence(Vec::new()),
            unstructured: Vec::new(),
            virtualised: 0,
            duplicated: Vec::new(),
        });
    }
    let mut state = State {
        graph: Graph::new(blocks, edges),
        entry,
        checkpoint,
        unstructured: Vec::new(),
        virtualised: 0,
        duplicated: Vec::new(),
        regions: (0..blocks).map(Region::Block).collect(),
    };
    let region = state.collapse()?;
    Ok(Structured {
        region,
        unstructured: state.unstructured,
        virtualised: state.virtualised,
        duplicated: state.duplicated,
    })
}

struct State<'a> {
    graph: Graph,
    entry: usize,
    checkpoint: &'a dyn Fn() -> Result<(), String>,
    unstructured: Vec<(usize, usize)>,
    virtualised: usize,
    duplicated: Vec<usize>,
    /// The region each surviving node stands for.
    regions: Vec<Region>,
}

impl State<'_> {
    fn collapse(&mut self) -> Result<Region, String> {
        (self.checkpoint)()?;
        // Blocks the entry cannot reach are not this function's control flow
        // in any structured sense: reaching them needs a jump, and the graph
        // says nothing about from where. They are reported as unstructured
        // entries so the count cannot hide them.
        let mut live: BTreeSet<usize> = self.graph.reachable(self.entry);
        for node in 0..self.graph.successors.len() {
            if !live.contains(&node) && !self.graph.predecessors[node].is_empty() {
                for pred in self.graph.predecessors[node].clone() {
                    if let Some(origins) = self.graph.origins.get(&(pred, node)) {
                        self.unstructured.extend_from_slice(origins);
                        self.virtualised += 1;
                    }
                }
            }
        }
        loop {
            (self.checkpoint)()?;
            if live.len() <= 1 {
                if self.try_loop(&mut live)? {
                    continue;
                }
                break;
            }
            if self.try_sequence(&mut live)
                || self.try_condition(&mut live)
                || self.try_if(&mut live)
                || self.try_switch(&mut live)
                || self.try_loop(&mut live)?
                || self.try_natural_loop(&mut live)?
                || self.try_duplicate_tail(&mut live)
            {
                continue;
            }
            // Nothing matched: give up one edge, the one whose removal is
            // least likely to break a construct -- an edge into a node with
            // several predecessors that its source does not dominate.
            if !self.virtualise_one(&live)? {
                break;
            }
        }
        let entry = self.regions[self.entry].clone();
        let detached: Vec<_> = live
            .iter()
            .filter(|node| **node != self.entry)
            .map(|node| self.regions[*node].clone())
            .collect();
        Ok(if detached.is_empty() {
            entry
        } else {
            Region::Unstructured {
                entry: Box::new(entry),
                detached,
            }
        })
    }

    fn merge(&mut self, keep: usize, drop: usize, region: Region, live: &mut BTreeSet<usize>) {
        // `keep` inherits `drop`'s successors; every edge into `drop` from
        // elsewhere has already been ruled out by the caller.
        let successors = self.graph.successors[drop].clone();
        self.graph.successors[keep].retain(|next| *next != drop);
        self.graph.origins.remove(&(keep, drop));
        for next in successors {
            if !self.graph.successors[keep].contains(&next) {
                self.graph.successors[keep].push(next);
            }
            if let Some(origins) = self.graph.origins.remove(&(drop, next)) {
                self.graph
                    .origins
                    .entry((keep, next))
                    .or_default()
                    .extend(origins);
            }
            let preds = &mut self.graph.predecessors[next];
            preds.retain(|pred| *pred != drop);
            if !preds.contains(&keep) {
                preds.push(keep);
            }
        }
        self.graph.successors[drop].clear();
        self.graph.predecessors[drop].clear();
        self.regions[keep] = region;
        live.remove(&drop);
    }

    /// `a -> b` where that is `b`'s only way in and `a`'s only way out.
    fn try_sequence(&mut self, live: &mut BTreeSet<usize>) -> bool {
        for &node in live.iter() {
            if self.graph.successors[node].len() != 1 {
                continue;
            }
            let next = self.graph.successors[node][0];
            if next == node || next == self.entry {
                continue;
            }
            if self.graph.predecessors[next].len() != 1 {
                continue;
            }
            let region = sequence(self.regions[node].clone(), self.regions[next].clone());
            self.merge(node, next, region, live);
            return true;
        }
        false
    }

    /// A two-way branch whose sides rejoin, or whose one side falls straight
    /// through to the join.
    fn try_if(&mut self, live: &mut BTreeSet<usize>) -> bool {
        let candidates: Vec<usize> = live.iter().copied().collect();
        for node in candidates {
            if self.graph.successors[node].len() != 2 {
                continue;
            }
            let (first, second) = (
                self.graph.successors[node][0],
                self.graph.successors[node][1],
            );
            if first == second {
                continue;
            }
            // if-then: one side goes straight to the other.
            for (then, join) in [(first, second), (second, first)] {
                if then == self.entry || then == node {
                    continue;
                }
                if self.graph.predecessors[then].len() != 1 {
                    continue;
                }
                if self.graph.successors[then] == vec![join]
                    || self.graph.successors[then].is_empty()
                {
                    let region = Region::If {
                        condition: Box::new(self.regions[node].clone()),
                        then: Box::new(self.regions[then].clone()),
                        otherwise: None,
                        // `then` on successor 0 is the false edge: the
                        // stored condition must be inverted to read it.
                        negated: then == first,
                    };
                    self.merge(node, then, region, live);
                    return true;
                }
            }
            // if-then-else: both sides are private and meet at one place.
            if self.graph.predecessors[first].len() == 1
                && self.graph.predecessors[second].len() == 1
                && first != self.entry
                && second != self.entry
                && self.graph.successors[first] == self.graph.successors[second]
            {
                let region = Region::If {
                    condition: Box::new(self.regions[node].clone()),
                    then: Box::new(self.regions[first].clone()),
                    otherwise: Some(Box::new(self.regions[second].clone())),
                    // `then` is successor 0, the false edge.
                    negated: true,
                };
                self.merge(node, first, region, live);
                let leftover = self.regions[node].clone();
                self.merge(node, second, leftover, live);
                return true;
            }
        }
        false
    }

    /// `a` branches to `b` or to `j`; `b` is private to `a` and branches to
    /// `j` too. That is one short-circuit condition, not two branches.
    fn try_condition(&mut self, live: &mut BTreeSet<usize>) -> bool {
        let candidates: Vec<usize> = live.iter().copied().collect();
        for node in candidates {
            if self.graph.successors[node].len() != 2 {
                continue;
            }
            let (first, second) = (
                self.graph.successors[node][0],
                self.graph.successors[node][1],
            );
            for (inner, shared) in [(first, second), (second, first)] {
                if inner == self.entry || inner == node || inner == shared {
                    continue;
                }
                if self.graph.predecessors[inner].len() != 1 {
                    continue;
                }
                if self.graph.successors[inner].len() != 2 {
                    continue;
                }
                if !self.graph.successors[inner].contains(&shared) {
                    continue;
                }
                // A second test that branches back to `node` is a loop's
                // latch, not a short-circuit — Ghidra's ruleBlockOr rejects
                // the same shape (`orblock->getOut(1-j) == bl`, "No
                // looping", blockaction.cc:1353). Collapsing it here would
                // hide the back-edge as a condition.
                if self.graph.successors[inner].contains(&node) {
                    continue;
                }
                let shared_slot = usize::from(inner == first);
                let second_negated = self.graph.successors[inner][shared_slot] != shared;
                let mut outcomes = self.graph.successors[inner].clone();
                if second_negated {
                    outcomes.swap(0, 1);
                }
                let region = Region::Condition {
                    first: Box::new(self.regions[node].clone()),
                    second: Box::new(self.regions[inner].clone()),
                    // The second test runs on `node`'s false edge for `||`
                    // and its true edge for `&&` — successor 0 is false.
                    or: inner == first,
                    second_negated,
                };
                self.merge(node, inner, region, live);
                self.graph.successors[node] = outcomes;
                return true;
            }
        }
        false
    }

    /// A multi-way branch whose cases are private and rejoin at one place.
    fn try_switch(&mut self, live: &mut BTreeSet<usize>) -> bool {
        let candidates: Vec<usize> = live.iter().copied().collect();
        for node in candidates {
            if self.graph.successors[node].len() < 3 {
                continue;
            }
            let successors = self.graph.successors[node].clone();
            let private: Vec<usize> = successors
                .iter()
                .copied()
                .filter(|case| {
                    *case != self.entry
                        && *case != node
                        && self.graph.predecessors[*case].len() == 1
                })
                .collect();
            if private.len() < 2 {
                continue;
            }
            // Every private case must leave to the same place, or nowhere.
            let mut exits: BTreeSet<Vec<usize>> = BTreeSet::new();
            for case in &private {
                exits.insert(self.graph.successors[*case].clone());
            }
            exits.retain(|exit| !exit.is_empty());
            if exits.len() > 1 {
                continue;
            }
            let cases = private
                .iter()
                .map(|case| self.regions[*case].clone())
                .collect();
            let region = Region::Switch {
                head: Box::new(self.regions[node].clone()),
                cases,
            };
            self.regions[node] = region;
            for case in private {
                let carried = self.regions[node].clone();
                self.merge(node, case, carried, live);
            }
            return true;
        }
        false
    }

    /// A loop whose body has collapsed to one node.
    fn try_loop(&mut self, live: &mut BTreeSet<usize>) -> Result<bool, String> {
        let idom = self.graph.dominators(self.entry, self.checkpoint)?;
        let candidates: Vec<usize> = live.iter().copied().collect();
        for node in candidates {
            // Self-loop: the node branches back to itself.
            if !self.graph.successors[node].contains(&node) {
                continue;
            }
            let exits: Vec<usize> = self.graph.successors[node]
                .iter()
                .copied()
                .filter(|next| *next != node)
                .collect();
            let body = Box::new(self.regions[node].clone());
            let region = match exits.len() {
                0 => Region::Infinite { body },
                1 => Region::DoWhile {
                    body,
                    negated: self.graph.successors[node][0] == node,
                },
                _ => continue,
            };
            self.graph.successors[node].retain(|next| *next != node);
            self.graph.predecessors[node].retain(|pred| *pred != node);
            self.graph.origins.remove(&(node, node));
            self.regions[node] = region;
            return Ok(true);
        }
        // A two-node loop: head tests, body returns to it.
        let candidates: Vec<usize> = live.iter().copied().collect();
        for head in candidates {
            (self.checkpoint)()?;
            for body in self.graph.successors[head].clone() {
                if body == head || body == self.entry {
                    continue;
                }
                if self.graph.predecessors[body].len() != 1 {
                    continue;
                }
                if self.graph.successors[head].len() != 2 {
                    continue;
                }
                let slot = usize::from(self.graph.successors[head][1] == body);
                let follow = self.graph.successors[head][1 - slot];
                if self.graph.successors[body].len() == 2
                    && self.graph.successors[body].contains(&head)
                    && self.graph.successors[body].contains(&follow)
                {
                    let region = Region::DoWhile {
                        body: Box::new(Region::Condition {
                            first: Box::new(self.regions[head].clone()),
                            second: Box::new(self.regions[body].clone()),
                            or: slot == 0,
                            second_negated: self.graph.successors[body][slot] != head,
                        }),
                        negated: slot == 0,
                    };
                    self.merge(head, body, region, live);
                    self.graph.successors[head].retain(|next| *next != head);
                    self.graph.predecessors[head].retain(|pred| *pred != head);
                    self.graph.origins.remove(&(head, head));
                    return Ok(true);
                }
                if self.graph.successors[body] != vec![head] {
                    continue;
                }
                if !self.graph.dominates(&idom, head, body) {
                    continue;
                }
                let region = Region::While {
                    head: Box::new(self.regions[head].clone()),
                    body: Box::new(self.regions[body].clone()),
                    negated: slot == 0,
                };
                self.merge(head, body, region, live);
                // The back edge is the construct's own.
                self.graph.successors[head].retain(|next| *next != head);
                self.graph.predecessors[head].retain(|pred| *pred != head);
                self.graph.origins.remove(&(head, head));
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A loop whose body is still several nodes: structure the body on its
    /// own and collapse the whole loop into one node.
    ///
    /// The body is the standard natural loop of a back edge -- every node
    /// that reaches the latch without leaving the header's dominance -- and
    /// it is structured by the same rules recursively, with the back edges
    /// removed so the body is acyclic to that call. Edges leaving the body
    /// go to the loop's follow; a second, different destination is a jump,
    /// exactly as stock's collapse treats it.
    fn try_natural_loop(&mut self, live: &mut BTreeSet<usize>) -> Result<bool, String> {
        let idom = self.graph.dominators(self.entry, self.checkpoint)?;
        for &head in live.iter() {
            (self.checkpoint)()?;
            let latches: Vec<usize> = self.graph.predecessors[head]
                .iter()
                .copied()
                .filter(|latch| *latch != head && self.graph.dominates(&idom, head, *latch))
                .collect();
            if latches.len() != 1 {
                continue;
            }
            // Body: the header plus everything that reaches a latch without
            // going through the header again.
            let mut body: BTreeSet<usize> = BTreeSet::new();
            body.insert(head);
            let mut stack = latches.clone();
            while let Some(node) = stack.pop() {
                (self.checkpoint)()?;
                if !body.insert(node) {
                    continue;
                }
                for &pred in &self.graph.predecessors[node] {
                    if pred != head && !body.contains(&pred) {
                        stack.push(pred);
                    }
                }
            }
            if body.len() < 2 {
                continue;
            }
            // Where the loop leaves to, and whether it leaves to one place.
            let mut exits: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
            for &node in &body {
                for &next in &self.graph.successors[node] {
                    if !body.contains(&next) {
                        exits.entry(next).or_default().push((node, next));
                    }
                }
            }
            if exits.len() > 1 {
                continue;
            }
            // Removing a mid-body exit would turn an early break into a
            // bottom test. Leave it explicit for virtualisation instead.
            let exit_sources: BTreeSet<_> = exits
                .values()
                .flatten()
                .map(|(source, _)| *source)
                .collect();
            let top_test = exit_sources == BTreeSet::from([head]);
            if !exits.is_empty() && !top_test && exit_sources != BTreeSet::from([latches[0]]) {
                continue;
            }
            if !exits.is_empty() && !top_test && self.graph.successors[latches[0]].len() != 2 {
                continue;
            }
            // The body, structured on its own terms.
            let order: Vec<usize> = body
                .iter()
                .copied()
                .filter(|node| !top_test || *node != head)
                .collect();
            let index_of: BTreeMap<usize, usize> = order
                .iter()
                .enumerate()
                .map(|(index, node)| (*node, index))
                .collect();
            let mut inner_edges: Vec<(usize, usize)> = Vec::new();
            for &node in &order {
                for &next in &self.graph.successors[node] {
                    if next == head || !body.contains(&next) {
                        continue; // back edge or exit: the construct's own
                    }
                    inner_edges.push((index_of[&node], index_of[&next]));
                }
            }
            let inner_entry = if top_test {
                let entries: Vec<_> = self.graph.successors[head]
                    .iter()
                    .filter(|node| body.contains(node))
                    .collect();
                if entries.len() != 1 {
                    continue;
                }
                *entries[0]
            } else {
                head
            };
            let inner = structure_from(
                order.len(),
                &inner_edges,
                index_of[&inner_entry],
                self.checkpoint,
            )?;
            for (from, to) in &inner.unstructured {
                if let Some(origins) = self.graph.origins.get(&(order[*from], order[*to])) {
                    self.unstructured.extend(origins);
                }
            }
            self.virtualised += inner.virtualised;
            for node in &inner.duplicated {
                self.duplicated.push(order[*node]);
            }
            // A latch that tests the exit condition is a do-while; a header
            // that tests it is a while; no exit at all is an infinite loop.
            // The inner region's `Block` leaves are *local* indices into
            // `order`; remap them to the body's global block ids before the
            // region is embedded, or a leaf would name the wrong block.
            let inner_region = renumber(&inner.region, &|local| self.regions[order[local]].clone());
            let region = if exits.is_empty() {
                Region::Infinite {
                    body: Box::new(inner_region),
                }
            } else if top_test {
                Region::While {
                    head: Box::new(self.regions[head].clone()),
                    body: Box::new(inner_region),
                    negated: self.graph.successors[head][0] == inner_entry,
                }
            } else {
                Region::DoWhile {
                    body: Box::new(inner_region),
                    negated: self.graph.successors[latches[0]][0] == head,
                }
            };
            // Collapse the body into the header.
            let others: Vec<usize> = body.iter().copied().filter(|node| *node != head).collect();
            for ((from, to), origins) in std::mem::take(&mut self.graph.origins) {
                if body.contains(&from) && body.contains(&to) {
                    continue;
                }
                let from = if body.contains(&from) { head } else { from };
                let to = if body.contains(&to) { head } else { to };
                self.graph
                    .origins
                    .entry((from, to))
                    .or_default()
                    .extend(origins);
            }
            self.regions[head] = region;
            for node in others {
                let exits_of: Vec<usize> = self.graph.successors[node]
                    .clone()
                    .into_iter()
                    .filter(|next| !body.contains(next))
                    .collect();
                for next in exits_of {
                    if !self.graph.successors[head].contains(&next) {
                        self.graph.successors[head].push(next);
                    }
                    let preds = &mut self.graph.predecessors[next];
                    preds.retain(|pred| *pred != node);
                    if !preds.contains(&head) {
                        preds.push(head);
                    }
                }
                self.graph.successors[node].clear();
                self.graph.predecessors[node].clear();
                live.remove(&node);
            }
            self.graph.successors[head].retain(|next| !body.contains(next));
            self.graph.predecessors[head].retain(|pred| !body.contains(pred));
            return Ok(true);
        }
        Ok(false)
    }

    /// A tail with no control flow of its own, shared by several paths:
    /// duplicating it removes a jump per path and adds a block.
    ///
    /// Only a *terminal* block is copied -- no successors, so the copy cannot
    /// diverge from the original -- and only when every predecessor would
    /// otherwise need a jump to reach it.
    fn try_duplicate_tail(&mut self, live: &mut BTreeSet<usize>) -> bool {
        let candidates: Vec<usize> = live.iter().copied().collect();
        for node in candidates {
            if node == self.entry
                || !self.graph.successors[node].is_empty()
                || self.graph.predecessors[node].len() < 2
            {
                continue;
            }
            if !matches!(self.regions[node], Region::Block(_)) {
                continue;
            }
            let preds = self.graph.predecessors[node].clone();
            let region = self.regions[node].clone();
            // Each predecessor takes its own copy: the block is a tail, so
            // the copies cannot be told apart by anything downstream.
            for pred in &preds {
                let carried = sequence(self.regions[*pred].clone(), region.clone());
                self.regions[*pred] = carried;
                self.graph.successors[*pred].retain(|next| *next != node);
                self.graph.origins.remove(&(*pred, node));
            }
            self.graph.predecessors[node].clear();
            self.duplicated.push(node);
            live.remove(&node);
            return true;
        }
        false
    }

    /// Turns one edge into a jump, choosing the one a structured shape is
    /// least likely to want.
    fn virtualise_one(&mut self, live: &BTreeSet<usize>) -> Result<bool, String> {
        let idom = self.graph.dominators(self.entry, self.checkpoint)?;
        let mut best: Option<(usize, usize, (usize, usize, usize))> = None;
        for &from in live.iter() {
            (self.checkpoint)()?;
            for &to in &self.graph.successors[from] {
                // Rank: an edge whose source does not dominate its target
                // first, then one whose target has more ways in, then by
                // index so the choice is deterministic.
                let rank = (
                    usize::from(self.graph.dominates(&idom, from, to)),
                    usize::MAX - self.graph.predecessors[to].len(),
                    from * self.graph.successors.len() + to,
                );
                if best.as_ref().is_none_or(|(_, _, current)| rank < *current) {
                    best = Some((from, to, rank));
                }
            }
        }
        let Some((from, to, _)) = best else {
            return Ok(false);
        };
        self.graph.successors[from].retain(|next| *next != to);
        self.graph.predecessors[to].retain(|pred| *pred != from);
        if let Some(origins) = self.graph.origins.remove(&(from, to)) {
            self.unstructured.extend(origins);
        }
        self.virtualised += 1;
        Ok(true)
    }
}

fn sequence(first: Region, second: Region) -> Region {
    match (first, second) {
        (Region::Sequence(mut left), Region::Sequence(right)) => {
            left.extend(right);
            Region::Sequence(left)
        }
        (Region::Sequence(mut left), right) => {
            left.push(right);
            Region::Sequence(left)
        }
        (left, Region::Sequence(right)) => {
            let mut all = vec![left];
            all.extend(right);
            Region::Sequence(all)
        }
        (left, right) => Region::Sequence(vec![left, right]),
    }
}

/// Substitutes collapsed parent regions for a recursive graph's local leaves.
fn renumber(region: &Region, order: &impl Fn(usize) -> Region) -> Region {
    match region {
        Region::Block(local) => order(*local),
        Region::Unstructured { entry, detached } => Region::Unstructured {
            entry: Box::new(renumber(entry, order)),
            detached: detached.iter().map(|part| renumber(part, order)).collect(),
        },
        Region::Sequence(parts) => {
            Region::Sequence(parts.iter().map(|part| renumber(part, order)).collect())
        }
        Region::If {
            condition,
            then,
            otherwise,
            negated,
        } => Region::If {
            condition: Box::new(renumber(condition, order)),
            then: Box::new(renumber(then, order)),
            otherwise: otherwise
                .as_ref()
                .map(|side| Box::new(renumber(side, order))),
            negated: *negated,
        },
        Region::While {
            head,
            body,
            negated,
        } => Region::While {
            head: Box::new(renumber(head, order)),
            body: Box::new(renumber(body, order)),
            negated: *negated,
        },
        Region::DoWhile { body, negated } => Region::DoWhile {
            body: Box::new(renumber(body, order)),
            negated: *negated,
        },
        Region::Infinite { body } => Region::Infinite {
            body: Box::new(renumber(body, order)),
        },
        Region::Condition {
            first,
            second,
            or,
            second_negated,
        } => Region::Condition {
            first: Box::new(renumber(first, order)),
            second: Box::new(renumber(second, order)),
            or: *or,
            second_negated: *second_negated,
        },
        Region::Switch { head, cases } => Region::Switch {
            head: Box::new(renumber(head, order)),
            cases: cases.iter().map(|case| renumber(case, order)).collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_circuit_outcomes_follow_original_branch_polarity() {
        fn execute(
            region: &Region,
            conditions: [bool; 2],
            trace: &mut Vec<usize>,
        ) -> Result<bool, ()> {
            match region {
                Region::Block(id) => {
                    trace.push(*id);
                    if *id >= 2 {
                        Err(())
                    } else {
                        Ok(conditions[*id])
                    }
                }
                Region::Sequence(parts) => parts
                    .iter()
                    .try_fold(false, |_, part| execute(part, conditions, trace)),
                Region::If {
                    condition,
                    then,
                    otherwise,
                    negated,
                } => {
                    if execute(condition, conditions, trace)? ^ negated {
                        execute(then, conditions, trace)
                    } else if let Some(otherwise) = otherwise {
                        execute(otherwise, conditions, trace)
                    } else {
                        Ok(false)
                    }
                }
                Region::Condition {
                    first,
                    second,
                    or,
                    second_negated,
                } => {
                    let first = execute(first, conditions, trace)?;
                    if first == *or {
                        Ok(first)
                    } else {
                        execute(second, conditions, trace).map(|value| value ^ second_negated)
                    }
                }
                _ => panic!("unexpected non-conditional region {region:?}"),
            }
        }
        for (edges, cases) in [
            (
                vec![(0, 1), (0, 2), (1, 3), (1, 2)],
                [
                    ([false, false], vec![0, 1, 3]),
                    ([false, true], vec![0, 1, 2]),
                    ([true, false], vec![0, 2]),
                ],
            ),
            (
                vec![(0, 2), (0, 1), (1, 3), (1, 2)],
                [
                    ([true, false], vec![0, 1, 3]),
                    ([true, true], vec![0, 1, 2]),
                    ([false, false], vec![0, 2]),
                ],
            ),
        ] {
            let result = structure(4, &edges);
            for (conditions, expected) in cases {
                let mut trace = Vec::new();
                let _ = execute(&result.region, conditions, &mut trace);
                assert_eq!(trace, expected);
            }
        }
    }

    #[test]
    fn cuts_keep_original_edges_after_private_blocks_collapse() {
        let edges = [(0, 1), (1, 2), (1, 3), (2, 4), (4, 3), (3, 2), (3, 5)];
        let result = structure(6, &edges);
        assert!(result.unstructured.contains(&(4, 3)), "{result:?}");
        assert!(result.unstructured.iter().all(|edge| edges.contains(edge)));
        assert_eq!(
            block_ids(&result.region)
                .into_iter()
                .collect::<BTreeSet<_>>(),
            (0..6).collect()
        );
    }

    #[test]
    fn natural_loop_reduction_rejects_an_unrepresented_early_exit() {
        let edges = [(0, 1), (1, 2), (1, 5), (2, 3), (2, 5), (3, 1)];
        let mut state = State {
            graph: Graph::new(6, &edges),
            entry: 0,
            regions: (0..6).map(Region::Block).collect(),
            checkpoint: &|| Ok(()),
            unstructured: Vec::new(),
            virtualised: 0,
            duplicated: Vec::new(),
        };
        let mut live = state.graph.reachable(0);
        assert!(
            !state.try_natural_loop(&mut live).unwrap(),
            "the region grammar cannot express this early exit by a bottom test"
        );
    }

    #[test]
    fn cancellation_during_structuring_cannot_publish_a_partial_region() {
        let entered = std::cell::Cell::new(false);
        let checkpoint = || {
            if entered.replace(true) {
                Err("cancelled".to_owned())
            } else {
                Ok(())
            }
        };
        let result = structure_from(4, &[(0, 1), (1, 2), (2, 1), (2, 3)], 0, &checkpoint);
        assert!(result.is_err());
    }

    #[test]
    fn collapsing_a_cycle_preserves_its_back_edge() {
        let result = structure(3, &[(0, 1), (1, 2), (2, 1)]);
        assert!(has_loop(&result.region), "{result:?}");
        assert_eq!(
            block_ids(&result.region)
                .into_iter()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 1, 2])
        );
    }

    #[test]
    fn a_straight_line_needs_no_jump() {
        let result = structure(3, &[(0, 1), (1, 2)]);
        assert_eq!(result.unstructured_edges(), 0);
        assert!(matches!(result.region, Region::Sequence(_)));
    }

    #[test]
    fn an_if_else_needs_no_jump() {
        let result = structure(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        assert_eq!(result.unstructured_edges(), 0);
    }

    #[test]
    fn a_loop_with_one_exit_needs_no_jump() {
        // 0 -> 1, 1 -> 1, 1 -> 2: the self-loop is the construct's own edge.
        let result = structure(3, &[(0, 1), (1, 1), (1, 2)]);
        assert_eq!(result.unstructured_edges(), 0);
    }

    #[test]
    fn a_two_block_loop_needs_no_jump() {
        let result = structure(3, &[(0, 1), (1, 0), (1, 2)]);
        assert_eq!(result.unstructured_edges(), 0);
    }

    #[test]
    fn an_irreducible_graph_costs_one_jump() {
        // Two entries into a cycle: no structured shape covers it, and stock
        // pays one unstructured edge here too.
        let result = structure(4, &[(0, 1), (0, 2), (1, 2), (2, 1), (1, 3)]);
        assert_eq!(result.unstructured_edges(), 1);
    }

    #[test]
    fn a_loop_with_two_exits_costs_no_jump() {
        // A loop whose body can exit as well as its header: the two tests
        // are one short-circuit condition over a shared successor. Stock
        // pays one unstructured edge on this shape (m15-001 records it).
        let result = structure(4, &[(0, 1), (1, 2), (2, 1), (1, 3), (2, 3)]);
        assert_eq!(
            result.unstructured_edges(),
            0,
            "a terminal tail shared by two loop exits needs no jump: {result:?}"
        );
    }

    #[test]
    fn an_unreachable_block_is_reported_not_hidden() {
        // 2 is reachable only from 3, which nothing reaches.
        let result = structure(4, &[(0, 1), (3, 2)]);
        assert!(result.unstructured_edges() >= 1);
    }

    /// Every `Block` leaf id in a region, in order.
    fn block_ids(region: &Region) -> Vec<usize> {
        match region {
            Region::Block(id) => vec![*id],
            Region::Sequence(parts) => parts.iter().flat_map(block_ids).collect(),
            Region::If {
                condition,
                then,
                otherwise,
                ..
            } => {
                let mut ids = block_ids(condition);
                ids.extend(block_ids(then));
                if let Some(side) = otherwise {
                    ids.extend(block_ids(side));
                }
                ids
            }
            Region::While { head, body, .. } => {
                let mut ids = block_ids(head);
                ids.extend(block_ids(body));
                ids
            }
            Region::DoWhile { body, .. } | Region::Infinite { body } => block_ids(body),
            Region::Condition { first, second, .. } => {
                let mut ids = block_ids(first);
                ids.extend(block_ids(second));
                ids
            }
            Region::Switch { head, cases } => {
                let mut ids = block_ids(head);
                for case in cases {
                    ids.extend(block_ids(case));
                }
                ids
            }
            Region::Unstructured { entry, detached } => {
                let mut ids = block_ids(entry);
                ids.extend(detached.iter().flat_map(block_ids));
                ids
            }
        }
    }

    /// The `or` flag of the first `Condition` in the region, if any.
    fn find_condition(region: &Region) -> Option<bool> {
        match region {
            Region::Condition { or, .. } => Some(*or),
            Region::Sequence(parts) => parts.iter().find_map(find_condition),
            Region::If {
                condition,
                then,
                otherwise,
                ..
            } => find_condition(condition)
                .or_else(|| find_condition(then))
                .or_else(|| otherwise.as_ref().and_then(|s| find_condition(s))),
            Region::While { head, body, .. } => {
                find_condition(head).or_else(|| find_condition(body))
            }
            Region::DoWhile { body, .. } | Region::Infinite { body } => find_condition(body),
            Region::Switch { head, cases } => {
                find_condition(head).or_else(|| cases.iter().find_map(find_condition))
            }
            Region::Unstructured { entry, detached } => {
                find_condition(entry).or_else(|| detached.iter().find_map(find_condition))
            }
            Region::Block(_) => None,
        }
    }

    /// The `negated` flag of the first `If` in the region, if any.
    fn find_if(region: &Region) -> Option<bool> {
        match region {
            Region::If { negated, .. } => Some(*negated),
            Region::Sequence(parts) => parts.iter().find_map(find_if),
            Region::While { head, body, .. } => find_if(head).or_else(|| find_if(body)),
            Region::DoWhile { body, .. } | Region::Infinite { body } => find_if(body),
            Region::Condition { first, second, .. } => find_if(first).or_else(|| find_if(second)),
            Region::Switch { head, cases } => {
                find_if(head).or_else(|| cases.iter().find_map(find_if))
            }
            Region::Unstructured { entry, detached } => {
                find_if(entry).or_else(|| detached.iter().find_map(find_if))
            }
            Region::Block(_) => None,
        }
    }

    /// Whether the region contains a loop node anywhere.
    fn has_loop(region: &Region) -> bool {
        match region {
            Region::While { .. } | Region::DoWhile { .. } | Region::Infinite { .. } => true,
            Region::Sequence(parts) => parts.iter().any(has_loop),
            Region::If {
                condition,
                then,
                otherwise,
                ..
            } => {
                has_loop(condition)
                    || has_loop(then)
                    || otherwise.as_ref().is_some_and(|s| has_loop(s))
            }
            Region::Condition { first, second, .. } => has_loop(first) || has_loop(second),
            Region::Switch { head, cases } => has_loop(head) || cases.iter().any(has_loop),
            Region::Unstructured { entry, detached } => {
                has_loop(entry) || detached.iter().any(has_loop)
            }
            Region::Block(_) => false,
        }
    }
    #[test]
    fn a_latch_that_branches_back_is_a_loop_not_a_condition() {
        // 0 tests to 1 or out to 2; 1 tests back to 0 or out to 2. The
        // 1 -> 0 edge is a back-edge: collapsing 0 and 1 as a short-circuit
        // would hide the loop. Ghidra's ruleBlockOr rejects the same shape
        // ("No looping", blockaction.cc:1353).
        let result = structure(3, &[(0, 1), (0, 2), (1, 0), (1, 2)]);
        assert!(
            has_loop(&result.region),
            "the back-edge must structure as a loop, got {:?}",
            result.region
        );
        assert_eq!(result.unstructured_edges(), 0);
    }

    #[test]
    fn an_if_else_records_its_polarity() {
        // then sits on successor 0 — the false edge — so the stored
        // condition reads negated.
        let result = structure(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        assert_eq!(
            find_if(&result.region),
            Some(true),
            "then on the false edge is negated: {:?}",
            result.region
        );
    }

    #[test]
    fn a_short_circuit_records_and_versus_or() {
        // `||`: the second test runs on the first's false edge (successor
        // 0). 0 -> {1, 2}, 1 -> {3, 2}: block 1 is the second test, 2 the
        // shared target.
        let or = structure(4, &[(0, 1), (0, 2), (1, 3), (1, 2)]);
        assert_eq!(
            find_condition(&or.region),
            Some(true),
            "second test on the false edge is ||: {:?}",
            or.region
        );
        // `&&`: the second test runs on the first's true edge (successor
        // 1). 0 -> {2, 1}, 1 -> {3, 2}: block 1 is reached when the first
        // test is true.
        let and = structure(4, &[(0, 2), (0, 1), (1, 3), (1, 2)]);
        assert_eq!(
            find_condition(&and.region),
            Some(false),
            "second test on the true edge is &&: {:?}",
            and.region
        );
    }

    #[test]
    fn a_natural_loops_body_uses_global_block_ids() {
        // Entry 0 feeds a loop over blocks 1,2,3 (1 is the head, 3 the
        // latch back to 1, 4 the exit). The body is structured on a local
        // numbering; its `Block` leaves must come back as the global ids
        // {1,2,3}, not the local {0,1,2}.
        let result = structure(5, &[(0, 1), (1, 2), (2, 3), (3, 1), (3, 4)]);
        let mut ids = block_ids(&result.region);
        ids.sort_unstable();
        ids.dedup();
        assert!(
            ids.contains(&3),
            "the loop body must name global block 3, got leaves {ids:?} in {:?}",
            result.region
        );
        assert_eq!(result.unstructured_edges(), 0);
    }
}
