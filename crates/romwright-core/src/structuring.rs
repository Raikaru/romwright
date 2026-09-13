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
    /// A two-way branch: condition, then the taken side and, where there is
    /// one, the other side.
    If {
        condition: Box<Region>,
        then: Box<Region>,
        otherwise: Option<Box<Region>>,
    },
    /// A loop whose exit is tested at the top.
    While { head: Box<Region>, body: Box<Region> },
    /// A loop whose exit is tested at the bottom.
    DoWhile { body: Box<Region> },
    /// A loop with no exit edge at all.
    Infinite { body: Box<Region> },
    /// Two conditions the source combined with `&&` or `||`: both blocks
    /// branch to the same place, so one test guards the other. Ghidra's
    /// `BlockCondition` (`t_condition`) is the same shape; without it a
    /// short-circuit costs a jump.
    Condition {
        first: Box<Region>,
        second: Box<Region>,
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
    /// Edges that could not be placed in a construct, as (from, to) block
    /// indices: the measure stock's `structureGraph` reports too.
    pub unstructured: Vec<(usize, usize)>,
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
}

impl Graph {
    fn new(blocks: usize, edges: &[(usize, usize)]) -> Self {
        let mut successors = vec![Vec::new(); blocks];
        let mut predecessors = vec![Vec::new(); blocks];
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
        }
        Self {
            successors,
            predecessors,
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
    fn reverse_post_order(&self, entry: usize) -> Vec<usize> {
        let mut order = Vec::new();
        let mut seen = vec![false; self.successors.len()];
        let mut stack = vec![(entry, 0usize)];
        seen[entry] = true;
        while let Some((node, index)) = stack.pop() {
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
        order
    }

    /// Immediate dominators, by the Cooper/Harvey/Kennedy iteration.
    fn dominators(&self, entry: usize) -> Vec<Option<usize>> {
        let order = self.reverse_post_order(entry);
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
        idom
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
    structure_from(blocks, edges, 0)
}

/// Structures a graph whose entry is not block zero: the body of a loop
/// keeps its own numbering when it is structured on its own.
pub fn structure_from(blocks: usize, edges: &[(usize, usize)], entry: usize) -> Structured {
    if blocks == 0 {
        return Structured {
            region: Region::Sequence(Vec::new()),
            unstructured: Vec::new(),
            duplicated: Vec::new(),
        };
    }
    let mut state = State {
        graph: Graph::new(blocks, edges),
        entry,
        unstructured: Vec::new(),
        duplicated: Vec::new(),
        regions: (0..blocks).map(Region::Block).collect(),
    };
    let region = state.collapse();
    Structured {
        region,
        unstructured: state.unstructured,
        duplicated: state.duplicated,
    }
}

struct State {
    graph: Graph,
    entry: usize,
    unstructured: Vec<(usize, usize)>,
    duplicated: Vec<usize>,
    /// The region each surviving node stands for.
    regions: Vec<Region>,
}

impl State {
    fn collapse(&mut self) -> Region {
        // Blocks the entry cannot reach are not this function's control flow
        // in any structured sense: reaching them needs a jump, and the graph
        // says nothing about from where. They are reported as unstructured
        // entries so the count cannot hide them.
        let mut live: BTreeSet<usize> = self.graph.reachable(self.entry);
        for node in 0..self.graph.successors.len() {
            if !live.contains(&node) && !self.graph.predecessors[node].is_empty() {
                for pred in self.graph.predecessors[node].clone() {
                    self.unstructured.push((pred, node));
                }
            }
        }
        loop {
            if live.len() <= 1 {
                break;
            }
            if self.try_sequence(&mut live)
                || self.try_condition(&mut live)
                || self.try_if(&mut live)
                || self.try_switch(&mut live)
                || self.try_loop(&mut live)
                || self.try_natural_loop(&mut live)
                || self.try_duplicate_tail(&mut live)
            {
                continue;
            }
            // Nothing matched: give up one edge, the one whose removal is
            // least likely to break a construct -- an edge into a node with
            // several predecessors that its source does not dominate.
            if !self.virtualise_one(&live) {
                break;
            }
        }
        self.regions[self.entry].clone()
    }

    fn merge(&mut self, keep: usize, drop: usize, region: Region, live: &mut BTreeSet<usize>) {
        // `keep` inherits `drop`'s successors; every edge into `drop` from
        // elsewhere has already been ruled out by the caller.
        let successors = self.graph.successors[drop].clone();
        self.graph.successors[keep].retain(|next| *next != drop);
        for next in successors {
            if next != keep && !self.graph.successors[keep].contains(&next) {
                self.graph.successors[keep].push(next);
            }
            let preds = &mut self.graph.predecessors[next];
            preds.retain(|pred| *pred != drop);
            if next != keep && !preds.contains(&keep) {
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
            let region = sequence(
                self.regions[node].clone(),
                self.regions[next].clone(),
            );
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
                if self.graph.successors[then] == vec![join] {
                    let region = Region::If {
                        condition: Box::new(self.regions[node].clone()),
                        then: Box::new(self.regions[then].clone()),
                        otherwise: None,
                    };
                    self.merge(node, then, region, live);
                    return true;
                }
                // A then-side that ends the function is still a then-side.
                if self.graph.successors[then].is_empty() {
                    let region = Region::If {
                        condition: Box::new(self.regions[node].clone()),
                        then: Box::new(self.regions[then].clone()),
                        otherwise: None,
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
                let region = Region::Condition {
                    first: Box::new(self.regions[node].clone()),
                    second: Box::new(self.regions[inner].clone()),
                };
                self.merge(node, inner, region, live);
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
    fn try_loop(&mut self, live: &mut BTreeSet<usize>) -> bool {
        let idom = self.graph.dominators(self.entry);
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
                1 => Region::DoWhile { body },
                _ => continue,
            };
            self.graph.successors[node].retain(|next| *next != node);
            self.graph.predecessors[node].retain(|pred| *pred != node);
            self.regions[node] = region;
            return true;
        }
        // A two-node loop: head tests, body returns to it.
        let candidates: Vec<usize> = live.iter().copied().collect();
        for head in candidates {
            for body in self.graph.successors[head].clone() {
                if body == head || body == self.entry {
                    continue;
                }
                if self.graph.predecessors[body].len() != 1 {
                    continue;
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
                };
                self.merge(head, body, region, live);
                // The back edge is the construct's own.
                self.graph.successors[head].retain(|next| *next != head);
                self.graph.predecessors[head].retain(|pred| *pred != head);
                return true;
            }
        }
        false
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
    fn try_natural_loop(&mut self, live: &mut BTreeSet<usize>) -> bool {
        let idom = self.graph.dominators(self.entry);
        for &head in live.iter() {
            let latches: Vec<usize> = self.graph.predecessors[head]
                .iter()
                .copied()
                .filter(|latch| *latch != head && self.graph.dominates(&idom, head, *latch))
                .collect();
            if latches.is_empty() {
                continue;
            }
            // Body: the header plus everything that reaches a latch without
            // going through the header again.
            let mut body: BTreeSet<usize> = BTreeSet::new();
            body.insert(head);
            let mut stack = latches.clone();
            while let Some(node) = stack.pop() {
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
            // The body, structured on its own terms.
            let order: Vec<usize> = body.iter().copied().collect();
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
            let inner = structure_from(order.len(), &inner_edges, index_of[&head]);
            for (from, to) in &inner.unstructured {
                self.unstructured.push((order[*from], order[*to]));
            }
            for node in &inner.duplicated {
                self.duplicated.push(order[*node]);
            }
            // A latch that tests the exit condition is a do-while; a header
            // that tests it is a while; no exit at all is an infinite loop.
            let region = if exits.is_empty() {
                Region::Infinite {
                    body: Box::new(inner.region.clone()),
                }
            } else if exits
                .values()
                .flatten()
                .all(|(from, _)| *from == head)
            {
                Region::While {
                    head: Box::new(Region::Block(head)),
                    body: Box::new(inner.region.clone()),
                }
            } else {
                Region::DoWhile {
                    body: Box::new(inner.region.clone()),
                }
            };
            // Collapse the body into the header.
            let head = head;
            let others: Vec<usize> = body.iter().copied().filter(|node| *node != head).collect();
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
            return true;
        }
        false
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
    fn virtualise_one(&mut self, live: &BTreeSet<usize>) -> bool {
        let idom = self.graph.dominators(self.entry);
        let mut best: Option<(usize, usize, (usize, usize, usize))> = None;
        for &from in live.iter() {
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
            return false;
        };
        self.graph.successors[from].retain(|next| *next != to);
        self.graph.predecessors[to].retain(|pred| *pred != from);
        self.unstructured.push((from, to));
        true
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
