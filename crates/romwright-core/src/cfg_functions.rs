//! Functions found by the shape of the control-flow graph, not by what
//! points at them.
//!
//! Every producer this project has needed something to start from: a symbol
//! table, a relocation, a call from code somebody already walked, or a byte
//! pattern the compiler happens to emit. Code nothing points at -- reached
//! only through a jump table nobody recovered, or through a pointer stored
//! in data, or not reached at all in a stripped library -- is invisible to
//! all of them.
//!
//! Nucleus (Andriesse, Slowinska & Bos, "Compiler-Agnostic Function
//! Detection in Binaries", EuroS&P 2017) makes the observation that a
//! function is a *shape*: the interprocedural CFG breaks into connected
//! components at exactly the places calls and returns cross, so clustering
//! basic blocks by intraprocedural edges recovers functions with no
//! signature and no symbol. This is that, over the blocks our own console
//! decodes:
//!
//! * decode forward through a region of code, block by block;
//! * connect blocks by branches and fallthrough -- never by calls, which
//!   are exactly the edges that leave a function;
//! * each weakly connected component is a candidate function, entered at
//!   its lowest address.
//!
//! The candidates carry their own provenance so they can be scored as their
//! own producer: the question a gate has to answer is not "did discovery
//! improve" but "what did *this* pass find, and was it right".

use std::collections::{BTreeMap, BTreeSet};

/// One decoded instruction, as this pass needs it.
#[derive(Debug, Clone)]
pub struct Step {
    pub address: u64,
    pub length: u8,
    /// Where control can go next inside the same function: branch targets
    /// and fallthrough. A call's callee is deliberately absent.
    pub successors: Vec<u64>,
    /// True when the instruction ends a block (branch, return, or an
    /// undecodable byte run).
    pub terminal: bool,
    /// Addresses this instruction calls, which are function entries in
    /// their own right.
    pub calls: Vec<u64>,
}

/// What the pass found.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Clustered {
    /// Candidate function entries, in address order.
    pub entries: Vec<u64>,
    /// Entries that are the target of a call: the strongest evidence a
    /// component is a function rather than a fragment.
    pub called: Vec<u64>,
    /// Blocks the clustering saw.
    pub blocks: u64,
    /// Components it split them into.
    pub components: u64,
}

/// Clusters decoded instructions into candidate functions.
///
/// `steps` need not be contiguous or complete: whatever was decoded is
/// clustered, and an address with no step is simply not part of any
/// component. That matters because a sweep over stripped bytes decodes
/// rubbish in places, and the answer must degrade to "found nothing here"
/// rather than to a component spanning the rubbish.
pub fn cluster(steps: &[Step]) -> Clustered {
    if steps.is_empty() {
        return Clustered::default();
    }
    let decoded: BTreeMap<u64, &Step> = steps.iter().map(|step| (step.address, step)).collect();
    // Block leaders: the first instruction, every branch target, and the
    // instruction after a terminal one.
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    let first = *decoded.keys().next().expect("non-empty");
    leaders.insert(first);
    let mut called: BTreeSet<u64> = BTreeSet::new();
    for step in steps {
        for target in &step.successors {
            if decoded.contains_key(target) && *target != step.address + u64::from(step.length) {
                leaders.insert(*target);
            }
        }
        for target in &step.calls {
            called.insert(*target);
            // A call target is a function entry wherever it lands.
            if decoded.contains_key(target) {
                leaders.insert(*target);
            }
        }
        let next = step.address.saturating_add(u64::from(step.length));
        if step.terminal && decoded.contains_key(&next) {
            leaders.insert(next);
        }
    }
    let blocks: Vec<u64> = leaders.iter().copied().collect();
    let block_of = |address: u64| -> Option<usize> {
        match blocks.binary_search(&address) {
            Ok(index) => Some(index),
            Err(0) => None,
            Err(index) => Some(index - 1),
        }
    };
    // Union-find over blocks, joined by intraprocedural edges only.
    let mut parent: Vec<usize> = (0..blocks.len()).collect();
    fn find(parent: &mut Vec<usize>, mut node: usize) -> usize {
        while parent[node] != node {
            parent[node] = parent[parent[node]];
            node = parent[node];
        }
        node
    }
    let mut union = |parent: &mut Vec<usize>, left: usize, right: usize| {
        let (left, right) = (find(parent, left), find(parent, right));
        if left != right {
            parent[right.max(left)] = right.min(left);
        }
    };
    for step in steps {
        let Some(source) = block_of(step.address) else {
            continue;
        };
        for target in &step.successors {
            // An edge into a call target crosses a function boundary: the
            // callee is its own component even when the caller falls into
            // it. This is the split Nucleus makes.
            if called.contains(target) {
                continue;
            }
            if let Some(destination) = block_of(*target)
                && decoded.contains_key(target)
            {
                union(&mut parent, source, destination);
            }
        }
    }
    let mut components: BTreeMap<usize, u64> = BTreeMap::new();
    for (index, address) in blocks.iter().enumerate() {
        let root = find(&mut parent, index);
        components
            .entry(root)
            .and_modify(|entry| *entry = (*entry).min(*address))
            .or_insert(*address);
    }
    let mut entries: Vec<u64> = components.values().copied().collect();
    entries.sort_unstable();
    entries.dedup();
    Clustered {
        called: {
            let mut called: Vec<u64> = called.into_iter().collect();
            called.sort_unstable();
            called
        },
        components: components.len() as u64,
        blocks: blocks.len() as u64,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(address: u64, successors: &[u64], calls: &[u64], terminal: bool) -> Step {
        Step {
            address,
            length: 4,
            successors: successors.to_vec(),
            calls: calls.to_vec(),
            terminal,
        }
    }

    #[test]
    fn a_straight_run_is_one_function() {
        let steps = vec![
            step(0x1000, &[0x1004], &[], false),
            step(0x1004, &[0x1008], &[], false),
            step(0x1008, &[], &[], true),
        ];
        let found = cluster(&steps);
        assert_eq!(found.entries, vec![0x1000]);
        assert_eq!(found.components, 1);
    }

    #[test]
    fn a_call_splits_two_functions_that_are_adjacent() {
        // 0x1000 calls 0x1008 and returns; 0x1008 is its own function even
        // though it follows in memory.
        let steps = vec![
            step(0x1000, &[0x1004], &[0x1008], false),
            step(0x1004, &[], &[], true),
            step(0x1008, &[0x100c], &[], false),
            step(0x100c, &[], &[], true),
        ];
        let found = cluster(&steps);
        assert_eq!(found.entries, vec![0x1000, 0x1008]);
        assert_eq!(found.called, vec![0x1008]);
    }

    #[test]
    fn a_function_nothing_calls_is_still_found() {
        // Two components with no edge between them: the second is code
        // reached only through something this pass cannot see, and its
        // shape is the only evidence it exists.
        let steps = vec![
            step(0x1000, &[0x1004], &[], false),
            step(0x1004, &[], &[], true),
            step(0x2000, &[0x2004], &[], false),
            step(0x2004, &[0x2000], &[], true),
        ];
        let found = cluster(&steps);
        assert_eq!(found.entries, vec![0x1000, 0x2000]);
        assert_eq!(found.components, 2);
    }

    #[test]
    fn a_branch_backwards_keeps_one_function() {
        let steps = vec![
            step(0x1000, &[0x1004], &[], false),
            step(0x1004, &[0x1008, 0x1000], &[], true),
            step(0x1008, &[], &[], true),
        ];
        let found = cluster(&steps);
        assert_eq!(found.entries, vec![0x1000]);
    }

    #[test]
    fn nothing_decoded_finds_nothing() {
        assert_eq!(cluster(&[]).entries.len(), 0);
    }
}
