//! Maximum-weight bipartite matching on a sparse candidate set.
//!
//! The network-alignment matcher linearises its quadratic objective and then
//! needs the best one-to-one assignment under those linear weights (Leordeanu,
//! Hebert & Sukthankar, "An integer projected fixed point method for graph
//! matching and MAP inference", NIPS 2009, §3: each iteration projects the
//! gradient onto the assignment polytope, whose vertices are exactly the
//! one-to-one matchings).
//!
//! It is solved as a minimum-cost flow with unit capacities, one left node at
//! a time: every left ships one unit to the sink, either through a right
//! (cost `-weight`) or through a private zero-cost exit that means "stay
//! unmatched". Adding the lefts one by one and routing each along a shortest
//! augmenting path keeps the flow optimal for the lefts processed so far
//! (successive shortest paths with the source arcs introduced in turn), so
//! the final flow is the maximum-weight matching -- a pair nobody wants stays
//! unmatched instead of being assigned at a loss.
//!
//! The search is local. A search from the global source (the textbook form)
//! reaches every free left at distance ~0 and so explores the whole graph
//! for every pair it adds; from one left it stops at the first free right or
//! exit, which on a 45k-node cross-binary candidate graph is the difference
//! between hours and seconds. Potentials follow Johnson's reweighting with
//! the early-stop correction: a node settled at distance `d` before the sink
//! (at `D`) moves by `d - D`, every other node by nothing, which keeps every
//! reduced cost non-negative without touching the untouched part of the
//! graph. The sink's potential stays 0 under that convention.

/// One candidate pair and the weight of matching it.
#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub left: u32,
    pub right: u32,
    pub weight: f64,
}

/// Matches `left_count` left nodes against `right_count` right nodes over
/// `edges`, maximising total weight.
///
/// Returns the partner of each left node. Determinism: lefts are routed in
/// index order, adjacency keeps input order and shortest-path ties break by
/// node index, so equal inputs give equal matchings, which the gates depend
/// on.
pub fn max_weight_matching(
    left_count: usize,
    right_count: usize,
    edges: &[Edge],
) -> Vec<Option<u32>> {
    // A pair worth nothing is never better than staying unmatched, which
    // frees its right for someone else at no loss, so it is not a candidate.
    let mut start = vec![0usize; left_count + 1];
    for edge in edges {
        if edge.weight > 0.0 {
            start[edge.left as usize + 1] += 1;
        }
    }
    for left in 0..left_count {
        start[left + 1] += start[left];
    }
    let mut fill = start.clone();
    let mut adjacency: Vec<(u32, f64)> = vec![(0, 0.0); start[left_count]];
    for edge in edges {
        if edge.weight > 0.0 {
            let slot = &mut fill[edge.left as usize];
            adjacency[*slot] = (edge.right, edge.weight);
            *slot += 1;
        }
    }

    // Nodes: lefts 0..L, rights L..L+R, then the sink.
    let sink = left_count + right_count;
    let nodes = sink + 1;
    let mut matched_left: Vec<Option<u32>> = vec![None; left_count];
    let mut matched_right: Vec<Option<u32>> = vec![None; right_count];
    // Weight of the pair each right is currently matched through.
    let mut matched_weight = vec![0.0f64; right_count];
    let mut potential = vec![0.0f64; nodes];
    let mut distance = vec![f64::INFINITY; nodes];
    let mut settled = vec![false; nodes];
    // Predecessor on the shortest path: for a right, the left whose forward
    // arc reached it (and that arc's weight); for a left, the right whose
    // reverse arc reached it; for the sink, the node that exited.
    let mut previous = vec![u32::MAX; nodes];
    let mut previous_weight = vec![0.0f64; right_count];
    let mut touched: Vec<u32> = Vec::new();
    let mut queue = std::collections::BinaryHeap::new();

    for source in 0..left_count {
        let arcs = &adjacency[start[source]..start[source + 1]];
        if arcs.is_empty() {
            continue;
        }
        // A new left has no incoming residual arcs; this potential makes its
        // outgoing ones (every pair, and its exit) non-negative.
        potential[source] = arcs
            .iter()
            .map(|&(right, weight)| weight + potential[left_count + right as usize])
            .fold(0.0, f64::max);

        distance[source] = 0.0;
        touched.push(source as u32);
        queue.push(Entry {
            key: 0.0,
            node: source as u32,
        });
        let relax = |to: usize,
                     step: f64,
                     from: u32,
                     distance: &mut [f64],
                     previous: &mut [u32],
                     touched: &mut Vec<u32>,
                     queue: &mut std::collections::BinaryHeap<Entry>|
         -> bool {
            if step + 1e-12 < distance[to] {
                if distance[to].is_infinite() {
                    touched.push(to as u32);
                }
                distance[to] = step;
                previous[to] = from;
                queue.push(Entry {
                    key: step,
                    node: to as u32,
                });
                true
            } else {
                false
            }
        };
        while let Some(Entry { key, node }) = queue.pop() {
            let node = node as usize;
            if settled[node] || key > distance[node] + f64::EPSILON {
                continue;
            }
            settled[node] = true;
            if node == sink {
                break;
            }
            let here = distance[node];
            if node < left_count {
                // Forward arcs to every candidate right but its own partner.
                for &(right, weight) in &adjacency[start[node]..start[node + 1]] {
                    if matched_left[node] == Some(right) {
                        continue;
                    }
                    let to = left_count + right as usize;
                    // Reduced costs are non-negative under a feasible
                    // potential; floating point can still produce a tiny
                    // negative, which would only misorder the queue.
                    let reduced = -weight + potential[node] - potential[to];
                    if relax(
                        to,
                        here + feasible(reduced),
                        node as u32,
                        &mut distance,
                        &mut previous,
                        &mut touched,
                        &mut queue,
                    ) {
                        previous_weight[right as usize] = weight;
                    }
                }
                // The exit: this left gives up its pair (or, for the source,
                // never takes one). Every left the search reaches is either
                // the source or matched, so its exit is free.
                let reduced = potential[node] - potential[sink];
                relax(
                    sink,
                    here + feasible(reduced),
                    node as u32,
                    &mut distance,
                    &mut previous,
                    &mut touched,
                    &mut queue,
                );
            } else {
                let right = node - left_count;
                match matched_right[right] {
                    // The reverse arc back to the right's partner.
                    Some(partner) => {
                        let to = partner as usize;
                        let reduced = matched_weight[right] + potential[node] - potential[to];
                        relax(
                            to,
                            here + feasible(reduced),
                            node as u32,
                            &mut distance,
                            &mut previous,
                            &mut touched,
                            &mut queue,
                        );
                    }
                    None => {
                        let reduced = potential[node] - potential[sink];
                        relax(
                            sink,
                            here + feasible(reduced),
                            node as u32,
                            &mut distance,
                            &mut previous,
                            &mut touched,
                            &mut queue,
                        );
                    }
                }
            }
        }
        queue.clear();

        // The sink is always reached: the source's own exit leads there.
        let total = distance[sink];
        for &node in &touched {
            let node = node as usize;
            if settled[node] && node != sink {
                potential[node] += distance[node] - total;
            }
        }

        // Augment back from the sink. An exit through a left unmatches it
        // and hands its right down the path; an exit through a free right
        // starts the hand-down there.
        let exit = previous[sink] as usize;
        let mut open: Option<usize> = if exit < left_count {
            let left = exit;
            let freed = matched_left[left].take();
            if let Some(right) = freed {
                matched_right[right as usize] = None;
            }
            if left == source {
                None
            } else {
                freed.map(|right| right as usize)
            }
        } else {
            Some(exit - left_count)
        };
        while let Some(right) = open {
            let left = previous[left_count + right] as usize;
            let handed = matched_left[left].replace(right as u32);
            matched_right[right] = Some(left as u32);
            matched_weight[right] = previous_weight[right];
            open = if left == source {
                None
            } else {
                handed.map(|right| right as usize)
            };
        }

        for &node in &touched {
            let node = node as usize;
            distance[node] = f64::INFINITY;
            settled[node] = false;
            previous[node] = u32::MAX;
        }
        touched.clear();
    }
    matched_left
}

/// A reduced cost, clamped at zero. Under a feasible potential it is
/// non-negative up to rounding; anything more negative means the
/// potential update broke feasibility, which the clamp would otherwise
/// hide by fabricating a distance.
fn feasible(reduced: f64) -> f64 {
    debug_assert!(reduced >= -1e-9, "infeasible potential: reduced cost {reduced}");
    reduced.max(0.0)
}

/// Heap entry ordered by ascending key, ties by node index: `BinaryHeap` is
/// a max-heap, so the ordering is reversed here.
#[derive(Clone, Copy)]
struct Entry {
    key: f64,
    node: u32,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.node == other.node
    }
}
impl Eq for Entry {}
impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .key
            .partial_cmp(&self.key)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(other.node.cmp(&self.node))
    }
}
impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(left: u32, right: u32, weight: f64) -> Edge {
        Edge {
            left,
            right,
            weight,
        }
    }

    #[test]
    fn it_takes_the_better_of_two_conflicting_pairs() {
        let matching = max_weight_matching(
            2,
            2,
            &[
                edge(0, 0, 0.9),
                edge(1, 0, 0.5),
                edge(0, 1, 0.4),
                edge(1, 1, 0.3),
            ],
        );
        assert_eq!(matching, vec![Some(0), Some(1)]);
    }

    #[test]
    fn a_global_optimum_beats_the_greedy_choice() {
        // Greedy takes (0,0)=0.9 and is then stuck with (1,1)=0.1 for 1.0;
        // the optimum is (0,1)=0.8 with (1,0)=0.8 for 1.6.
        let matching = max_weight_matching(
            2,
            2,
            &[
                edge(0, 0, 0.9),
                edge(0, 1, 0.8),
                edge(1, 0, 0.8),
                edge(1, 1, 0.1),
            ],
        );
        assert_eq!(matching, vec![Some(1), Some(0)]);
    }

    #[test]
    fn a_negative_pair_is_left_unmatched() {
        let matching = max_weight_matching(2, 2, &[edge(0, 0, 0.5), edge(1, 1, -1.0)]);
        assert_eq!(matching, vec![Some(0), None]);
    }

    #[test]
    fn it_matches_nothing_without_candidates() {
        assert_eq!(max_weight_matching(3, 3, &[]), vec![None, None, None]);
    }

    #[test]
    fn a_rectangular_problem_matches_every_left_node_it_can() {
        // Three lefts, two rights: one left must go unmatched, and it is the
        // one whose pairs are worth least.
        let matching = max_weight_matching(
            3,
            2,
            &[
                edge(0, 0, 0.9),
                edge(1, 0, 0.8),
                edge(1, 1, 0.7),
                edge(2, 1, 0.2),
            ],
        );
        assert_eq!(matching, vec![Some(0), Some(1), None]);
    }

    /// Best total by exhaustion: each left takes a free right or nothing.
    fn brute_force(left: usize, taken: u32, weights: &[Vec<Option<f64>>]) -> f64 {
        if left == weights.len() {
            return 0.0;
        }
        let mut best = brute_force(left + 1, taken, weights);
        for (right, weight) in weights[left].iter().enumerate() {
            if let Some(weight) = weight {
                if taken & (1 << right) == 0 {
                    best = best.max(weight + brute_force(left + 1, taken | (1 << right), weights));
                }
            }
        }
        best
    }

    #[test]
    fn it_is_optimal_on_random_sparse_instances() {
        // Local searches from one left at a time must still find the global
        // optimum, including chains that unmatch an earlier left through its
        // exit. Sparse, mixed-sign weights force both.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) as f64 / (1u64 << 53) as f64
        };
        for _ in 0..3000 {
            let lefts = 1 + (next() * 9.0) as usize;
            let rights = 1 + (next() * 8.0) as usize;
            let mut weights = vec![vec![None; rights]; lefts];
            let mut edges = Vec::new();
            for (left, row) in weights.iter_mut().enumerate() {
                for (right, slot) in row.iter_mut().enumerate() {
                    if next() < 0.5 {
                        let weight = next() * 2.0 - 0.5;
                        *slot = Some(weight);
                        edges.push(edge(left as u32, right as u32, weight));
                    }
                }
            }
            let matching = max_weight_matching(lefts, rights, &edges);
            let mut used = vec![false; rights];
            let mut total = 0.0;
            for (left, partner) in matching.iter().enumerate() {
                if let Some(right) = partner {
                    let right = *right as usize;
                    assert!(!used[right], "right {right} matched twice");
                    used[right] = true;
                    total += weights[left][right].expect("matched a non-candidate");
                }
            }
            let best = brute_force(0, 0, &weights);
            assert!((total - best).abs() < 1e-9, "{total} vs optimum {best}: {edges:?}");
        }
    }
}
