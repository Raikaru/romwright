//! Maximum-weight bipartite matching on a sparse candidate set.
//!
//! The network-alignment matcher linearises its quadratic objective and then
//! needs the best one-to-one assignment under those linear weights (Leordeanu,
//! Hebert & Sukthankar, "An integer projected fixed point method for graph
//! matching and MAP inference", NIPS 2009, §3: each iteration projects the
//! gradient onto the assignment polytope, whose vertices are exactly the
//! one-to-one matchings).
//!
//! It is solved as a minimum-cost flow with unit capacities: source to each
//! left node, candidate edges carrying cost `-weight`, each right node to the
//! sink. Successive shortest augmenting paths give the optimum for every
//! cardinality in turn, so stopping as soon as the next path would not lower
//! the cost yields the maximum-weight matching rather than a forced perfect
//! one -- a pair nobody wants stays unmatched instead of being assigned at a
//! loss.
//!
//! Costs are negative, which Dijkstra cannot take, so the first potentials
//! come from one pass over the graph in topological order: source, lefts,
//! rights, sink is a DAG before any flow is pushed. Every later round uses
//! Johnson's reweighting, under which reduced costs are non-negative.

/// One candidate pair and the weight of matching it.
#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub left: u32,
    pub right: u32,
    pub weight: f64,
}

/// Residual arc.
#[derive(Clone, Copy)]
struct Arc {
    to: u32,
    capacity: u32,
    cost: f64,
    /// Index of the paired arc in the same list.
    mirror: u32,
}

/// Matches `left_count` left nodes against `right_count` right nodes over
/// `edges`, maximising total weight.
///
/// Returns the partner of each left node. Determinism: arcs are built in
/// input order and shortest-path ties break by node index, so equal inputs
/// give equal matchings, which the gates depend on.
pub fn max_weight_matching(
    left_count: usize,
    right_count: usize,
    edges: &[Edge],
) -> Vec<Option<u32>> {
    let source = left_count + right_count;
    let sink = source + 1;
    let nodes = sink + 1;
    let mut graph: Vec<Vec<u32>> = vec![Vec::new(); nodes];
    let mut arcs: Vec<Arc> = Vec::with_capacity(2 * (edges.len() + left_count + right_count));
    let mut connect = |arcs: &mut Vec<Arc>,
                       graph: &mut Vec<Vec<u32>>,
                       from: usize,
                       to: usize,
                       cost: f64| {
        let forward = arcs.len() as u32;
        arcs.push(Arc {
            to: to as u32,
            capacity: 1,
            cost,
            mirror: forward + 1,
        });
        arcs.push(Arc {
            to: from as u32,
            capacity: 0,
            cost: -cost,
            mirror: forward,
        });
        graph[from].push(forward);
        graph[to].push(forward + 1);
    };
    for left in 0..left_count {
        connect(&mut arcs, &mut graph, source, left, 0.0);
    }
    for right in 0..right_count {
        connect(&mut arcs, &mut graph, left_count + right, sink, 0.0);
    }
    // Candidate arcs: the pair's weight, as a cost to be minimised.
    let mut pair_arc: Vec<u32> = Vec::with_capacity(edges.len());
    for edge in edges {
        pair_arc.push(arcs.len() as u32);
        connect(
            &mut arcs,
            &mut graph,
            edge.left as usize,
            left_count + edge.right as usize,
            -edge.weight,
        );
    }

    // Initial potentials: one relaxation pass in topological order.
    let mut potential = vec![f64::INFINITY; nodes];
    potential[source] = 0.0;
    for left in 0..left_count {
        potential[left] = 0.0;
    }
    for edge in edges {
        let right = left_count + edge.right as usize;
        let candidate = -edge.weight;
        if candidate < potential[right] {
            potential[right] = candidate;
        }
    }
    let mut best_right = f64::INFINITY;
    for right in 0..right_count {
        if potential[left_count + right].is_infinite() {
            potential[left_count + right] = 0.0;
        }
        best_right = best_right.min(potential[left_count + right]);
    }
    potential[sink] = best_right.min(0.0);

    let rounds = left_count.min(right_count);
    for _ in 0..rounds {
        // Dijkstra in reduced costs.
        let mut distance = vec![f64::INFINITY; nodes];
        let mut arrived: Vec<u32> = vec![u32::MAX; nodes];
        let mut settled = vec![false; nodes];
        distance[source] = 0.0;
        let mut queue = std::collections::BinaryHeap::new();
        queue.push(Entry {
            key: 0.0,
            node: source as u32,
        });
        while let Some(Entry { key, node }) = queue.pop() {
            let node = node as usize;
            if settled[node] || key > distance[node] + f64::EPSILON {
                continue;
            }
            settled[node] = true;
            for &index in &graph[node] {
                let arc = arcs[index as usize];
                if arc.capacity == 0 {
                    continue;
                }
                let to = arc.to as usize;
                let reduced = arc.cost + potential[node] - potential[to];
                // Reduced costs are non-negative under a feasible potential;
                // floating point can still produce a tiny negative, which
                // would only misorder the queue, so it is clamped.
                let step = distance[node] + reduced.max(0.0);
                if step + 1e-12 < distance[to] {
                    distance[to] = step;
                    arrived[to] = index;
                    queue.push(Entry {
                        key: step,
                        node: arc.to,
                    });
                }
            }
        }
        if !distance[sink].is_finite() {
            break;
        }
        // True cost of this augmenting path, under Johnson's reweighting.
        let path_cost = distance[sink] - potential[source] + potential[sink];
        if path_cost >= -1e-12 {
            // The next pair would not increase the total weight.
            break;
        }
        for node in 0..nodes {
            if distance[node].is_finite() {
                potential[node] += distance[node];
            }
        }
        let mut node = sink;
        while node != source {
            let index = arrived[node];
            let arc = &mut arcs[index as usize];
            arc.capacity -= 1;
            let previous = arc.to;
            let mirror = arc.mirror;
            arcs[mirror as usize].capacity += 1;
            node = arcs[mirror as usize].to as usize;
            debug_assert_ne!(previous as usize, node);
        }
    }

    let mut matching = vec![None; left_count];
    for (edge, &index) in edges.iter().zip(&pair_arc) {
        if arcs[index as usize].capacity == 0 {
            matching[edge.left as usize] = Some(edge.right);
        }
    }
    matching
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
}
