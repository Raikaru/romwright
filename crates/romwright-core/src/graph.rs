//! Complete native function control flow and shared layered layout.
//! Layout keys are block identities, never instruction addresses: native
//! blocks can share an address or contain no operations.

use std::collections::{HashMap, VecDeque};

/// One layout node, keyed by stable native block identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BbNode {
    pub address: u64,
    pub size: u64,
}

/// Edge kind mirrors the roadmap typing: true / false / unconditional / call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BbEdgeKind {
    True,
    False,
    Unconditional,
    Call,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BbEdge {
    pub from: u64,
    pub to: u64,
    pub kind: BbEdgeKind,
}

#[derive(Clone, Debug, Default)]
pub struct BbGraph {
    pub nodes: Vec<BbNode>,
    pub edges: Vec<BbEdge>,
}

/// One laid-out native block. `id` is the stable block identity; `address`
/// is its first operation's RAM offset and `last` its highest operation
/// offset (both none for an empty block).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeGraphNode {
    pub id: u64,
    pub address: Option<u64>,
    pub last: Option<u64>,
    pub operations: usize,
    pub x: i64,
    pub y: i64,
}

/// The complete native CFG of one function with shared layered layout
/// positions: what every UI renders (API JSON, desktop typed).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeGraph {
    pub nodes: Vec<NativeGraphNode>,
    pub edges: Vec<BbEdge>,
}

impl BbEdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BbEdgeKind::True => "true",
            BbEdgeKind::False => "false",
            BbEdgeKind::Unconditional => "unconditional",
            BbEdgeKind::Call => "call",
        }
    }
}

/// Every exported native block and successor is retained, including empty
/// blocks, loops and disconnected components. Calls are operations, not CFG
/// successors; no architecture-specific byte decoder or walk limit is used.
pub fn native_layout(ir: &romwright_model::function_ir::FunctionIr) -> NativeGraph {
    use romwright_model::function_ir::Opcode;
    let graph = BbGraph {
        nodes: ir.blocks.iter().map(|block| BbNode {
            address: block.id.0,
            size: block.operations.len() as u64,
        }).collect(),
        edges: ir.blocks.iter().flat_map(|block| {
            let conditional = block.operations.last().is_some_and(|op| op.opcode == Opcode::CBRANCH)
                && block.successors.len() == 2;
            block.successors.iter().enumerate().map(move |(slot, target)| BbEdge {
                from: block.id.0,
                to: target.0,
                kind: if conditional {
                    if slot == 0 { BbEdgeKind::False } else { BbEdgeKind::True }
                } else { BbEdgeKind::Unconditional },
            })
        }).collect(),
    };
    let layout = layered_layout(&graph);
    let positions: HashMap<_, _> = layout.iter().map(|node| (node.address, (node.x, node.y))).collect();
    let nodes = ir.blocks.iter().map(|block| {
        let (x, y) = positions[&block.id.0];
        NativeGraphNode {
            id: block.id.0,
            address: block.operations.first().map(|op| op.address.offset),
            last: block.operations.iter().map(|op| op.address.offset).max(),
            operations: block.operations.len(),
            x,
            y,
        }
    }).collect();
    NativeGraph { nodes, edges: graph.edges }
}

impl NativeGraph {
    /// The JSON shape (`function_bb_graph`, `decompile_doc.graph`).
    pub fn to_json(&self) -> serde_json::Value {
        let nodes: Vec<_> = self.nodes.iter().map(|node| serde_json::json!({
            "id": node.id.to_string(),
            "address": node.address.map(|offset| format!("0x{offset:x}")),
            "operations": node.operations,
            "x": node.x, "y": node.y,
        })).collect();
        let edges: Vec<_> = self.edges.iter().map(|edge| serde_json::json!({
            "from": edge.from.to_string(), "to": edge.to.to_string(),
            "kind": edge.kind.as_str(),
        })).collect();
        serde_json::json!({
            "source": "native_function_ir", "complete": true, "nodes": nodes, "edges": edges,
        })
    }
}

/// [`native_layout`] as JSON.
pub fn native_graph(ir: &romwright_model::function_ir::FunctionIr) -> serde_json::Value {
    native_layout(ir).to_json()
}

/// Longest-path layering after excluding DFS feedback edges from ranking.
/// Feedback edges remain in the CFG. Bidirectional barycenter sweeps order
/// each rank; shorter ranks are centered within the widest rank.
pub struct LayoutNode {
    pub address: u64,
    pub rank: usize,
    pub order: usize,
    pub x: i64,
    pub y: i64,
}

pub const LAYOUT_NODE_WIDTH: i64 = 180;
pub const LAYOUT_NODE_HEIGHT: i64 = 60;
pub const LAYOUT_COL_GAP: i64 = 60;
pub const LAYOUT_ROW_GAP: i64 = 90;

pub fn layered_layout(graph: &BbGraph) -> Vec<LayoutNode> {
    let count = graph.nodes.len();
    if count == 0 {
        return Vec::new();
    }
    let indices: HashMap<_, _> = graph.nodes.iter().enumerate()
        .map(|(index, node)| (node.address, index)).collect();
    let mut successors = vec![Vec::new(); count];
    let mut predecessors = vec![Vec::new(); count];
    for (edge_index, edge) in graph.edges.iter().enumerate() {
        if edge.kind == BbEdgeKind::Call {
            continue;
        }
        if let (Some(&from), Some(&to)) = (indices.get(&edge.from), indices.get(&edge.to)) {
            successors[from].push((to, edge_index));
            predecessors[to].push((from, edge_index));
        }
    }

    // Iterative DFS also visits disconnected components. Removing only edges
    // to active ancestors produces a DAG without recursion or cycle relaxation.
    let mut color = vec![0u8; count];
    let mut feedback = vec![false; graph.edges.len()];
    let mut stack = Vec::new();
    for root in 0..count {
        if color[root] != 0 {
            continue;
        }
        color[root] = 1;
        stack.push((root, 0usize));
        while let Some((node, next)) = stack.last_mut() {
            if *next == successors[*node].len() {
                color[*node] = 2;
                stack.pop();
                continue;
            }
            let (target, edge_index) = successors[*node][*next];
            *next += 1;
            match color[target] {
                0 => {
                    color[target] = 1;
                    stack.push((target, 0));
                }
                1 => feedback[edge_index] = true,
                _ => {}
            }
        }
    }

    let mut pending: Vec<_> = predecessors.iter()
        .map(|edges| edges.iter().filter(|(_, edge)| !feedback[*edge]).count()).collect();
    let mut queue: VecDeque<_> = (0..count).filter(|&node| pending[node] == 0).collect();
    let mut rank = vec![0usize; count];
    while let Some(node) = queue.pop_front() {
        for &(target, edge) in &successors[node] {
            if feedback[edge] {
                continue;
            }
            rank[target] = rank[target].max(rank[node] + 1);
            pending[target] -= 1;
            if pending[target] == 0 {
                queue.push_back(target);
            }
        }
    }

    let mut levels = vec![Vec::new(); rank.iter().copied().max().unwrap_or(0) + 1];
    for (node, &level) in rank.iter().enumerate() {
        levels[level].push(node);
    }
    let width = levels.iter().map(Vec::len).max().unwrap_or(0);
    let mut positions = vec![0.0; count];
    for level in &levels {
        for (order, &node) in level.iter().enumerate() {
            positions[node] = order as f64 + (width - level.len()) as f64 / 2.0;
        }
    }
    let mut scored = Vec::with_capacity(width);
    for _ in 0..4 {
        for down in [true, false] {
            for step in 0..levels.len() {
                let level_index = if down { step } else { levels.len() - step - 1 };
                let level = &mut levels[level_index];
                scored.clear();
                for &node in level.iter() {
                    let neighbors = if down { &predecessors[node] } else { &successors[node] };
                    let mut sum = 0.0;
                    let mut degree = 0usize;
                    for &(neighbor, edge) in neighbors {
                        if !feedback[edge] {
                            sum += positions[neighbor];
                            degree += 1;
                        }
                    }
                    let center = if degree == 0 { positions[node] } else { sum / degree as f64 };
                    scored.push((center, node));
                }
                scored.sort_by(|a, b| a.0.total_cmp(&b.0)
                    .then_with(|| graph.nodes[a.1].address.cmp(&graph.nodes[b.1].address)));
                for (order, &(_, node)) in scored.iter().enumerate() {
                    level[order] = node;
                    positions[node] = order as f64 + (width - level.len()) as f64 / 2.0;
                }
            }
        }
    }

    let mut nodes = Vec::with_capacity(count);
    for (level_index, level) in levels.iter().enumerate() {
        for (order, &node) in level.iter().enumerate() {
            nodes.push(LayoutNode {
                address: graph.nodes[node].address,
                rank: level_index,
                order,
                x: (positions[node] * (LAYOUT_NODE_WIDTH + LAYOUT_COL_GAP) as f64) as i64,
                y: level_index as i64 * (LAYOUT_NODE_HEIGHT + LAYOUT_ROW_GAP),
            });
        }
    }
    nodes
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn layout_keeps_shortcut_merges_below_their_long_predecessor_chain() {
        let graph = BbGraph {
            nodes: (0..7).map(|address| BbNode { address, size: 1 }).collect(),
            edges: [(0, 4), (0, 1), (1, 2), (2, 3), (3, 4), (3, 1), (5, 6), (6, 6)]
                .into_iter().map(|(from, to)| BbEdge { from, to, kind: BbEdgeKind::Unconditional })
                .collect(),
        };
        let layout = layered_layout(&graph);
        let by_id: HashMap<_, _> = layout.iter().map(|node| (node.address, node)).collect();
        for (from, to) in [(0, 4), (0, 1), (1, 2), (2, 3), (3, 4), (5, 6)] {
            assert!(by_id[&from].y + LAYOUT_NODE_HEIGHT < by_id[&to].y);
        }
        assert_eq!(by_id.len(), graph.nodes.len());
        let boxes: std::collections::HashSet<_> = layout.iter().map(|node| (node.x, node.y)).collect();
        assert_eq!(boxes.len(), graph.nodes.len());
    }

    #[test]
    fn native_graph_preserves_shared_addresses_empty_blocks_and_loops() {
        use romwright_model::function_ir::*;
        use romwright_model::{Address, AddressSpace};
        let operation = |id, opcode| IrOperation {
            id: OperationId(id), address: Address { space: AddressSpace::Ram, offset: 0x1000 },
            opcode, output: None, inputs: vec![],
        };
        let ir = FunctionIr {
            blocks: vec![
                IrBlock { id: BlockId(0), operations: vec![operation(0, Opcode::CBRANCH)],
                    predecessors: vec![BlockId(0)], successors: vec![BlockId(1), BlockId(0)] },
                IrBlock { id: BlockId(1), operations: vec![operation(1, Opcode::RETURN)],
                    predecessors: vec![BlockId(0)], successors: vec![] },
                IrBlock { id: BlockId(2), operations: vec![], predecessors: vec![], successors: vec![] },
            ],
            values: BTreeMap::new(), high_variables: vec![], type_evidence: BTreeMap::new(),
            control_flow_cuts: vec![], passes: vec![], diagnostics: vec![], cast_types: vec![],
        };
        let result = native_graph(&ir);
        let nodes = result["nodes"].as_array().unwrap();
        assert_eq!(nodes.iter().map(|n| n["id"].as_str().unwrap()).collect::<Vec<_>>(), ["0", "1", "2"]);
        assert_eq!(nodes[0]["address"], nodes[1]["address"]);
        assert!(nodes[2]["address"].is_null());
        assert_ne!((nodes[0]["x"].clone(), nodes[0]["y"].clone()),
                   (nodes[1]["x"].clone(), nodes[1]["y"].clone()));
        assert_eq!(result["edges"], serde_json::json!([
            {"from": "0", "to": "1", "kind": "false"},
            {"from": "0", "to": "0", "kind": "true"},
        ]));
    }
}
