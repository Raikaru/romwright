//! Accounting of who produced a printed function (docs/ownership.md).
//!
//! A [`PrintStats`] is computed for every function the Rust printer prints,
//! from data the printer already has: how many visible text tokens it was
//! handed, how many of those it replayed from fragments PrintC's own handlers
//! recorded (the vendored C++ chose them), and a census of the structured
//! block tree before and after the structuring models (the "before" tree is
//! Ghidra's `ActionFinalStructure`). Nothing here changes the printed text.

use super::ir::{CaseBody, Detail, Node, kind};
use super::printer::FragmentCounts;
use super::render::ExprStats;
use std::collections::BTreeMap;

/// Text tokens by who emitted them.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct TokenStats {
    /// Visible text tokens handed to the pretty printer.
    pub total: u64,
    /// Of those, replayed from PrintC-recorded fragments.
    pub fragments: u64,
    /// Of those, the tokens of expressions the worker printed itself from
    /// the exported print trees (`printc/render.rs`).
    pub rust_expressions: u64,
    /// The rest: emitted by the block layer (`printc/printer.rs`).
    pub block_layer: u64,
    /// Spacing tokens (indentation and line-break layout).
    pub spacing: u64,
    pub fragments_by_region: BTreeMap<String, u64>,
    pub fragments_by_kind: BTreeMap<String, u64>,
    pub rust_expressions_by_kind: BTreeMap<String, u64>,
}

impl TokenStats {
    pub fn from_counts(counts: &FragmentCounts) -> Self {
        Self {
            total: counts.text_tokens,
            fragments: counts.total,
            rust_expressions: counts.rust_total,
            block_layer: counts
                .text_tokens
                .saturating_sub(counts.total)
                .saturating_sub(counts.rust_total),
            spacing: counts.spacing_tokens,
            fragments_by_region: counts
                .by_region
                .iter()
                .map(|(key, value)| (key.to_string(), *value))
                .collect(),
            fragments_by_kind: counts
                .by_kind
                .iter()
                .map(|(key, value)| (key.to_string(), *value))
                .collect(),
            rust_expressions_by_kind: counts
                .rust_by_kind
                .iter()
                .map(|(key, value)| (key.to_string(), *value))
                .collect(),
        }
    }
}

/// Control-flow constructs of the printed tree against Ghidra's.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ConstructStats {
    /// Constructs in the tree Ghidra structured (`ghidra_opt`'s final
    /// structure).
    pub ghidra: u64,
    /// Constructs in the printed tree.
    pub printed: u64,
    /// Printed constructs that are also in Ghidra's tree (same kind, block
    /// and exit), as a multiset: a copied leaf counts once as Ghidra's and
    /// once as created.
    pub kept: u64,
    pub created_by_kind: BTreeMap<String, u64>,
    pub removed_by_kind: BTreeMap<String, u64>,
}

/// Everything the ownership log records about one printed function.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct PrintStats {
    pub tokens: TokenStats,
    /// Expressions the worker printed from print trees, by context and
    /// kind, and why the others kept PrintC's fragment.
    pub expressions: ExprStats,
    /// GTE macro calls folded into the printed statements (printc/gte.rs).
    pub gte: super::gte::GteStats,
    pub constructs: ConstructStats,
    /// Printed gotos and labels before/after the models.
    pub gotos: [u64; 2],
    pub labels: [u64; 2],
    /// Rewrites kept, per model.
    pub applied: BTreeMap<String, u64>,
    pub structuring_refused: Option<String>,
    /// The models ran and the printed tree is theirs.
    pub restructured: bool,
    /// The types the worker's casts name: the document's type model lacks
    /// them (the decompiler no longer casts for this function).
    #[serde(skip)]
    pub cast_types: Vec<romwright_model::DecompType>,
    /// What the document's prototypes of undeclared callees must say after the casts.
    #[serde(skip)]
    pub call_types: Vec<super::ir::CallPrototypeTypes>,
    /// The p-code changes of the worker's casts, applied to the semantic IR.
    #[serde(skip)]
    pub cast_edits: Vec<super::casts::IrEdit>,
}

fn name(node: &Node) -> Option<&'static str> {
    Some(match node.kind {
        kind::IF => "if",
        kind::WHILE_DO => "while",
        kind::DO_WHILE => "do_while",
        kind::INFINITE_LOOP => "infinite_loop",
        kind::SWITCH => "switch",
        kind::GOTO => "goto_block",
        kind::MULTIGOTO => "multigoto",
        kind::CONDITION => "condition",
        kind::COPY => "leaf",
        _ => return None,
    })
}

fn exit(goto_kind: u64, target: &Option<super::ir::GotoTarget>) -> String {
    format!(
        "{goto_kind}>{}",
        target.as_ref().map_or(-1, |target| target.block)
    )
}

fn census(node: &Node, into: &mut BTreeMap<(&'static str, String), u64>) {
    if let Some(label) = name(node) {
        let detail = match &node.detail {
            Detail::Goto {
                prints,
                goto_kind,
                target,
            } => format!("{prints}:{}", exit(*goto_kind, target)),
            Detail::If { goto_kind, target } => exit(*goto_kind, target),
            Detail::Condition { and } => and.to_string(),
            Detail::Switch { cases } => cases
                .iter()
                .map(|case| match &case.body {
                    CaseBody::Goto { goto_kind, target } => format!("g{}", exit(*goto_kind, target)),
                    CaseBody::Child(index) => format!("c{index}"),
                    CaseBody::Block(_) => "b".to_string(),
                })
                .collect::<Vec<_>>()
                .join(","),
            _ => String::new(),
        };
        *into
            .entry((label, format!("{}:{detail}", node.index)))
            .or_default() += 1;
    }
    for child in &node.children {
        census(child, into);
    }
    if let Detail::Switch { cases } = &node.detail {
        for case in cases {
            if let CaseBody::Block(block) = &case.body {
                census(block, into);
            }
        }
    }
}

fn census_of(body: &[Node]) -> BTreeMap<(&'static str, String), u64> {
    let mut into = BTreeMap::new();
    for node in body {
        census(node, &mut into);
    }
    into
}

/// Compares the printed tree with the one Ghidra structured.
pub fn construct_stats(ghidra: &[Node], printed: &[Node]) -> ConstructStats {
    let before = census_of(ghidra);
    let after = census_of(printed);
    let mut stats = ConstructStats {
        ghidra: before.values().sum(),
        printed: after.values().sum(),
        ..ConstructStats::default()
    };
    for (key, count) in &after {
        let had = before.get(key).copied().unwrap_or(0);
        stats.kept += (*count).min(had);
        if *count > had {
            *stats.created_by_kind.entry(key.0.to_string()).or_default() += count - had;
        }
    }
    for (key, count) in &before {
        let has = after.get(key).copied().unwrap_or(0);
        if *count > has {
            *stats.removed_by_kind.entry(key.0.to_string()).or_default() += count - has;
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::printc::ir::{Detail, Node, kind};

    fn node(kind: u64, index: i64, children: Vec<Node>) -> Node {
        Node {
            kind,
            index,
            last_op: None,
            label: None,
            children,
            detail: Detail::None,
        }
    }

    #[test]
    fn identical_trees_keep_every_construct() {
        let tree = vec![node(kind::IF, 1, vec![node(kind::COPY, 2, vec![])])];
        let stats = construct_stats(&tree, &tree);
        assert_eq!((stats.ghidra, stats.printed, stats.kept), (2, 2, 2));
        assert!(stats.created_by_kind.is_empty() && stats.removed_by_kind.is_empty());
    }

    #[test]
    fn a_copied_leaf_is_created_and_a_removed_goto_is_counted() {
        let ghidra = vec![node(kind::COPY, 2, vec![]), node(kind::GOTO, 3, vec![])];
        let printed = vec![node(kind::COPY, 2, vec![]), node(kind::COPY, 2, vec![])];
        let stats = construct_stats(&ghidra, &printed);
        assert_eq!((stats.ghidra, stats.printed, stats.kept), (2, 2, 1));
        assert_eq!(stats.created_by_kind.get("leaf"), Some(&1));
        assert_eq!(stats.removed_by_kind.get("goto_block"), Some(&1));
    }

    #[test]
    fn token_stats_split_fragments_from_the_block_layer() {
        let mut counts = FragmentCounts {
            text_tokens: 10,
            total: 7,
            ..Default::default()
        };
        counts.by_kind.insert("variable", 7);
        let stats = TokenStats::from_counts(&counts);
        assert_eq!((stats.total, stats.fragments, stats.block_layer), (10, 7, 3));
        assert_eq!(stats.fragments_by_kind.get("variable"), Some(&7));
    }
}
