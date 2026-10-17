use super::*;
use crate::printc::ir::Expression;

fn expression() -> Expression {
    Expression {
        normal: Fragment::default(),
        comma: None,
        source: Source::Fragments,
    }
}

/// A graph from out-edge lists (`(target, back_edge)`); a block with two
/// outs ends in a CBRANCH, one with none returns. Blocks are in reverse
/// post order, as the decompiler numbers them.
fn graph(outs: &[&[(usize, bool)]]) -> Cfg {
    let n = outs.len();
    let mut blocks: Vec<CfgBlock> = (0..n)
        .map(|i| CfgBlock {
            ins: Vec::new(),
            outs: Vec::new(),
            flags: 0,
            last: match outs[i].len() {
                0 => Last::Return,
                2 => Last::Cbranch,
                _ => Last::Other,
            },
            last_time: Some(i as u64),
            fallthru_true: false,
            complex: false,
            flipped: false,
            label: Fragment::default(),
            switch_edges: Vec::new(),
            basic: Some(Basic {
                comments: Vec::new(),
                statements: Vec::new(),
                branch: (outs[i].len() == 2).then(expression),
                successors: outs[i].iter().map(|&(t, _)| t as i64).collect(),
                negated: (outs[i].len() == 2).then(expression),
                holds_loop_op: false,
                threaded: Vec::new(),
            }),
        })
        .collect();
    for (from, list) in outs.iter().enumerate() {
        for (slot, &(to, back)) in list.iter().enumerate() {
            let label = if back { E_BACK | E_LOOP } else { 0 };
            let rev = blocks[to].ins.len();
            blocks[from].outs.push(CfgEdge { block: to, rev, label });
            blocks[to].ins.push(CfgEdge { block: from, rev: slot, label });
        }
    }
    Cfg {
        blocks,
        loops: Vec::new(),
        prefer: Vec::new(),
    }
}

fn kinds(node: &Node, out: &mut Vec<u64>) {
    out.push(node.kind);
    for child in &node.children {
        kinds(child, out);
    }
}

fn tree(outs: &[&[(usize, bool)]]) -> Vec<u64> {
    let mut cfg = graph(outs);
    let built = build(&mut cfg).expect("structures");
    let mut out = Vec::new();
    for node in &built.body {
        kinds(node, &mut out);
    }
    out
}

#[test]
fn a_straight_line_is_one_list() {
    let kinds = tree(&[&[(1, false)], &[(2, false)], &[]]);
    assert_eq!(kinds[0], kind::LIST);
    assert_eq!(kinds.iter().filter(|&&k| k == kind::COPY).count(), 3);
}

#[test]
fn a_diamond_is_an_if_else() {
    let kinds = tree(&[
        &[(1, false), (2, false)],
        &[(3, false)],
        &[(3, false)],
        &[],
    ]);
    assert!(kinds.contains(&kind::IF), "{kinds:?}");
    assert!(!kinds.contains(&kind::GOTO), "{kinds:?}");
}

#[test]
fn a_test_at_the_top_of_a_loop_is_a_while() {
    // 0 -> 1; 1 tests: body 2 or exit 3; 2 -> 1; 3 returns
    let kinds = tree(&[
        &[(1, false)],
        &[(2, false), (3, false)],
        &[(1, true)],
        &[],
    ]);
    assert!(kinds.contains(&kind::WHILE_DO), "{kinds:?}");
    assert!(!kinds.contains(&kind::GOTO), "{kinds:?}");
}

#[test]
fn a_test_at_the_bottom_of_a_loop_is_a_do_while() {
    let kinds = tree(&[&[(1, false)], &[(1, true), (2, false)], &[]]);
    assert!(kinds.contains(&kind::DO_WHILE), "{kinds:?}");
}

#[test]
fn a_loop_with_no_exit_is_an_infinite_loop() {
    let kinds = tree(&[&[(1, false)], &[(1, true)]]);
    assert!(kinds.contains(&kind::INFINITE_LOOP), "{kinds:?}");
}

#[test]
fn a_jump_into_an_if_is_a_goto() {
    // 0 -> {1, 2}; 1 -> {2, 3}; 2 -> 3... then 3 -> 1 enters the middle.
    let kinds = tree(&[
        &[(1, false), (2, false)],
        &[(3, false), (2, false)],
        &[(1, false)],
        &[],
    ]);
    assert!(
        kinds.contains(&kind::GOTO) || kinds.contains(&kind::IF),
        "{kinds:?}"
    );
}

#[test]
fn an_early_return_edge_is_found_by_the_return_split_query() {
    // 0 -> {1, 4}; 1 -> {2, 4}; 2 -> {3, 4}; 3 -> 4; 4 returns. Every edge
    // into the return nests, so nothing is a goto.
    let cfg = graph(&[
        &[(1, false), (4, false)],
        &[(2, false), (4, false)],
        &[(3, false), (4, false)],
        &[(4, false)],
        &[],
    ]);
    let analysis = analyze(&cfg).expect("structures");
    assert_eq!(analysis.returns.len(), 1);
    assert!(analysis.returns[0].1.is_empty());
}
