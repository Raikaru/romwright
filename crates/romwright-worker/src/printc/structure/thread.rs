//! `thread_test`: jump-threading reversal on the structured tree.
//!
//! A compiler that knows a test's outcome on one path jumps that path
//! straight to the test's taken arm and skips the test:
//!
//! ```text
//! switch (x) { case 2: if (a || b) { ...; break; } goto L; }   // goto L
//! if (!b) { L: ... }                                          // L: arm entry
//! ```
//!
//! SAILR's reversal re-inserts the skipped test on that path instead of
//! copying the arm. Here: when a printed `goto L` sits where control would
//! otherwise continue into the test of the `if` whose arm starts at `L`
//! (it falls through, `break`s or `continue`s there), and the conditions
//! that hold on every edge into `L` decide that test's outcome, the `goto`
//! is dropped and the test runs again, taking the same edge. Nothing is
//! copied.
//!
//! Soundness rests on [`Facts`] (printc/expr.rs): conditions are compared as
//! trees (opcode and variable identity), and a fact is killed by any
//! statement on the path that writes a variable it reads or, for aliased
//! variables and memory loads, calls or stores. Facts are never carried
//! through a label other code jumps to, or a loop (every effect in the loop
//! kills them). The re-inserted test must print nothing but the test and
//! contain no call. The checker then accepts the changed edges
//! (`Basic::threaded`) only for exactly the leaves proved here, and a block
//! that carries one is never copied.

use super::{
    Analysis, BREAK_GOTO, CONTINUE_GOTO, CaseBody, Detail, Edit, Flow, Form, GOTO_GOTO,
    GotoTarget, Node, Step, bare_condition, basic_of, entry, is_loop, kind, node_at,
    primary_instance,
};
use crate::printc::expr::{Facts, code};
use crate::printc::ir::{Basic, Statement};

/// The CBRANCH statement of a block that ends in a branch.
fn branch(basic: &Basic) -> Option<&Statement> {
    basic
        .statements
        .iter()
        .rev()
        .find(|statement| statement.is_branch && statement.effect.code == code::CBRANCH)
}

fn each_effect(node: &Node, visit: &mut impl FnMut(&Statement)) {
    if let Some(basic) = basic_of(node)
        && matches!(node.kind, kind::BASIC | kind::COPY)
    {
        basic.statements.iter().for_each(&mut *visit);
        return;
    }
    for child in &node.children {
        each_effect(child, visit);
    }
    if let Detail::Switch { cases } = &node.detail {
        for case in cases {
            if let CaseBody::Block(block) = &case.body {
                each_effect(block, visit);
            }
        }
    }
}

/// Drops the facts anything in `node` may invalidate.
fn kill_all(facts: &mut Facts, node: &Node) {
    each_effect(node, &mut |statement| facts.kill(&statement.effect));
}

/// `node` has run: what it may have changed is forgotten, and a block's
/// `variable = constant` statements are learned.
fn account(facts: &mut Facts, node: &Node) {
    match (node.kind, basic_of(node)) {
        (kind::BASIC | kind::COPY, Some(basic)) => {
            for statement in &basic.statements {
                facts.kill(&statement.effect);
                facts.assign(&statement.effect);
            }
        }
        _ => kill_all(facts, node),
    }
}

/// Whether other code can enter `node` (it prints a label some goto uses).
fn entered_elsewhere(node: &Node, analysis: &Analysis) -> bool {
    if node.label.is_some()
        && let Some(block) = entry(node)
        && analysis.targets.get(&block).copied().unwrap_or(0) > 0
    {
        return true;
    }
    node.children
        .iter()
        .any(|child| entered_elsewhere(child, analysis))
        || match &node.detail {
            Detail::Switch { cases } => cases.iter().any(|case| match &case.body {
                CaseBody::Block(block) => entered_elsewhere(block, analysis),
                _ => false,
            }),
            _ => false,
        }
}

/// `condition == truth` holds: the facts of a printed condition tree.
fn assume(cond: &Node, truth: bool, facts: &mut Facts) {
    match cond.kind {
        kind::COPY => {
            if let Some(child) = cond.children.first() {
                assume(child, truth, facts);
            }
        }
        kind::BASIC => {
            if let Some(basic) = basic_of(cond)
                && let Some(statement) = branch(basic)
                && !statement.effect.calls
                && let Some(tree) = statement.effect.args.first()
            {
                facts.assume(tree, truth != statement.effect.flip);
            }
        }
        kind::CONDITION => {
            let Detail::Condition { and } = cond.detail else {
                return;
            };
            // `a && b` true: both; `a || b` false: neither.
            if and == truth {
                for child in &cond.children {
                    assume(child, truth, facts);
                }
            }
        }
        _ => {}
    }
}

/// What a printed condition (statements ahead of its tests excluded: the
/// caller requires none) evaluates to under `facts`.
fn value(cond: &Node, facts: &Facts) -> Option<bool> {
    match cond.kind {
        kind::COPY => value(cond.children.first()?, facts),
        kind::BASIC => {
            let statement = branch(basic_of(cond)?)?;
            if statement.effect.calls || statement.effect.stores {
                return None;
            }
            let known = facts.value(statement.effect.args.first()?)?;
            Some(known != statement.effect.flip)
        }
        kind::CONDITION => {
            let Detail::Condition { and } = cond.detail else {
                return None;
            };
            let values: Vec<Option<bool>> =
                cond.children.iter().map(|child| value(child, facts)).collect();
            // `&&` is false when any test is, `||` true when any is.
            if values.contains(&Some(!and)) {
                Some(!and)
            } else if values.iter().all(|known| *known == Some(and)) {
                Some(and)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// No test of the condition calls or stores (re-running it must be free of
/// side effects).
fn pure_condition(cond: &Node) -> bool {
    let mut pure = true;
    each_effect(cond, &mut |statement| {
        if statement.effect.calls || statement.effect.stores {
            pure = false;
        }
    });
    pure
}

/// The conditions that hold at the entry of the node at `path`: the
/// enclosing `if` arms' tests, less what statements and loops on the way
/// may have changed, and nothing at all past a label other code jumps to.
fn facts_at(root: &Node, analysis: &Analysis, path: &[Step]) -> Option<Facts> {
    let mut facts = Facts::default();
    let mut node = root;
    for step in path {
        let Step::Child(position) = *step else {
            return None;
        };
        let child = node.children.get(position)?;
        match node.kind {
            kind::LIST | kind::GRAPH => {
                for earlier in &node.children[..position] {
                    account(&mut facts, earlier);
                    if entered_elsewhere(earlier, analysis) {
                        facts = Facts::default();
                    }
                }
            }
            kind::IF if position >= 1 => {
                let cond = &node.children[0];
                kill_all(&mut facts, cond);
                assume(cond, position == 1, &mut facts);
            }
            kind::GOTO if position == 0 => {}
            kind::SWITCH => kill_all(&mut facts, node),
            other if is_loop(other) => kill_all(&mut facts, node),
            _ => return None,
        }
        if entered_elsewhere_root(child, analysis) {
            facts = Facts::default();
        }
        node = child;
    }
    Some(facts)
}

/// Whether `node` itself (not what it holds) is a jump target.
fn entered_elsewhere_root(node: &Node, analysis: &Analysis) -> bool {
    node.label.is_some()
        && entry(node)
            .is_some_and(|block| analysis.targets.get(&block).copied().unwrap_or(0) > 0)
}

/// Every edge into `target` made by a leaf of `node`, with what holds on it.
/// `false` when `node` holds such an edge in a shape this does not follow.
fn exits(
    node: &Node,
    analysis: &Analysis,
    target: i64,
    facts: &Facts,
    out: &mut Vec<(i64, Facts)>,
) -> bool {
    match node.kind {
        kind::PLAIN => true,
        kind::BASIC | kind::COPY => {
            let Some(basic) = basic_of(node) else {
                return false;
            };
            if basic.successors.contains(&target) {
                let mut now = facts.clone();
                account(&mut now, node);
                out.push((entry(node).unwrap_or(node.index), now));
            }
            true
        }
        kind::LIST | kind::GRAPH => {
            let mut now = facts.clone();
            for child in &node.children {
                if entered_elsewhere(child, analysis) {
                    now = Facts::default();
                }
                if !exits(child, analysis, target, &now, out) {
                    return false;
                }
                account(&mut now, child);
            }
            true
        }
        kind::IF => {
            let Detail::If { target: goes, .. } = &node.detail else {
                return false;
            };
            if goes.is_some() {
                // `if (c) goto M;` prints its own jump.
                return true;
            }
            let Some(cond) = node.children.first() else {
                return false;
            };
            let mut after_tests = facts.clone();
            kill_all(&mut after_tests, cond);
            if !cond_exits(cond, target, facts, out) {
                return false;
            }
            for (position, arm) in node.children.iter().enumerate().skip(1) {
                let mut inside = after_tests.clone();
                assume(cond, position == 1, &mut inside);
                if !exits(arm, analysis, target, &inside, out) {
                    return false;
                }
            }
            true
        }
        kind::GOTO => {
            let Detail::Goto { prints, .. } = &node.detail else {
                return false;
            };
            if *prints {
                // A printed jump does not flow on.
                true
            } else {
                node.children
                    .first()
                    .is_none_or(|child| exits(child, analysis, target, facts, out))
            }
        }
        _ => !reaches(node, target),
    }
}

/// Whether any leaf under `node` has `target` among its successors.
fn reaches(node: &Node, target: i64) -> bool {
    basic_of(node).is_some_and(|basic| basic.successors.contains(&target))
        && matches!(node.kind, kind::BASIC | kind::COPY)
        || node.children.iter().any(|child| reaches(child, target))
        || match &node.detail {
            Detail::Switch { cases } => cases.iter().any(|case| match &case.body {
                CaseBody::Block(block) => reaches(block, target),
                _ => false,
            }),
            _ => false,
        }
}

/// The edges into `target` out of the tests of a condition: the leaf, and
/// what holds when it is taken.
fn cond_exits(
    cond: &Node,
    target: i64,
    facts: &Facts,
    out: &mut Vec<(i64, Facts)>,
) -> bool {
    match cond.kind {
        kind::COPY => cond
            .children
            .first()
            .is_none_or(|child| cond_exits(child, target, facts, out)),
        kind::BASIC => {
            let Some(basic) = basic_of(cond) else {
                return false;
            };
            if let [false_out, true_out] = basic.successors.as_slice() {
                for (successor, truth) in [(*true_out, true), (*false_out, false)] {
                    if successor != target {
                        continue;
                    }
                    let mut now = facts.clone();
                    assume(cond, truth, &mut now);
                    out.push((entry(cond).unwrap_or(cond.index), now));
                }
            } else if basic.successors.contains(&target) {
                return false;
            }
            true
        }
        kind::CONDITION => {
            let Detail::Condition { and } = cond.detail else {
                return false;
            };
            let [first, second] = cond.children.as_slice() else {
                return false;
            };
            if !cond_exits(first, target, facts, out) {
                return false;
            }
            // Reaching the second test: `&&` held the first, `||` did not.
            let mut reached = facts.clone();
            assume(first, and, &mut reached);
            cond_exits(second, target, &reached, out)
        }
        _ => !reaches(cond, target),
    }
}

/// The `if` one of whose arms starts at the block `target` and which arm:
/// (path of the if, 1 for then / 2 for else).
fn arm_starting_at(root: &Node, leaf: &[Step], target: i64) -> Option<(Vec<Step>, usize)> {
    let mut path = leaf.to_vec();
    loop {
        let (last, parent_path) = path.split_last()?;
        let parent = node_at(root, parent_path)?;
        let Step::Child(position) = *last else {
            return None;
        };
        match parent.kind {
            kind::IF if matches!(position, 1 | 2) => {
                let arm = parent.children.get(position)?;
                return (entry(arm) == Some(target) && matches!(parent.detail, Detail::If { target: None, .. }))
                    .then(|| (parent_path.to_vec(), position));
            }
            // Still the first thing of the enclosing statement (an arm that
            // starts with an `if` starts with its test).
            kind::LIST | kind::GRAPH | kind::GOTO | kind::COPY | kind::IF | kind::CONDITION
                if position == 0 =>
            {
                path = parent_path.to_vec();
            }
            _ => return None,
        }
    }
}

/// Marks the leaves `blocks` of `node` as flowing from their edge to `target`
/// through the test starting at `through`.
fn mark(node: &mut Node, blocks: &[i64], target: i64, through: i64) {
    if matches!(node.kind, kind::BASIC)
        && blocks.contains(&node.index)
        && let Detail::Basic(basic) = &mut node.detail
    {
        basic.threaded.push((target, through));
    }
    for child in &mut node.children {
        mark(child, blocks, target, through);
    }
    if let Detail::Switch { cases } = &mut node.detail {
        for case in cases {
            if let CaseBody::Block(block) = &mut case.body {
                mark(block, blocks, target, through);
            }
        }
    }
}

/// The reversals available in the tree, as edits.
pub(super) fn candidates(root: &Node, analysis: &Analysis) -> Vec<Edit> {
    let mut found = Vec::new();
    for site in &analysis.sites {
        if site.form != Form::Goto || site.kind != GOTO_GOTO {
            continue;
        }
        let Some(goto) = node_at(root, &site.path) else {
            continue;
        };
        let Some(body) = goto.children.first() else {
            continue;
        };
        let target = site.target;
        // The target must be one place in the tree.
        if analysis.leaves.get(&target).is_none_or(|leaves| leaves.len() != 1) {
            continue;
        }
        let Some(leaf) = primary_instance(root, analysis, target) else {
            continue;
        };
        let Some((if_path, arm)) = arm_starting_at(root, leaf, target) else {
            continue;
        };
        let Some(test) = node_at(root, &if_path).and_then(|node| node.children.first()) else {
            continue;
        };
        if !bare_condition(test) || !pure_condition(test) {
            continue;
        }
        let Some(first) = entry(test) else {
            continue;
        };
        // Where the dropped goto's position continues: into the test.
        let jump = if site.scope.follow.is(first) {
            None
        } else if site.scope.brk.as_ref().is_some_and(|flow| flow.is(first)) {
            Some(BREAK_GOTO)
        } else if site.scope.cont.as_ref().is_some_and(|flow| flow.is(first)) {
            Some(CONTINUE_GOTO)
        } else {
            continue;
        };
        let Some(facts) = facts_at(root, analysis, &site.path) else {
            continue;
        };
        let mut edges = Vec::new();
        if !exits(body, analysis, target, &facts, &mut edges) || edges.is_empty() {
            continue;
        }
        let wanted = arm == 1;
        if !edges
            .iter()
            .all(|(_, known)| value(test, known) == Some(wanted))
        {
            continue;
        }
        let blocks: Vec<i64> = edges.iter().map(|(block, _)| *block).collect();
        let mut body = body.clone();
        mark(&mut body, &blocks, target, first);
        let replaced = match jump {
            None => body,
            Some(goto_kind) => {
                let mut jump_node = goto.clone();
                if let Detail::Goto { goto_kind: slot, .. } = &mut jump_node.detail {
                    *slot = goto_kind;
                }
                jump_node.children = vec![body];
                jump_node
            }
        };
        found.push(Edit::Node(site.path.clone(), Box::new(replaced)));
    }
    found
}

/// The `if` whose test starts at the block `target` (the leaf at `leaf` is
/// that test's first block): the if's path.
fn test_starting_at(root: &Node, leaf: &[Step], target: i64) -> Option<Vec<Step>> {
    let mut path = leaf.to_vec();
    loop {
        let (last, parent_path) = path.split_last()?;
        let parent = node_at(root, parent_path)?;
        let Step::Child(position) = *last else {
            return None;
        };
        match parent.kind {
            kind::IF if position == 0 => {
                return (entry(parent) == Some(target)
                    && matches!(parent.detail, Detail::If { target: None, .. }))
                .then(|| parent_path.to_vec());
            }
            kind::CONDITION | kind::COPY | kind::LIST if position == 0 => {
                path = parent_path.to_vec();
            }
            _ => return None,
        }
    }
}

/// Where control goes when the `if` at `if_path` takes its then arm
/// (`true`) or its else arm / falls out: the first block of that arm, or
/// of what follows the if.
fn taken(root: &Node, analysis: &Analysis, if_path: &[Step], then: bool) -> Option<i64> {
    let node = node_at(root, if_path)?;
    match node.children.get(node_arm(then)) {
        Some(arm) => entry(arm).map_or_else(|| after(analysis, if_path), Some),
        None => after(analysis, if_path),
    }
}

fn node_arm(then: bool) -> usize {
    if then { 1 } else { 2 }
}

fn after(analysis: &Analysis, if_path: &[Step]) -> Option<i64> {
    match analysis.scopes.get(if_path)?.follow {
        Flow::Leaf(block) => Some(block),
        Flow::End => None,
    }
}

/// `goto L` to the test of an `if` whose outcome the conditions on the
/// jump decide goes straight to the arm that outcome takes (SAILR's jump
/// threading, applied): `flag = 1; goto L; ... L: if (flag != 0) { A }`
/// jumps to A. Nothing is copied. The result is a goto to a later place, a
/// fallthrough, `break` or `continue`; only the last three remove a goto,
/// so the first is kept only when the other models then remove it
/// (`Run::attempt_sink`). Returns the edits that make up one rewrite.
pub(super) fn forward(root: &Node, analysis: &Analysis) -> Vec<Vec<Edit>> {
    let mut found = Vec::new();
    for site in &analysis.sites {
        if !matches!(site.form, Form::Goto | Form::If) || site.kind != GOTO_GOTO {
            continue;
        }
        let Some(jump_node) = node_at(root, &site.path) else {
            continue;
        };
        // What flows to the target: a goto's body, or an `if (c) goto L;`'s
        // test (its taken edge).
        let Some(part) = jump_node.children.first() else {
            continue;
        };
        let origin = site.target;
        let Some(facts) = facts_at(root, analysis, &site.path) else {
            continue;
        };
        let mut edges = Vec::new();
        let followed = if site.form == Form::Goto {
            exits(part, analysis, origin, &facts, &mut edges)
        } else {
            cond_exits(part, origin, &facts, &mut edges)
        };
        if !followed || edges.is_empty() {
            continue;
        }
        // Follow the tests whose outcome every edge decides.
        let mut at = origin;
        for _ in 0..4 {
            if analysis.leaves.get(&at).is_none_or(|leaves| leaves.len() != 1) {
                break;
            }
            let Some(leaf) = primary_instance(root, analysis, at) else {
                break;
            };
            let Some(if_path) = test_starting_at(root, leaf, at) else {
                break;
            };
            let Some(test) = node_at(root, &if_path).and_then(|node| node.children.first()) else {
                break;
            };
            if !bare_condition(test) || !pure_condition(test) {
                break;
            }
            let mut outcome = None;
            for (_, known) in &edges {
                match (value(test, known), outcome) {
                    (Some(now), None) => outcome = Some(now),
                    (Some(now), Some(before)) if now == before => {}
                    _ => {
                        outcome = None;
                        break;
                    }
                }
            }
            let Some(then) = outcome else {
                break;
            };
            let Some(next) = taken(root, analysis, &if_path, then) else {
                break;
            };
            if next == at {
                break;
            }
            at = next;
        }
        if at == origin {
            continue;
        }
        let blocks: Vec<i64> = edges.iter().map(|(block, _)| *block).collect();
        let mut part = part.clone();
        mark(&mut part, &blocks, origin, at);
        let jump = if site.scope.follow.is(at) {
            None
        } else if site.scope.brk.as_ref().is_some_and(|flow| flow.is(at)) {
            Some(BREAK_GOTO)
        } else if site.scope.cont.as_ref().is_some_and(|flow| flow.is(at)) {
            Some(CONTINUE_GOTO)
        } else {
            // A goto to where the tests lead: its label goes on that block.
            if analysis.leaves.get(&at).is_none_or(|leaves| leaves.len() != 1) {
                continue;
            }
            let leaf_path = &analysis.leaves[&at][0];
            let Some(leaf_node) = node_at(root, leaf_path) else {
                continue;
            };
            if leaf_node.kind != kind::COPY || has_loop_ancestor_starting_at(root, leaf_path, at) {
                continue;
            }
            let Detail::Copy { label } = &leaf_node.detail else {
                continue;
            };
            let mut labelled = leaf_node.clone();
            labelled.label = Some(label.clone());
            let mut moved = jump_node.clone();
            match &mut moved.detail {
                Detail::Goto { target, .. } | Detail::If { target, .. } => {
                    *target = Some(GotoTarget {
                        block: at,
                        label: label.clone(),
                    });
                }
                _ => continue,
            }
            moved.children = vec![part];
            found.push(vec![
                Edit::Node(site.path.clone(), Box::new(moved)),
                Edit::Node(leaf_path.clone(), Box::new(labelled)),
            ]);
            continue;
        };
        let replaced = match (jump, site.form) {
            (None, Form::Goto) => part,
            // `if (c) goto L;` with the goto now where the code continues
            // anyway has nothing left to do: not a rewrite this makes.
            (None, _) => continue,
            (Some(goto_kind), _) => {
                let mut moved = jump_node.clone();
                match &mut moved.detail {
                    Detail::Goto { goto_kind: slot, .. } | Detail::If { goto_kind: slot, .. } => {
                        *slot = goto_kind;
                    }
                    _ => continue,
                }
                moved.children = vec![part];
                moved
            }
        };
        found.push(vec![Edit::Node(site.path.clone(), Box::new(replaced))]);
    }
    found
}

/// Whether a loop starts at the block of the leaf at `leaf` (a label there
/// would belong to the loop, not the leaf).
fn has_loop_ancestor_starting_at(root: &Node, leaf: &[Step], block: i64) -> bool {
    (0..leaf.len()).any(|depth| {
        node_at(root, &leaf[..depth])
            .is_some_and(|node| is_loop(node.kind) && entry(node) == Some(block))
    })
}
