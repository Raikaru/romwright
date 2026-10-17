//! Small shapes cut from real console functions where Ghidra's own
//! structuring printed gotos (the cases StructureGotos diagnosed). Each test
//! builds Ghidra's tree as the printer IR carries it, runs one model, and
//! checks the printed C and that the control flow still checks.

use super::*;
use crate::doc::decode_tokens;
use crate::printc::expr::code;
use crate::printc::ir::{
    Basic, Effect, Event, Expr, Expression, Fragment, Source, Statement, Storage,
};
use crate::printc::pretty::{BraceStyle, Space};
use romwright_model::TokenKind;

fn print_text(text: &str) -> Fragment {
    Fragment(vec![Event::Print {
        text: text.into(),
        highlight: 0,
    }])
}

fn label_fragment(block: i64) -> Fragment {
    Fragment(vec![Event::Label {
        name: format!("LAB_{block}"),
        highlight: 0,
        space: Space::Index(1),
        offset: block as u64,
    }])
}

fn target(block: i64) -> Option<GotoTarget> {
    Some(GotoTarget {
        block,
        label: label_fragment(block),
    })
}

fn expression(text: &str) -> Expression {
    Expression {
        normal: print_text(text),
        comma: Some(print_text(text)),
        source: Source::Fragments,
    }
}

fn copy(index: i64, basic: Basic, last_op: Option<u64>) -> Node {
    Node {
        kind: kind::COPY,
        index: 1000 + index,
        last_op,
        label: None,
        children: vec![Node {
            kind: kind::BASIC,
            index,
            last_op,
            label: None,
            children: Vec::new(),
            detail: Detail::Basic(basic),
        }],
        detail: Detail::Copy {
            label: label_fragment(index),
        },
    }
}

fn statements(index: i64, lines: &[&str]) -> Vec<Statement> {
    lines
        .iter()
        .enumerate()
        .map(|(position, line)| Statement {
            op: index as u64 * 10 + position as u64,
            is_branch: false,
            comment_bound: 0,
            expression: expression(line),
            effect: Default::default(),
        })
        .collect()
}

/// A block of statements flowing to `successors` (none: it returns).
fn leaf(index: i64, lines: &[&str], successors: &[i64]) -> Node {
    let last_op = Some(index as u64 * 10 + lines.len().saturating_sub(1) as u64);
    copy(
        index,
        Basic {
            comments: Vec::new(),
            statements: statements(index, lines),
            branch: None,
            successors: successors.to_vec(),
            negated: None,
            holds_loop_op: false,
            threaded: Vec::new(),
        },
        last_op,
    )
}

/// A block ending in `if (test)`: true goes to `yes`, false to `no`.
fn test(index: i64, lines: &[&str], test: &str, no: i64, yes: i64) -> Node {
    let op = index as u64 * 10 + 9;
    let mut body = statements(index, lines);
    body.push(Statement {
        op,
        is_branch: true,
        comment_bound: 0,
        expression: Expression {
            normal: print_text(&format!("({test})")),
            comma: Some(print_text(test)),
            source: Source::Fragments,
        },
        effect: Default::default(),
    });
    copy(
        index,
        Basic {
            comments: Vec::new(),
            statements: body,
            branch: Some(Expression {
                normal: print_text(&format!("({test})")),
                comma: Some(print_text(test)),
                source: Source::Fragments,
            }),
            successors: vec![no, yes],
            negated: Some(Expression {
                normal: print_text(&format!("(!{test})")),
                comma: Some(print_text(&format!("!{test}"))),
                source: Source::Fragments,
            }),
            holds_loop_op: false,
            threaded: Vec::new(),
        },
        Some(op),
    )
}

fn labelled(mut node: Node, block: i64) -> Node {
    node.label = Some(label_fragment(block));
    node
}

fn list(children: Vec<Node>) -> Node {
    Node {
        kind: kind::LIST,
        index: children[0].index,
        last_op: children.last().and_then(|child| child.last_op),
        label: None,
        detail: Detail::List {
            flow_breaks: vec![false; children.len() - 1],
        },
        children,
    }
}

fn if_goto(condition: Node, block: i64) -> Node {
    Node {
        kind: kind::IF,
        index: condition.index + 500,
        last_op: condition.last_op,
        label: None,
        detail: Detail::If {
            goto_kind: GOTO_GOTO,
            target: target(block),
        },
        children: vec![condition],
    }
}

fn if_else(condition: Node, then: Node, otherwise: Option<Node>) -> Node {
    let mut children = vec![condition, then];
    children.extend(otherwise);
    Node {
        kind: kind::IF,
        index: children[0].index + 500,
        last_op: children[0].last_op,
        label: None,
        detail: Detail::If {
            goto_kind: 0,
            target: None,
        },
        children,
    }
}

fn goto(body: Node, block: i64) -> Node {
    Node {
        kind: kind::GOTO,
        index: body.index + 700,
        last_op: body.last_op,
        label: None,
        detail: Detail::Goto {
            prints: true,
            goto_kind: GOTO_GOTO,
            target: target(block),
        },
        children: vec![body],
    }
}

fn infinite_loop(body: Node) -> Node {
    Node {
        kind: kind::INFINITE_LOOP,
        index: body.index + 900,
        last_op: body.last_op,
        label: None,
        detail: Detail::None,
        children: vec![body],
    }
}

fn do_while(body: Node) -> Node {
    Node {
        kind: kind::DO_WHILE,
        index: body.index + 900,
        last_op: body.last_op,
        label: None,
        detail: Detail::None,
        children: vec![body],
    }
}

fn function(body: Vec<Node>) -> PrinterIr {
    PrinterIr {
        max_line_size: 100,
        indent_increment: 2,
        brace_function: BraceStyle::SkipLine,
        brace_if_else: BraceStyle::SameLine,
        brace_loop: BraceStyle::SameLine,
        brace_switch: BraceStyle::SameLine,
        count_after: 0,
        header: Fragment::default(),
        declaration: print_text("void f(void)"),
        locals: Fragment::default(),
        body,
        cfg: None,
        native_tree: true,
        comment_slots: 0,
        expressions: Default::default(),
        cast_types: Vec::new(),
        call_types: Vec::new(),
        cast_edits: Vec::new(),
    }
}

fn printed(ir: &PrinterIr) -> String {
    let markup = crate::printc::print(ir).expect("prints");
    let mut out = String::new();
    for token in decode_tokens(&markup) {
        if token.kind == TokenKind::Break {
            out.push('\n');
            out.push_str(&" ".repeat(token.indent.unwrap_or(0) as usize));
        } else {
            out.push_str(&token.text);
        }
    }
    out
}

/// Runs `models`; the result must still check and print no more gotos.
fn restructured(ir: PrinterIr, models: &[Model]) -> (String, Outcome) {
    // These fixtures number their blocks freely, not in code order.
    restructured_with(ir, Settings { order_arms: false, ..Settings::new(models) })
}

fn restructured_with(mut ir: PrinterIr, settings: Settings) -> (String, Outcome) {
    let outcome = restructure(&mut ir, &settings);
    assert_eq!(outcome.refused, None, "Ghidra's tree must check");
    assert!(outcome.after.gotos <= outcome.before.gotos);
    let after = counts(&ir).expect("the rewritten tree checks");
    assert_eq!(after, outcome.after);
    (printed(&ir), outcome)
}

fn applied(outcome: &Outcome, model: Model) -> usize {
    outcome
        .applied
        .iter()
        .find(|(name, _)| *name == model)
        .map_or(0, |(_, count)| *count)
}

/// gc 0x80036140: the outer `do { ... } while (true)` ends in an if-chain
/// whose last arm `goto`s the loop's first block (LAB_800363b4).
#[test]
fn goto_to_the_loop_head_prints_continue() {
    let body = list(vec![
        leaf(1, &["c = next()"], &[2]),
        if_goto(test(2, &[], "c == 2", 3, 1), 1),
        if_goto(test(3, &["log()"], "c != 3", 4, 1), 1),
        leaf(4, &["stop()"], &[]),
    ]);
    let ir = function(vec![labelled(infinite_loop(body), 1)]);
    let (text, outcome) = restructured(ir, &[Model::BreakContinue]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (2, 0));
    assert_eq!(applied(&outcome, Model::BreakContinue), 2);
    assert!(text.contains("if (c == 2) continue;"), "{text}");
    assert!(!text.contains("LAB_1"), "the label is orphaned: {text}");
}

/// gba 0x080824fc: `case 0` jumps into the middle of `case 5`
/// (LAB_0808260c), whose tail then leaves the switch; the tail is copied
/// into `case 0` and ends in `break`.
#[test]
fn a_case_jumping_into_another_cases_tail_copies_it() {
    let head = test(0, &["s = state()"], "s", 1, 3);
    let mut head_basic = basic_of(&head).unwrap().clone();
    head_basic.successors = vec![1, 2, 3];
    let head = copy(0, head_basic, Some(9));
    let cases = vec![
        Case {
            labels: vec![print_text("case 0:")],
            exit: false,
            body: CaseBody::Child(1),
        },
        Case {
            labels: vec![print_text("case 1:")],
            exit: true,
            body: CaseBody::Child(2),
        },
        Case {
            labels: vec![print_text("case 5:")],
            exit: true,
            body: CaseBody::Child(3),
        },
    ];
    let switch = Node {
        kind: kind::SWITCH,
        index: 50,
        last_op: Some(9),
        label: None,
        detail: Detail::Switch { cases },
        children: vec![
            head,
            goto(leaf(1, &["p = base", "v = 1"], &[4]), 4),
            leaf(2, &["poll()"], &[5]),
            list(vec![
                leaf(3, &["p = base", "v = *p + 1"], &[4]),
                labelled(leaf(4, &["*p = v", "timer = 0"], &[5]), 4),
            ]),
        ],
    };
    let ir = function(vec![list(vec![switch, leaf(5, &["return 0"], &[])])]);
    let (text, outcome) = restructured(ir, &[Model::SwitchTails]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (1, 0));
    assert!(
        text.contains("v = 1;\n    *p = v;\n    timer = 0;\n    break;"),
        "{text}"
    );
    assert!(!text.contains("LAB_4"), "{text}");
}

/// ps2 dungeon 0x0011de20: deep in an if-chain, `if (lVar1 == 0) goto
/// LAB_0011e2f0;` enters the retry loop below at its second block. Ghidra's
/// entry (the loop head) is kept; the other entry gets its own copy.
#[test]
fn a_second_entry_into_a_loop_is_split_off() {
    let chain = if_else(
        test(7, &["r = load(0)"], "r == 0", 0, 6),
        leaf(6, &["code = 0x9a"], &[2]),
        Some(list(vec![
            if_goto(test(0, &["r = load(1)"], "r == 0", 1, 5), 5),
            leaf(1, &["code = 0x9b"], &[2]),
        ])),
    );
    let retry = infinite_loop(list(vec![
        leaf(2, &["report(code)"], &[5]),
        labelled(leaf(5, &["code = 0xa8"], &[2]), 5),
    ]));
    let ir = function(vec![list(vec![chain, retry])]);
    let (text, outcome) = restructured(ir, &[Model::IrreducibleEntry]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (1, 0));
    assert!(
        text.contains(
            "if (r == 0) {\n      code = 0xa8;\n    }\n    else {\n      code = 0x9b;\n    }"
        ),
        "{text}"
    );
    assert!(!text.contains("LAB_5"), "{text}");
}

/// x360 0x823570c8: `if (0x3ff < len) { ...; goto LAB_8235729c; }` jumps
/// into the other arm's tail (LAB_8235729c, LAB_823572ac), which rejoins
/// after the if; the arm takes its own copy and the rest becomes the else.
#[test]
fn a_goto_into_the_other_arm_is_split_off() {
    let ir = function(vec![list(vec![
        if_else(
            test(0, &["s = lookup()"], "s == 0", 4, 1),
            list(vec![
                labelled(leaf(1, &["warn()"], &[2]), 1),
                leaf(2, &["*out = 0"], &[3]),
            ]),
            Some(list(vec![
                if_else(
                    test(4, &["n = strlen(s)"], "0x3ff < n", 6, 5),
                    goto(leaf(5, &["report(n)"], &[1]), 1),
                    None,
                ),
                leaf(6, &["copy(s)"], &[3]),
            ])),
        ),
        leaf(3, &["done()", "return"], &[]),
    ])]);
    let (text, outcome) = restructured(ir, &[Model::IrreducibleEntry]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (1, 0));
    assert!(
        text.contains(
            "if (0x3ff < n) {\n      report(n);\n      warn();\n      *out = 0;\n    }\n    else {\n      copy(s);\n    }"
        ),
        "{text}"
    );
    assert!(!text.contains("LAB_1"), "{text}");
}

/// gc 0x8002bac0: inside the bytecode loop, a case `goto`s the shared
/// epilogue (LAB_8002c3d0: `FUN_8009af14(); return;`); the loop has no
/// other way out, so the epilogue is copied into the loop and the original
/// becomes unreachable.
#[test]
fn a_loop_exit_to_a_returning_tail_returns_in_place() {
    let body = list(vec![
        if_goto(test(1, &["op = next()"], "op == 0xc4", 2, 9), 9),
        leaf(2, &["run(op)"], &[1]),
    ]);
    let ir = function(vec![list(vec![
        if_goto(test(0, &["p = self()"], "p == 0", 3, 9), 9),
        leaf(3, &["start(p)"], &[1]),
        infinite_loop(body),
        labelled(leaf(9, &["finish()", "return"], &[]), 9),
    ])]);
    let (text, outcome) = restructured(ir.clone(), &[Model::LoopExits]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (2, 1));
    assert!(
        text.contains("if (op == 0xc4) {\n      finish();\n      return;\n    }"),
        "{text}"
    );
    // Both models together leave neither the goto nor the dead epilogue.
    let (text, outcome) = restructured(ir, &[Model::SwitchTails, Model::LoopExits]);
    assert_eq!(outcome.after.gotos, 0, "{text}");
    assert_eq!(text.matches("finish();").count(), 2, "{text}");
    assert!(!text.contains("LAB_9"), "{text}");
}

/// gc 0x80036140: `uVar4 = 0; goto LAB_80036a4c;` jumps to an epilogue that
/// is itself structured (`if (GQR0 ...) ldexpf(...); FUN_8009aef8(uVar4);
/// return;`); the copy takes the whole run of statements.
#[test]
fn a_structured_epilogue_is_copied_whole() {
    let ir = function(vec![list(vec![
        if_else(
            test(0, &["f = f + step"], "f < limit", 2, 1),
            goto(leaf(1, &["result = 0"], &[5]), 5),
            None,
        ),
        leaf(2, &["f = f - limit", "result = 1"], &[5]),
        if_else(
            labelled(test(5, &[], "gqr != 0", 7, 6), 5),
            leaf(6, &["ldexpf()"], &[7]),
            None,
        ),
        leaf(7, &["finish(result)", "return"], &[]),
    ])]);
    let (text, outcome) = restructured(ir, &[Model::SwitchTails]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (1, 0));
    assert!(
        text.contains(
            "if (f < limit) {\n    result = 0;\n    if (gqr != 0) {\n      ldexpf();\n    }\n    finish(result);\n    return;\n  }"
        ),
        "{text}"
    );
    assert!(!text.contains("LAB_5"), "{text}");
}

/// libc 0x0010a940: Ghidra folds `if (local_8c == 0) goto L;` into the
/// condition block of the next `if ((int)uVar14 != 7) goto L;` (statements
/// ahead of its test); the two tests still share one goto.
#[test]
fn a_goto_ahead_of_the_same_goto_in_a_condition_list_merges() {
    let condition = list(vec![
        leaf(3, &["n = len"], &[4]),
        if_goto(test(4, &[], "flag == 0", 5, 9), 9),
        test(5, &[], "n != 7", 6, 9),
    ]);
    let mut outer = if_goto(test(0, &[], "ready", 6, 6), 9);
    outer.children = vec![condition];
    let ir = function(vec![list(vec![
        outer,
        leaf(6, &["work()"], &[9]),
        labelled(
            leaf(
                9,
                &["a()", "b()", "c()", "d()", "e()", "f()", "return"],
                &[],
            ),
            9,
        ),
    ])]);
    let (text, outcome) = restructured(ir, &[Model::CollapsedEdges]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (2, 1));
    assert!(
        text.contains("n = len;\n  if ((flag == 0) || (n != 7)) goto LAB_9;"),
        "{text}"
    );
}

/// libc-style early exits: two tests in a row that jump to one label are
/// one collapsed edge and print one goto.
#[test]
fn adjacent_gotos_to_one_label_share_one_test() {
    let ir = function(vec![list(vec![
        if_goto(test(0, &["a = f()"], "a == 0", 1, 5), 5),
        if_goto(test(1, &[], "b != 0", 2, 5), 5),
        leaf(2, &["work()"], &[5]),
        labelled(
            leaf(
                5,
                &[
                    "x = y + z",
                    "y = 0",
                    "z = 0",
                    "w = 1",
                    "v = 2",
                    "u = 3",
                    "return",
                ],
                &[],
            ),
            5,
        ),
    ])]);
    let (text, outcome) = restructured(ir, &[Model::CollapsedEdges]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (2, 1));
    assert!(
        text.contains("if ((a == 0) || (b != 0)) goto LAB_5;"),
        "{text}"
    );
}

/// An if/else whose arms both end in `goto L` prints the goto once.
#[test]
fn arms_ending_in_one_goto_hoist_it() {
    let inner = if_else(
        test(10, &[], "b", 2, 1),
        goto(leaf(1, &["x = 1"], &[5]), 5),
        Some(goto(leaf(2, &["x = 2"], &[5]), 5)),
    );
    let ir = function(vec![list(vec![
        if_else(
            test(0, &[], "a", 6, 10),
            inner,
            Some(leaf(6, &["y()"], &[7])),
        ),
        leaf(7, &["more()"], &[5]),
        labelled(
            leaf(
                5,
                &["use(x)", "a()", "b()", "c()", "d()", "e()", "return"],
                &[],
            ),
            5,
        ),
    ])]);
    let (text, outcome) = restructured(ir, &[Model::CollapsedEdges]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (2, 1));
    assert!(
        text.contains("    else {\n      x = 2;\n    }\n    goto LAB_5;\n  }\n  else {\n    y();"),
        "{text}"
    );
}

/// A test that jumps over the next statements to a label they fall into
/// prints as the negated test around them (PrintC's own negation).
#[test]
fn a_goto_over_statements_becomes_a_negated_if() {
    let ir = function(vec![list(vec![
        if_goto(test(0, &[], "flag", 1, 3), 3),
        leaf(1, &["a()"], &[2]),
        leaf(2, &["b()"], &[3]),
        labelled(leaf(3, &["return"], &[]), 3),
    ])]);
    let (text, outcome) = restructured(ir, &[Model::IrreducibleEntry]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (1, 0));
    assert!(
        text.contains("if (!flag) {\n    a();\n    b();\n  }\n  return;"),
        "{text}"
    );
}

/// gc 0x800a4578 (a lowered switch): `if (key == 0x704) { u = 0x21; goto
/// LAB_800a4888; }` skips the rest of the compare chain, which falls into
/// the same label; the chain becomes the else arm, nothing is copied.
#[test]
fn a_goto_ending_an_arm_makes_the_skipped_code_its_else() {
    let ir = function(vec![list(vec![
        if_else(
            test(0, &[], "key == 0x704", 3, 1),
            goto(leaf(1, &["u = 0x21"], &[9]), 9),
            None,
        ),
        if_else(
            test(3, &[], "key < 0x704", 7, 4),
            leaf(4, &["u = 0x15"], &[9]),
            Some(leaf(7, &["u = 3"], &[9])),
        ),
        labelled(leaf(9, &["finish(u)", "return"], &[]), 9),
    ])]);
    let (text, outcome) = restructured(ir, &[Model::ElseJoin]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (1, 0));
    assert!(
        text.contains(
            "if (key == 0x704) {\n    u = 0x21;\n  }\n  else if (key < 0x704) {\n    u = 0x15;\n  }\n  else {\n    u = 3;\n  }\n  finish(u);"
        ),
        "{text}"
    );
    assert!(!text.contains("LAB_9"), "{text}");
}

/// x360 0x8247d8a8: both arms test `uVar6 == uVar5` and jump past the
/// call the compiler merged out of them (`FUN_82833c00(lVar3,lVar4)`,
/// cross-jumping). The call moves back into each arm, and each test
/// becomes a negated if around the rest of its arm.
#[test]
fn statements_between_an_if_and_its_jump_target_sink_into_the_arms() {
    let ir = function(vec![list(vec![
        if_else(
            test(0, &[], "high == 0", 5, 1),
            list(vec![
                if_goto(test(1, &["up = round_up(v)"], "up == v", 2, 9), 9),
                leaf(2, &["len = up - v"], &[8]),
            ]),
            Some(list(vec![
                if_goto(test(5, &["up = round_down(v)"], "up == v", 6, 9), 9),
                leaf(6, &["len = v - up"], &[8]),
            ])),
        ),
        leaf(8, &["flush(len)"], &[9]),
        labelled(leaf(9, &["store(up)", "return"], &[]), 9),
    ])]);
    // The sink alone removes no goto; the negated ifs it enables do.
    let (_, outcome) = restructured(ir.clone(), &[Model::SinkJoin]);
    assert_eq!(outcome.after.gotos, 2);
    let (text, outcome) = restructured(ir, &[Model::IrreducibleEntry, Model::SinkJoin]);
    assert_eq!(
        (outcome.before.gotos, outcome.after.gotos),
        (2, 0),
        "{text}"
    );
    assert_eq!(applied(&outcome, Model::SinkJoin), 1);
    assert_eq!(text.matches("flush(len);").count(), 2, "{text}");
    assert!(
        text.contains("if (!up == v) {\n      len = up - v;\n      flush(len);\n    }"),
        "{text}"
    );
    assert!(!text.contains("LAB_9"), "{text}");
}

/// nds 0x0204babc: inside a do-while, arms `goto LAB_0204bbd6`, the label
/// of the loop's bottom test. The test prints nothing else, so the jump is
/// `continue` even though the test carries the label.
#[test]
fn a_goto_to_a_labelled_bottom_test_prints_continue() {
    let body = list(vec![
        if_else(
            test(1, &["i = next()"], "i == n", 5, 2),
            list(vec![
                if_goto(test(2, &["found = scan()"], "found", 3, 5), 5),
                leaf(3, &["n = n + 1"], &[5]),
            ]),
            None,
        ),
        labelled(test(5, &[], "n != m", 6, 1), 5),
    ]);
    let ir = function(vec![list(vec![do_while(body), leaf(6, &["return"], &[])])]);
    let (text, outcome) = restructured(ir, &[Model::BreakContinue]);
    assert_eq!(
        (outcome.before.gotos, outcome.after.gotos),
        (1, 0),
        "{text}"
    );
    assert!(text.contains("if (found) continue;"), "{text}");
    assert!(!text.contains("LAB_5"), "{text}");
}

/// A tree whose printed flow disagrees with the block graph is not
/// rewritten at all.
#[test]
fn a_tree_that_does_not_check_is_left_alone() {
    let mut ir = function(vec![list(vec![
        if_goto(test(0, &[], "flag", 1, 3), 3),
        leaf(1, &["a()"], &[7]),
        labelled(leaf(3, &["return"], &[]), 3),
    ])]);
    let before = printed(&ir);
    let outcome = restructure(&mut ir, &Settings::new(&Model::ALL));
    assert!(outcome.refused.is_some());
    assert!(!outcome.changed());
    assert_eq!(printed(&ir), before);
}

#[test]
fn settings_parse() {
    assert_eq!(parse_settings("").unwrap(), Settings::new(&[]));
    assert_eq!(
        parse_settings("all").unwrap(),
        Settings::new(&Model::ALL)
    );
    // Models run in their fixed order, whatever order they are named in.
    assert_eq!(
        parse_settings("loop_exits, break_continue").unwrap(),
        Settings::new(&[Model::BreakContinue, Model::LoopExits])
    );
    assert_eq!(
        parse_settings("all,budget=12").unwrap(),
        Settings {
            models: Model::ALL.to_vec(),
            budget: 12,
            order_arms: true,
        }
    );
    assert!(!parse_settings("all,no_arm_order").unwrap().order_arms);
    assert!(parse_settings("tail_duplication").is_err());
    assert!(parse_settings("all,budget=x").is_err());
}

fn var(high: u32, ssa: u64) -> Expr {
    Expr::Var {
        size: 4,
        ssa,
        high,
        storage: Storage {
            class: 0,
            aliased: false,
        },
    }
}

fn constant(value: u64) -> Expr {
    Expr::Const { size: 4, value }
}

fn compare(opcode: u32, left: Expr, right: Expr) -> Expr {
    Expr::Op {
        code: opcode,
        args: vec![left, right],
    }
}

/// `node`'s branch statement carries `tree` as its condition (printed as
/// the tree unless `flip`).
fn conditioned(mut node: Node, tree: Expr, flip: bool) -> Node {
    let Some(inner) = node.children.first_mut() else {
        return node;
    };
    if let Detail::Basic(basic) = &mut inner.detail {
        for statement in &mut basic.statements {
            if statement.is_branch {
                statement.effect = Effect {
                    code: code::CBRANCH,
                    flip,
                    args: vec![tree.clone()],
                    ..Effect::default()
                };
            }
        }
    }
    node
}

/// gba 0x0816f9d4: a path that knows `v == 0` jumps straight into the arm
/// of the later `if (v < 5)`; the test is re-inserted instead (the same
/// edge is taken), so the arm needs no label and the goto goes.
#[test]
fn a_jump_past_a_test_the_path_decides_re_runs_the_test() {
    let first = conditioned(
        test(1, &[], "v == 0", 3, 2),
        compare(code::INT_EQUAL, var(1, 1), constant(0)),
        false,
    );
    let second = conditioned(
        test(4, &[], "v < 5", 7, 6),
        compare(code::INT_LESS, var(1, 9), constant(5)),
        false,
    );
    let ir = function(vec![list(vec![
        if_else(
            first,
            goto(leaf(2, &["a()"], &[6]), 6),
            Some(leaf(3, &["b()"], &[4])),
        ),
        if_else(
            second,
            labelled(leaf(6, &["c()"], &[8]), 6),
            Some(leaf(7, &["d()"], &[8])),
        ),
        leaf(8, &["e()"], &[]),
    ])]);
    let (text, outcome) = restructured(ir.clone(), &[Model::ThreadTest]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (1, 0), "{text}");
    assert!(
        text.contains("if (v == 0) {\n    a();\n  }\n  else {\n    b();\n  }\n  if (v < 5) {"),
        "{text}"
    );
    assert!(!text.contains("LAB_6"), "{text}");
    // The outcome is not decided when the tested range is wider: v < 5 does
    // not follow from v != 0.
    let undecided = conditioned(
        test(1, &[], "v != 3", 3, 2),
        compare(code::INT_NOTEQUAL, var(1, 1), constant(3)),
        false,
    );
    let ir = function(vec![list(vec![
        if_else(
            undecided,
            goto(leaf(2, &["a()"], &[6]), 6),
            Some(leaf(3, &["b()"], &[4])),
        ),
        if_else(
            conditioned(
                test(4, &[], "v < 5", 7, 6),
                compare(code::INT_LESS, var(1, 9), constant(5)),
                false,
            ),
            labelled(leaf(6, &["c()"], &[8]), 6),
            Some(leaf(7, &["d()"], &[8])),
        ),
        leaf(8, &["e()"], &[]),
    ])]);
    let (_, outcome) = restructured(ir, &[Model::ThreadTest]);
    assert_eq!(outcome.after.gotos, 1);
}

/// A statement that rewrites the tested variable between the deciding test
/// and the jump stops the reversal.
#[test]
fn a_write_to_the_tested_variable_blocks_the_threading() {
    let first = conditioned(
        test(1, &[], "v == 0", 3, 2),
        compare(code::INT_EQUAL, var(1, 1), constant(0)),
        false,
    );
    let mut writes = leaf(2, &["v = f()"], &[6]);
    if let Detail::Basic(basic) = &mut writes.children[0].detail {
        basic.statements[0].effect = Effect {
            code: 1,
            out: Some(var(1, 5)),
            ..Effect::default()
        };
    }
    let second = conditioned(
        test(4, &[], "v < 5", 7, 6),
        compare(code::INT_LESS, var(1, 9), constant(5)),
        false,
    );
    let ir = function(vec![list(vec![
        if_else(first, goto(writes, 6), Some(leaf(3, &["b()"], &[4]))),
        if_else(
            second,
            labelled(leaf(6, &["c()"], &[8]), 6),
            Some(leaf(7, &["d()"], &[8])),
        ),
        leaf(8, &["e()"], &[]),
    ])]);
    let (_, outcome) = restructured(ir, &[Model::ThreadTest]);
    assert_eq!(outcome.after.gotos, 1);
}

/// gba 0x080ba174 / 0x0804a154: cases that jump over the statement after
/// the switch (`goto L` skipping `ok = 1`) take the statement into their
/// own bodies instead, and the jumps become `break`.
#[test]
fn a_statement_after_a_switch_is_moved_into_the_cases() {
    let mut head = test(0, &["s = state()"], "s", 1, 3);
    let mut head_basic = basic_of(&head).unwrap().clone();
    head_basic.successors = vec![1, 2, 9];
    head = copy(0, head_basic, Some(9));
    let cases = vec![
        Case {
            labels: vec![print_text("case 0:")],
            exit: true,
            body: CaseBody::Child(1),
        },
        Case {
            labels: vec![print_text("case 1:")],
            exit: true,
            body: CaseBody::Child(2),
        },
        Case {
            labels: vec![print_text("default:")],
            exit: false,
            body: CaseBody::Goto {
                goto_kind: GOTO_GOTO,
                target: target(9),
            },
        },
    ];
    let switch = Node {
        kind: kind::SWITCH,
        index: 50,
        last_op: Some(9),
        label: None,
        detail: Detail::Switch { cases },
        children: vec![
            head,
            if_goto(test(1, &[], "a != b", 8, 9), 9),
            if_goto(test(2, &[], "a == b", 8, 9), 9),
        ],
    };
    let ir = function(vec![list(vec![
        switch,
        leaf(8, &["ok = 1"], &[9]),
        labelled(leaf(9, &["use(ok)", "return"], &[]), 9),
    ])]);
    let (text, outcome) = restructured(ir, &[Model::BreakContinue, Model::SinkJoin]);
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (3, 0), "{text}");
    // The default case jumped over the statement: it stays empty.
    assert_eq!(text.matches("ok = 1;").count(), 2, "{text}");
    assert!(text.contains("default:"), "{text}");
    assert!(!text.contains("LAB_9"), "{text}");
}

/// gba 0x0800d158: `if (a) { if (b) goto L; } R; L:` is `if (a && b) goto
/// L; R; L:` once the nested ifs merge, and the existing negation turns it
/// into `if (!a || !b) { R }`.
#[test]
fn nested_ifs_around_a_goto_merge_and_negate() {
    let ir = function(vec![list(vec![
        if_else(
            test(1, &[], "a", 3, 2),
            if_goto(test(2, &[], "b", 3, 4), 4),
            None,
        ),
        leaf(
            3,
            &["r1()", "r2()", "r3()", "r4()", "r5()", "r6()", "r7()", "r8()"],
            &[4],
        ),
        labelled(leaf(4, &["done()", "return"], &[]), 4),
    ])]);
    let (text, outcome) = restructured(
        ir.clone(),
        &[Model::IrreducibleEntry, Model::SinkJoin, Model::CondMerge],
    );
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (1, 0), "{text}");
    assert_eq!(text.matches("r1();").count(), 1, "{text}");
    assert!(!text.contains("LAB_4"), "{text}");
    // Without the merge the only way out is copying the long R: too dear.
    let (_, outcome) = restructured(ir, &[Model::IrreducibleEntry, Model::SinkJoin]);
    assert_eq!(outcome.after.gotos, 1);
}

/// gba 0x080cf5c4: `flag = 1; goto L;` jumps to `L: if (flag == 0) { A }`
/// past code the path must skip. The path's value of `flag` decides the
/// test, so the goto goes on to where the test leads -- past the whole
/// `if` -- and the models that follow turn the skipped code into an else.
#[test]
fn a_goto_to_a_test_the_path_decides_goes_past_it() {
    let mut assigns = leaf(2, &["flag = 1"], &[5]);
    if let Detail::Basic(basic) = &mut assigns.children[0].detail {
        basic.statements[0].effect = Effect {
            code: code::COPY,
            out: Some(var(1, 5)),
            args: vec![constant(1)],
            ..Effect::default()
        };
    }
    let test_flag = conditioned(
        test(5, &[], "flag == 0", 7, 6),
        compare(code::INT_EQUAL, var(1, 9), constant(0)),
        false,
    );
    let ir = function(vec![list(vec![
        if_else(test(1, &[], "c", 3, 2), goto(assigns, 5), None),
        leaf(3, &["x()"], &[5]),
        if_else(labelled(test_flag, 5), leaf(6, &["a()"], &[7]), None),
        leaf(7, &["b()"], &[]),
    ])]);
    let (text, outcome) = restructured(
        ir.clone(),
        &[Model::BreakContinue, Model::ElseJoin, Model::ThreadTest],
    );
    assert_eq!((outcome.before.gotos, outcome.after.gotos), (1, 0), "{text}");
    assert!(text.contains("flag = 1;"), "{text}");
    assert!(!text.contains("LAB_"), "{text}");
    // A path that does not know the flag keeps its goto.
    let mut unknown = ir;
    if let Detail::Basic(basic) = &mut unknown.body[0].children[0].children[1].children[0].children[0].detail {
        basic.statements[0].effect = Effect::default();
    }
    let (_, outcome) = restructured(
        unknown,
        &[Model::BreakContinue, Model::ElseJoin, Model::ThreadTest],
    );
    assert!(outcome.after.gotos <= 1);
}

/// `if (c) B else A` where the code lays `A` out first: Ghidra prints the
/// arms in the order of its own test normal form, the compiler wrote them
/// the other way round.
#[test]
fn an_if_else_prints_its_arms_in_code_order() {
    let ir = function(vec![list(vec![
        if_else(
            test(0, &[], "flag", 1, 2),
            leaf(2, &["b()"], &[3]),
            Some(leaf(1, &["a()"], &[3])),
        ),
        leaf(3, &["return"], &[]),
    ])]);
    let (text, outcome) = restructured_with(ir, Settings::new(&[Model::BreakContinue]));
    assert_eq!(outcome.ordered, 1);
    assert!(text.contains("if (!flag) {"), "{text}");
    assert!(text.find("a()") < text.find("b()"), "{text}");
}

#[test]
fn arms_already_in_code_order_are_left_alone() {
    let ir = function(vec![list(vec![
        if_else(
            test(0, &[], "flag", 2, 1),
            leaf(1, &["a()"], &[3]),
            Some(leaf(2, &["b()"], &[3])),
        ),
        leaf(3, &["return"], &[]),
    ])]);
    let (text, outcome) = restructured_with(ir, Settings::new(&[Model::BreakContinue]));
    assert_eq!(outcome.ordered, 0);
    assert!(text.contains("if (flag) {"), "{text}");
}

fn constant_store(index: i64, line: &str, value: u64, successors: &[i64]) -> Node {
    let mut node = leaf(index, &[line], successors);
    if let Detail::Basic(basic) = &mut node.children[0].detail {
        basic.statements[0].effect = Effect {
            code: code::COPY,
            out: Some(var(1, index as u64)),
            args: vec![constant(value)],
            ..Default::default()
        };
    }
    node
}

/// `if (c) r = 1; else r = 0;` is a merged `return`: the compiler's block
/// order says nothing about which arm the source wrote first.
#[test]
fn arms_that_only_store_constants_keep_ghidras_order() {
    let ir = function(vec![list(vec![
        if_else(
            test(0, &[], "flag", 1, 2),
            constant_store(2, "r = 0", 0, &[3]),
            Some(constant_store(1, "r = 1", 1, &[3])),
        ),
        leaf(3, &["return r"], &[]),
    ])]);
    let (text, outcome) = restructured_with(ir, Settings::new(&[Model::BreakContinue]));
    assert_eq!(outcome.ordered, 0);
    assert!(text.contains("if (flag) {"), "{text}");
}
