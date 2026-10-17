//! Match-shaped canonicalization of one emitted C function (P4.6).
//!
//! The decompiler states what the machine code computes, not how a compiler
//! was asked to produce it. Three spellings recur that no compiler's source
//! would use, and each one changes the code a matching compiler generates:
//!
//! - **Mask instead of a narrow type.** Counters and digits that the source
//!   declared `u8`/`u16` come back as a 32-bit local that every assignment
//!   masks (`i = (i + 1) & 0xffff`). The mask is the narrow type's wrap; a
//!   local whose every assignment is a mask of the same width (or a constant
//!   that fits) is that narrow type, and is declared so.
//! - **A loop guard folded over the counter's first value.** Loop inversion
//!   puts a copy of the loop test in front of the loop
//!   (`if (i < n) do { ... } while (i < n);`); the decompiler folds that copy
//!   over the counter's known first value (`if (n != 0)`), which compiles
//!   back to a test of `n` where the original compared the counter. When the
//!   guard is the loop test evaluated at that first value, the guard is
//!   written as the loop test again.
//! - **A negative constant against a `char`.** `*(char *)p == -2` is false on
//!   every target whose `char` is unsigned; comparing the same byte with `0xfe`
//!   as an `unsigned char` is the same test on every target.
//! - **A strict test against a constant is a non-strict one.** The decompiler
//!   normalises `x >= 7` to `6 < x`; MWCC compiles `6 < x` and `x > 6` to a
//!   set-less-than into the assembler temporary and `x >= 7` to one into the
//!   result register, the form a source of the original shape produces. For
//!   integers they are one test, so `K < x` is written `x >= K + 1` (a test
//!   against zero has its own branch instructions and is kept).
//!
//! Each rule is a proven equivalence, applied to the parsed function and
//! re-parsed; a rule whose result does not parse is dropped. Nothing here
//! reads a compiler, a project or a library: the input is the printed C.
use tree_sitter::{Node, Parser, Tree};

struct Edit {
    start: usize,
    end: usize,
    text: String,
}

type Rule = fn(&str, &Tree) -> Vec<Edit>;

/// The rules in the order they run, by the name `ROMWRIGHT_NO_CANONICAL` takes.
const RULES: [(&str, Rule); 7] = [
    ("char_negative_equality", char_negative_equality),
    ("fuse_mask_statements", fuse_mask_statements),
    ("narrow_locals", narrow_locals),
    ("narrow_uses", narrow_uses),
    ("guarded_loops", guarded_loops),
    ("guarded_loops", guarded_loops),
    ("strict_greater_constant", strict_greater_constant),
];

/// Rewrites `source` (one printed function definition) with every rule except
/// those `ROMWRIGHT_NO_CANONICAL` names (comma separated; `all` for none): the
/// reference a measurement compares a rule against. A rule the compiler
/// rules layer governs (`canonical-*` in `compiler_rules/common.json`) also
/// runs only when it covers `compiler` (the program's compiler id).
pub(super) fn apply(source: &str, compiler: &str) -> String {
    apply_with(source, &|name| crate::compiler::rules::canonical_enabled(name, compiler))
}

/// [`apply`] with the policy that decides which rules run given: the engines are tested
/// through this, whatever the rule files say.
fn apply_with(source: &str, enabled: &dyn Fn(&str) -> bool) -> String {
    let disabled = std::env::var("ROMWRIGHT_NO_CANONICAL").unwrap_or_default();
    if disabled.split(',').any(|name| name.trim() == "all") {
        return source.to_string();
    }
    let mut parser = Parser::new();
    if parser.set_language(&tree_sitter_c::LANGUAGE.into()).is_err() {
        return source.to_string();
    }
    let mut text = source.to_string();
    for (name, rule) in RULES {
        if disabled.split(',').any(|off| off.trim() == name) || !enabled(name) {
            continue;
        }
        let Some(tree) = parser.parse(&text, None) else {
            return text;
        };
        if tree.root_node().has_error() {
            return text;
        }
        let mut edits = rule(&text, &tree);
        if edits.is_empty() {
            continue;
        }
        edits.sort_by_key(|edit| (edit.start, edit.end));
        let mut kept: Vec<Edit> = Vec::new();
        for edit in edits {
            if kept.last().is_some_and(|last| edit.start < last.end) {
                continue;
            }
            kept.push(edit);
        }
        let mut next = text.clone();
        for edit in kept.iter().rev() {
            next.replace_range(edit.start..edit.end, &edit.text);
        }
        if parser
            .parse(&next, None)
            .is_some_and(|tree| !tree.root_node().has_error())
        {
            text = next;
        }
    }
    text
}

fn text_of<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn strip_parens(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let mut cursor = node.walk();
        let Some(inner) = node.named_children(&mut cursor).find(|n| n.kind() != "comment") else {
            break;
        };
        node = inner;
    }
    node
}

/// Parentheses and value-preserving integer casts around an operand.
fn strip_casts<'t>(mut node: Node<'t>, source: &str) -> Node<'t> {
    loop {
        node = strip_parens(node);
        if node.kind() != "cast_expression" {
            return node;
        }
        let Some(value) = node.child_by_field_name("value") else {
            return node;
        };
        let Some(kind) = node.child_by_field_name("type") else {
            return node;
        };
        if !matches!(
            squash(text_of(kind, source)).as_str(),
            "int" | "unsigned int" | "unsigned" | "uint" | "unsigned short" | "unsigned char"
        ) {
            return node;
        }
        node = value;
    }
}

fn literal(node: Node<'_>, source: &str) -> Option<u64> {
    let node = strip_parens(node);
    if node.kind() != "number_literal" {
        return None;
    }
    literal_text(text_of(node, source))
}

fn literal_text(text: &str) -> Option<u64> {
    let text = text.trim_end_matches(['u', 'U', 'l', 'L']);
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// `-N` as the grammar spells it: a signed literal or a unary minus.
fn negative_literal(node: Node<'_>, source: &str) -> Option<u64> {
    let node = strip_parens(node);
    match node.kind() {
        "number_literal" => text_of(node, source)
            .strip_prefix('-')
            .and_then(literal_text),
        "unary_expression" if operator(node, source) == Some("-") => {
            node.child_by_field_name("argument").and_then(|argument| literal(argument, source))
        }
        _ => None,
    }
}

fn operator<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    node.child_by_field_name("operator")
        .map(|operator| text_of(operator, source))
}

fn visit<'t>(node: Node<'t>, found: &mut dyn FnMut(Node<'t>)) {
    found(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit(child, found);
    }
}

fn function_body<'t>(tree: &'t Tree) -> Option<Node<'t>> {
    let root = tree.root_node();
    let mut cursor = root.walk();
    let function = root
        .named_children(&mut cursor)
        .find(|node| node.kind() == "function_definition")?;
    function.child_by_field_name("body")
}

fn statements<'t>(block: Node<'t>) -> Vec<Node<'t>> {
    let mut cursor = block.walk();
    block
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "comment")
        .collect()
}

/// `v = RHS;` -> (v, RHS).
fn simple_assignment<'t, 's>(statement: Node<'t>, source: &'s str) -> Option<(&'s str, Node<'t>)> {
    if statement.kind() != "expression_statement" {
        return None;
    }
    let mut cursor = statement.walk();
    let expression = statement.named_children(&mut cursor).next()?;
    if expression.kind() != "assignment_expression" || operator(expression, source) != Some("=") {
        return None;
    }
    let left = expression.child_by_field_name("left")?;
    let right = expression.child_by_field_name("right")?;
    if left.kind() != "identifier" {
        return None;
    }
    Some((left.utf8_text(source.as_bytes()).ok()?, right))
}

// ---------------------------------------------------------------------------
// Rule: a `char` equal to a negative constant
// ---------------------------------------------------------------------------

fn char_negative_equality(source: &str, tree: &Tree) -> Vec<Edit> {
    let mut edits = Vec::new();
    visit(tree.root_node(), &mut |node| {
        if node.kind() != "binary_expression" || !matches!(operator(node, source), Some("==" | "!=")) {
            return;
        }
        let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else {
            return;
        };
        for (value, constant) in [(left, right), (right, left)] {
            let Some(magnitude) = negative_literal(constant, source).filter(|magnitude| (1..=128).contains(magnitude)) else {
                continue;
            };
            let value = strip_parens(value);
            if value.kind() != "pointer_expression" || operator(value, source) != Some("*") {
                continue;
            }
            let Some(cast) = value.child_by_field_name("argument").map(strip_parens) else {
                continue;
            };
            if cast.kind() != "cast_expression" {
                continue;
            }
            let Some(kind) = cast.child_by_field_name("type") else { continue };
            if squash(text_of(kind, source)) != "char *" {
                continue;
            }
            edits.push(Edit {
                start: kind.start_byte(),
                end: kind.end_byte(),
                text: "unsigned char *".into(),
            });
            edits.push(Edit {
                start: constant.start_byte(),
                end: constant.end_byte(),
                text: format!("{:#x}", 256 - magnitude),
            });
            return;
        }
    });
    edits
}

// ---------------------------------------------------------------------------
// Rule: `K < x` is `x >= K + 1`
// ---------------------------------------------------------------------------

/// The literal `K + 1` for a positive integer literal `K` (`6`, `0xb`, `4U`),
/// spelled in `K`'s base and suffix; `None` for zero (a test against zero has
/// its own branch instructions), for anything else, and when `K + 1` does not
/// fit the 32-bit operand the comparison is made in.
fn successor(node: Node<'_>, source: &str) -> Option<String> {
    let node = strip_parens(node);
    if node.kind() != "number_literal" {
        return None;
    }
    let text = text_of(node, source);
    let digits = text.trim_end_matches(['u', 'U', 'l', 'L']);
    let suffix = &text[digits.len()..];
    let hex = digits.starts_with("0x") || digits.starts_with("0X");
    if !hex && digits.contains(['.', 'e', 'E', '-']) {
        return None;
    }
    let value = literal_text(digits)?;
    if value == 0 || value >= 0x7fff_ffff {
        return None;
    }
    Some(if hex { format!("{:#x}{suffix}", value + 1) } else { format!("{}{suffix}", value + 1) })
}

fn strict_greater_constant(source: &str, tree: &Tree) -> Vec<Edit> {
    let mut edits = Vec::new();
    visit(tree.root_node(), &mut |node| {
        if node.kind() != "binary_expression" {
            return;
        }
        let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else {
            return;
        };
        let (value, constant) = match operator(node, source) {
            Some("<") => (right, left),
            Some(">") => (left, right),
            _ => return,
        };
        if matches!(strip_parens(value).kind(), "number_literal") {
            return;
        }
        let Some(next) = successor(constant, source) else { return };
        edits.push(Edit {
            start: node.start_byte(),
            end: node.end_byte(),
            text: format!("{} >= {next}", text_of(value, source)),
        });
    });
    edits
}

// ---------------------------------------------------------------------------
// Rule: `v = E; v = v & M;` is `v = E & M;`
// ---------------------------------------------------------------------------

const MASKS: [u64; 2] = [0xff, 0xffff];

/// `X & M` with `M` a byte/halfword mask -> (X, M).
fn masked<'t>(expression: Node<'t>, source: &str) -> Option<(Node<'t>, u64)> {
    let expression = strip_parens(expression);
    if expression.kind() != "binary_expression" || operator(expression, source) != Some("&") {
        return None;
    }
    let left = expression.child_by_field_name("left")?;
    let right = expression.child_by_field_name("right")?;
    for (operand, mask) in [(left, right), (right, left)] {
        if let Some(mask) = literal(mask, source).filter(|mask| MASKS.contains(mask)) {
            return Some((operand, mask));
        }
    }
    None
}

fn needs_parens(node: Node<'_>) -> bool {
    !matches!(
        node.kind(),
        "identifier"
            | "number_literal"
            | "parenthesized_expression"
            | "call_expression"
            | "subscript_expression"
            | "field_expression"
    )
}

fn fuse_mask_statements(source: &str, tree: &Tree) -> Vec<Edit> {
    let mut edits = Vec::new();
    visit(tree.root_node(), &mut |node| {
        if node.kind() != "compound_statement" {
            return;
        }
        let list = statements(node);
        for pair in list.windows(2) {
            let [first, second] = pair else { continue };
            if second.prev_named_sibling() != Some(*first) {
                continue;
            }
            let (Some((name, value)), Some((again, mask_expression))) =
                (simple_assignment(*first, source), simple_assignment(*second, source))
            else {
                continue;
            };
            if name != again {
                continue;
            }
            let Some((operand, mask)) = masked(mask_expression, source) else {
                continue;
            };
            let operand = strip_parens(operand);
            if operand.kind() != "identifier" || text_of(operand, source) != name {
                continue;
            }
            let already = masked(value, source).is_some();
            let value_text = text_of(value, source);
            let joined = if already {
                value_text.to_string()
            } else if needs_parens(value) {
                format!("({value_text}) & {mask:#x}")
            } else {
                format!("{value_text} & {mask:#x}")
            };
            edits.push(Edit { start: value.start_byte(), end: value.end_byte(), text: joined });
            edits.push(Edit { start: first.end_byte(), end: second.end_byte(), text: String::new() });
        }
    });
    edits
}

// ---------------------------------------------------------------------------
// Rule: a local every assignment of which masks is the narrow type
// ---------------------------------------------------------------------------

struct Local<'t> {
    kind: Node<'t>,
    name: &'t str,
}

/// Plain `int x;` / `unsigned int x;` declarations directly in the body.
fn plain_locals<'t>(body: Node<'t>, source: &'t str) -> Vec<Local<'t>> {
    let mut locals = Vec::new();
    for statement in statements(body) {
        if statement.kind() != "declaration" {
            continue;
        }
        let Some(kind) = statement.child_by_field_name("type") else { continue };
        let mut cursor = statement.walk();
        let declarators: Vec<_> = statement.children_by_field_name("declarator", &mut cursor).collect();
        let [declarator] = declarators.as_slice() else { continue };
        if declarator.kind() != "identifier" {
            continue;
        }
        // Only the type specifier itself: no storage class, qualifier or attribute.
        let mut cursor = statement.walk();
        if statement
            .named_children(&mut cursor)
            .any(|child| !matches!(child.kind(), "identifier" | "primitive_type" | "sized_type_specifier") && child != kind)
        {
            continue;
        }
        let name = declarator.utf8_text(source.as_bytes()).unwrap_or("");
        locals.push(Local { kind, name });
    }
    locals
}

/// How a local is assigned; `None` means it is used in a way the rule
/// cannot prove (address taken, compound assignment, `++`).
struct Assignments<'t> {
    masked: Vec<(Node<'t>, u64)>,
    fitting: Vec<(Node<'t>, u64)>,
    other: usize,
}

fn assignments<'t>(body: Node<'t>, source: &str, name: &str) -> Option<Assignments<'t>> {
    let mut result = Assignments { masked: Vec::new(), fitting: Vec::new(), other: 0 };
    let mut sound = true;
    visit(body, &mut |node| {
        if node.kind() != "identifier" || text_of(node, source) != name {
            return;
        }
        let Some(parent) = node.parent() else { return };
        match parent.kind() {
            "assignment_expression" if parent.child_by_field_name("left") == Some(node) => {
                if operator(parent, source) != Some("=") {
                    sound = false;
                    return;
                }
                let Some(right) = parent.child_by_field_name("right") else { return };
                if let Some((_, mask)) = masked(right, source) {
                    result.masked.push((right, mask));
                } else if let Some(value) = literal(right, source) {
                    result.fitting.push((right, value));
                } else {
                    result.other += 1;
                }
            }
            "update_expression" => sound = false,
            "pointer_expression" if operator(parent, source) == Some("&") => sound = false,
            _ => {}
        }
    });
    sound.then_some(result)
}

fn narrow_locals(source: &str, tree: &Tree) -> Vec<Edit> {
    let Some(body) = function_body(tree) else { return Vec::new() };
    let mut edits = Vec::new();
    for local in plain_locals(body, source) {
        if !matches!(squash(text_of(local.kind, source)).as_str(), "int" | "unsigned int") {
            continue;
        }
        let Some(found) = assignments(body, source, local.name) else { continue };
        let Some(&(_, mask)) = found.masked.first() else { continue };
        if found.other != 0
            || found.masked.iter().any(|(_, other)| *other != mask)
            || found.fitting.iter().any(|(_, value)| *value > mask)
        {
            continue;
        }
        let narrow = if mask == 0xff { "unsigned char" } else { "unsigned short" };
        edits.push(Edit { start: local.kind.start_byte(), end: local.kind.end_byte(), text: narrow.into() });
        for (right, _) in &found.masked {
            let Some((operand, _)) = masked(*right, source) else { continue };
            let operand = strip_parens(operand);
            edits.push(Edit {
                start: right.start_byte(),
                end: right.end_byte(),
                text: text_of(operand, source).to_string(),
            });
        }
    }
    edits
}

/// Uses of an already-narrow local that the narrow type makes redundant.
fn narrow_uses(source: &str, tree: &Tree) -> Vec<Edit> {
    let Some(body) = function_body(tree) else { return Vec::new() };
    let mut edits = Vec::new();
    for local in plain_locals(body, source) {
        let (type_text, mask) = match squash(text_of(local.kind, source)).as_str() {
            "unsigned char" => ("unsigned char", 0xffu64),
            "unsigned short" => ("unsigned short", 0xffff),
            _ => continue,
        };
        visit(body, &mut |node| {
            if node.kind() == "binary_expression" && operator(node, source) == Some("&") {
                let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else {
                    return;
                };
                for (variable, constant) in [(left, right), (right, left)] {
                    let variable = strip_parens(variable);
                    if variable.kind() == "identifier"
                        && text_of(variable, source) == local.name
                        && literal(constant, source).is_some_and(|value| value >= mask && value & mask == mask && (value + 1).is_power_of_two())
                    {
                        edits.push(Edit { start: node.start_byte(), end: node.end_byte(), text: local.name.to_string() });
                        return;
                    }
                }
            } else if node.kind() == "cast_expression" {
                let (Some(kind), Some(value)) = (node.child_by_field_name("type"), node.child_by_field_name("value")) else {
                    return;
                };
                let value = strip_parens(value);
                if squash(text_of(kind, source)) == type_text
                    && value.kind() == "identifier"
                    && text_of(value, source) == local.name
                {
                    edits.push(Edit { start: node.start_byte(), end: node.end_byte(), text: local.name.to_string() });
                }
            }
        });
    }
    edits
}

// ---------------------------------------------------------------------------
// Rule: a guard that is the loop test at the counter's first value
// ---------------------------------------------------------------------------

fn pure(node: Node<'_>) -> bool {
    let mut pure = true;
    visit(node, &mut |inner| {
        if matches!(inner.kind(), "call_expression" | "assignment_expression" | "update_expression") {
            pure = false;
        }
    });
    pure
}

fn normal(node: Node<'_>, source: &str) -> String {
    squash(text_of(strip_casts(node, source), source))
}

/// Whether `guard` is `condition` with `variable` replaced by `initial`:
/// `initial < x` for `variable < x`, `x > initial` for `x > variable`,
/// and `x != 0` for an unsigned `variable < x` from zero.
fn guard_is_entry_test(guard: Node<'_>, condition: Node<'_>, variable: &str, initial: u64, source: &str) -> bool {
    let guard = strip_parens(guard);
    let condition = strip_parens(condition);
    if guard.kind() != "binary_expression" || condition.kind() != "binary_expression" {
        return false;
    }
    let (Some(g_left), Some(g_right), Some(c_left), Some(c_right)) = (
        guard.child_by_field_name("left"),
        guard.child_by_field_name("right"),
        condition.child_by_field_name("left"),
        condition.child_by_field_name("right"),
    ) else {
        return false;
    };
    let (Some(g_op), Some(c_op)) = (operator(guard, source), operator(condition, source)) else {
        return false;
    };
    let is_variable = |node: Node<'_>| {
        let node = strip_casts(node, source);
        node.kind() == "identifier" && text_of(node, source) == variable
    };
    let bound = match c_op {
        "<" if is_variable(c_left) => c_right,
        ">" if is_variable(c_right) => c_left,
        _ => return false,
    };
    if !pure(bound) || normal(bound, source).contains(variable) {
        return false;
    }
    let bound_text = normal(bound, source);
    let same = |a: Node<'_>, b_text: &str| normal(a, source) == b_text;
    // `initial < x` / `x > initial`, as the condition says it.
    if (g_op == "<" && literal(g_left, source) == Some(initial) && same(g_right, &bound_text))
        || (g_op == ">" && literal(g_right, source) == Some(initial) && same(g_left, &bound_text))
    {
        return true;
    }
    // Unsigned `0 < x` is `x != 0`, which is how the decompiler prints it.
    initial == 0
        && g_op == "!="
        && ((literal(g_right, source) == Some(0) && same(g_left, &bound_text))
            || (literal(g_left, source) == Some(0) && same(g_right, &bound_text)))
        && !text_of(condition, source).contains("(int)")
}

fn single_do<'t>(statement: Node<'t>) -> Option<Node<'t>> {
    if statement.kind() != "if_statement" || statement.child_by_field_name("alternative").is_some() {
        return None;
    }
    let consequence = statement.child_by_field_name("consequence")?;
    let inner = if consequence.kind() == "compound_statement" {
        let list = statements(consequence);
        let [only] = list.as_slice() else { return None };
        *only
    } else {
        consequence
    };
    (inner.kind() == "do_statement").then_some(inner)
}

fn guarded_loops(source: &str, tree: &Tree) -> Vec<Edit> {
    let mut edits = Vec::new();
    let mut taken: Vec<(usize, usize)> = Vec::new();
    visit(tree.root_node(), &mut |block| {
        if block.kind() != "compound_statement" {
            return;
        }
        let list = statements(block);
        for (index, statement) in list.iter().enumerate() {
            let Some(do_statement) = single_do(*statement) else { continue };
            if taken.iter().any(|(start, end)| statement.start_byte() < *end && *start < statement.end_byte()) {
                continue;
            }
            let (Some(guard), Some(condition), Some(loop_body)) = (
                statement.child_by_field_name("condition"),
                do_statement.child_by_field_name("condition"),
                do_statement.child_by_field_name("body"),
            ) else {
                continue;
            };
            if loop_body.kind() != "compound_statement" {
                continue;
            }
            // Constant initializers directly before the guard.
            let mut initial: Vec<(usize, &str, u64)> = Vec::new();
            for back in (0..index).rev() {
                match simple_assignment(list[back], source) {
                    Some((name, value)) if literal(value, source).is_some() => {
                        initial.push((back, name, literal(value, source).unwrap()));
                    }
                    _ => break,
                }
            }
            let matched = initial.iter().any(|(position, name, value)| {
                guard_is_entry_test(guard, condition, name, *value, source)
                    && !initial.iter().any(|(other, other_name, _)| other > position && other_name == name)
            });
            if !matched {
                continue;
            }
            // The guard becomes the loop's own test, over the counter instead of its
            // first value: the shape a compiler's loop inversion produces and the
            // one that compiles back to it (`if (n != 0)` compares `n`, this
            // compares the counter register, as the original loop test did).
            let guard = strip_parens(guard);
            let (start, replacement) = (guard.start_byte(), text_of(strip_parens(condition), source).to_string());
            taken.push((statement.start_byte(), statement.end_byte()));
            edits.push(Edit { start, end: guard.end_byte(), text: replacement });
        }
    });
    edits
}

#[cfg(test)]
mod tests {
    use super::apply_with;

    #[test]
    fn a_counter_that_masks_every_assignment_is_the_narrow_type() {
        let source = "unsigned short f(const unsigned char * s)\n{\n  unsigned int n;\n  n = 0;\n  while (s[n] != 0xff) {\n    n = (n + 1) & 0xffff;\n  }\n  return (unsigned short)n;\n}\n";
        let out = apply_with(source, &|_| true);
        assert!(out.contains("unsigned short n;"), "{out}");
        assert!(out.contains("n = n + 1;"), "{out}");
        assert!(out.contains("return n;"), "{out}");
    }

    #[test]
    fn a_local_with_an_unmasked_assignment_keeps_its_type() {
        let source = "int f(int a)\n{\n  unsigned int n;\n  n = a;\n  n = (n + 1) & 0xff;\n  return n;\n}\n";
        let out = apply_with(source, &|_| true);
        assert!(out.contains("unsigned int n;"), "{out}");
    }

    #[test]
    fn an_assignment_masked_on_the_next_statement_is_one_masked_assignment() {
        let source = "int f(int a, int b)\n{\n  unsigned int d;\n  d = g(a, b);\n  d = d & 0xffff;\n  return d;\n}\n";
        let out = apply_with(source, &|_| true);
        assert!(out.contains("unsigned short d;"), "{out}");
        assert!(out.contains("d = g(a, b);"), "{out}");
    }

    #[test]
    fn a_guard_that_is_the_entry_test_becomes_the_loop_test() {
        let source = "void f(char * d, const char * s, unsigned int n)\n{\n  unsigned int i;\n  i = 0;\n  if (n != 0) {\n    do {\n      d[i] = s[i];\n      i = i + 1;\n    } while (i < n);\n  }\n  return;\n}\n";
        let out = apply_with(source, &|_| true);
        assert!(out.contains("if (i < n) {\n    do {\n      d[i] = s[i];\n      i = i + 1;\n    } while (i < n);"), "{out}");
        assert!(!out.contains("if (n != 0)"), "{out}");
    }

    #[test]
    fn a_signed_guard_is_the_loop_test_at_the_first_value() {
        let source = "void f(char * d, int n)\n{\n  unsigned int i;\n  i = 0;\n  if (0 < n) {\n    do {\n      d[i] = 0;\n      if (d[i] == 3) {\n        break;\n      }\n      i = i + 1;\n    } while ((int)i < n);\n  }\n}\n";
        let out = apply_with(source, &|_| true);
        assert!(out.contains("if ((int)i < n) {"), "{out}");
        assert!(!out.contains("if (0 < n)"), "{out}");
    }

    #[test]
    fn a_guard_that_is_not_the_entry_test_is_kept() {
        let source = "void f(char * d, unsigned int n, unsigned int m)\n{\n  unsigned int i;\n  i = 0;\n  if (m != 0) {\n    do {\n      d[i] = 0;\n      i = i + 1;\n    } while (i < n);\n  }\n}\n";
        assert_eq!(apply_with(source, &|_| true), source);
    }

    #[test]
    fn a_strict_test_against_a_constant_is_a_non_strict_one() {
        let source = "int f(int a, unsigned int b)\n{\n  if (6 < a + 1) {\n    return 1;\n  }\n  if (0xb < b) {\n    return 2;\n  }\n  if (b > 4U) {\n    return 3;\n  }\n  return 0;\n}\n";
        let out = apply_with(source, &|_| true);
        assert!(out.contains("if (a + 1 >= 7) {"), "{out}");
        assert!(out.contains("if (b >= 0xc) {"), "{out}");
        assert!(out.contains("if (b >= 5U) {"), "{out}");
    }

    #[test]
    fn a_comparison_of_two_constants_or_without_a_constant_is_kept() {
        let source = "int f(int a, int b)\n{\n  if (a < b) {\n    return 1;\n  }\n  if (3 < 4) {\n    return 2;\n  }\n  if (a < 0x7fffffff) {\n    return 4;\n  }\n  if (0 < a) {\n    return 5;\n  }\n  if (-1 < a) {\n    return 6;\n  }\n  return 0;\n}\n";
        assert_eq!(apply_with(source, &|_| true), source);
    }

    #[test]
    fn a_char_compared_with_a_negative_constant_is_an_unsigned_byte() {
        let source = "int f(int p)\n{\n  if (*(char *)(p + 5) == -2) {\n    return 1;\n  }\n  return 0;\n}\n";
        let out = apply_with(source, &|_| true);
        assert!(out.contains("*(unsigned char *)(p + 5) == 0xfe"), "{out}");
    }
}
