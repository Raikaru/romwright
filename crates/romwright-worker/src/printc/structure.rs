//! Structuring passes over the printer IR (default: every model;
//! `ROMWRIGHT_RUST_STRUCTURING` selects models or `none` for ablation).
//!
//! Each pass rewrites the structured block tree `ghidra_opt` exported
//! (Ghidra's own structuring, after `ActionFinalStructure`) to print fewer
//! `goto`s, then the Rust printer prints the result. Ghidra's tree is the
//! starting point, so its loop, `for`, `&&`/`||` and switch recovery are kept
//! and a pass only has to remove what Ghidra left unstructured.
//!
//! Every rewrite is checked before it is kept:
//!
//! * **Control flow.** [`Analysis`] interprets the printed tree -- where C
//!   control goes after every printed basic block on every edge, including
//!   `break`, `continue`, fallthrough between cases and loop back edges --
//!   and compares it with the basic-block graph's out-edges. A function whose
//!   original tree does not check out is left untouched; a rewrite whose
//!   result does not check out is undone.
//! * **Gotos.** A rewrite is kept only when it strictly lowers the printed
//!   `goto` count, so no function ever prints more gotos than PrintC's own
//!   structure of the same Funcdata.
//! * **Size.** A rewrite may add at most `budget` printed lines ([`size`])
//!   per goto it removes (`budget=N`, default [`DEFAULT_BUDGET`]): the cost
//!   model every copy goes through.
//!
//! Models (comma-separated in `ROMWRIGHT_RUST_STRUCTURING`, or `all`, the
//! default; they always run in the order below):
//!
//! * `break_continue` -- a `goto` to the innermost loop's continue point
//!   prints `continue` (Ghidra never emits one), a `goto` to the innermost
//!   loop or switch exit prints `break`, and a `goto` to the block that
//!   follows anyway is dropped.
//! * `collapsed_edges` -- one goto per collapsed edge: `if (a) goto L;
//!   if (b) goto L;` becomes `if (a || b) goto L;`, an if/else whose arms
//!   both end in `goto L` prints it once after the if, and switch cases that
//!   jump to the same block share one `goto`.
//! * `else_join` -- `if (c) { A; goto L; } R; L:` becomes `if (c) { A }
//!   else { R }` (also for a goto ending the else arm); nothing is copied.
//! * `thread_test` -- jump threading, undone (structure/thread.rs): a
//!   `goto` to the arm of an `if` whose test the conditions on the jump
//!   decide re-runs that test instead (`goto L` falls out, `break`s or
//!   `continue`s into it), and a `goto` to a test whose outcome the jump
//!   decides goes on to where that outcome leads. Conditions are compared
//!   as expression trees (printc/expr.rs); nothing is copied.
//! * `switch_tails` -- a `goto` to a shared tail (an if-chain's or a
//!   switch's common code, or a return epilogue) that does not leave a loop
//!   is replaced by a copy of the tail, when the copy ends where the goto's
//!   own position falls through to, where the enclosing `break`/`continue`
//!   goes (that statement then ends the copy), or returns.
//! * `loop_exits` -- the same for a `goto` that leaves a loop (a loop with
//!   several exits): the exit returns or breaks in place.
//! * `irreducible_entry` -- a second entry into a region keeps Ghidra's
//!   choice of primary entry and splits the other one: `if (c) goto L; R`
//!   and `if (c) { A; goto L; } R` become if/else with a copy of L's tail
//!   when both end at the same place, and `if (c) goto L; R; L:` becomes
//!   `if (!c) { R }` (PrintC's own negation of the condition).
//! * `sink_join` -- `if (c) { ... goto L ... } M; L:` moves M into every arm
//!   that falls through to it, after which the goto ends its arm and the
//!   models above remove it (reverting cross-jumping and jump threading by
//!   duplication); also for a switch: its cases that reach the end take M
//!   and `case n: goto L` becomes an empty case. Kept only when those
//!   follow-ups remove gotos within the budget.
//! * `cond_merge` -- `if (a) { if (b) goto L; } R; L:` is `if (a && b) goto
//!   L; R; L:` once the nested ifs merge, which `irreducible_entry` negates
//!   without copying R; kept only when those follow-ups remove a goto.
//!
//! Tails follow single out-edges of plain blocks, or the target's run of
//! statements in its list; they never include a loop, a switch, a jump or a
//! block holding a `for` initializer or iterator (those print in the loop
//! header). Ghidra's nested lists are flattened first and the statements it
//! collapsed into an if's condition block move in front of the `if` (the
//! same C); labels the rewrites orphaned are dropped, and so is code they
//! made unreachable.

use std::collections::{BTreeMap, HashMap};

use super::ir::{Basic, Case, CaseBody, Detail, Event, Expr, GotoTarget, Node, PrinterIr, kind};

// FlowBlock goto types.
pub const GOTO_GOTO: u64 = 1;
pub const BREAK_GOTO: u64 = 2;
pub const CONTINUE_GOTO: u64 = 4;

/// How much one copied tail may hold.
#[derive(Clone, Copy, Debug)]
struct Limits {
    /// Non-branch statements.
    statements: usize,
    /// Basic blocks.
    blocks: usize,
}

/// The tails the remaining-goto classification measures.
const MEASURE: Limits = Limits {
    statements: 64,
    blocks: 32,
};
/// Rewrite attempts per function, a bound on pathological trees.
const ATTEMPTS: usize = 4000;
/// Printed lines a rewrite may add per goto it removes (`budget=N`).
/// 4 was the largest budget at which neither the console samples nor the
/// whole structuring gate set printed more lines than the former fixed tail
/// bound (6 statements, 3 blocks); 5 is the smallest that also removes the
/// last goto the pokeemerald samples print that its C source does not have
/// (party_menu.c DisplaySelectionWindow: a struct copy shared by three
/// cases), at +35 console lines (docs/structuring-baseline.md, "Fake-match
/// metric").
pub const DEFAULT_BUDGET: usize = 5;
/// How many [`Model::SinkJoin`] moves one rewrite may chain before the
/// follow-up rewrites must have removed a goto.
const SINK_DEPTH: usize = 3;
/// Follow-up rewrites after one sink.
const FOLLOW_UPS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Model {
    BreakContinue,
    CollapsedEdges,
    ElseJoin,
    ThreadTest,
    SwitchTails,
    LoopExits,
    IrreducibleEntry,
    SinkJoin,
    CondMerge,
}

impl Model {
    /// Every model, in the order they run.
    pub const ALL: [Model; 9] = [
        Model::BreakContinue,
        Model::CollapsedEdges,
        Model::ElseJoin,
        Model::ThreadTest,
        Model::SwitchTails,
        Model::LoopExits,
        Model::IrreducibleEntry,
        Model::SinkJoin,
        Model::CondMerge,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Model::BreakContinue => "break_continue",
            Model::CollapsedEdges => "collapsed_edges",
            Model::ElseJoin => "else_join",
            Model::ThreadTest => "thread_test",
            Model::SwitchTails => "switch_tails",
            Model::LoopExits => "loop_exits",
            Model::IrreducibleEntry => "irreducible_entry",
            Model::SinkJoin => "sink_join",
            Model::CondMerge => "cond_merge",
        }
    }

    pub fn parse(name: &str) -> Option<Model> {
        Model::ALL.into_iter().find(|model| model.name() == name)
    }
}

/// What `ROMWRIGHT_RUST_STRUCTURING` asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub models: Vec<Model>,
    /// Printed lines a rewrite may add per goto it removes.
    pub budget: usize,
    /// Print `if`/`else` arms in code order ([`order_arms`]); `no_arm_order`
    /// turns it off.
    pub order_arms: bool,
}

impl Settings {
    pub fn new(models: &[Model]) -> Settings {
        Settings {
            models: models.to_vec(),
            budget: DEFAULT_BUDGET,
            order_arms: true,
        }
    }
}

/// The settings `ROMWRIGHT_RUST_STRUCTURING` names; every model, budget
/// [`DEFAULT_BUDGET`], when unset.
pub fn settings_from_env() -> Result<Settings, String> {
    match std::env::var("ROMWRIGHT_RUST_STRUCTURING") {
        Ok(value) => parse_settings(&value),
        Err(std::env::VarError::NotPresent) => Ok(Settings::new(&Model::ALL)),
        Err(error) => Err(format!("ROMWRIGHT_RUST_STRUCTURING: {error}")),
    }
}

/// A comma-separated list of `all` (every model), model names,
/// `budget=N` and `no_arm_order`; empty/`0`/`none` for no passes.
pub fn parse_settings(value: &str) -> Result<Settings, String> {
    let mut settings = Settings::new(&[]);
    let value = value.trim();
    if value.is_empty() || value == "0" || value == "none" {
        return Ok(settings);
    }
    for name in value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        if name == "no_arm_order" {
            settings.order_arms = false;
            continue;
        }
        if let Some(budget) = name.strip_prefix("budget=") {
            settings.budget = budget
                .parse()
                .map_err(|_| format!("structuring budget `{budget}` is not a line count"))?;
            continue;
        }
        let models = if name == "all" || name == "1" {
            Model::ALL.to_vec()
        } else {
            vec![Model::parse(name).ok_or_else(|| {
                let known: Vec<_> = Model::ALL.iter().map(|model| model.name()).collect();
                format!(
                    "unknown structuring model `{name}` (expected all, budget=N or {})",
                    known.join(", ")
                )
            })?]
        };
        for model in models {
            if !settings.models.contains(&model) {
                settings.models.push(model);
            }
        }
    }
    // Models run in one fixed order, whatever order they were named in.
    settings
        .models
        .sort_by_key(|model| Model::ALL.iter().position(|known| known == model));
    Ok(settings)
}

/// Printed gotos and labels of a tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub gotos: usize,
    pub labels: usize,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub before: Counts,
    pub after: Counts,
    /// Rewrites kept, per model.
    pub applied: Vec<(Model, usize)>,
    /// Why the original tree was left alone (its control flow did not check).
    pub refused: Option<String>,
    /// Printed gotos left after the models, by [`classify`] cause.
    pub remaining: BTreeMap<String, usize>,
    /// Rewrites tried (bounded by [`ATTEMPTS`]).
    pub attempts: usize,
    /// `if`/`else` blocks whose arms were put in machine-code order
    /// ([`order_arms`]).
    pub ordered: usize,
}

impl Outcome {
    pub fn changed(&self) -> bool {
        self.ordered > 0 || self.applied.iter().any(|(_, count)| *count > 0)
    }
}

/// Runs the models `settings` names over the function's block tree.
pub fn restructure(ir: &mut PrinterIr, settings: &Settings) -> Outcome {
    let mut root = Node {
        kind: kind::GRAPH,
        index: -1,
        last_op: None,
        label: None,
        children: std::mem::take(&mut ir.body),
        detail: Detail::None,
    };
    let outcome = run(&mut root, settings);
    ir.body = root.children;
    outcome
}

/// Counts the printed gotos and labels of a function; `None` when its
/// control flow does not check.
pub fn counts(ir: &PrinterIr) -> Result<Counts, String> {
    let root = Node {
        kind: kind::GRAPH,
        index: -1,
        last_op: None,
        label: None,
        children: ir.body.clone(),
        detail: Detail::None,
    };
    Ok(analyse(&root)?.counts)
}

// ---------------------------------------------------------------------------
// Control-flow model of the printed tree.

/// Where control goes next.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Flow {
    /// The basic block with this index.
    Leaf(i64),
    /// Off the end of the function.
    End,
}

impl Flow {
    fn is(&self, block: i64) -> bool {
        matches!(self, Flow::Leaf(leaf) if *leaf == block)
    }
}

#[derive(Clone, Debug)]
struct Scope {
    /// Where control goes when the node completes normally.
    follow: Flow,
    /// Where `break` goes, inside a loop or switch.
    brk: Option<Flow>,
    /// Where `continue` goes, inside a loop that has a usable one.
    cont: Option<Flow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Step {
    Child(usize),
    /// The in-place block of a switch's case.
    Case(usize),
}

type Path = Vec<Step>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    /// A `BlockGoto`: body, then the goto.
    Goto,
    /// `if (c) goto L;`.
    If,
    /// `case n: goto L;`, by case position; the path is the switch's.
    Case(usize),
}

#[derive(Clone, Debug)]
struct Site {
    path: Path,
    form: Form,
    kind: u64,
    target: i64,
    /// For a case, the scope inside the switch (follow = the switch's exit).
    scope: Scope,
    /// The innermost loop around the site.
    lp: Option<Path>,
}

#[derive(Default)]
struct Analysis {
    counts: Counts,
    /// Printed `goto`s per target block.
    targets: HashMap<i64, usize>,
    sites: Vec<Site>,
    /// Leaf instances by basic block index, in walk order.
    leaves: HashMap<i64, Vec<Path>>,
    /// Innermost loop around each leaf instance.
    leaf_loops: HashMap<Path, Option<Path>>,
    scopes: HashMap<Path, Scope>,
    lists: Vec<Path>,
    ifs: Vec<Path>,
    switches: Vec<Path>,
}

fn is_loop(kind: u64) -> bool {
    matches!(kind, kind::WHILE_DO | kind::DO_WHILE | kind::INFINITE_LOOP)
}

/// The basic block a node starts with.
fn entry(node: &Node) -> Option<i64> {
    match node.kind {
        kind::PLAIN => None,
        kind::BASIC => Some(node.index),
        _ => node.children.iter().find_map(entry),
    }
}

fn entry_or(node: &Node, follow: &Flow) -> Flow {
    entry(node).map_or_else(|| follow.clone(), Flow::Leaf)
}

fn sequence_follow(children: &[Node], from: usize, follow: &Flow) -> Flow {
    children
        .get(from..)
        .and_then(|rest| rest.iter().find_map(entry))
        .map_or_else(|| follow.clone(), Flow::Leaf)
}

fn basic_of(node: &Node) -> Option<&Basic> {
    match (&node.detail, node.kind) {
        (Detail::Basic(basic), _) => Some(basic),
        (_, kind::COPY) => node.children.first().and_then(basic_of),
        _ => None,
    }
}

fn statement_count(basic: &Basic) -> usize {
    basic
        .statements
        .iter()
        .filter(|statement| !statement.is_branch)
        .count()
}

fn resolve(goto_kind: u64, target: Option<&GotoTarget>, scope: &Scope) -> Result<Flow, String> {
    match goto_kind {
        GOTO_GOTO => target
            .map(|target| Flow::Leaf(target.block))
            .ok_or_else(|| "goto without a target".into()),
        BREAK_GOTO => scope
            .brk
            .clone()
            .ok_or_else(|| "break outside a loop or switch".into()),
        CONTINUE_GOTO => scope
            .cont
            .clone()
            .ok_or_else(|| "continue outside a loop".into()),
        other => Err(format!("goto kind {other}")),
    }
}

/// Whether the printed flow `flow` stands for the edge to `next` of a
/// block whose `threaded` edges name it (`thread_test` proved the test it
/// flows through takes that edge).
fn threaded(basic: &Basic, next: i64, flow: &Flow) -> bool {
    matches!(flow, Flow::Leaf(printed) if basic.threaded.contains(&(next, *printed)))
}

fn leaf_exit(index: i64, basic: &Basic, follow: &Flow) -> Result<(), String> {
    match basic.successors.as_slice() {
        [] => Ok(()),
        [next] if follow.is(*next) || threaded(basic, *next, follow) => Ok(()),
        successors => Err(format!(
            "block {index} branches to {successors:?} but prints flowing to {follow:?}"
        )),
    }
}

fn analyse(root: &Node) -> Result<Analysis, String> {
    let mut analysis = Analysis::default();
    let scope = Scope {
        follow: Flow::End,
        brk: None,
        cont: None,
    };
    analysis.walk(root, &mut Vec::new(), &scope, &mut Vec::new())?;
    Ok(analysis)
}

impl Analysis {
    fn goto(&mut self, goto_kind: u64, target: Option<&GotoTarget>) {
        if goto_kind == GOTO_GOTO {
            self.counts.gotos += 1;
            if let Some(target) = target {
                *self.targets.entry(target.block).or_default() += 1;
            }
        }
    }

    fn leaf(&mut self, node: &Node, path: &Path, loops: &[Path]) {
        if let Some(block) = entry(node) {
            self.leaves.entry(block).or_default().push(path.clone());
            self.leaf_loops.insert(path.clone(), loops.last().cloned());
        }
    }

    fn walk(
        &mut self,
        node: &Node,
        path: &mut Path,
        scope: &Scope,
        loops: &mut Vec<Path>,
    ) -> Result<(), String> {
        self.scopes.insert(path.clone(), scope.clone());
        if node.label.is_some() && (node.kind == kind::COPY || is_loop(node.kind)) {
            self.counts.labels += 1;
        }
        match node.kind {
            kind::PLAIN => Ok(()),
            kind::BASIC | kind::COPY => {
                self.leaf(node, path, loops);
                let basic = basic_of(node).ok_or("leaf without a basic block")?;
                leaf_exit(node.index, basic, &scope.follow)
            }
            kind::GOTO => {
                let Detail::Goto {
                    prints,
                    goto_kind,
                    target,
                } = &node.detail
                else {
                    return Err("goto block without its edge".into());
                };
                let dest = if *prints {
                    let dest = resolve(*goto_kind, target.as_ref(), scope)?;
                    self.goto(*goto_kind, target.as_ref());
                    if let (GOTO_GOTO, Some(target)) = (*goto_kind, target) {
                        self.sites.push(Site {
                            path: path.clone(),
                            form: Form::Goto,
                            kind: *goto_kind,
                            target: target.block,
                            scope: scope.clone(),
                            lp: loops.last().cloned(),
                        });
                    }
                    dest
                } else {
                    // gotoPrints: the target is next in flow anyway.
                    if !target
                        .as_ref()
                        .is_some_and(|target| scope.follow.is(target.block))
                    {
                        return Err("an unprinted goto is not a fallthrough".into());
                    }
                    scope.follow.clone()
                };
                let inner = Scope {
                    follow: dest,
                    ..scope.clone()
                };
                self.child(node, 0, path, &inner, loops)
            }
            kind::LIST | kind::GRAPH => {
                self.lists.push(path.clone());
                for position in 0..node.children.len() {
                    let inner = Scope {
                        follow: sequence_follow(&node.children, position + 1, &scope.follow),
                        ..scope.clone()
                    };
                    self.child(node, position, path, &inner, loops)?;
                }
                Ok(())
            }
            kind::IF => self.walk_if(node, path, scope, loops),
            kind::WHILE_DO => {
                let Detail::WhileDo {
                    overflow, iterate, ..
                } = &node.detail
                else {
                    return Err("while block without its loop".into());
                };
                let (condition, body) = (&node.children[0], &node.children[1]);
                let head = Flow::Leaf(entry(condition).ok_or("while without a head")?);
                let into = entry_or(body, &head);
                let inner = Scope {
                    follow: head.clone(),
                    brk: Some(scope.follow.clone()),
                    // A for loop's continue runs the iterator first.
                    cont: iterate.is_none().then(|| head.clone()),
                };
                path.push(Step::Child(0));
                if *overflow {
                    // `while (true) { ...; if (c) break; body }`: the printed
                    // condition is the exit (blockaction.cc ruleBlockWhileDo).
                    self.condition(condition, path, &scope.follow, &into, &inner, loops)?;
                } else {
                    self.condition(condition, path, &into, &scope.follow, &inner, loops)?;
                }
                path.pop();
                loops.push(path.clone());
                let checked = self.child(node, 1, path, &inner, loops);
                loops.pop();
                checked
            }
            kind::DO_WHILE => {
                // `do { body; test-block } while (test)`: the body's last
                // block is the bottom test.
                let body = &node.children[0];
                let top = Flow::Leaf(entry(body).ok_or("do-while without a body")?);
                let listed = matches!(body.kind, kind::LIST | kind::GRAPH);
                let (lead, test) = if listed {
                    let last = body.children.len().checked_sub(1).ok_or("empty do-while")?;
                    (&body.children[..last], &body.children[last])
                } else {
                    (&body.children[..0], body)
                };
                let test_entry = Flow::Leaf(entry(test).ok_or("do-while without its test")?);
                let inner = Scope {
                    follow: test_entry.clone(),
                    brk: Some(scope.follow.clone()),
                    // `continue` evaluates the test, skipping the statements
                    // its block prints in the body.
                    cont: bare_test(test).then(|| test_entry.clone()),
                };
                loops.push(path.clone());
                path.push(Step::Child(0));
                self.scopes.insert(path.clone(), inner.clone());
                if listed {
                    self.lists.push(path.clone());
                }
                for (position, item) in lead.iter().enumerate() {
                    let step = Scope {
                        follow: sequence_follow(&body.children, position + 1, &test_entry),
                        ..inner.clone()
                    };
                    path.push(Step::Child(position));
                    self.walk(item, path, &step, loops)?;
                    path.pop();
                }
                if listed {
                    path.push(Step::Child(lead.len()));
                }
                self.condition(test, path, &top, &scope.follow, &inner, loops)?;
                if listed {
                    path.pop();
                }
                path.pop();
                loops.pop();
                Ok(())
            }
            kind::INFINITE_LOOP => {
                let top = Flow::Leaf(entry(&node.children[0]).ok_or("loop without a body")?);
                let inner = Scope {
                    follow: top.clone(),
                    brk: Some(scope.follow.clone()),
                    cont: Some(top),
                };
                loops.push(path.clone());
                let checked = self.child(node, 0, path, &inner, loops);
                loops.pop();
                checked
            }
            kind::SWITCH => self.walk_switch(node, path, scope, loops),
            other => Err(format!("block kind {other} in statement position")),
        }
    }

    fn child(
        &mut self,
        node: &Node,
        position: usize,
        path: &mut Path,
        scope: &Scope,
        loops: &mut Vec<Path>,
    ) -> Result<(), String> {
        let child = node
            .children
            .get(position)
            .ok_or("block without its child")?;
        path.push(Step::Child(position));
        let checked = self.walk(child, path, scope, loops);
        path.pop();
        checked
    }

    fn walk_if(
        &mut self,
        node: &Node,
        path: &mut Path,
        scope: &Scope,
        loops: &mut Vec<Path>,
    ) -> Result<(), String> {
        let Detail::If { goto_kind, target } = &node.detail else {
            return Err("if block without its edge".into());
        };
        self.ifs.push(path.clone());
        let condition = &node.children[0];
        if let Some(target) = target {
            // printc: an if with a goto target prints only `if (c) goto L;`.
            let dest = resolve(*goto_kind, Some(target), scope)?;
            self.goto(*goto_kind, Some(target));
            if *goto_kind == GOTO_GOTO {
                self.sites.push(Site {
                    path: path.clone(),
                    form: Form::If,
                    kind: *goto_kind,
                    target: target.block,
                    scope: scope.clone(),
                    lp: loops.last().cloned(),
                });
            }
            path.push(Step::Child(0));
            let checked = self.condition(condition, path, &dest, &scope.follow, scope, loops);
            path.pop();
            return checked;
        }
        let then = node.children.get(1).ok_or("if without a body")?;
        let otherwise = node.children.get(2);
        let yes = entry_or(then, &scope.follow);
        let no = otherwise.map_or_else(
            || scope.follow.clone(),
            |other| entry_or(other, &scope.follow),
        );
        path.push(Step::Child(0));
        let checked = self.condition(condition, path, &yes, &no, scope, loops);
        path.pop();
        checked?;
        let inner = scope.clone();
        self.child(node, 1, path, &inner, loops)?;
        if otherwise.is_some() {
            self.child(node, 2, path, &inner, loops)?;
        }
        Ok(())
    }

    /// A branch condition: `yes` when it holds, `no` when it does not.
    /// `outer` is where `break`/`continue` go from statements ahead of it.
    fn condition(
        &mut self,
        node: &Node,
        path: &mut Path,
        yes: &Flow,
        no: &Flow,
        outer: &Scope,
        loops: &mut Vec<Path>,
    ) -> Result<(), String> {
        self.scopes.insert(
            path.clone(),
            Scope {
                follow: no.clone(),
                brk: None,
                cont: None,
            },
        );
        match node.kind {
            kind::BASIC | kind::COPY => {
                self.leaf(node, path, loops);
                if node.label.is_some() {
                    self.counts.labels += 1;
                }
                let basic = basic_of(node).ok_or("condition without a basic block")?;
                match basic.successors.as_slice() {
                    [false_out, true_out]
                        if (yes.is(*true_out) || threaded(basic, *true_out, yes))
                            && (no.is(*false_out) || threaded(basic, *false_out, no)) =>
                    {
                        Ok(())
                    }
                    successors => Err(format!(
                        "condition {} branches to {successors:?}, printed as {yes:?}/{no:?}",
                        node.index
                    )),
                }
            }
            kind::CONDITION => {
                let Detail::Condition { and } = node.detail else {
                    return Err("condition block without its operator".into());
                };
                let right = node
                    .children
                    .get(1)
                    .ok_or("condition without its second test")?;
                let second = Flow::Leaf(entry(right).ok_or("empty condition")?);
                path.push(Step::Child(0));
                let checked = if and {
                    self.condition(&node.children[0], path, &second, no, outer, loops)
                } else {
                    self.condition(&node.children[0], path, yes, &second, outer, loops)
                };
                path.pop();
                checked?;
                path.push(Step::Child(1));
                let checked = self.condition(right, path, yes, no, outer, loops);
                path.pop();
                checked
            }
            kind::LIST => {
                // Statements ahead of the test: Ghidra collapses them into
                // the condition block; only the last child branches.
                let last = node
                    .children
                    .len()
                    .checked_sub(1)
                    .ok_or("empty condition list")?;
                for position in 0..last {
                    let scope = Scope {
                        follow: sequence_follow(&node.children, position + 1, no),
                        ..outer.clone()
                    };
                    path.push(Step::Child(position));
                    self.walk(&node.children[position], path, &scope, loops)?;
                    path.pop();
                }
                path.push(Step::Child(last));
                let checked = self.condition(&node.children[last], path, yes, no, outer, loops);
                path.pop();
                checked
            }
            other => Err(format!("block kind {other} as a condition")),
        }
    }

    fn walk_switch(
        &mut self,
        node: &Node,
        path: &mut Path,
        scope: &Scope,
        loops: &mut Vec<Path>,
    ) -> Result<(), String> {
        let Detail::Switch { cases } = &node.detail else {
            return Err("switch block without cases".into());
        };
        self.switches.push(path.clone());
        let inner = Scope {
            follow: scope.follow.clone(),
            brk: Some(scope.follow.clone()),
            cont: scope.cont.clone(),
        };
        // Where each case starts.
        let mut entries = Vec::with_capacity(cases.len());
        for case in cases {
            entries.push(match &case.body {
                CaseBody::Goto { goto_kind, target } => {
                    resolve(*goto_kind, target.as_ref(), &inner)?
                }
                CaseBody::Child(child) => entry_or(
                    node.children.get(*child).ok_or("case out of range")?,
                    &scope.follow,
                ),
                CaseBody::Block(block) => entry_or(block, &scope.follow),
            });
        }
        // The head: statements, then the multi-way branch.
        let mut head = node.children.first().ok_or("switch without its head")?;
        if head.kind == kind::MULTIGOTO {
            head = head.children.first().ok_or("multigoto without its block")?;
        }
        let switch_leaf = match head.kind {
            kind::COPY | kind::BASIC => head,
            _ => return Err(format!("switch head of kind {}", head.kind)),
        };
        let basic = basic_of(switch_leaf).ok_or("switch head without a basic block")?;
        for successor in &basic.successors {
            if !entries.iter().any(|flow| flow.is(*successor)) && !scope.follow.is(*successor) {
                return Err(format!("switch edge to {successor} has no case"));
            }
        }
        path.push(Step::Child(0));
        self.leaf(switch_leaf, path, loops);
        path.pop();
        for (position, case) in cases.iter().enumerate() {
            let follow = if case.exit {
                scope.follow.clone()
            } else {
                entries
                    .get(position + 1)
                    .cloned()
                    .unwrap_or_else(|| scope.follow.clone())
            };
            let case_scope = Scope {
                follow,
                ..inner.clone()
            };
            match &case.body {
                CaseBody::Goto { goto_kind, target } => {
                    self.goto(*goto_kind, target.as_ref());
                    if let (GOTO_GOTO, Some(target)) = (*goto_kind, target) {
                        self.sites.push(Site {
                            path: path.clone(),
                            form: Form::Case(position),
                            kind: *goto_kind,
                            target: target.block,
                            scope: inner.clone(),
                            lp: loops.last().cloned(),
                        });
                    }
                }
                CaseBody::Child(child) => {
                    path.push(Step::Child(*child));
                    let checked = self.walk(&node.children[*child], path, &case_scope, loops);
                    path.pop();
                    checked?;
                }
                CaseBody::Block(block) => {
                    path.push(Step::Case(position));
                    let checked = self.walk(block, path, &case_scope, loops);
                    path.pop();
                    checked?;
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tree edits.

fn node_at<'n>(mut node: &'n Node, path: &[Step]) -> Option<&'n Node> {
    for step in path {
        node = match *step {
            Step::Child(index) => node.children.get(index)?,
            Step::Case(index) => match &node.detail {
                Detail::Switch { cases } => match &cases.get(index)?.body {
                    CaseBody::Block(block) => block,
                    _ => return None,
                },
                _ => return None,
            },
        };
    }
    Some(node)
}

fn node_at_mut<'n>(mut node: &'n mut Node, path: &[Step]) -> Option<&'n mut Node> {
    for step in path {
        node = match *step {
            Step::Child(index) => node.children.get_mut(index)?,
            Step::Case(index) => match &mut node.detail {
                Detail::Switch { cases } => match &mut cases.get_mut(index)?.body {
                    CaseBody::Block(block) => block,
                    _ => return None,
                },
                _ => return None,
            },
        };
    }
    Some(node)
}

enum Edit {
    /// Replace the node at `path`.
    Node(Path, Box<Node>),
    /// Replace `start..end` of the children of the list at `path`.
    Splice {
        path: Path,
        start: usize,
        end: usize,
        nodes: Vec<Node>,
    },
    /// Replace the cases of the switch at `path`.
    Cases(Path, Vec<Case>),
    /// Change a goto's kind (or, for `prints`, whether a goto prints).
    Kind {
        path: Path,
        form: Form,
        kind: u64,
        prints: bool,
    },
}

/// Applies `edit`; returns its inverse.
fn apply(root: &mut Node, edit: Edit) -> Option<Edit> {
    match edit {
        Edit::Node(path, node) => {
            let slot = node_at_mut(root, &path)?;
            let old = std::mem::replace(slot, *node);
            Some(Edit::Node(path, Box::new(old)))
        }
        Edit::Splice {
            path,
            start,
            end,
            nodes,
        } => {
            let list = node_at_mut(root, &path)?;
            if end > list.children.len() || start > end {
                return None;
            }
            let count = nodes.len();
            let removed: Vec<Node> = list.children.splice(start..end, nodes).collect();
            fix_flow_breaks(list);
            Some(Edit::Splice {
                path,
                start,
                end: start + count,
                nodes: removed,
            })
        }
        Edit::Cases(path, cases) => {
            let switch = node_at_mut(root, &path)?;
            let Detail::Switch { cases: current } = &mut switch.detail else {
                return None;
            };
            let old = std::mem::replace(current, cases);
            Some(Edit::Cases(path, old))
        }
        Edit::Kind {
            path,
            form,
            kind,
            prints,
        } => {
            let node = node_at_mut(root, &path)?;
            let (old_kind, old_prints) = match (form, &mut node.detail) {
                (
                    Form::Goto,
                    Detail::Goto {
                        prints: slot_prints,
                        goto_kind,
                        ..
                    },
                ) => {
                    let old = (*goto_kind, *slot_prints);
                    *goto_kind = kind;
                    *slot_prints = prints;
                    old
                }
                (Form::If, Detail::If { goto_kind, .. }) => {
                    let old = (*goto_kind, true);
                    *goto_kind = kind;
                    old
                }
                (Form::Case(position), Detail::Switch { cases }) => {
                    match &mut cases.get_mut(position)?.body {
                        CaseBody::Goto { goto_kind, .. } => {
                            let old = (*goto_kind, true);
                            *goto_kind = kind;
                            old
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            };
            Some(Edit::Kind {
                path,
                form,
                kind: old_kind,
                prints: old_prints,
            })
        }
    }
}

fn fix_flow_breaks(list: &mut Node) {
    if let Detail::List { flow_breaks } = &mut list.detail {
        flow_breaks.resize(list.children.len().saturating_sub(1), false);
    }
}

fn list_of(nodes: Vec<Node>) -> Node {
    if nodes.len() == 1 {
        return nodes.into_iter().next().expect("one node");
    }
    let index = nodes.first().map_or(-1, |node| node.index);
    let last_op = nodes.last().and_then(|node| node.last_op);
    Node {
        kind: kind::LIST,
        index,
        last_op,
        label: None,
        detail: Detail::List {
            flow_breaks: vec![false; nodes.len().saturating_sub(1)],
        },
        children: nodes,
    }
}

fn strip_labels(node: &mut Node) {
    node.label = None;
    for child in &mut node.children {
        strip_labels(child);
    }
}

/// Whether control can leave `node` other than by a jump.
fn completes(node: &Node) -> bool {
    match node.kind {
        kind::COPY | kind::BASIC => basic_of(node).is_none_or(|basic| !basic.successors.is_empty()),
        kind::GOTO => match &node.detail {
            Detail::Goto { prints: true, .. } => false,
            _ => node.children.first().is_none_or(completes),
        },
        kind::LIST | kind::GRAPH => node.children.last().is_none_or(completes),
        kind::IF => match &node.detail {
            Detail::If { target: None, .. } if node.children.len() == 3 => {
                completes(&node.children[1]) || completes(&node.children[2])
            }
            _ => true,
        },
        kind::INFINITE_LOOP => node.children.iter().any(breaks_out),
        _ => true,
    }
}

/// Whether `node` holds a `break` out of the loop around it (one not
/// inside a nested loop or switch).
fn breaks_out(node: &Node) -> bool {
    match (&node.detail, node.kind) {
        (_, kind::WHILE_DO | kind::DO_WHILE | kind::INFINITE_LOOP | kind::SWITCH) => false,
        (
            Detail::Goto {
                prints: true,
                goto_kind: BREAK_GOTO,
                ..
            },
            _,
        )
        | (
            Detail::If {
                goto_kind: BREAK_GOTO,
                target: Some(_),
            },
            _,
        ) => true,
        _ => node.children.iter().any(breaks_out),
    }
}

fn has_label(node: &Node) -> bool {
    node.label.is_some()
        || node.children.iter().any(has_label)
        || match &node.detail {
            Detail::Switch { cases } => cases.iter().any(|case| match &case.body {
                CaseBody::Block(block) => has_label(block),
                _ => false,
            }),
            _ => false,
        }
}

/// Drops labels no goto prints to any more (only those the rewrites
/// orphaned) and code that became unreachable.
fn cleanup(node: &mut Node, original: &HashMap<i64, usize>, now: &HashMap<i64, usize>) {
    if node.label.is_some()
        && let Some(block) = entry(node)
        && original.get(&block).copied().unwrap_or(0) > 0
        && now.get(&block).copied().unwrap_or(0) == 0
    {
        node.label = None;
    }
    for child in &mut node.children {
        cleanup(child, original, now);
    }
    if let Detail::Switch { cases } = &mut node.detail {
        for case in cases {
            if let CaseBody::Block(block) = &mut case.body {
                cleanup(block, original, now);
            }
        }
    }
    if matches!(node.kind, kind::LIST | kind::GRAPH) {
        let mut position = 1;
        while position < node.children.len() {
            if !completes(&node.children[position - 1]) && !has_label(&node.children[position]) {
                node.children.remove(position);
            } else {
                position += 1;
            }
        }
        fix_flow_breaks(node);
    }
    // An arm left holding one statement is that statement, so an else arm
    // holding one if prints as `else if`.
    if node.kind == kind::IF && matches!(node.detail, Detail::If { target: None, .. }) {
        for arm in node.children.iter_mut().skip(1) {
            if arm.kind == kind::LIST && arm.label.is_none() && arm.children.len() == 1 {
                *arm = arm.children.pop().expect("one statement");
            }
        }
    }
}

/// Negates a condition tree: leaves take PrintC's negated rendering and
/// swap their out-edges, `&&`/`||` swap by De Morgan.
fn negate(node: &mut Node) -> bool {
    match node.kind {
        kind::COPY => node.children.first_mut().is_some_and(negate),
        kind::BASIC => {
            let last_op = node.last_op;
            let Detail::Basic(basic) = &mut node.detail else {
                return false;
            };
            let (Some(negated), Some(branch)) = (&mut basic.negated, &mut basic.branch) else {
                return false;
            };
            if basic.successors.len() != 2 {
                return false;
            }
            std::mem::swap(negated, branch);
            for statement in &mut basic.statements {
                if statement.is_branch && Some(statement.op) == last_op {
                    statement.expression = branch.clone();
                    statement.effect.flip = !statement.effect.flip;
                }
            }
            basic.successors.swap(0, 1);
            true
        }
        kind::CONDITION => {
            let Detail::Condition { and } = &mut node.detail else {
                return false;
            };
            *and = !*and;
            node.children.iter_mut().all(negate)
        }
        kind::LIST => node.children.last_mut().is_some_and(negate),
        _ => false,
    }
}

fn negatable(node: &Node) -> bool {
    match node.kind {
        kind::COPY => node.children.first().is_some_and(negatable),
        kind::BASIC => basic_of(node)
            .is_some_and(|basic| basic.negated.is_some() && basic.successors.len() == 2),
        kind::CONDITION => node.children.iter().all(negatable),
        kind::LIST => node.children.last().is_some_and(negatable),
        _ => false,
    }
}

/// A condition every test of which prints nothing but the test itself.
fn bare_condition(node: &Node) -> bool {
    node.label.is_none()
        && match node.kind {
            kind::COPY => node.children.first().is_some_and(bare_condition),
            kind::BASIC => basic_of(node).is_some_and(|basic| statement_count(basic) == 0),
            kind::CONDITION => node.children.iter().all(bare_condition),
            _ => false,
        }
}

/// A loop test `continue` can jump to: one that prints nothing but the test.
/// A label on its first test is where `continue` goes anyway.
fn bare_test(node: &Node) -> bool {
    match node.kind {
        kind::COPY => node.children.first().is_some_and(bare_test),
        kind::BASIC => basic_of(node).is_some_and(|basic| statement_count(basic) == 0),
        kind::CONDITION => {
            node.children.first().is_some_and(bare_test)
                && node.children[1..].iter().all(bare_condition)
        }
        _ => false,
    }
}

/// Printed lines of a tree as the copy budget counts them, the way PrintC
/// lays it out: statements, jumps and labels, two lines (header, closing
/// brace) per `if`, loop and switch, two more for an `else` (none for an
/// `else if`), one per case label.
fn size(node: &Node) -> usize {
    let children: usize = node.children.iter().map(size).sum();
    let own = match (&node.detail, node.kind) {
        (_, kind::PLAIN) => 0,
        (_, kind::BASIC | kind::COPY) => basic_of(node).map_or(0, statement_count),
        (Detail::Goto { prints, .. }, _) => children + usize::from(*prints),
        (
            Detail::If {
                target: Some(_), ..
            },
            _,
        ) => children + 1,
        // `else {` and its closing brace, or nothing for `else if`.
        (_, kind::IF) => {
            children
                + 2
                + node.children.get(2).map_or(
                    0,
                    |otherwise| if otherwise.kind == kind::IF { 0 } else { 2 },
                )
        }
        (Detail::Switch { cases }, _) => {
            children
                + 2
                + cases
                    .iter()
                    .map(|case| {
                        case.labels.len()
                            + usize::from(case.exit)
                            + match &case.body {
                                CaseBody::Goto { .. } => 1,
                                CaseBody::Child(_) => 0,
                                CaseBody::Block(block) => size(block),
                            }
                    })
                    .sum::<usize>()
        }
        (_, kind) if is_loop(kind) => children + 2,
        _ => children,
    };
    own + usize::from(node.label.is_some())
}

// ---------------------------------------------------------------------------
// The models.

struct Run<'s> {
    settings: &'s Settings,
    original_targets: HashMap<i64, usize>,
    attempts: usize,
}

fn run(root: &mut Node, settings: &Settings) -> Outcome {
    // Ghidra nests sequences (a list inside a list); printing them flat is
    // the same C, and the rewrites see a statement's neighbours directly.
    flatten(root);
    let first = match analyse(root) {
        Ok(analysis) => analysis,
        Err(error) => {
            return Outcome {
                refused: Some(error),
                ..Outcome::default()
            };
        }
    };
    let before = first.counts;
    let mut applied: Vec<(Model, usize)> =
        settings.models.iter().map(|model| (*model, 0)).collect();
    let mut state = Run {
        settings,
        original_targets: first.targets.clone(),
        attempts: 0,
    };
    let mut current = first;
    while current.counts.gotos > 0 && state.attempts < ATTEMPTS {
        let Some((model, next)) = state.step(root, &current, 0, None) else {
            break;
        };
        current = next;
        if let Some(slot) = applied.iter_mut().find(|(known, _)| *known == model) {
            slot.1 += 1;
        }
    }
    let remaining = classify(root, &current);
    // After the goto models, so every rewrite sees Ghidra's own arm order.
    let before_order = root.clone();
    let ordered = if settings.order_arms { order_arms(root) } else { 0 };
    let ordered = if ordered > 0 && analyse(root).is_err() {
        *root = before_order;
        0
    } else {
        ordered
    };
    Outcome {
        before,
        after: current.counts,
        applied,
        refused: None,
        remaining,
        attempts: state.attempts,
        ordered,
    }
}

/// Where the code of a node starts: the address its first leaf's label names
/// (`emitLabel`, exported for every leaf whether or not it prints). Block
/// *indices* are not addresses -- Ghidra numbers them in its own flow order.
fn layout_address(node: &Node) -> Option<u64> {
    if let Detail::Copy { label } = &node.detail {
        return label.0.iter().find_map(|event| match event {
            Event::Label { offset, .. } => Some(*offset),
            _ => None,
        });
    }
    node.children.iter().find_map(layout_address)
}

/// An arm that does nothing but store a constant: with a twin arm it is the
/// two-valued result of a merged `return`, whose arms the compiler lays out in
/// the order of its own jump threading, not of any source `if`/`else`.
fn stores_a_constant(node: &Node) -> bool {
    let Some(basic) = basic_of(node) else { return false };
    let mut printed = basic.statements.iter().filter(|statement| !statement.is_branch);
    matches!(
        (printed.next(), printed.next()),
        (Some(only), None)
            if only.effect.out.is_some() && matches!(only.effect.args.as_slice(), [Expr::Const { .. }])
    )
}

/// An `if`/`else` whose `else` arm is the one the machine code lays out first
/// prints that arm first, under the negated test. A compiler lays an
/// `if (c) A else B` out as the test, `A`, then `B`; Ghidra's choice of which
/// arm is the `if` follows its own normal form for the test, which flips the
/// arms of every `if ((x & 1) == 0) B else A`-shaped test. Arms of a test that
/// cannot be negated stay. Returns how many blocks were reordered.
fn order_arms(node: &mut Node) -> usize {
    let mut ordered = 0;
    if let Detail::Switch { cases } = &mut node.detail {
        for case in cases {
            if let CaseBody::Block(block) = &mut case.body {
                ordered += order_arms(block);
            }
        }
    }
    for child in &mut node.children {
        ordered += order_arms(child);
    }
    if node.kind == kind::IF
        && matches!(node.detail, Detail::If { target: None, .. })
        && node.children.len() == 3
        && let (Some(then), Some(other)) =
            (layout_address(&node.children[1]), layout_address(&node.children[2]))
        && other < then
        && !(stores_a_constant(&node.children[1]) && stores_a_constant(&node.children[2]))
        && negatable(&node.children[0])
    {
        negate(&mut node.children[0]);
        node.children.swap(1, 2);
        ordered += 1;
    }
    ordered
}

/// Why each printed goto is still there: where its target sits relative to
/// it, and how many statements a copy of the target's tail would take
/// (`/tail<=N`, up to [`MEASURE`]; `/no-tail` when no tail ends where the
/// goto's position continues).
fn classify(root: &Node, analysis: &Analysis) -> BTreeMap<String, usize> {
    let mut causes = BTreeMap::new();
    for site in &analysis.sites {
        let copy = match site.form {
            Form::Case(_) => {
                tail(root, analysis, site.target, &site.scope.follow, MEASURE).map(|(copy, _)| copy)
            }
            _ => site_tail(root, analysis, site, MEASURE).map(|(copy, _)| copy),
        };
        let size = copy.map(|copy| {
            let (mut statements, mut leaves) = (0, 0);
            for node in &copy {
                copyable(node, &mut statements, &mut leaves);
            }
            statements
        });
        let bucket = match size {
            None => "no-tail",
            Some(0..=6) => "tail<=6",
            Some(7..=12) => "tail<=12",
            Some(13..=24) => "tail<=24",
            Some(_) => "tail<=64",
        };
        *causes
            .entry(format!("{}/{bucket}", cause(root, analysis, site)))
            .or_default() += 1;
    }
    causes
}

/// Where a goto's target sits relative to it (docs/structuring-baseline.md
/// relates each to the compiler optimization that typically produces it):
///
/// * `case` -- a switch case's goto;
/// * `into_loop` -- into a loop the goto is not in (a loop entered in the
///   middle: rotation, unrolling remainders);
/// * `loop_exit` -- out of the goto's loop (a loop with several exits);
/// * `backward` -- to an earlier statement that is not a loop head;
/// * `into_arm` -- into the middle of a later statement;
/// * `cross_arm` -- from one arm of an if into the other;
/// * `flat_skip` -- over statements of its own list;
/// * `exit_nested` -- from inside a statement to the one right after it;
/// * `skip_after` -- from inside a statement past the statements after it.
fn cause(root: &Node, analysis: &Analysis, site: &Site) -> &'static str {
    if let Form::Case(_) = site.form {
        return "case";
    }
    let Some(target) = primary_instance(root, analysis, site.target) else {
        return "unplaced";
    };
    if let Some(Some(lp)) = analysis.leaf_loops.get(target)
        && !site.path.starts_with(lp)
    {
        return "into_loop";
    }
    if leaves_loop(site, analysis, root) {
        return "loop_exit";
    }
    let common = site
        .path
        .iter()
        .zip(target)
        .take_while(|(a, b)| a == b)
        .count();
    let (Some(from), Some(to), Some(parent)) = (
        site.path.get(common),
        target.get(common),
        node_at(root, &target[..common]),
    ) else {
        return "nested";
    };
    match (parent.kind, *from, *to) {
        (kind::LIST | kind::GRAPH, Step::Child(from), Step::Child(to)) => {
            if to < from {
                "backward"
            } else if entry(&parent.children[to]) != Some(site.target) {
                "into_arm"
            } else if site.path.len() == common + 1 {
                "flat_skip"
            } else if to == from + 1 {
                "exit_nested"
            } else {
                "skip_after"
            }
        }
        (kind::IF, ..) => "cross_arm",
        (other, ..) if is_loop(other) => "in_loop",
        _ => "other",
    }
}

impl Run<'_> {
    /// How much one copied tail may hold: a copy of `statements` removes
    /// at most a goto and a label, so a larger one is over the budget.
    fn limits(&self) -> Limits {
        Limits {
            statements: self.settings.budget + 2,
            blocks: self.settings.budget + 4,
        }
    }

    /// Whether a tree of `size` printing `gotos` stays within the budget
    /// against one of `base_size` printing `base_gotos`.
    fn affordable(&self, base_size: usize, base_gotos: usize, size: usize, gotos: usize) -> bool {
        size <= base_size + self.settings.budget * base_gotos.saturating_sub(gotos)
    }

    /// The first rewrite, in model order, that is kept. A sink nests at most
    /// [`SINK_DEPTH`] deep and, nested, only moves code to the same label.
    fn step(
        &mut self,
        root: &mut Node,
        current: &Analysis,
        depth: usize,
        sinking: Option<i64>,
    ) -> Option<(Model, Analysis)> {
        let limits = self.limits();
        for model in self.settings.models.clone() {
            if model == Model::SinkJoin {
                if depth >= SINK_DEPTH {
                    continue;
                }
                for (target, edit) in sink_join(root, current, sinking) {
                    if let Some(next) =
                        self.attempt_sink(root, current, vec![edit], depth, Some(target))
                    {
                        return Some((model, next));
                    }
                    if self.attempts >= ATTEMPTS {
                        return None;
                    }
                }
                continue;
            }
            if model == Model::CondMerge {
                if depth >= SINK_DEPTH {
                    continue;
                }
                for edit in cond_merge(root, current) {
                    if let Some(next) =
                        self.attempt_sink(root, current, vec![edit], depth, sinking)
                    {
                        return Some((model, next));
                    }
                    if self.attempts >= ATTEMPTS {
                        return None;
                    }
                }
                continue;
            }
            if model == Model::ThreadTest {
                for edit in thread::candidates(root, current) {
                    if let Some(next) = self.attempt(root, current, edit) {
                        return Some((model, next));
                    }
                    if self.attempts >= ATTEMPTS {
                        return None;
                    }
                }
                if depth >= SINK_DEPTH {
                    continue;
                }
                for edits in thread::forward(root, current) {
                    if let Some(next) = self.attempt_sink(root, current, edits, depth, sinking) {
                        return Some((model, next));
                    }
                    if self.attempts >= ATTEMPTS {
                        return None;
                    }
                }
                continue;
            }
            for edit in candidates(model, root, current, limits) {
                if let Some(next) = self.attempt(root, current, edit) {
                    return Some((model, next));
                }
                if self.attempts >= ATTEMPTS {
                    return None;
                }
            }
        }
        None
    }

    /// Applies `edit` when the result checks, prints fewer gotos and stays
    /// within the budget.
    fn attempt(&mut self, root: &mut Node, current: &Analysis, edit: Edit) -> Option<Analysis> {
        self.attempts += 1;
        let base_size = size(root);
        let inverse = apply(root, edit)?;
        let analysis = match analyse(root) {
            Ok(analysis) if analysis.counts.gotos < current.counts.gotos => analysis,
            _ => {
                apply(root, inverse);
                return None;
            }
        };
        let before_cleanup = root.clone();
        cleanup(root, &self.original_targets, &analysis.targets);
        let kept = match analyse(root) {
            Ok(cleaned) if cleaned.counts.gotos <= analysis.counts.gotos => cleaned,
            _ => {
                *root = before_cleanup.clone();
                analysis
            }
        };
        if !self.affordable(
            base_size,
            current.counts.gotos,
            size(root),
            kept.counts.gotos,
        ) {
            *root = before_cleanup;
            apply(root, inverse);
            return None;
        }
        Some(kept)
    }

    /// A sink removes no goto itself: it is kept when the rewrites it
    /// enables (at most [`FOLLOW_UPS`]) bring the function below `current`
    /// within the budget; otherwise everything is undone.
    fn attempt_sink(
        &mut self,
        root: &mut Node,
        current: &Analysis,
        edits: Vec<Edit>,
        depth: usize,
        target: Option<i64>,
    ) -> Option<Analysis> {
        self.attempts += 1;
        let base_size = size(root);
        let snapshot = root.clone();
        let applied = edits.into_iter().all(|edit| apply(root, edit).is_some());
        let mut now = match applied.then(|| analyse(root)) {
            Some(Ok(analysis)) => analysis,
            _ => {
                *root = snapshot;
                return None;
            }
        };
        for _ in 0..FOLLOW_UPS {
            // Stop once the function prints fewer gotos within the budget:
            // a sink that copies code to remove many gotos is priced on all
            // of them, so keep removing until it pays for itself.
            if self.attempts >= ATTEMPTS
                || (now.counts.gotos < current.counts.gotos
                    && self.affordable(
                        base_size,
                        current.counts.gotos,
                        size(root),
                        now.counts.gotos,
                    ))
            {
                break;
            }
            match self.step(root, &now, depth + 1, target) {
                Some((_, next)) => now = next,
                None => break,
            }
        }
        if now.counts.gotos < current.counts.gotos
            && self.affordable(
                base_size,
                current.counts.gotos,
                size(root),
                now.counts.gotos,
            )
        {
            Some(now)
        } else {
            *root = snapshot;
            None
        }
    }
}

fn candidates(model: Model, root: &Node, analysis: &Analysis, limits: Limits) -> Vec<Edit> {
    match model {
        Model::BreakContinue => break_continue(analysis),
        Model::CollapsedEdges => collapsed_edges(root, analysis),
        Model::ElseJoin => else_join(root, analysis),
        Model::SwitchTails => tails(root, analysis, false, limits),
        Model::LoopExits => tails(root, analysis, true, limits),
        Model::IrreducibleEntry => irreducible_entry(root, analysis, limits),
        // A sink, a condition merge and a threading are tried by
        // `Run::step` itself (`attempt_sink`, `attempt`).
        Model::SinkJoin | Model::CondMerge | Model::ThreadTest => Vec::new(),
    }
}

fn break_continue(analysis: &Analysis) -> Vec<Edit> {
    let mut edits = Vec::new();
    for site in &analysis.sites {
        let (kind, prints) = if site
            .scope
            .cont
            .as_ref()
            .is_some_and(|flow| flow.is(site.target))
        {
            (CONTINUE_GOTO, true)
        } else if site
            .scope
            .brk
            .as_ref()
            .is_some_and(|flow| flow.is(site.target))
        {
            (BREAK_GOTO, true)
        } else if site.form == Form::Goto && site.scope.follow.is(site.target) {
            (site.kind, false)
        } else {
            continue;
        };
        edits.push(Edit::Kind {
            path: site.path.clone(),
            form: site.form,
            kind,
            prints,
        });
    }
    edits
}

/// Whether a goto leaves the loop it sits in.
fn leaves_loop(site: &Site, analysis: &Analysis, root: &Node) -> bool {
    let Some(lp) = &site.lp else {
        return false;
    };
    match primary_instance(root, analysis, site.target) {
        Some(path) => !path.starts_with(lp),
        None => true,
    }
}

/// The instance of a block a goto's label refers to: the labelled one.
fn primary_instance<'a>(root: &Node, analysis: &'a Analysis, block: i64) -> Option<&'a Path> {
    let instances = analysis.leaves.get(&block)?;
    instances
        .iter()
        .find(|path| node_at(root, path).is_some_and(|node| node.label.is_some()))
        .or_else(|| instances.first())
}

/// Copies of the statements a goto's target starts: first along single
/// out-edges of plain blocks ([`chain_tail`]), else the target's run of
/// statements in its list as the tree prints them ([`structured_tail`]).
fn tail(
    root: &Node,
    analysis: &Analysis,
    start: i64,
    desired: &Flow,
    limits: Limits,
) -> Option<(Vec<Node>, bool)> {
    chain_tail(root, analysis, start, desired, limits)
        .or_else(|| structured_tail(root, analysis, start, desired, limits))
}

/// Splices lists nested in lists into their parent, and moves the
/// statements Ghidra collapsed into an if's condition block (printed ahead
/// of the `if`) out in front of it, so the rewrites see them as the
/// statements they print as.
fn flatten(node: &mut Node) {
    for child in &mut node.children {
        flatten(child);
    }
    if let Detail::Switch { cases } = &mut node.detail {
        for case in cases {
            if let CaseBody::Block(block) = &mut case.body {
                flatten(block);
            }
        }
    }
    if node.kind == kind::IF && matches!(node.detail, Detail::If { target: None, .. }) {
        for arm in node.children.iter_mut().skip(1) {
            if let Some(lead) = hoist(arm) {
                let test = std::mem::replace(arm, list_of(Vec::new()));
                let mut nodes = lead;
                nodes.push(test);
                *arm = list_of(nodes);
            }
        }
    }
    if matches!(node.kind, kind::LIST | kind::GRAPH)
        && node
            .children
            .iter()
            .any(|child| child.kind == kind::LIST || hoistable(child))
    {
        let children = std::mem::take(&mut node.children);
        for mut child in children {
            if child.kind == kind::LIST {
                node.children.extend(child.children);
            } else if let Some(lead) = hoist(&mut child) {
                node.children.extend(lead);
                node.children.push(child);
            } else {
                node.children.push(child);
            }
        }
        fix_flow_breaks(node);
    }
}

/// An unlabelled if whose condition is a list (statements, then the test).
fn hoistable(node: &Node) -> bool {
    node.kind == kind::IF
        && node.label.is_none()
        && node
            .children
            .first()
            .is_some_and(|condition| condition.kind == kind::LIST && condition.children.len() > 1)
}

/// Takes the statements ahead of a [`hoistable`] if's test out of its
/// condition.
fn hoist(node: &mut Node) -> Option<Vec<Node>> {
    if !hoistable(node) {
        return None;
    }
    let mut condition = std::mem::replace(&mut node.children[0], list_of(Vec::new()));
    let test = condition
        .children
        .pop()
        .expect("a condition list ends in its test");
    node.children[0] = test;
    Some(condition.children)
}

/// Counts what a structured tail would copy; `false` for what it must not
/// (loops, switches, jumps, `for` loop ops).
fn copyable(node: &Node, statements: &mut usize, leaves: &mut usize) -> bool {
    match node.kind {
        kind::COPY | kind::BASIC => {
            let Some(basic) = basic_of(node) else {
                return false;
            };
            *statements += statement_count(basic);
            *leaves += 1;
            // A block that flows through a re-inserted test is justified
            // where it stands only.
            !basic.holds_loop_op && basic.threaded.is_empty()
        }
        kind::IF if matches!(node.detail, Detail::If { target: None, .. }) => node
            .children
            .iter()
            .all(|child| copyable(child, statements, leaves)),
        kind::CONDITION | kind::LIST => node
            .children
            .iter()
            .all(|child| copyable(child, statements, leaves)),
        _ => false,
    }
}

/// The target's statements in its list, from the one it starts, until one
/// returns (`true`) or what follows is `desired` (`false`).
fn structured_tail(
    root: &Node,
    analysis: &Analysis,
    start: i64,
    desired: &Flow,
    limits: Limits,
) -> Option<(Vec<Node>, bool)> {
    let mut path: &[Step] = primary_instance(root, analysis, start)?;
    // Climb to the statement that starts with the target.
    let (position, list_path) = loop {
        let (last, parent_path) = path.split_last()?;
        let parent = node_at(root, parent_path)?;
        match (parent.kind, *last) {
            (kind::LIST | kind::GRAPH, Step::Child(position))
                if analysis.lists.iter().any(|list| list == parent_path) =>
            {
                break (position, parent_path);
            }
            (kind::IF | kind::CONDITION | kind::LIST, Step::Child(0)) => path = parent_path,
            _ => return None,
        }
    };
    let list = node_at(root, list_path)?;
    let follow = &analysis.scopes.get(list_path)?.follow;
    let (mut nodes, mut statements, mut leaves) = (Vec::new(), 0, 0);
    for (offset, node) in list.children.get(position..)?.iter().enumerate() {
        if !copyable(node, &mut statements, &mut leaves)
            || statements > limits.statements
            || leaves > limits.blocks + 1
        {
            return None;
        }
        let mut copy = node.clone();
        strip_labels(&mut copy);
        nodes.push(copy);
        if !completes(node) {
            return Some((nodes, true));
        }
        if sequence_follow(&list.children, position + offset + 1, follow) == *desired {
            return Some((nodes, false));
        }
    }
    None
}

/// Copies of the blocks from `start` along their single out-edges until one
/// returns (`true`) or the next is `desired` (`false`).
fn chain_tail(
    root: &Node,
    analysis: &Analysis,
    start: i64,
    desired: &Flow,
    limits: Limits,
) -> Option<(Vec<Node>, bool)> {
    if desired.is(start) {
        return None;
    }
    let mut nodes = Vec::new();
    let mut statements = 0;
    let mut block = start;
    loop {
        if nodes.len() >= limits.blocks {
            return None;
        }
        let path = analysis.leaves.get(&block)?.first()?;
        let node = node_at(root, path)?;
        if !matches!(node.kind, kind::COPY | kind::BASIC) {
            return None;
        }
        let basic = basic_of(node)?;
        if basic.holds_loop_op || basic.successors.len() > 1 || !basic.threaded.is_empty() {
            return None;
        }
        statements += statement_count(basic);
        if statements > limits.statements {
            return None;
        }
        let mut copy = node.clone();
        strip_labels(&mut copy);
        nodes.push(copy);
        match basic.successors.as_slice() {
            [] => return Some((nodes, true)),
            [next] if desired.is(*next) => return Some((nodes, false)),
            [next] => {
                if *next == start || nodes.iter().any(|node| entry(node) == Some(*next)) {
                    return None;
                }
                block = *next;
            }
            _ => return None,
        }
    }
}

/// A goto's replacement tail: one that ends where the goto's position falls
/// through to, returns, or ends where `break` or `continue` there goes (then
/// that jump is appended: a loop exit that rejoins the loop's follow). The
/// shortest wins; on a tie, plain fallthrough, then `break`, then `continue`.
fn site_tail(
    root: &Node,
    analysis: &Analysis,
    site: &Site,
    limits: Limits,
) -> Option<(Vec<Node>, Option<u64>)> {
    let mut best: Option<(Vec<Node>, Option<u64>)> = None;
    let options = [
        (Some(&site.scope.follow), None),
        (site.scope.brk.as_ref(), Some(BREAK_GOTO)),
        (site.scope.cont.as_ref(), Some(CONTINUE_GOTO)),
    ];
    for (flow, jump) in options {
        let Some(flow) = flow else {
            continue;
        };
        if let Some((copy, terminal)) = tail(root, analysis, site.target, flow, limits)
            && best
                .as_ref()
                .is_none_or(|(shortest, _)| copy.len() < shortest.len())
        {
            best = Some((copy, if terminal { None } else { jump }));
        }
    }
    best
}

/// `nodes`, then `break`/`continue` when `jump` says so.
fn jumping(nodes: Vec<Node>, jump: Option<u64>) -> Node {
    let body = list_of(nodes);
    match jump {
        None => body,
        Some(goto_kind) => Node {
            kind: kind::GOTO,
            index: body.index,
            last_op: body.last_op,
            label: None,
            detail: Detail::Goto {
                prints: true,
                goto_kind,
                target: None,
            },
            children: vec![body],
        },
    }
}

/// Goto sites replaced by a copy of their target's tail, either inside
/// their loop (`switch_tails`) or leaving it (`loop_exits`).
fn tails(root: &Node, analysis: &Analysis, leaving: bool, limits: Limits) -> Vec<Edit> {
    let mut edits = Vec::new();
    for site in &analysis.sites {
        if leaves_loop(site, analysis, root) != leaving {
            continue;
        }
        match site.form {
            Form::Goto => {
                let Some((copy, jump)) = site_tail(root, analysis, site, limits) else {
                    continue;
                };
                let Some(node) = node_at(root, &site.path) else {
                    continue;
                };
                let mut nodes = vec![node.children[0].clone()];
                nodes.extend(copy);
                let parent = site.path.split_last().filter(|(step, parent_path)| {
                    matches!(step, Step::Child(_))
                        && node_at(root, parent_path)
                            .is_some_and(|parent| matches!(parent.kind, kind::LIST | kind::GRAPH))
                });
                match (jump, parent) {
                    // Splice into the enclosing list when there is one.
                    (None, Some((Step::Child(position), parent_path))) => {
                        edits.push(Edit::Splice {
                            path: parent_path.to_vec(),
                            start: *position,
                            end: position + 1,
                            nodes,
                        })
                    }
                    _ => edits.push(Edit::Node(site.path.clone(), Box::new(jumping(nodes, jump)))),
                }
            }
            Form::If => {
                let Some(node) = node_at(root, &site.path) else {
                    continue;
                };
                if node.children.len() != 1 {
                    continue;
                }
                let Some((copy, jump)) = site_tail(root, analysis, site, limits) else {
                    continue;
                };
                let mut replaced = Node {
                    detail: Detail::If {
                        goto_kind: 0,
                        target: None,
                    },
                    ..node.clone()
                };
                replaced.children.push(jumping(copy, jump));
                edits.push(Edit::Node(site.path.clone(), Box::new(replaced)));
            }
            Form::Case(position) => {
                let Some(Detail::Switch { cases }) =
                    node_at(root, &site.path).map(|node| &node.detail)
                else {
                    continue;
                };
                // Out of the switch (`break`), on into the next case, or
                // `continue` for the loop around the switch.
                let next_case = node_at(root, &site.path).and_then(|switch| {
                    cases.get(position + 1).and_then(|case| match &case.body {
                        CaseBody::Child(child) => switch.children.get(*child).and_then(entry),
                        CaseBody::Block(block) => entry(block),
                        CaseBody::Goto { .. } => None,
                    })
                });
                let mut found = tail(root, analysis, site.target, &site.scope.follow, limits)
                    .map(|(copy, terminal)| (list_of(copy), !terminal));
                if found.is_none()
                    && let Some(next) = next_case
                {
                    found = tail(root, analysis, site.target, &Flow::Leaf(next), limits)
                        .map(|(copy, _)| (list_of(copy), false));
                }
                if found.is_none()
                    && let Some(cont) = &site.scope.cont
                {
                    found =
                        tail(root, analysis, site.target, cont, limits).map(|(copy, terminal)| {
                            (jumping(copy, (!terminal).then_some(CONTINUE_GOTO)), false)
                        });
                }
                let Some((body, exit)) = found else {
                    continue;
                };
                let mut cases = cases.clone();
                cases[position].exit = exit;
                cases[position].body = CaseBody::Block(Box::new(body));
                edits.push(Edit::Cases(site.path.clone(), cases));
            }
        }
    }
    edits
}

fn collapsed_edges(root: &Node, analysis: &Analysis) -> Vec<Edit> {
    let mut edits = Vec::new();
    // `if (a) goto L; if (b) goto L;` -> `if (a || b) goto L;`
    for path in &analysis.lists {
        let Some(list) = node_at(root, path) else {
            continue;
        };
        for position in 1..list.children.len() {
            let (first, second) = (&list.children[position - 1], &list.children[position]);
            let (
                Detail::If {
                    goto_kind: GOTO_GOTO,
                    target: Some(first_target),
                },
                Detail::If {
                    goto_kind: GOTO_GOTO,
                    target: Some(second_target),
                },
            ) = (&first.detail, &second.detail)
            else {
                continue;
            };
            if first.kind != kind::IF
                || second.kind != kind::IF
                || first.children.len() != 1
                || second.children.len() != 1
                || first_target.block != second_target.block
                || second.label.is_some()
                || !bare_condition(&second.children[0])
            {
                continue;
            }
            let (left, right) = (first.children[0].clone(), second.children[0].clone());
            let condition = Node {
                kind: kind::CONDITION,
                index: right.index,
                last_op: right.last_op,
                label: None,
                detail: Detail::Condition { and: false },
                children: vec![left, right],
            };
            let merged = Node {
                last_op: second.last_op,
                children: vec![condition],
                ..first.clone()
            };
            edits.push(Edit::Splice {
                path: path.clone(),
                start: position - 1,
                end: position + 1,
                nodes: vec![merged],
            });
        }
    }
    // The same pair inside a condition list: `s; if (a) goto L;` is
    // statements ahead of the test of `if (b) goto L;`.
    for path in &analysis.ifs {
        let Some(node) = node_at(root, path) else {
            continue;
        };
        let Detail::If {
            goto_kind: GOTO_GOTO,
            target: Some(target),
        } = &node.detail
        else {
            continue;
        };
        let Some(condition) = node
            .children
            .first()
            .filter(|condition| condition.kind == kind::LIST)
        else {
            continue;
        };
        let count = condition.children.len();
        if node.children.len() != 1 || count < 2 {
            continue;
        }
        let (inner, test) = (
            &condition.children[count - 2],
            &condition.children[count - 1],
        );
        let same = matches!(&inner.detail, Detail::If { goto_kind: GOTO_GOTO, target: Some(other) } if other.block == target.block);
        if inner.kind != kind::IF || !same || inner.children.len() != 1 || !bare_condition(test) {
            continue;
        }
        let either = Node {
            kind: kind::CONDITION,
            index: test.index,
            last_op: test.last_op,
            label: None,
            detail: Detail::Condition { and: false },
            children: vec![inner.children[0].clone(), test.clone()],
        };
        let mut lead = condition.children[..count - 2].to_vec();
        let merged_condition = if lead.is_empty() {
            either
        } else {
            lead.push(either);
            list_of(lead)
        };
        let merged = Node {
            children: vec![merged_condition],
            ..node.clone()
        };
        edits.push(Edit::Node(path.clone(), Box::new(merged)));
    }
    // if/else whose arms both end in `goto L` -> the if, then one `goto L`.
    for path in &analysis.ifs {
        let Some(node) = node_at(root, path) else {
            continue;
        };
        if node.children.len() != 3 || !matches!(node.detail, Detail::If { target: None, .. }) {
            continue;
        }
        let (Some(then), Some(otherwise)) = (
            ends_in_goto(&node.children[1]),
            ends_in_goto(&node.children[2]),
        ) else {
            continue;
        };
        if then.block != otherwise.block {
            continue;
        }
        let target = then.clone();
        let mut stripped = node.clone();
        strip_goto(&mut stripped.children[1]);
        strip_goto(&mut stripped.children[2]);
        let hoisted = Node {
            kind: kind::GOTO,
            index: node.index,
            last_op: node.last_op,
            label: None,
            detail: Detail::Goto {
                prints: true,
                goto_kind: GOTO_GOTO,
                target: Some(target),
            },
            children: vec![stripped],
        };
        edits.push(Edit::Node(path.clone(), Box::new(hoisted)));
    }
    // Switch cases jumping to the same block share one goto.
    for path in &analysis.switches {
        let Some(Detail::Switch { cases }) = node_at(root, path).map(|node| &node.detail) else {
            continue;
        };
        for later in 1..cases.len() {
            let CaseBody::Goto {
                goto_kind: GOTO_GOTO,
                target: Some(target),
            } = &cases[later].body
            else {
                continue;
            };
            let Some(earlier) = (0..later).find(|position| {
                matches!(&cases[*position].body, CaseBody::Goto { goto_kind: GOTO_GOTO, target: Some(other) } if other.block == target.block)
            }) else {
                continue;
            };
            let mut merged = cases.clone();
            let moved = merged.remove(later);
            merged[earlier].labels.extend(moved.labels);
            edits.push(Edit::Cases(path.clone(), merged));
        }
    }
    edits
}

/// The target of the `goto` an arm ends with.
fn ends_in_goto(node: &Node) -> Option<&GotoTarget> {
    match (&node.detail, node.kind) {
        (
            Detail::Goto {
                prints: true,
                goto_kind: GOTO_GOTO,
                target,
            },
            kind::GOTO,
        ) => target.as_ref(),
        (_, kind::LIST) => node.children.last().and_then(ends_in_goto),
        _ => None,
    }
}

fn strip_goto(node: &mut Node) {
    if node.kind == kind::GOTO {
        let body = node.children.swap_remove(0);
        *node = body;
    } else if let Some(last) = node.children.last_mut() {
        strip_goto(last);
    }
}

fn irreducible_entry(root: &Node, analysis: &Analysis, limits: Limits) -> Vec<Edit> {
    let mut edits = Vec::new();
    for site in &analysis.sites {
        if site.form != Form::If {
            continue;
        }
        let Some((Step::Child(position), parent_path)) = site.path.split_last() else {
            continue;
        };
        let position = *position;
        let Some(list) = node_at(root, parent_path) else {
            continue;
        };
        if !matches!(list.kind, kind::LIST | kind::GRAPH) || position + 1 >= list.children.len() {
            continue;
        }
        let node = &list.children[position];
        if node.children.len() != 1 {
            continue;
        }
        // `if (c) goto L; R; L: ...` -> `if (!c) { R }`, also when L is
        // where the list itself continues.
        let continues_to_target = analysis
            .scopes
            .get(parent_path)
            .is_some_and(|scope| scope.follow.is(site.target));
        if let Some(skip_to) = (position + 2..list.children.len())
            .find(|later| entry(&list.children[*later]) == Some(site.target))
            .or_else(|| continues_to_target.then_some(list.children.len()))
            && negatable(&node.children[0])
        {
            let mut condition = node.children[0].clone();
            negate(&mut condition);
            let body = list_of(list.children[position + 1..skip_to].to_vec());
            let replaced = Node {
                detail: Detail::If {
                    goto_kind: 0,
                    target: None,
                },
                children: vec![condition, body],
                ..node.clone()
            };
            edits.push(Edit::Splice {
                path: parent_path.to_vec(),
                start: position,
                end: skip_to,
                nodes: vec![replaced],
            });
        }
        // `if (c) goto L; R` -> `if (c) { tail of L } else { R }`.
        let Some(list_scope) = analysis.scopes.get(parent_path) else {
            continue;
        };
        let Some((copy, false)) = tail(root, analysis, site.target, &list_scope.follow, limits)
        else {
            continue;
        };
        let rest = list_of(list.children[position + 1..].to_vec());
        let replaced = Node {
            detail: Detail::If {
                goto_kind: 0,
                target: None,
            },
            children: vec![node.children[0].clone(), list_of(copy), rest],
            ..node.clone()
        };
        edits.push(Edit::Splice {
            path: parent_path.to_vec(),
            start: position,
            end: list.children.len(),
            nodes: vec![replaced],
        });
    }
    // `if (c) { A; goto L; } R` -> `if (c) { A; tail of L } else { R }`.
    for site in &analysis.sites {
        if site.form != Form::Goto {
            continue;
        }
        let Some(goto_node) = node_at(root, &site.path) else {
            continue;
        };
        // The goto ends the then-arm of an if without an else.
        let Some((Step::Child(slot), parent_path)) = site.path.split_last() else {
            continue;
        };
        let Some(parent) = node_at(root, parent_path) else {
            continue;
        };
        let (if_path, lead): (&[Step], &[Node]) = match parent.kind {
            kind::IF if *slot == 1 => (parent_path, &[]),
            kind::LIST if *slot + 1 == parent.children.len() => match parent_path.split_last() {
                Some((Step::Child(1), if_path)) => (if_path, &parent.children[..*slot]),
                _ => continue,
            },
            _ => continue,
        };
        let Some(if_node) = node_at(root, if_path) else {
            continue;
        };
        if if_node.kind != kind::IF
            || if_node.children.len() != 2
            || !matches!(if_node.detail, Detail::If { target: None, .. })
        {
            continue;
        }
        let Some((Step::Child(position), list_path)) = if_path.split_last() else {
            continue;
        };
        let Some(list) = node_at(root, list_path) else {
            continue;
        };
        if !analysis.lists.iter().any(|path| path == list_path)
            || position + 1 >= list.children.len()
        {
            continue;
        }
        let Some(list_scope) = analysis.scopes.get(list_path) else {
            continue;
        };
        let Some((copy, false)) = tail(root, analysis, site.target, &list_scope.follow, limits)
        else {
            continue;
        };
        let mut then = lead.to_vec();
        then.push(goto_node.children[0].clone());
        then.extend(copy);
        let replaced = Node {
            children: vec![
                if_node.children[0].clone(),
                list_of(then),
                list_of(list.children[position + 1..].to_vec()),
            ],
            ..if_node.clone()
        };
        edits.push(Edit::Splice {
            path: list_path.to_vec(),
            start: *position,
            end: list.children.len(),
            nodes: vec![replaced],
        });
    }
    edits
}

/// Where `target` starts a statement of the list at `list_path` after
/// `position`, or `len` when it is where the list itself continues.
fn later_in_list(
    analysis: &Analysis,
    list_path: &[Step],
    list: &Node,
    position: usize,
    target: i64,
) -> Option<usize> {
    (position + 1..list.children.len())
        .find(|later| entry(&list.children[*later]) == Some(target))
        .or_else(|| {
            analysis
                .scopes
                .get(list_path)
                .is_some_and(|scope| scope.follow.is(target))
                .then_some(list.children.len())
        })
}

/// `arm`, then `moved`.
fn append(arm: &Node, moved: &[Node]) -> Node {
    if arm.kind == kind::LIST && arm.label.is_none() {
        let mut arm = arm.clone();
        arm.children.extend(moved.iter().cloned());
        fix_flow_breaks(&mut arm);
        arm
    } else {
        let mut nodes = vec![arm.clone()];
        nodes.extend(moved.iter().cloned());
        list_of(nodes)
    }
}

/// The if a `goto` ends one arm of: (if path, arm, the arm's statements
/// ahead of the goto).
fn arm_end<'r>(root: &'r Node, site: &'r Site) -> Option<(&'r [Step], usize, &'r [Node])> {
    let (Step::Child(slot), parent_path) = site.path.split_last()? else {
        return None;
    };
    let parent = node_at(root, parent_path)?;
    match parent.kind {
        kind::IF if matches!(slot, 1 | 2) => Some((parent_path, *slot, &[])),
        kind::LIST if *slot + 1 == parent.children.len() => match parent_path.split_last()? {
            (Step::Child(arm @ (1 | 2)), if_path) => {
                Some((if_path, *arm, &parent.children[..*slot]))
            }
            _ => None,
        },
        _ => None,
    }
}

/// `if (c) { A; goto L; } R; L:` -> `if (c) { A } else { R }`, and the same
/// for a goto ending the else arm (R then follows the then arm): the code
/// the goto skips becomes the other arm. Nothing is copied.
fn else_join(root: &Node, analysis: &Analysis) -> Vec<Edit> {
    let mut edits = Vec::new();
    for site in &analysis.sites {
        if site.form != Form::Goto {
            continue;
        }
        let (Some(goto_node), Some((if_path, arm, lead))) =
            (node_at(root, &site.path), arm_end(root, site))
        else {
            continue;
        };
        let Some(if_node) = node_at(root, if_path) else {
            continue;
        };
        let Some((Step::Child(position), list_path)) = if_path.split_last() else {
            continue;
        };
        let Some(list) = node_at(root, list_path) else {
            continue;
        };
        if if_node.kind != kind::IF
            || !matches!(if_node.detail, Detail::If { target: None, .. })
            || !analysis.lists.iter().any(|path| path == list_path)
        {
            continue;
        }
        let Some(end) = later_in_list(analysis, list_path, list, *position, site.target) else {
            continue;
        };
        if end == position + 1 {
            continue;
        }
        let skipped = &list.children[position + 1..end];
        let mut kept = lead.to_vec();
        kept.push(goto_node.children[0].clone());
        let mut replaced = if_node.clone();
        replaced.children[arm] = list_of(kept);
        if arm == 2 {
            replaced.children[1] = append(&if_node.children[1], skipped);
        } else if let Some(otherwise) = if_node.children.get(2) {
            replaced.children[2] = append(otherwise, skipped);
        } else {
            replaced.children.push(list_of(skipped.to_vec()));
        }
        edits.push(Edit::Splice {
            path: list_path.to_vec(),
            start: *position,
            end,
            nodes: vec![replaced],
        });
    }
    edits
}

/// `if (c) { ... goto L ... } M; L:` -> `if (c) { ... goto L ... M } else
/// { M }`: the statements M between an if holding a goto to L and L itself
/// move into every arm that falls through to them, so the goto skips to
/// the end of its arm, which the other models then remove (a negated if,
/// [`else_join`], a dropped goto). This reverses the compiler merging
/// equal tails (cross-jumping) and threading a jump past a test it knows
/// the outcome of, at the cost of the copies of M. Returns (L, edit);
/// `only` keeps the sinks towards one label.
fn sink_join(root: &Node, analysis: &Analysis, only: Option<i64>) -> Vec<(i64, Edit)> {
    let mut edits = Vec::new();
    let mut seen: Vec<(&[Step], usize)> = Vec::new();
    for site in &analysis.sites {
        if only.is_some_and(|target| target != site.target) {
            continue;
        }
        // The lists holding the site in an if's arm or a switch's case,
        // innermost first.
        let mut spots: Vec<(&[Step], usize, Step)> = Vec::new();
        if let Form::Case(position) = site.form {
            // `case n: goto L;`: the site is the switch itself.
            if let Some((Step::Child(at), list_path)) = site.path.split_last() {
                spots.push((list_path, *at, Step::Case(position)));
            }
        } else {
            for depth in (0..site.path.len().saturating_sub(1)).rev() {
                let (list_path, rest) = site.path.split_at(depth);
                if let Step::Child(position) = rest[0] {
                    spots.push((list_path, position, rest[1]));
                }
            }
        }
        for (list_path, position, inside) in spots {
            if !analysis.lists.iter().any(|path| path == list_path) {
                continue;
            }
            let Some(list) = node_at(root, list_path) else {
                continue;
            };
            let statement = &list.children[position];
            let wanted = match (statement.kind, &statement.detail) {
                (kind::IF, Detail::If { target: None, .. }) => {
                    matches!(inside, Step::Child(1 | 2))
                }
                (kind::SWITCH, Detail::Switch { .. }) => true,
                _ => false,
            };
            if !wanted {
                continue;
            }
            let Some(end) = later_in_list(analysis, list_path, list, position, site.target) else {
                continue;
            };
            let moved = &list.children[position + 1..end];
            let (mut statements, mut leaves) = (0, 0);
            if moved.is_empty()
                || moved.iter().any(has_label)
                || !moved
                    .iter()
                    .all(|node| copyable(node, &mut statements, &mut leaves))
                || seen.contains(&(list_path, position))
            {
                break;
            }
            let replaced = if statement.kind == kind::SWITCH {
                match sink_switch(statement, moved, site.target) {
                    Some(replaced) => replaced,
                    None => break,
                }
            } else {
                let mut replaced = statement.clone();
                if completes(&statement.children[1]) {
                    replaced.children[1] = append(&statement.children[1], moved);
                }
                match statement.children.get(2) {
                    Some(otherwise) if completes(otherwise) => {
                        replaced.children[2] = append(otherwise, moved);
                    }
                    Some(_) => {}
                    None => replaced.children.push(list_of(moved.to_vec())),
                }
                replaced
            };
            seen.push((list_path, position));
            edits.push((
                site.target,
                Edit::Splice {
                    path: list_path.to_vec(),
                    start: position,
                    end,
                    nodes: vec![replaced],
                },
            ));
            break;
        }
    }
    edits
}

/// A switch whose every case that reaches its end (a `break` or the last
/// case falling out) runs `moved` first, and whose `case n: goto L` becomes
/// an empty case: the compiler's lowered `switch` with a shared tail after
/// it, undone. `None` when a case holds a `break` of its own (it would
/// bypass the copy).
fn sink_switch(switch: &Node, moved: &[Node], target: i64) -> Option<Node> {
    let Detail::Switch { cases } = &switch.detail else {
        return None;
    };
    let in_place_break = cases.iter().any(|case| match &case.body {
        CaseBody::Block(block) => breaks_out(block),
        _ => false,
    });
    if switch.children.iter().skip(1).any(breaks_out) || in_place_break || cases.is_empty() {
        return None;
    }
    let mut replaced = switch.clone();
    let mut new_cases = cases.clone();
    for (position, case) in new_cases.iter_mut().enumerate() {
        let relocate = matches!(
            &case.body,
            CaseBody::Goto { goto_kind: GOTO_GOTO, target: Some(to) } if to.block == target
        );
        if relocate {
            case.exit = true;
            case.body = CaseBody::Block(Box::new(list_of(Vec::new())));
            continue;
        }
        if !(case.exit || position + 1 == cases.len()) {
            continue;
        }
        match &mut case.body {
            CaseBody::Child(child) => {
                let body = &replaced.children[*child];
                if completes(body) {
                    let appended = append(body, moved);
                    replaced.children[*child] = appended;
                }
            }
            CaseBody::Block(block) => {
                if completes(block) {
                    let appended = append(block, moved);
                    **block = appended;
                }
            }
            CaseBody::Goto { .. } => {}
        }
    }
    if let Detail::Switch { cases } = &mut replaced.detail {
        *cases = new_cases;
    }
    Some(replaced)
}

/// `if (a) { if (b) T }` -> `if (a && b) T`, and the same for an inner
/// `if (b) goto L;`: Ghidra keeps the nested ifs when the inner one is
/// an unstructured jump, which hides `if (a && b) goto L; R; L:` from the
/// models that negate it (`irreducible_entry`). Only the inner test must
/// print nothing but itself (`&&` short-circuits what ran before it); kept
/// only when the follow-ups remove a goto ([`Run::attempt_sink`]).
fn cond_merge(root: &Node, analysis: &Analysis) -> Vec<Edit> {
    let mut edits = Vec::new();
    for path in &analysis.ifs {
        let Some(outer) = node_at(root, path) else {
            continue;
        };
        if outer.kind != kind::IF
            || !matches!(outer.detail, Detail::If { target: None, .. })
            || outer.children.len() != 2
        {
            continue;
        }
        let body = &outer.children[1];
        let inner = if body.kind == kind::LIST && body.label.is_none() && body.children.len() == 1 {
            &body.children[0]
        } else {
            body
        };
        let Detail::If {
            target: inner_target,
            ..
        } = &inner.detail
        else {
            continue;
        };
        let shaped = if inner_target.is_some() {
            inner.children.len() == 1
        } else {
            inner.children.len() == 2
        };
        if inner.kind != kind::IF
            || inner.label.is_some()
            || !shaped
            || !bare_condition(&inner.children[0])
        {
            continue;
        }
        let condition = Node {
            kind: kind::CONDITION,
            index: inner.children[0].index,
            last_op: inner.children[0].last_op,
            label: None,
            detail: Detail::Condition { and: true },
            children: vec![outer.children[0].clone(), inner.children[0].clone()],
        };
        let mut merged = outer.clone();
        merged.detail = inner.detail.clone();
        merged.last_op = inner.last_op;
        merged.children = std::iter::once(condition)
            .chain(inner.children[1..].iter().cloned())
            .collect();
        edits.push(Edit::Node(path.clone(), Box::new(merged)));
    }
    edits
}

mod thread;

#[cfg(test)]
mod tests;
