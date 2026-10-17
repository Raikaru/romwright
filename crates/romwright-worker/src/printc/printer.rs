//! PrintC's block layer (`docFunction`, `emitBlock*`, statement, label,
//! goto and comment placement), ported from the pinned
//! `third_party/ghidra/decompiler/printc.cc` (Apache-2.0) to run over the
//! exported block tree. Expressions, declarations, labels and comment lines
//! are fragments PrintC's own handlers produced; they are replayed into the
//! pretty printer in the order this layer decides.

use super::ir::{
    Basic, CaseBody, Detail, Event, Expression, Fragment, Node, PrinterIr, Source, kind,
};
use super::pretty::{CONST_COLOR, KEYWORD_COLOR, NO_COLOR, PrettyPrint};

type Result<T, E = String> = std::result::Result<T, E>;

// PrintLanguage::modifiers.
const NO_BRANCH: u32 = 0x80;
const ONLY_BRANCH: u32 = 0x100;
const COMMA_SEPARATE: u32 = 0x200;
const NOFALLTHRU: u32 = 0x1000;
const PENDING_BRACE: u32 = 0x8000;

// FlowBlock::block_flags for unstructured branches.
const GOTO_GOTO: u64 = 1;
const BREAK_GOTO: u64 = 2;
const CONTINUE_GOTO: u64 = 4;

struct Printer<'a> {
    ir: &'a PrinterIr,
    emit: PrettyPrint,
    mods: u32,
    mod_stack: Vec<u32>,
    /// `Comment::isEmitted`, by comment slot.
    emitted: Vec<bool>,
    /// `CommentSorter` state: the block last set up and the walk position.
    sorter: Option<(&'a Basic, usize)>,
    /// Which part of the function [`Printer::replay`] is replaying for.
    region: &'static str,
    /// Text events replayed from PrintC fragments (docs/ownership.md).
    fragments: FragmentCounts,
}

/// Text tokens the printer took from fragments PrintC's own handlers
/// recorded, by the part of the function and the kind of token. Every other
/// token was emitted by this module's block layer.
#[derive(Clone, Debug, Default)]
pub struct FragmentCounts {
    pub by_region: std::collections::BTreeMap<&'static str, u64>,
    pub by_kind: std::collections::BTreeMap<&'static str, u64>,
    pub total: u64,
    /// Text tokens of expressions the worker's own printer rendered
    /// (`printc/render.rs`), by kind of token.
    pub rust_by_kind: std::collections::BTreeMap<&'static str, u64>,
    pub rust_total: u64,
    /// Text and spacing tokens handed to the pretty printer.
    pub text_tokens: u64,
    pub spacing_tokens: u64,
}

/// Prints the function; returns the markup and the TokenSplit ids consumed.
pub fn print_function(ir: &PrinterIr, count_base: i32) -> Result<(Vec<u8>, i32)> {
    let (markup, consumed, _) = print_function_counted(ir, count_base)?;
    Ok((markup, consumed))
}

/// [`print_function`], also accounting for where each text token came from.
pub fn print_function_counted(
    ir: &PrinterIr,
    count_base: i32,
) -> Result<(Vec<u8>, i32, FragmentCounts)> {
    let mut printer = Printer {
        ir,
        emit: PrettyPrint::new(ir.max_line_size, ir.indent_increment, count_base),
        mods: 0,
        mod_stack: Vec::new(),
        emitted: vec![false; ir.comment_slots],
        sorter: None,
        region: "body",
        fragments: FragmentCounts::default(),
    };
    printer.doc_function()?;
    let consumed = printer.emit.count_base().wrapping_sub(count_base);
    let mut fragments = std::mem::take(&mut printer.fragments);
    fragments.text_tokens = printer.emit.text_tokens();
    fragments.spacing_tokens = printer.emit.spacing_tokens();
    Ok((printer.emit.into_bytes(), consumed, fragments))
}

/// The kind a replayed event counts as when it is a visible text token.
fn text_kind(event: &Event) -> Option<&'static str> {
    Some(match event {
        Event::Variable { .. } => "variable",
        Event::Op { .. } => "operator",
        Event::FuncName { .. } => "function_name",
        Event::Type { .. } => "type",
        Event::Field { .. } | Event::BitField { .. } => "field",
        Event::Comment { .. } => "comment",
        Event::Label { .. } => "label",
        Event::CaseLabel { .. } => "case_label",
        Event::Print { .. } => "punctuation",
        Event::OpenParen(..) | Event::CloseParen(..) => "paren",
        _ => return None,
    })
}

impl<'a> Printer<'a> {
    fn is_set(&self, mods: u32) -> bool {
        self.mods & mods != 0
    }

    fn push_mod(&mut self) {
        self.mod_stack.push(self.mods);
    }

    fn pop_mod(&mut self) -> Result<()> {
        self.mods = self
            .mod_stack
            .pop()
            .ok_or("printing modification stack underflow")?;
        Ok(())
    }

    fn set_mod(&mut self, mods: u32) {
        self.mods |= mods;
    }

    fn unset_mod(&mut self, mods: u32) {
        self.mods &= !mods;
    }

    /// Replays one fragment PrintC recorded.
    fn replay(&mut self, fragment: &Fragment) -> Result<()> {
        self.replay_from(fragment, Source::Fragments)
    }

    /// Replays one fragment, mapping its local ids onto the printer's;
    /// `source` says who produced it (docs/ownership.md).
    fn replay_from(&mut self, fragment: &Fragment, source: Source) -> Result<()> {
        let mut ids: Vec<i32> = Vec::new();
        fn opened(ids: &mut Vec<i32>, local: u64, id: i32) -> Result<()> {
            if local != ids.len() as u64 + 1 {
                return Err(format!("fragment id {local} opened out of order"));
            }
            ids.push(id);
            Ok(())
        }
        fn mapped(ids: &[i32], local: u64) -> Result<i32> {
            local
                .checked_sub(1)
                .and_then(|index| ids.get(index as usize))
                .copied()
                .ok_or_else(|| format!("fragment closes unopened id {local}"))
        }
        let emit = &mut self.emit;
        for event in &fragment.0 {
            if let Some(kind) = text_kind(event) {
                if source == Source::Rust {
                    *self.fragments.rust_by_kind.entry(kind).or_default() += 1;
                    self.fragments.rust_total += 1;
                } else {
                    *self.fragments.by_kind.entry(kind).or_default() += 1;
                    *self.fragments.by_region.entry(self.region).or_default() += 1;
                    self.fragments.total += 1;
                }
            }
            match event {
                Event::BeginDocument(local) => opened(&mut ids, *local, emit.begin_document())?,
                Event::EndDocument(local) => emit.end_document(mapped(&ids, *local)?),
                Event::BeginFunction(local) => opened(&mut ids, *local, emit.begin_function())?,
                Event::EndFunction(local) => emit.end_function(mapped(&ids, *local)?),
                Event::BeginBlock(local, index) => {
                    opened(&mut ids, *local, emit.begin_block(*index))?
                }
                Event::EndBlock(local) => emit.end_block(mapped(&ids, *local)?),
                Event::TagLine => emit.tag_line(),
                Event::TagLineIndent(indent) => emit.tag_line_indent(*indent),
                Event::BeginReturnType(local, varnode) => {
                    opened(&mut ids, *local, emit.begin_return_type(*varnode))?
                }
                Event::EndReturnType(local) => emit.end_return_type(mapped(&ids, *local)?),
                Event::BeginVarDecl(local, symbol) => {
                    opened(&mut ids, *local, emit.begin_var_decl(*symbol))?
                }
                Event::EndVarDecl(local) => emit.end_var_decl(mapped(&ids, *local)?),
                Event::BeginStatement(local, op) => {
                    opened(&mut ids, *local, emit.begin_statement(*op))?
                }
                Event::EndStatement(local) => emit.end_statement(mapped(&ids, *local)?),
                Event::BeginFuncProto(local) => opened(&mut ids, *local, emit.begin_func_proto())?,
                Event::EndFuncProto(local) => emit.end_func_proto(mapped(&ids, *local)?),
                Event::Variable {
                    name,
                    highlight,
                    varnode,
                    op,
                } => emit.tag_variable(name, *highlight, *varnode, *op),
                Event::Op {
                    name,
                    highlight,
                    op,
                } => emit.tag_op(name, *highlight, *op),
                Event::FuncName {
                    name,
                    highlight,
                    op,
                } => emit.tag_func_name(name, *highlight, *op),
                Event::Type {
                    name,
                    highlight,
                    id,
                } => emit.tag_type(name, *highlight, *id),
                Event::Field {
                    name,
                    highlight,
                    field,
                } => emit.tag_field(name, *highlight, field.clone()),
                Event::BitField {
                    name,
                    highlight,
                    field,
                } => emit.tag_bit_field(name, *highlight, field.clone()),
                Event::Comment {
                    name,
                    highlight,
                    space,
                    offset,
                } => emit.tag_comment(name, *highlight, *space, *offset),
                Event::Label {
                    name,
                    highlight,
                    space,
                    offset,
                } => emit.tag_label(name, *highlight, *space, *offset),
                Event::CaseLabel {
                    name,
                    highlight,
                    op,
                    value,
                } => emit.tag_case_label(name, *highlight, *op, *value),
                Event::Print { text, highlight } => emit.print(text, *highlight),
                Event::OpenParen(local, paren) => opened(&mut ids, *local, emit.open_paren(paren))?,
                Event::CloseParen(local, paren) => emit.close_paren(paren, mapped(&ids, *local)?),
                Event::OpenGroup(local) => opened(&mut ids, *local, emit.open_group())?,
                Event::CloseGroup(local) => emit.close_group(mapped(&ids, *local)?),
                Event::Spaces(count, bump) => emit.spaces(*count, *bump),
                Event::StartIndent(local) => opened(&mut ids, *local, emit.start_indent())?,
                Event::StopIndent(local) => emit.stop_indent(mapped(&ids, *local)?),
                Event::StartComment(local) => opened(&mut ids, *local, emit.start_comment())?,
                Event::StopComment(local) => emit.stop_comment(mapped(&ids, *local)?),
            }
        }
        Ok(())
    }

    /// `PrintC::docFunction`.
    fn doc_function(&mut self) -> Result<()> {
        let ir = self.ir;
        let function = self.emit.begin_function();
        self.region = "header";
        self.replay(&ir.header)?;
        self.emit.tag_line();
        self.region = "declaration";
        self.replay(&ir.declaration)?;
        let brace = self.emit.open_brace_indent("{", ir.brace_function);
        self.region = "locals";
        self.replay(&ir.locals)?;
        self.region = "body";
        self.block_graph(&ir.body)?;
        self.emit.close_brace_indent("}", brace);
        self.emit.tag_line();
        self.emit.end_function(function);
        self.emit.flush()?;
        if !self.mod_stack.is_empty() || self.mods != 0 {
            return Err("Printing modification stack has not been purged".into());
        }
        Ok(())
    }

    /// `FlowBlock::emit` dispatch.
    fn block(&mut self, node: &'a Node) -> Result<()> {
        match node.kind {
            kind::PLAIN => Ok(()),
            kind::BASIC => self.block_basic(node),
            kind::GRAPH => self.block_graph(&node.children),
            kind::COPY => {
                self.any_label_statement(node)?;
                self.block(&node.children[0])
            }
            kind::GOTO => self.block_goto(node),
            kind::MULTIGOTO => self.block(&node.children[0]),
            kind::LIST => self.block_list(node),
            kind::CONDITION => self.block_condition(node),
            kind::IF => self.block_if(node),
            kind::WHILE_DO => self.block_while_do(node),
            kind::DO_WHILE => self.block_do_while(node),
            kind::SWITCH => self.block_switch(node),
            kind::INFINITE_LOOP => self.block_infinite_loop(node),
            other => Err(format!("unknown block kind {other}")),
        }
    }

    fn wrapped(&mut self, node: &'a Node) -> Result<()> {
        let id = self.emit.begin_block(node.index);
        self.block(node)?;
        self.emit.end_block(id);
        Ok(())
    }

    /// `PrintC::emitBlockGraph`.
    fn block_graph(&mut self, children: &'a [Node]) -> Result<()> {
        for child in children {
            self.wrapped(child)?;
        }
        Ok(())
    }

    fn basic_of(node: &'a Node) -> Result<&'a Basic> {
        match &node.detail {
            Detail::Basic(basic) => Ok(basic),
            _ => Err("basic block without statements".into()),
        }
    }

    /// `PrintC::emitBlockBasic` in structured mode.
    fn block_basic(&mut self, node: &'a Node) -> Result<()> {
        let basic = Self::basic_of(node)?;
        self.sorter = Some((basic, 0));
        if self.is_set(ONLY_BRANCH) {
            if let Some(branch) = &basic.branch {
                let comma = self.is_set(COMMA_SEPARATE);
                self.replay_from(branch.select(comma), branch.source)?;
            }
            return Ok(());
        }
        let mut separator = false;
        for statement in &basic.statements {
            if statement.is_branch && self.is_set(NO_BRANCH) {
                continue;
            }
            let comma = self.is_set(COMMA_SEPARATE);
            if separator {
                if comma {
                    self.emit.print(",", NO_COLOR);
                    self.emit.spaces(1, 0);
                } else {
                    self.comment_group(Some(statement.comment_bound))?;
                    self.emit.tag_line();
                }
            } else if !comma {
                self.comment_group(Some(statement.comment_bound))?;
                self.emit.tag_line();
            }
            self.statement(statement.op, &statement.expression)?;
            separator = true;
        }
        self.comment_group(None)
    }

    /// `PrintC::emitStatement`.
    fn statement(&mut self, op: u64, expression: &Expression) -> Result<()> {
        let comma = self.is_set(COMMA_SEPARATE);
        let id = self.emit.begin_statement(Some(op));
        self.replay_from(expression.select(comma), expression.source)?;
        self.emit.end_statement(id);
        if !comma {
            self.emit.print(";", NO_COLOR);
        }
        Ok(())
    }

    /// `PrintC::emitCommentGroup`; `bound` is `setupOpList` for a statement,
    /// `None` for the block's remaining comments.
    fn comment_group(&mut self, bound: Option<usize>) -> Result<()> {
        let Some((basic, mut start)) = self.sorter else {
            return Ok(());
        };
        let stop = bound.unwrap_or(basic.comments.len());
        while start < stop {
            let comment = &basic.comments[start];
            start += 1;
            self.sorter = Some((basic, start));
            if self.emitted[comment.slot] || !comment.printable {
                continue;
            }
            self.replay(&comment.line)?;
            self.emitted[comment.slot] = true;
        }
        self.sorter = Some((basic, start));
        Ok(())
    }

    /// `PrintC::emitCommentBlockTree`.
    fn comment_block_tree(&mut self, node: &'a Node) -> Result<()> {
        let node = if node.kind == kind::COPY {
            &node.children[0]
        } else {
            node
        };
        if node.kind == kind::PLAIN {
            return Ok(());
        }
        if node.kind != kind::BASIC {
            for child in &node.children {
                self.comment_block_tree(child)?;
            }
            return Ok(());
        }
        self.sorter = Some((Self::basic_of(node)?, 0));
        self.comment_group(None)
    }

    /// `PrintC::emitAnyLabelStatement`.
    fn any_label_statement(&mut self, node: &'a Node) -> Result<()> {
        if self.is_set(ONLY_BRANCH) {
            return Ok(());
        }
        if let Some(label) = &node.label {
            self.emit.tag_line_indent(0);
            self.replay(label)?;
            self.emit.print(":", NO_COLOR);
        }
        Ok(())
    }

    /// `PrintC::emitGotoStatement`; `source_op` is the source block's last op.
    fn goto_statement(
        &mut self,
        source_op: Option<u64>,
        goto_kind: u64,
        target: Option<&Fragment>,
    ) -> Result<()> {
        let id = self.emit.begin_statement(source_op);
        match goto_kind {
            BREAK_GOTO => self.emit.print("break", KEYWORD_COLOR),
            CONTINUE_GOTO => self.emit.print("continue", KEYWORD_COLOR),
            GOTO_GOTO => {
                self.emit.print("goto", KEYWORD_COLOR);
                self.emit.spaces(1, 0);
                if let Some(target) = target {
                    self.replay(target)?;
                }
            }
            _ => {}
        }
        self.emit.print(";", NO_COLOR);
        self.emit.end_statement(id);
        Ok(())
    }

    /// `PrintC::emitBlockGoto`.
    fn block_goto(&mut self, node: &'a Node) -> Result<()> {
        let Detail::Goto {
            prints,
            goto_kind,
            target,
        } = &node.detail
        else {
            return Err("goto block without its edge".into());
        };
        let body = &node.children[0];
        self.push_mod();
        self.set_mod(NO_BRANCH);
        self.block(body)?;
        self.pop_mod()?;
        if *prints {
            self.emit.tag_line();
            self.goto_statement(body.last_op, *goto_kind, target.as_ref().map(|t| &t.label))?;
        }
        Ok(())
    }

    /// `PrintC::emitBlockLs`.
    fn block_list(&mut self, node: &'a Node) -> Result<()> {
        let Detail::List { flow_breaks } = &node.detail else {
            return Err("list block without flow".into());
        };
        let children = &node.children;
        if self.is_set(ONLY_BRANCH) {
            if let Some(last) = children.last() {
                self.block(last)?;
            }
            return Ok(());
        }
        let Some(first) = children.first() else {
            return Ok(());
        };
        let id = self.emit.begin_block(first.index);
        if children.len() == 1 {
            self.block(first)?;
            self.emit.end_block(id);
            return Ok(());
        }
        self.push_mod();
        self.set_mod(NO_BRANCH);
        self.list_member(first, flow_breaks[0])?;
        self.emit.end_block(id);
        for position in 1..children.len() - 1 {
            let child = &children[position];
            let id = self.emit.begin_block(child.index);
            self.list_member(child, flow_breaks[position])?;
            self.emit.end_block(id);
        }
        self.pop_mod()?;
        let last = &children[children.len() - 1];
        let id = self.emit.begin_block(last.index);
        self.block(last)?;
        self.emit.end_block(id);
        Ok(())
    }

    fn list_member(&mut self, child: &'a Node, flow_break: bool) -> Result<()> {
        if flow_break {
            self.push_mod();
            self.set_mod(NOFALLTHRU);
            self.block(child)?;
            self.pop_mod()
        } else {
            self.block(child)
        }
    }

    /// `PrintC::emitBlockCondition`.
    fn block_condition(&mut self, node: &'a Node) -> Result<()> {
        let Detail::Condition { and } = node.detail else {
            return Err("condition block without its operator".into());
        };
        let (left, right) = (&node.children[0], &node.children[1]);
        if self.is_set(NO_BRANCH) {
            return self.wrapped(left);
        }
        if self.is_set(ONLY_BRANCH) || self.is_set(COMMA_SEPARATE) {
            let id = self.emit.open_paren("(");
            self.block(left)?;
            self.push_mod();
            self.unset_mod(ONLY_BRANCH);
            self.set_mod(COMMA_SEPARATE);
            // emitOp of boolean_and/boolean_or (printc.cc:53-55): binary,
            // spacing 1, bump 0, no op.
            self.emit.spaces(1, 0);
            self.emit
                .tag_op(if and { "&&" } else { "||" }, NO_COLOR, None);
            self.emit.spaces(1, 0);
            let inner = self.emit.open_paren("(");
            self.block(right)?;
            self.emit.close_paren(")", inner);
            self.pop_mod()?;
            self.emit.close_paren(")", id);
        }
        Ok(())
    }

    /// `PrintC::emitBlockIf`.
    fn block_if(&mut self, node: &'a Node) -> Result<()> {
        let Detail::If { goto_kind, target } = &node.detail else {
            return Err("if block without its edge".into());
        };
        let style = self.ir.brace_if_else;
        let pending = self
            .is_set(PENDING_BRACE)
            .then(|| self.emit.set_pending_brace(style));
        self.push_mod();
        self.unset_mod(NO_BRANCH | ONLY_BRANCH | PENDING_BRACE);
        self.push_mod();
        self.set_mod(NO_BRANCH);
        let condition = &node.children[0];
        self.block(condition)?;
        self.pop_mod()?;
        self.comment_block_tree(condition)?;
        if pending.is_some_and(|pending| self.emit.has_pending(pending)) {
            self.emit.cancel_pending();
            self.emit.spaces(1, 0);
        } else {
            self.emit.tag_line();
        }
        self.emit.tag_op("if", KEYWORD_COLOR, condition.last_op);
        self.emit.spaces(1, 0);
        self.push_mod();
        self.set_mod(ONLY_BRANCH);
        self.block(condition)?;
        self.pop_mod()?;
        if let Some(target) = target {
            self.emit.spaces(1, 0);
            self.goto_statement(condition.last_op, *goto_kind, Some(&target.label))?;
        } else {
            self.set_mod(NO_BRANCH);
            let id = self.emit.open_brace_indent("{", style);
            self.wrapped(&node.children[1])?;
            self.emit.close_brace_indent("}", id);
            if let Some(otherwise) = node.children.get(2) {
                self.emit.tag_line();
                self.emit.print("else", KEYWORD_COLOR);
                if otherwise.kind == kind::IF {
                    self.set_mod(PENDING_BRACE);
                    self.wrapped(otherwise)?;
                } else {
                    let id = self.emit.open_brace_indent("{", style);
                    self.wrapped(otherwise)?;
                    self.emit.close_brace_indent("}", id);
                }
            }
        }
        self.pop_mod()?;
        if let Some(indent) = pending.and_then(|pending| self.emit.pending_indent(pending)) {
            self.emit.close_brace_indent("}", indent);
        }
        Ok(())
    }

    /// `PrintC::emitForLoop`.
    fn for_loop(
        &mut self,
        node: &'a Node,
        initialize: Option<&(u64, Fragment, Source)>,
        iterate: &(u64, Fragment, Source),
    ) -> Result<()> {
        self.push_mod();
        self.unset_mod(NO_BRANCH | ONLY_BRANCH);
        self.any_label_statement(node)?;
        let condition = &node.children[0];
        self.comment_block_tree(condition)?;
        self.emit.tag_line();
        self.emit.tag_op("for", KEYWORD_COLOR, condition.last_op);
        self.emit.spaces(1, 0);
        let paren = self.emit.open_paren("(");
        self.push_mod();
        self.set_mod(COMMA_SEPARATE);
        if let Some((op, fragment, source)) = initialize {
            let id = self.emit.begin_statement(Some(*op));
            self.replay_from(fragment, *source)?;
            self.emit.end_statement(id);
        }
        self.emit.print(";", NO_COLOR);
        self.emit.spaces(1, 0);
        self.block(condition)?;
        self.emit.print(";", NO_COLOR);
        self.emit.spaces(1, 0);
        let id = self.emit.begin_statement(Some(iterate.0));
        self.replay_from(&iterate.1, iterate.2)?;
        self.emit.end_statement(id);
        self.pop_mod()?;
        self.emit.close_paren(")", paren);
        let indent = self.emit.open_brace_indent("{", self.ir.brace_loop);
        self.set_mod(NO_BRANCH);
        self.wrapped(&node.children[1])?;
        self.emit.close_brace_indent("}", indent);
        self.pop_mod()
    }

    /// `PrintC::emitBlockWhileDo`.
    fn block_while_do(&mut self, node: &'a Node) -> Result<()> {
        let Detail::WhileDo {
            overflow,
            initialize,
            iterate,
        } = &node.detail
        else {
            return Err("while block without its loop".into());
        };
        if let Some(iterate) = iterate {
            return self.for_loop(node, initialize.as_ref(), iterate);
        }
        self.push_mod();
        self.unset_mod(NO_BRANCH | ONLY_BRANCH);
        self.any_label_statement(node)?;
        let condition = &node.children[0];
        let op = condition.last_op;
        let style = self.ir.brace_loop;
        let indent;
        if *overflow {
            self.emit.tag_line();
            self.emit.tag_op("while", KEYWORD_COLOR, op);
            let paren = self.emit.open_paren("(");
            self.emit.spaces(1, 0);
            self.emit.print("true", CONST_COLOR);
            self.emit.spaces(1, 0);
            self.emit.close_paren(")", paren);
            indent = self.emit.open_brace_indent("{", style);
            self.push_mod();
            self.set_mod(NO_BRANCH);
            self.block(condition)?;
            self.pop_mod()?;
            self.comment_block_tree(condition)?;
            self.emit.tag_line();
            self.emit.tag_op("if", KEYWORD_COLOR, op);
            self.emit.spaces(1, 0);
            self.push_mod();
            self.set_mod(ONLY_BRANCH);
            self.block(condition)?;
            self.pop_mod()?;
            self.emit.spaces(1, 0);
            self.goto_statement(condition.last_op, BREAK_GOTO, None)?;
        } else {
            self.comment_block_tree(condition)?;
            self.emit.tag_line();
            self.emit.tag_op("while", KEYWORD_COLOR, op);
            self.emit.spaces(1, 0);
            let paren = self.emit.open_paren("(");
            self.push_mod();
            self.set_mod(COMMA_SEPARATE);
            self.block(condition)?;
            self.pop_mod()?;
            self.emit.close_paren(")", paren);
            indent = self.emit.open_brace_indent("{", style);
        }
        self.set_mod(NO_BRANCH);
        self.wrapped(&node.children[1])?;
        self.emit.close_brace_indent("}", indent);
        self.pop_mod()
    }

    /// `PrintC::emitBlockDoWhile`.
    fn block_do_while(&mut self, node: &'a Node) -> Result<()> {
        self.push_mod();
        self.unset_mod(NO_BRANCH | ONLY_BRANCH);
        self.any_label_statement(node)?;
        self.emit.tag_line();
        self.emit.print("do", KEYWORD_COLOR);
        let id = self.emit.open_brace_indent("{", self.ir.brace_loop);
        let body = &node.children[0];
        self.push_mod();
        let block = self.emit.begin_block(body.index);
        self.set_mod(NO_BRANCH);
        self.block(body)?;
        self.emit.end_block(block);
        self.pop_mod()?;
        self.emit.close_brace_indent("}", id);
        self.emit.spaces(1, 0);
        self.emit.tag_op("while", KEYWORD_COLOR, body.last_op);
        self.emit.spaces(1, 0);
        self.set_mod(ONLY_BRANCH);
        self.block(body)?;
        self.emit.print(";", NO_COLOR);
        self.pop_mod()
    }

    /// `PrintC::emitBlockInfLoop`.
    fn block_infinite_loop(&mut self, node: &'a Node) -> Result<()> {
        self.push_mod();
        self.unset_mod(NO_BRANCH | ONLY_BRANCH);
        self.any_label_statement(node)?;
        self.emit.tag_line();
        self.emit.print("do", KEYWORD_COLOR);
        let id = self.emit.open_brace_indent("{", self.ir.brace_loop);
        let body = &node.children[0];
        self.wrapped(body)?;
        self.emit.close_brace_indent("}", id);
        self.emit.spaces(1, 0);
        self.emit.tag_op("while", KEYWORD_COLOR, body.last_op);
        let paren = self.emit.open_paren("(");
        self.emit.spaces(1, 0);
        self.emit.print("true", CONST_COLOR);
        self.emit.spaces(1, 0);
        self.emit.close_paren(")", paren);
        self.emit.print(";", NO_COLOR);
        self.pop_mod()
    }

    /// `PrintC::emitBlockSwitch`.
    fn block_switch(&mut self, node: &'a Node) -> Result<()> {
        let Detail::Switch { cases } = &node.detail else {
            return Err("switch block without cases".into());
        };
        let head = node
            .children
            .first()
            .ok_or("switch block without its head")?;
        self.push_mod();
        self.unset_mod(NO_BRANCH | ONLY_BRANCH);
        self.push_mod();
        self.set_mod(NO_BRANCH);
        self.block(head)?;
        self.pop_mod()?;
        self.emit.tag_line();
        self.push_mod();
        self.set_mod(ONLY_BRANCH | COMMA_SEPARATE);
        self.block(head)?;
        self.pop_mod()?;
        self.emit.open_brace("{", self.ir.brace_switch);
        for (position, case) in cases.iter().enumerate() {
            for labels in &case.labels {
                self.replay(labels)?;
            }
            let id = self.emit.start_indent();
            let body = match &case.body {
                CaseBody::Goto { goto_kind, target } => {
                    self.emit.tag_line();
                    self.goto_statement(
                        head.last_op,
                        *goto_kind,
                        target.as_ref().map(|t| &t.label),
                    )?;
                    None
                }
                CaseBody::Child(child) => Some(&node.children[*child]),
                CaseBody::Block(block) => Some(block.as_ref()),
            };
            if let Some(body) = body {
                let block = self.emit.begin_block(body.index);
                self.block(body)?;
                if case.exit && position != cases.len() - 1 {
                    self.emit.tag_line();
                    self.goto_statement(body.last_op, BREAK_GOTO, None)?;
                }
                self.emit.end_block(block);
            }
            self.emit.stop_indent(id);
        }
        self.emit.tag_line();
        self.emit.print("}", NO_COLOR);
        self.pop_mod()
    }
}
