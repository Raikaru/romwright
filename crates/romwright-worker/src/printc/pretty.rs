//! `EmitPrettyPrint` over `EmitMarkup`, as configured by `ArchitectureGhidra`
//! (`print->setMarkup(true)`), ported from the pinned
//! `third_party/ghidra/decompiler/prettyprint.{hh,cc}` (Apache-2.0).
//!
//! Line breaking (Oppen's algorithm with Ghidra's `< 10` short-break rule,
//! the `999999` forced-break size and the overflow halving), the TokenSplit id
//! counter that becomes the `open`/`close` attributes of parentheses, and the
//! packed encoding of every markup element are reproduced exactly: the Rust
//! printer's bytes are compared against PrintC's own (benchmarks/printer_diff.py).
//!
//! Markup associations are resolved values (op time, varnode create index,
//! symbol id, type id) because the printer IR carries them that way.

use std::collections::VecDeque;

/// `Emit::syntax_highlight::no_color`.
pub const NO_COLOR: u8 = 8;
pub const KEYWORD_COLOR: u8 = 0;
pub const COMMENT_COLOR: u8 = 1;
pub const CONST_COLOR: u8 = 5;

/// `Emit::brace_style`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BraceStyle {
    SameLine,
    NextLine,
    SkipLine,
}

impl BraceStyle {
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::SameLine),
            1 => Some(Self::NextLine),
            2 => Some(Self::SkipLine),
            _ => None,
        }
    }
}

/// An address space as `PackedEncode::writeSpace` writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Space {
    Index(u64),
    Special(u8),
}

mod packed {
    //! `PackedEncode` (marshal.cc) for the markup elements.
    pub const ELEMENT_START: u8 = 0x40;
    pub const ELEMENT_END: u8 = 0x80;
    pub const ATTRIBUTE: u8 = 0xc0;

    pub fn header(out: &mut Vec<u8>, base: u8, id: u32) {
        if id > 0x1f {
            out.push(base | 0x20 | ((id >> 7) & 0x1f) as u8);
            out.push(0x80 | (id & 0x7f) as u8);
        } else {
            out.push(base | id as u8);
        }
    }

    /// `PackedEncode::writeInteger`: minimal seven-bit groups, most
    /// significant first.
    pub fn integer(out: &mut Vec<u8>, type_code: u8, value: u64) {
        let groups = if value == 0 {
            0
        } else {
            (64 - value.leading_zeros()).div_ceil(7)
        };
        out.push((type_code << 4) | groups as u8);
        for group in (0..groups).rev() {
            out.push(((value >> (group * 7)) & 0x7f) as u8 | 0x80);
        }
    }

    pub fn open(out: &mut Vec<u8>, id: u32) {
        header(out, ELEMENT_START, id);
    }

    pub fn close(out: &mut Vec<u8>, id: u32) {
        header(out, ELEMENT_END, id);
    }

    pub fn unsigned(out: &mut Vec<u8>, attribute: u32, value: u64) {
        header(out, ATTRIBUTE, attribute);
        integer(out, 4, value);
    }

    pub fn signed(out: &mut Vec<u8>, attribute: u32, value: i64) {
        header(out, ATTRIBUTE, attribute);
        if value < 0 {
            integer(out, 3, value.unsigned_abs());
        } else {
            integer(out, 2, value as u64);
        }
    }

    pub fn string(out: &mut Vec<u8>, attribute: u32, value: &str) {
        header(out, ATTRIBUTE, attribute);
        integer(out, 7, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
    }

    pub fn space(out: &mut Vec<u8>, attribute: u32, space: super::Space) {
        header(out, ATTRIBUTE, attribute);
        match space {
            super::Space::Index(index) => integer(out, 5, index),
            super::Space::Special(code) => out.push((6 << 4) | code),
        }
    }
}

// prettyprint.cc, funcdata.cc, block.cc, type.cc, comment.cc, marshal.cc ids.
const ELEM_VALUE: u32 = 9;
const ELEM_BREAK: u32 = 17;
const ELEM_CLANG_DOCUMENT: u32 = 18;
const ELEM_FUNCNAME: u32 = 19;
const ELEM_FUNCPROTO: u32 = 20;
const ELEM_LABEL: u32 = 21;
const ELEM_RETURN_TYPE: u32 = 22;
const ELEM_STATEMENT: u32 = 23;
const ELEM_SYNTAX: u32 = 24;
const ELEM_VARDECL: u32 = 25;
const ELEM_VARIABLE: u32 = 26;
const ELEM_OP: u32 = 27;
const ELEM_FIELD: u32 = 49;
const ELEM_TYPE: u32 = 60;
const ELEM_COMMENT: u32 = 86;
const ELEM_BLOCK: u32 = 103;
const ELEM_FUNCTION: u32 = 116;
const ELEM_BITFIELD: u32 = 289;
const ATTRIB_CONTENT: u32 = 1;
const ATTRIB_ID: u32 = 9;
const ATTRIB_NAME: u32 = 14;
const ATTRIB_SPACE: u32 = 20;
const ATTRIB_BLOCKREF: u32 = 35;
const ATTRIB_CLOSE: u32 = 36;
const ATTRIB_COLOR: u32 = 37;
const ATTRIB_INDENT: u32 = 38;
const ATTRIB_OFF: u32 = 39;
const ATTRIB_OPEN: u32 = 40;
const ATTRIB_OPREF: u32 = 41;
const ATTRIB_VARREF: u32 = 42;
const ATTRIB_SYMREF: u32 = 68;

/// `TokenSplit::printclass`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Begin,
    End,
    TokenString,
    TokenBreak,
    BeginIndent,
    EndIndent,
    BeginComment,
    EndComment,
    Ignore,
}

/// `TokenSplit::tag_type` with the markup each tag carries.
#[derive(Clone, Debug)]
enum Tag {
    DocumentBegin,
    DocumentEnd,
    FunctionBegin,
    FunctionEnd,
    BlockBegin(i64),
    BlockEnd,
    ReturnTypeBegin(Option<u64>),
    ReturnTypeEnd,
    VarDeclBegin(u64),
    VarDeclEnd,
    StatementBegin(Option<u64>),
    StatementEnd,
    ProtoBegin,
    ProtoEnd,
    Variable {
        varnode: Option<u64>,
        op: Option<u64>,
    },
    Op(Option<u64>),
    FuncName(Option<u64>),
    Type(u64),
    Field(Option<FieldRef>),
    BitField(FieldRef),
    Comment(Space, u64),
    Label(Space, u64),
    Case {
        op: Option<u64>,
        value: u64,
    },
    Syntax,
    OpenParen,
    CloseParen,
    InvisibleOpen,
    InvisibleClose,
    Spaces,
    /// A required line break relative to the current indent (`bump_t`).
    Bump,
    /// A required line break with a one-time absolute indent (`line_t`).
    Line,
}

/// The data-type markup on a field token: name, unsized id, offset/id, op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldRef {
    pub type_name: String,
    pub type_id: u64,
    pub offset: i64,
    pub op: Option<u64>,
}

#[derive(Clone, Debug)]
struct TokenSplit {
    tag: Tag,
    class: Class,
    text: String,
    highlight: u8,
    indent_bump: i32,
    spaces: i32,
    size: i32,
    count: i32,
}

impl TokenSplit {
    fn new(tag: Tag, class: Class) -> Self {
        Self {
            tag,
            class,
            text: String::new(),
            highlight: NO_COLOR,
            indent_bump: 0,
            spaces: 0,
            size: 0,
            count: 0,
        }
    }

    fn content(tag: Tag, text: &str, highlight: u8) -> Self {
        Self {
            text: text.to_string(),
            highlight,
            size: text.len() as i32,
            ..Self::new(tag, Class::TokenString)
        }
    }
}

/// The low-level `EmitMarkup`; only the calls `TokenSplit::print` and the
/// pretty printer's own breaks make.
fn print_markup(out: &mut Vec<u8>, token: &TokenSplit) {
    fn color(out: &mut Vec<u8>, highlight: u8) {
        if highlight != NO_COLOR {
            packed::unsigned(out, ATTRIB_COLOR, u64::from(highlight));
        }
    }
    fn op(out: &mut Vec<u8>, op: Option<u64>) {
        if let Some(op) = op {
            packed::unsigned(out, ATTRIB_OPREF, op);
        }
    }
    fn content(out: &mut Vec<u8>, element: u32, text: &str) {
        packed::string(out, ATTRIB_CONTENT, text);
        packed::close(out, element);
    }
    let text = token.text.as_str();
    let highlight = token.highlight;
    match &token.tag {
        Tag::DocumentBegin => packed::open(out, ELEM_CLANG_DOCUMENT),
        Tag::DocumentEnd => packed::close(out, ELEM_CLANG_DOCUMENT),
        Tag::FunctionBegin => packed::open(out, ELEM_FUNCTION),
        Tag::FunctionEnd => packed::close(out, ELEM_FUNCTION),
        Tag::BlockBegin(index) => {
            packed::open(out, ELEM_BLOCK);
            packed::signed(out, ATTRIB_BLOCKREF, *index);
        }
        Tag::BlockEnd => packed::close(out, ELEM_BLOCK),
        Tag::ReturnTypeBegin(varnode) => {
            packed::open(out, ELEM_RETURN_TYPE);
            if let Some(varnode) = varnode {
                packed::unsigned(out, ATTRIB_VARREF, *varnode);
            }
        }
        Tag::ReturnTypeEnd => packed::close(out, ELEM_RETURN_TYPE),
        Tag::VarDeclBegin(symbol) => {
            packed::open(out, ELEM_VARDECL);
            packed::unsigned(out, ATTRIB_SYMREF, *symbol);
        }
        Tag::VarDeclEnd => packed::close(out, ELEM_VARDECL),
        Tag::StatementBegin(statement) => {
            packed::open(out, ELEM_STATEMENT);
            op(out, *statement);
        }
        Tag::StatementEnd => packed::close(out, ELEM_STATEMENT),
        Tag::ProtoBegin => packed::open(out, ELEM_FUNCPROTO),
        Tag::ProtoEnd => packed::close(out, ELEM_FUNCPROTO),
        Tag::Variable {
            varnode,
            op: operation,
        } => {
            packed::open(out, ELEM_VARIABLE);
            color(out, highlight);
            if let Some(varnode) = varnode {
                packed::unsigned(out, ATTRIB_VARREF, *varnode);
            }
            op(out, *operation);
            content(out, ELEM_VARIABLE, text);
        }
        Tag::Op(operation) => {
            packed::open(out, ELEM_OP);
            color(out, highlight);
            op(out, *operation);
            content(out, ELEM_OP, text);
        }
        Tag::FuncName(operation) => {
            packed::open(out, ELEM_FUNCNAME);
            color(out, highlight);
            op(out, *operation);
            content(out, ELEM_FUNCNAME, text);
        }
        Tag::Type(id) => {
            packed::open(out, ELEM_TYPE);
            color(out, highlight);
            if *id != 0 {
                packed::unsigned(out, ATTRIB_ID, *id);
            }
            content(out, ELEM_TYPE, text);
        }
        Tag::Field(field) => {
            packed::open(out, ELEM_FIELD);
            color(out, highlight);
            if let Some(field) = field {
                packed::string(out, ATTRIB_NAME, &field.type_name);
                if field.type_id != 0 {
                    packed::unsigned(out, ATTRIB_ID, field.type_id);
                }
                packed::signed(out, ATTRIB_OFF, field.offset);
                op(out, field.op);
            }
            content(out, ELEM_FIELD, text);
        }
        Tag::BitField(field) => {
            packed::open(out, ELEM_BITFIELD);
            color(out, highlight);
            packed::string(out, ATTRIB_NAME, &field.type_name);
            if field.type_id != 0 {
                packed::unsigned(out, ATTRIB_ID, field.type_id);
            }
            packed::signed(out, ATTRIB_OFF, field.offset);
            op(out, field.op);
            content(out, ELEM_BITFIELD, text);
        }
        Tag::Comment(space, offset) | Tag::Label(space, offset) => {
            let element = if matches!(token.tag, Tag::Comment(..)) {
                ELEM_COMMENT
            } else {
                ELEM_LABEL
            };
            packed::open(out, element);
            color(out, highlight);
            packed::space(out, ATTRIB_SPACE, *space);
            packed::unsigned(out, ATTRIB_OFF, *offset);
            content(out, element, text);
        }
        Tag::Case {
            op: operation,
            value,
        } => {
            packed::open(out, ELEM_VALUE);
            color(out, highlight);
            packed::unsigned(out, ATTRIB_OFF, *value);
            op(out, *operation);
            content(out, ELEM_VALUE, text);
        }
        Tag::Syntax => syntax(out, text, highlight),
        Tag::OpenParen | Tag::CloseParen => {
            packed::open(out, ELEM_SYNTAX);
            let attribute = if matches!(token.tag, Tag::OpenParen) {
                ATTRIB_OPEN
            } else {
                ATTRIB_CLOSE
            };
            packed::signed(out, attribute, i64::from(token.count));
            content(out, ELEM_SYNTAX, text);
        }
        Tag::InvisibleOpen | Tag::InvisibleClose => {}
        Tag::Spaces => spaces(out, token.spaces),
        // TokenSplit::print throws for these; breaks never reach it.
        Tag::Bump | Tag::Line => unreachable!("line breaks are printed by the pretty printer"),
    }
}

fn syntax(out: &mut Vec<u8>, text: &str, highlight: u8) {
    packed::open(out, ELEM_SYNTAX);
    if highlight != NO_COLOR {
        packed::unsigned(out, ATTRIB_COLOR, u64::from(highlight));
    }
    packed::string(out, ATTRIB_CONTENT, text);
    packed::close(out, ELEM_SYNTAX);
}

/// `Emit::spaces` on the low-level emitter.
fn spaces(out: &mut Vec<u8>, count: i32) {
    syntax(out, &" ".repeat(count.max(0) as usize), NO_COLOR);
}

fn line_break(out: &mut Vec<u8>, indent: i32) {
    packed::open(out, ELEM_BREAK);
    packed::signed(out, ATTRIB_INDENT, i64::from(indent));
    packed::close(out, ELEM_BREAK);
}

/// A registered `PendingBrace` (printc.cc `emitBlockIf`), by identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingId(usize);

/// `EmitPrettyPrint` with an `EmitMarkup` low level, from a cleared state
/// (`spaceremain == maxlinesize`, empty queues), which is what every
/// `docFunction` in a worker session starts from.
pub struct PrettyPrint {
    out: Vec<u8>,
    indent_increment: i32,
    indent_stack: Vec<i32>,
    space_remain: i32,
    max_line_size: i32,
    left_total: i32,
    right_total: i32,
    need_break: bool,
    comment_mode: bool,
    comment_fill: String,
    /// Absolute token positions of open groups and pending breaks.
    scan_queue: VecDeque<usize>,
    tokens: VecDeque<TokenSplit>,
    /// Absolute position of `tokens[0]`.
    popped: usize,
    count_base: i32,
    pending: Option<(PendingId, BraceStyle)>,
    pending_serial: usize,
    fired: Vec<(PendingId, i32)>,
    /// Visible text tokens and spacing tokens pushed so far, for the
    /// ownership accounting (docs/ownership.md); they never affect output.
    text_tokens: u64,
    spacing_tokens: u64,
}

impl PrettyPrint {
    /// `count_base` is `TokenSplit::countbase` when the function starts.
    /// The comment fill is the C comment style's (`PrintC::resetDefaultsPrintC`
    /// -> `setCStyleComments`: three spaces), the only style the worker uses.
    pub fn new(max_line_size: i32, indent_increment: i32, count_base: i32) -> Self {
        Self {
            out: Vec::new(),
            indent_increment,
            indent_stack: Vec::new(),
            space_remain: max_line_size,
            max_line_size,
            left_total: 1,
            right_total: 1,
            need_break: false,
            comment_mode: false,
            comment_fill: "   ".to_string(),
            scan_queue: VecDeque::new(),
            tokens: VecDeque::new(),
            popped: 0,
            count_base,
            pending: None,
            pending_serial: 0,
            fired: Vec::new(),
            text_tokens: 0,
            spacing_tokens: 0,
        }
    }

    pub fn count_base(&self) -> i32 {
        self.count_base
    }

    /// Visible text tokens (identifiers, operators, types, keywords,
    /// punctuation, parentheses) the printer has been given.
    pub fn text_tokens(&self) -> u64 {
        self.text_tokens
    }

    /// Spacing tokens (`spaces`) the printer has been given.
    pub fn spacing_tokens(&self) -> u64 {
        self.spacing_tokens
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    fn next_count(&mut self) -> i32 {
        let count = self.count_base;
        self.count_base = self.count_base.wrapping_add(1);
        count
    }

    fn token(&mut self, position: usize) -> &mut TokenSplit {
        &mut self.tokens[position - self.popped]
    }

    fn top_position(&self) -> usize {
        self.popped + self.tokens.len() - 1
    }

    fn push(&mut self, token: TokenSplit) {
        self.tokens.push_back(token);
        self.scan();
    }

    fn overflow(&mut self) {
        let half = self.max_line_size / 2;
        for level in self.indent_stack.iter_mut().rev() {
            if *level < half {
                *level = half;
            } else {
                break;
            }
        }
        let new_remain = self
            .indent_stack
            .last()
            .copied()
            .unwrap_or(self.max_line_size);
        if new_remain == self.space_remain {
            return;
        }
        if self.comment_mode && new_remain == self.space_remain + self.comment_fill.len() as i32 {
            return;
        }
        self.space_remain = new_remain;
        line_break(&mut self.out, self.max_line_size - self.space_remain);
        if self.comment_mode && !self.comment_fill.is_empty() {
            syntax(&mut self.out, &self.comment_fill, COMMENT_COLOR);
            self.space_remain -= self.comment_fill.len() as i32;
        }
    }

    fn print_token(&mut self, token: &TokenSplit) {
        match token.class {
            Class::Ignore => print_markup(&mut self.out, token),
            Class::BeginIndent => {
                let level = self.indent_stack.last().copied().unwrap_or(0) - token.indent_bump;
                self.indent_stack.push(level);
            }
            Class::BeginComment | Class::Begin => {
                if token.class == Class::BeginComment {
                    self.comment_mode = true;
                }
                print_markup(&mut self.out, token);
                self.indent_stack.push(self.space_remain);
            }
            Class::EndIndent => {
                self.indent_stack.pop();
            }
            Class::EndComment | Class::End => {
                if token.class == Class::EndComment {
                    self.comment_mode = false;
                }
                print_markup(&mut self.out, token);
                self.indent_stack.pop();
            }
            Class::TokenString => {
                if token.size > self.space_remain {
                    self.overflow();
                }
                print_markup(&mut self.out, token);
                self.space_remain -= token.size;
            }
            Class::TokenBreak => {
                if token.size > self.space_remain {
                    if matches!(token.tag, Tag::Line) {
                        self.space_remain = self.max_line_size - token.indent_bump;
                    } else {
                        let level =
                            self.indent_stack.last().copied().unwrap_or(0) - token.indent_bump;
                        if token.spaces <= self.space_remain && level - self.space_remain < 10 {
                            spaces(&mut self.out, token.spaces);
                            self.space_remain -= token.spaces;
                            return;
                        }
                        if let Some(last) = self.indent_stack.last_mut() {
                            *last = level;
                        }
                        self.space_remain = level;
                    }
                    line_break(&mut self.out, self.max_line_size - self.space_remain);
                    if self.comment_mode && !self.comment_fill.is_empty() {
                        syntax(&mut self.out, &self.comment_fill, COMMENT_COLOR);
                        self.space_remain -= self.comment_fill.len() as i32;
                    }
                } else {
                    spaces(&mut self.out, token.spaces);
                    self.space_remain -= token.spaces;
                }
            }
        }
    }

    fn advance_left(&mut self) {
        let Some(mut size) = self.tokens.front().map(|token| token.size) else {
            return;
        };
        while size >= 0 {
            let token = self
                .tokens
                .pop_front()
                .expect("token queue checked non-empty");
            self.popped += 1;
            self.print_token(&token);
            match token.class {
                Class::TokenBreak => self.left_total += token.spaces,
                Class::TokenString => self.left_total += size,
                _ => {}
            }
            let Some(next) = self.tokens.front() else {
                break;
            };
            size = next.size;
        }
    }

    fn scan(&mut self) {
        let top = self.top_position();
        let class = self.token(top).class;
        match class {
            Class::BeginComment | Class::Begin => {
                if self.scan_queue.is_empty() {
                    self.left_total = 1;
                    self.right_total = 1;
                }
                let right_total = self.right_total;
                self.token(top).size = -right_total;
                self.scan_queue.push_back(top);
            }
            Class::EndComment | Class::End => {
                self.token(top).size = 0;
                if let Some(open) = self.scan_queue.pop_back() {
                    let right_total = self.right_total;
                    let reference = self.token(open);
                    reference.size += right_total;
                    if reference.class == Class::TokenBreak
                        && let Some(second) = self.scan_queue.pop_back()
                    {
                        self.token(second).size += right_total;
                    }
                    if self.scan_queue.is_empty() {
                        self.advance_left();
                    }
                }
            }
            Class::TokenBreak => {
                if self.scan_queue.is_empty() {
                    self.left_total = 1;
                    self.right_total = 1;
                } else {
                    let previous = *self
                        .scan_queue
                        .back()
                        .expect("scan queue checked non-empty");
                    let right_total = self.right_total;
                    if self.token(previous).class == Class::TokenBreak {
                        self.scan_queue.pop_back();
                        self.token(previous).size += right_total;
                    }
                }
                let right_total = self.right_total;
                let token = self.token(top);
                token.size = -right_total;
                let width = token.spaces;
                self.scan_queue.push_back(top);
                self.right_total += width;
            }
            Class::BeginIndent | Class::EndIndent | Class::Ignore => {
                self.token(top).size = 0;
            }
            Class::TokenString => {
                if !self.scan_queue.is_empty() {
                    self.right_total += self.token(top).size;
                    while self.right_total - self.left_total > self.space_remain {
                        let Some(oldest) = self.scan_queue.pop_front() else {
                            break;
                        };
                        self.token(oldest).size = 999_999;
                        self.advance_left();
                        if self.scan_queue.is_empty() {
                            break;
                        }
                    }
                }
            }
        }
    }

    fn check_start(&mut self) {
        if self.need_break {
            self.push_spaces(0, 0);
        }
        self.need_break = false;
    }

    fn check_string(&mut self) {
        if self.need_break {
            self.push_spaces(0, 0);
        }
        self.need_break = true;
    }

    fn check_end(&mut self) {
        if !self.need_break {
            self.push(TokenSplit::content(Tag::Syntax, "", NO_COLOR));
        }
        self.need_break = true;
    }

    fn check_break(&mut self) {
        if !self.need_break {
            self.push(TokenSplit::content(Tag::Syntax, "", NO_COLOR));
        }
        self.need_break = false;
    }

    fn push_spaces(&mut self, count: i32, bump: i32) {
        self.spacing_tokens += 1;
        self.push(TokenSplit {
            spaces: count,
            indent_bump: bump,
            ..TokenSplit::new(Tag::Spaces, Class::TokenBreak)
        });
    }

    fn begin(&mut self, tag: Tag) -> i32 {
        self.check_start();
        let count = self.next_count();
        self.push(TokenSplit {
            count,
            ..TokenSplit::new(tag, Class::Begin)
        });
        count
    }

    fn end(&mut self, tag: Tag, id: i32) {
        self.check_end();
        self.push(TokenSplit {
            count: id,
            ..TokenSplit::new(tag, Class::End)
        });
    }

    fn string(&mut self, token: TokenSplit) {
        self.text_tokens += 1;
        self.check_string();
        self.push(token);
    }

    pub fn begin_document(&mut self) -> i32 {
        self.begin(Tag::DocumentBegin)
    }

    pub fn end_document(&mut self, id: i32) {
        self.end(Tag::DocumentEnd, id);
    }

    pub fn begin_function(&mut self) -> i32 {
        self.begin(Tag::FunctionBegin)
    }

    pub fn end_function(&mut self, id: i32) {
        self.end(Tag::FunctionEnd, id);
    }

    pub fn begin_block(&mut self, index: i64) -> i32 {
        let count = self.next_count();
        self.push(TokenSplit {
            count,
            ..TokenSplit::new(Tag::BlockBegin(index), Class::Ignore)
        });
        count
    }

    pub fn end_block(&mut self, id: i32) {
        self.push(TokenSplit {
            count: id,
            ..TokenSplit::new(Tag::BlockEnd, Class::Ignore)
        });
    }

    pub fn tag_line(&mut self) {
        self.emit_pending();
        self.check_break();
        self.push(TokenSplit {
            spaces: 999_999,
            ..TokenSplit::new(Tag::Bump, Class::TokenBreak)
        });
    }

    pub fn tag_line_indent(&mut self, indent: i32) {
        self.emit_pending();
        self.check_break();
        self.push(TokenSplit {
            spaces: 999_999,
            indent_bump: indent,
            ..TokenSplit::new(Tag::Line, Class::TokenBreak)
        });
    }

    pub fn begin_return_type(&mut self, varnode: Option<u64>) -> i32 {
        self.begin(Tag::ReturnTypeBegin(varnode))
    }

    pub fn end_return_type(&mut self, id: i32) {
        self.end(Tag::ReturnTypeEnd, id);
    }

    pub fn begin_var_decl(&mut self, symbol: u64) -> i32 {
        self.begin(Tag::VarDeclBegin(symbol))
    }

    pub fn end_var_decl(&mut self, id: i32) {
        self.end(Tag::VarDeclEnd, id);
    }

    pub fn begin_statement(&mut self, op: Option<u64>) -> i32 {
        self.begin(Tag::StatementBegin(op))
    }

    pub fn end_statement(&mut self, id: i32) {
        self.end(Tag::StatementEnd, id);
    }

    pub fn begin_func_proto(&mut self) -> i32 {
        self.begin(Tag::ProtoBegin)
    }

    pub fn end_func_proto(&mut self, id: i32) {
        self.end(Tag::ProtoEnd, id);
    }

    pub fn tag_variable(
        &mut self,
        name: &str,
        highlight: u8,
        varnode: Option<u64>,
        op: Option<u64>,
    ) {
        self.string(TokenSplit::content(
            Tag::Variable { varnode, op },
            name,
            highlight,
        ));
    }

    pub fn tag_op(&mut self, name: &str, highlight: u8, op: Option<u64>) {
        self.string(TokenSplit::content(Tag::Op(op), name, highlight));
    }

    pub fn tag_func_name(&mut self, name: &str, highlight: u8, op: Option<u64>) {
        self.string(TokenSplit::content(Tag::FuncName(op), name, highlight));
    }

    pub fn tag_type(&mut self, name: &str, highlight: u8, type_id: u64) {
        self.string(TokenSplit::content(Tag::Type(type_id), name, highlight));
    }

    pub fn tag_field(&mut self, name: &str, highlight: u8, field: Option<FieldRef>) {
        self.string(TokenSplit::content(Tag::Field(field), name, highlight));
    }

    pub fn tag_bit_field(&mut self, name: &str, highlight: u8, field: FieldRef) {
        self.string(TokenSplit::content(Tag::BitField(field), name, highlight));
    }

    pub fn tag_comment(&mut self, name: &str, highlight: u8, space: Space, offset: u64) {
        self.string(TokenSplit::content(
            Tag::Comment(space, offset),
            name,
            highlight,
        ));
    }

    pub fn tag_label(&mut self, name: &str, highlight: u8, space: Space, offset: u64) {
        self.string(TokenSplit::content(
            Tag::Label(space, offset),
            name,
            highlight,
        ));
    }

    pub fn tag_case_label(&mut self, name: &str, highlight: u8, op: Option<u64>, value: u64) {
        self.string(TokenSplit::content(
            Tag::Case { op, value },
            name,
            highlight,
        ));
    }

    pub fn print(&mut self, data: &str, highlight: u8) {
        self.string(TokenSplit::content(Tag::Syntax, data, highlight));
    }

    pub fn open_paren(&mut self, paren: &str) -> i32 {
        self.text_tokens += 1;
        let id = self.open_group();
        self.push(TokenSplit {
            count: id,
            size: 1,
            text: paren.to_string(),
            ..TokenSplit::new(Tag::OpenParen, Class::TokenString)
        });
        self.need_break = true;
        id
    }

    pub fn close_paren(&mut self, paren: &str, id: i32) {
        self.text_tokens += 1;
        self.check_string();
        self.push(TokenSplit {
            count: id,
            size: 1,
            text: paren.to_string(),
            ..TokenSplit::new(Tag::CloseParen, Class::TokenString)
        });
        self.close_group(id);
    }

    pub fn open_group(&mut self) -> i32 {
        self.begin(Tag::InvisibleOpen)
    }

    pub fn close_group(&mut self, id: i32) {
        self.end(Tag::InvisibleClose, id);
    }

    pub fn spaces(&mut self, count: i32, bump: i32) {
        self.check_break();
        self.push_spaces(count, bump);
    }

    pub fn start_indent(&mut self) -> i32 {
        let count = self.next_count();
        let bump = self.indent_increment;
        self.push(TokenSplit {
            indent_bump: bump,
            count,
            ..TokenSplit::new(Tag::Bump, Class::BeginIndent)
        });
        count
    }

    pub fn stop_indent(&mut self, id: i32) {
        self.push(TokenSplit {
            count: id,
            ..TokenSplit::new(Tag::Bump, Class::EndIndent)
        });
    }

    pub fn start_comment(&mut self) -> i32 {
        self.check_start();
        let count = self.next_count();
        self.push(TokenSplit {
            count,
            ..TokenSplit::new(Tag::InvisibleOpen, Class::BeginComment)
        });
        count
    }

    pub fn stop_comment(&mut self, id: i32) {
        self.check_end();
        self.push(TokenSplit {
            count: id,
            ..TokenSplit::new(Tag::InvisibleClose, Class::EndComment)
        });
    }

    pub fn flush(&mut self) -> Result<(), String> {
        while let Some(token) = self.tokens.pop_front() {
            self.popped += 1;
            if token.size < 0 {
                return Err("Cannot flush pretty printer. Missing group end".into());
            }
            self.print_token(&token);
        }
        self.scan_queue.clear();
        self.need_break = false;
        Ok(())
    }

    /// `Emit::openBraceIndent`.
    pub fn open_brace_indent(&mut self, brace: &str, style: BraceStyle) -> i32 {
        self.brace_lead(style);
        let id = self.start_indent();
        self.print(brace, NO_COLOR);
        id
    }

    /// `Emit::openBrace`.
    pub fn open_brace(&mut self, brace: &str, style: BraceStyle) {
        self.brace_lead(style);
        self.print(brace, NO_COLOR);
    }

    fn brace_lead(&mut self, style: BraceStyle) {
        match style {
            BraceStyle::SameLine => self.spaces(1, 0),
            BraceStyle::SkipLine => {
                self.tag_line();
                self.tag_line();
            }
            BraceStyle::NextLine => self.tag_line(),
        }
    }

    /// `Emit::closeBraceIndent`.
    pub fn close_brace_indent(&mut self, brace: &str, id: i32) {
        self.stop_indent(id);
        self.tag_line();
        self.print(brace, NO_COLOR);
    }

    /// `Emit::setPendingPrint` with a fresh `PendingBrace`.
    pub fn set_pending_brace(&mut self, style: BraceStyle) -> PendingId {
        let id = PendingId(self.pending_serial);
        self.pending_serial += 1;
        self.pending = Some((id, style));
        id
    }

    /// `Emit::hasPendingPrint`.
    pub fn has_pending(&self, id: PendingId) -> bool {
        self.pending.is_some_and(|(pending, _)| pending == id)
    }

    /// `Emit::cancelPendingPrint`.
    pub fn cancel_pending(&mut self) {
        self.pending = None;
    }

    /// `PendingBrace::getIndentId`: the indent the brace opened, if it fired.
    pub fn pending_indent(&self, id: PendingId) -> Option<i32> {
        self.fired
            .iter()
            .find(|(fired, _)| *fired == id)
            .map(|(_, indent)| *indent)
    }

    /// `Emit::emitPending` and `PendingBrace::callback`.
    fn emit_pending(&mut self) {
        if let Some((id, style)) = self.pending.take() {
            let indent = self.open_brace_indent("{", style);
            self.fired.push((id, indent));
        }
    }
}
