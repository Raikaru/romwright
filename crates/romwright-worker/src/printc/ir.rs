//! Decoder for the printer IR blob written by `native/romwright_printir.hh`
//! (`<romwright_printir content=...>`, element id 4091).
//!
//! The blob uses NUL-free six-bit varints (zigzag for signed values) and
//! length-prefixed byte strings. It carries the structured block tree as
//! PrintC's block layer reads it and, for every expression, declaration,
//! label and comment, a [`Fragment`]: the Emit calls PrintC's handlers made
//! for it.

use super::casts::{self, CLeaf, CNode, COp, COut, CTree, CastRules, CastStats, Info};
use super::collapse::{Cfg, CfgBlock, CfgEdge, Last, LoopRecord, SwitchEdge};
use super::pretty::{BraceStyle, FieldRef, Space};
use super::render::{self, ExprMode, ExprStats};
use super::tree::{
    ConstKind, Extra, FieldDesc, Options, PConst, PNode, POp, PPartial, PieceKind, PrintTree, PtrsubKind,
    SymbolDesc, Tables, TypeDesc,
};

/// `FlowBlock::block_type` (block.hh).
pub mod kind {
    pub const PLAIN: u64 = 0;
    pub const BASIC: u64 = 1;
    pub const GRAPH: u64 = 2;
    pub const COPY: u64 = 3;
    pub const GOTO: u64 = 4;
    pub const MULTIGOTO: u64 = 5;
    pub const LIST: u64 = 6;
    pub const CONDITION: u64 = 7;
    pub const IF: u64 = 8;
    pub const WHILE_DO: u64 = 9;
    pub const DO_WHILE: u64 = 10;
    pub const SWITCH: u64 = 11;
    pub const INFINITE_LOOP: u64 = 12;
}

/// One recorded `Emit` call. Ids are fragment-local, numbered from 1 in the
/// order the opening calls were made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    BeginDocument(u64),
    EndDocument(u64),
    BeginFunction(u64),
    EndFunction(u64),
    BeginBlock(u64, i64),
    EndBlock(u64),
    TagLine,
    TagLineIndent(i32),
    BeginReturnType(u64, Option<u64>),
    EndReturnType(u64),
    BeginVarDecl(u64, u64),
    EndVarDecl(u64),
    BeginStatement(u64, Option<u64>),
    EndStatement(u64),
    BeginFuncProto(u64),
    EndFuncProto(u64),
    Variable {
        name: String,
        highlight: u8,
        varnode: Option<u64>,
        op: Option<u64>,
    },
    Op {
        name: String,
        highlight: u8,
        op: Option<u64>,
    },
    FuncName {
        name: String,
        highlight: u8,
        op: Option<u64>,
    },
    Type {
        name: String,
        highlight: u8,
        id: u64,
    },
    Field {
        name: String,
        highlight: u8,
        field: Option<FieldRef>,
    },
    BitField {
        name: String,
        highlight: u8,
        field: FieldRef,
    },
    Comment {
        name: String,
        highlight: u8,
        space: Space,
        offset: u64,
    },
    Label {
        name: String,
        highlight: u8,
        space: Space,
        offset: u64,
    },
    CaseLabel {
        name: String,
        highlight: u8,
        op: Option<u64>,
        value: u64,
    },
    Print {
        text: String,
        highlight: u8,
    },
    OpenParen(u64, String),
    CloseParen(u64, String),
    OpenGroup(u64),
    CloseGroup(u64),
    Spaces(i32, i32),
    StartIndent(u64),
    StopIndent(u64),
    StartComment(u64),
    StopComment(u64),
}

/// The Emit calls of one PrintC emission (an expression, a label, ...).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fragment(pub Vec<Event>);

/// A statement's expression; `comma` is the CBRANCH rendering under
/// `comma_separate` (no surrounding parentheses).
#[derive(Clone, Debug)]
pub struct Expression {
    pub normal: Fragment,
    pub comma: Option<Fragment>,
    /// Who produced the fragments.
    pub source: Source,
}

/// Who produced an expression's fragments: PrintC's own handlers, or the
/// worker's printer from the exported print tree (`printc/render.rs`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Source {
    #[default]
    Fragments,
    Rust,
}

impl Expression {
    pub fn select(&self, comma_separate: bool) -> &Fragment {
        match (&self.comma, comma_separate) {
            (Some(comma), true) => comma,
            _ => &self.normal,
        }
    }
}

/// A structural expression: the tree PrintC prints as RPN, with opcodes and
/// varnode identities instead of text. An implied varnode is its defining
/// op's subtree; an explicit one is a [`Expr::Var`] leaf. The text of the
/// expression stays in [`Expression`]'s fragments; this is what passes
/// compare, negate and propagate (`printc/expr.rs`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Expr {
    /// Past the exporter's depth or size bound.
    #[default]
    Opaque,
    Const { size: u32, value: u64 },
    /// An explicit variable: its SSA value (`Varnode::getCreateIndex`) and
    /// HighVariable (the C variable PrintC names; 0 when it has none).
    Var {
        size: u32,
        ssa: u64,
        high: u32,
        storage: Storage,
    },
    /// `PcodeOp::code` over its inputs.
    Op { code: u32, args: Vec<Expr> },
}

/// Where a variable lives and what may change it behind a statement's back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Storage {
    /// 0 register or unique, 1 stack, 2 other memory.
    pub class: u8,
    /// Persists beyond the function, or has its address taken or forced: a
    /// call or a store may change it.
    pub aliased: bool,
}

/// A statement candidate's effect, structurally (the exporter's
/// `effect()`): what it writes, what it reads, and whether it may change
/// memory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Effect {
    /// `PcodeOp::code`.
    pub code: u32,
    /// The statement, or an expression inside it, calls.
    pub calls: bool,
    /// The statement, or an expression inside it, stores.
    pub stores: bool,
    /// The explicit variable it writes.
    pub out: Option<Expr>,
    /// A CBRANCH prints the negation of its condition (`isBooleanFlip`).
    pub flip: bool,
    /// The inputs; a CBRANCH has its condition only.
    pub args: Vec<Expr>,
}

#[derive(Clone, Debug)]
pub struct Statement {
    /// `PcodeOp::getTime`, the statement's `opref`.
    pub op: u64,
    pub is_branch: bool,
    /// Comments of this block that sort at or before this op
    /// (`CommentSorter::setupOpList`).
    pub comment_bound: usize,
    pub expression: Expression,
    pub effect: Effect,
}

#[derive(Clone, Debug)]
pub struct Comment {
    /// Global comment slot for the emitted flag.
    pub slot: usize,
    /// Passes the printer's instruction-comment type mask.
    pub printable: bool,
    pub line: Fragment,
}

#[derive(Clone, Debug)]
pub struct Basic {
    pub comments: Vec<Comment>,
    /// Statement candidates in block order.
    pub statements: Vec<Statement>,
    /// The block's final op when it is a branch (`only_branch` printing).
    pub branch: Option<Expression>,
    /// Out-edges in the basic-block graph, by block index. For a CBRANCH,
    /// successor 1 is where control goes when the printed condition holds
    /// (`getTrueOut`), successor 0 when it does not.
    pub successors: Vec<i64>,
    /// The CBRANCH's condition as PrintC prints its negation (normal and
    /// `comma_separate` renderings).
    pub negated: Option<Expression>,
    /// The block holds a for-loop initializer or iterator, which prints in
    /// the loop header rather than here: a copy elsewhere would lose it.
    pub holds_loop_op: bool,
    /// Edges this block's printed flow takes through a test `thread_test`
    /// re-inserted: (successor in the basic-block graph, the block the
    /// printed code flows to instead). Decoded blocks have none.
    pub threaded: Vec<(i64, i64)>,
}

/// Where an unstructured branch goes: the target's front basic block and
/// the label PrintC prints for it.
#[derive(Clone, Debug)]
pub struct GotoTarget {
    pub block: i64,
    pub label: Fragment,
}

/// What a `case` prints after its labels.
#[derive(Clone, Debug)]
pub enum CaseBody {
    /// An unstructured case: `goto` (or `break`/`continue`) to `target`'s label.
    Goto {
        goto_kind: u64,
        target: Option<GotoTarget>,
    },
    /// The case block, by index among the switch's children.
    Child(usize),
    /// A case block that is not a child of the switch, exported in place.
    Block(Box<Node>),
}

#[derive(Clone, Debug)]
pub struct Case {
    /// `emitSwitchCase` output; several when cases were merged.
    pub labels: Vec<Fragment>,
    pub exit: bool,
    pub body: CaseBody,
}

#[derive(Clone, Debug)]
pub enum Detail {
    None,
    Basic(Basic),
    /// A leaf (`BlockCopy`): the label PrintC would print for it, whether
    /// or not it prints one.
    Copy {
        label: Fragment,
    },
    Goto {
        prints: bool,
        goto_kind: u64,
        target: Option<GotoTarget>,
    },
    List {
        flow_breaks: Vec<bool>,
    },
    Condition {
        and: bool,
    },
    If {
        goto_kind: u64,
        target: Option<GotoTarget>,
    },
    WhileDo {
        overflow: bool,
        initialize: Option<(u64, Fragment, Source)>,
        iterate: Option<(u64, Fragment, Source)>,
    },
    Switch {
        cases: Vec<Case>,
    },
}

#[derive(Clone, Debug)]
pub struct Node {
    pub kind: u64,
    pub index: i64,
    pub last_op: Option<u64>,
    /// `emitAnyLabelStatement`'s label, when this block prints one.
    pub label: Option<Fragment>,
    pub children: Vec<Node>,
    pub detail: Detail,
}

#[derive(Clone, Debug)]
pub struct PrinterIr {
    pub max_line_size: i32,
    pub indent_increment: i32,
    pub brace_function: BraceStyle,
    pub brace_if_else: BraceStyle,
    pub brace_loop: BraceStyle,
    pub brace_switch: BraceStyle,
    /// `TokenSplit::countbase` after PrintC's own `docFunction`.
    pub count_after: i32,
    pub header: Fragment,
    pub declaration: Fragment,
    pub locals: Fragment,
    pub body: Vec<Node>,
    /// The unstructured control-flow graph (version 5): what
    /// [`super::collapse`] structures. `body` is empty when the decompiler
    /// did not structure the function itself.
    pub cfg: Option<Cfg>,
    /// `body` is the decompiler's own structure (stock path), not the worker's.
    pub native_tree: bool,
    pub comment_slots: usize,
    /// What the worker's expression printer did with each expression.
    pub expressions: ExprStats,
    /// The types the worker's casts name, for the document's type model.
    pub cast_types: Vec<romwright_model::DecompType>,
    /// The prototypes of calls whose callee is not declared, read off the calls after the casts.
    pub call_types: Vec<CallPrototypeTypes>,
    /// The p-code changes of the worker's casts (version 6), for the semantic IR.
    pub cast_edits: Vec<casts::IrEdit>,
}

/// What the document's call prototype of an undeclared callee must say after the casts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallPrototypeTypes {
    pub time: u64,
    pub params: Option<Vec<romwright_model::DecompType>>,
    pub ret: Option<romwright_model::DecompType>,
}

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
    /// Comment emitted-flag slots by (basic block index, position): a block
    /// exported twice shares its comments' flags, as PrintC's do.
    comment_slots: std::collections::HashMap<(i64, usize), usize>,
    options: Options,
    tables: Tables,
    mode: ExprMode,
    expressions: ExprStats,
    /// Version 6: the statements' print trees are pre-cast and the worker
    /// casts them as it reads them (`casts.rs`).
    pending: bool,
    rules: CastRules,
    cast_time: u64,
    cast_stats: CastStats,
    cast_warnings: Vec<(u64, u32)>,
    /// A statement the worker could not print after casting it.
    cast_error: Option<String>,
    /// Types the worker's casts name (version 6, casts pending).
    cast_type_ids: std::collections::BTreeSet<usize>,
    /// The calls of unlocked callees, by op time, as they print after the casts.
    call_types: std::collections::BTreeMap<u64, casts::CallType>,
    /// The p-code changes of the worker's casts, in order.
    cast_edits: Vec<casts::IrEdit>,
}

type Result<T, E = String> = std::result::Result<T, E>;

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader {
            data,
            position: 0,
            comment_slots: Default::default(),
            options: Options::default(),
            tables: Tables::default(),
            mode: ExprMode::from_env(),
            expressions: ExprStats::default(),
            pending: false,
            rules: casts::current_rules(),
            cast_time: 1 << 40,
            cast_stats: CastStats::default(),
            cast_warnings: Vec::new(),
            cast_error: None,
            cast_type_ids: Default::default(),
            call_types: Default::default(),
            cast_edits: Vec::new(),
        }
    }

    fn byte(&mut self) -> Result<u8> {
        let byte = *self.data.get(self.position).ok_or("printer IR truncated")?;
        self.position += 1;
        Ok(byte)
    }

    /// Six-bit groups, least significant first; every byte carries 0x40 and
    /// all but the last 0x80, so the blob never contains NUL (the burst
    /// protocol reserves it).
    fn unsigned(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            if byte & 0x40 == 0 || shift >= 64 {
                return Err("printer IR integer is malformed".into());
            }
            value |= u64::from(byte & 0x3f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 6;
        }
    }

    fn signed(&mut self) -> Result<i64> {
        let raw = self.unsigned()?;
        Ok(((raw >> 1) as i64) ^ -((raw & 1) as i64))
    }

    fn int(&mut self) -> Result<i32> {
        i32::try_from(self.signed()?).map_err(|_| "printer IR value out of range".into())
    }

    fn flag(&mut self) -> Result<bool> {
        match self.unsigned()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(format!("printer IR flag {other}")),
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(self.unsigned()?).map_err(|_| "printer IR length")?;
        let end = self
            .position
            .checked_add(length)
            .ok_or("printer IR length")?;
        let bytes = self
            .data
            .get(self.position..end)
            .ok_or("printer IR truncated")?;
        self.position = end;
        Ok(bytes)
    }

    fn string(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| "printer IR string is not UTF-8".into())
    }

    fn optional(&mut self) -> Result<Option<u64>> {
        Ok(if self.flag()? {
            Some(self.unsigned()?)
        } else {
            None
        })
    }

    fn highlight(&mut self) -> Result<u8> {
        u8::try_from(self.unsigned()?).map_err(|_| "printer IR highlight".into())
    }

    fn space(&mut self) -> Result<Space> {
        Ok(if self.flag()? {
            Space::Special(u8::try_from(self.unsigned()?).map_err(|_| "printer IR space code")?)
        } else {
            Space::Index(self.unsigned()?)
        })
    }

    fn brace(&mut self) -> Result<BraceStyle> {
        BraceStyle::from_code(self.unsigned()?).ok_or_else(|| "printer IR brace style".into())
    }

    fn fragment(&mut self) -> Result<Fragment> {
        let bytes = self.bytes()?;
        let mut inner = Reader::new(bytes);
        inner.mode = ExprMode::Off;
        let mut events = Vec::new();
        while inner.position < bytes.len() {
            events.push(inner.event()?);
        }
        Ok(Fragment(events))
    }

    fn optional_fragment(&mut self) -> Result<Option<Fragment>> {
        Ok(if self.flag()? {
            Some(self.fragment()?)
        } else {
            None
        })
    }

    fn target(&mut self) -> Result<Option<GotoTarget>> {
        Ok(if self.flag()? {
            Some(GotoTarget {
                block: self.signed()?,
                label: self.fragment()?,
            })
        } else {
            None
        })
    }

    fn named(&mut self) -> Result<(String, u8)> {
        Ok((self.string()?, self.highlight()?))
    }

    fn event(&mut self) -> Result<Event> {
        let code = self.byte()?;
        Ok(match code {
            1 => Event::BeginDocument(self.unsigned()?),
            2 => Event::EndDocument(self.unsigned()?),
            3 => Event::BeginFunction(self.unsigned()?),
            4 => Event::EndFunction(self.unsigned()?),
            5 => Event::BeginBlock(self.unsigned()?, self.signed()?),
            6 => Event::EndBlock(self.unsigned()?),
            7 => Event::TagLine,
            8 => Event::TagLineIndent(self.int()?),
            9 => Event::BeginReturnType(self.unsigned()?, self.optional()?),
            10 => Event::EndReturnType(self.unsigned()?),
            11 => Event::BeginVarDecl(self.unsigned()?, self.unsigned()?),
            12 => Event::EndVarDecl(self.unsigned()?),
            13 => Event::BeginStatement(self.unsigned()?, self.optional()?),
            14 => Event::EndStatement(self.unsigned()?),
            15 => Event::BeginFuncProto(self.unsigned()?),
            16 => Event::EndFuncProto(self.unsigned()?),
            17 => {
                let (name, highlight) = self.named()?;
                Event::Variable {
                    name,
                    highlight,
                    varnode: self.optional()?,
                    op: self.optional()?,
                }
            }
            18 => {
                let (name, highlight) = self.named()?;
                Event::Op {
                    name,
                    highlight,
                    op: self.optional()?,
                }
            }
            19 => {
                let (name, highlight) = self.named()?;
                Event::FuncName {
                    name,
                    highlight,
                    op: self.optional()?,
                }
            }
            20 => {
                let (name, highlight) = self.named()?;
                Event::Type {
                    name,
                    highlight,
                    id: self.unsigned()?,
                }
            }
            21 => {
                let (name, highlight) = self.named()?;
                let field = if self.flag()? {
                    Some(self.field()?)
                } else {
                    None
                };
                Event::Field {
                    name,
                    highlight,
                    field,
                }
            }
            22 => {
                let (name, highlight) = self.named()?;
                Event::BitField {
                    name,
                    highlight,
                    field: self.field()?,
                }
            }
            23 | 24 => {
                let (name, highlight) = self.named()?;
                let space = self.space()?;
                let offset = self.unsigned()?;
                if code == 23 {
                    Event::Comment {
                        name,
                        highlight,
                        space,
                        offset,
                    }
                } else {
                    Event::Label {
                        name,
                        highlight,
                        space,
                        offset,
                    }
                }
            }
            25 => {
                let (name, highlight) = self.named()?;
                Event::CaseLabel {
                    name,
                    highlight,
                    op: self.optional()?,
                    value: self.unsigned()?,
                }
            }
            26 => {
                let (text, highlight) = self.named()?;
                Event::Print { text, highlight }
            }
            27 => Event::OpenParen(self.unsigned()?, self.string()?),
            28 => Event::CloseParen(self.unsigned()?, self.string()?),
            29 => Event::OpenGroup(self.unsigned()?),
            30 => Event::CloseGroup(self.unsigned()?),
            31 => Event::Spaces(self.int()?, self.int()?),
            32 => Event::StartIndent(self.unsigned()?),
            33 => Event::StopIndent(self.unsigned()?),
            34 => Event::StartComment(self.unsigned()?),
            35 => Event::StopComment(self.unsigned()?),
            other => return Err(format!("printer IR event code {other}")),
        })
    }

    fn field(&mut self) -> Result<FieldRef> {
        Ok(FieldRef {
            type_name: self.string()?,
            type_id: self.unsigned()?,
            offset: self.signed()?,
            op: self.optional()?,
        })
    }

    fn expression(&mut self) -> Result<Expression> {
        let normal = self.fragment()?;
        let comma = if self.flag()? {
            Some(self.fragment()?)
        } else {
            None
        };
        Ok(Expression {
            normal,
            comma,
            source: Source::Fragments,
        })
    }

    fn index(&mut self, limit: usize, what: &str) -> Result<usize> {
        let value = usize::try_from(self.unsigned()?).map_err(|_| format!("printer IR {what}"))?;
        if value >= limit {
            return Err(format!("printer IR {what} {value} out of range"));
        }
        Ok(value)
    }

    fn type_index(&mut self) -> Result<usize> {
        self.index(self.tables.types.len(), "type")
    }

    fn symbol_index(&mut self) -> Result<usize> {
        self.index(self.tables.symbols.len(), "symbol")
    }

    /// Version 4: the options PrintC's expression emission consults.
    fn options(&mut self) -> Result<Options> {
        let bits = self.unsigned()?;
        Ok(Options {
            no_casts: bits & 1 != 0,
            hide_exts: bits & 2 != 0,
            null_keyword: bits & 4 != 0,
            inplace_ops: bits & 8 != 0,
            hide_this: bits & 16 != 0,
            base_mods: u32::try_from(self.unsigned()?).map_err(|_| "printer IR mods")?,
            size_suffix: self.string()?,
        })
    }

    /// Version 4: the symbol and type tables the print trees index.
    fn tables(&mut self) -> Result<()> {
        let count = self.unsigned()?;
        let mut symbols = Vec::new();
        for _ in 0..count {
            let highlight = self.highlight()?;
            let name = self.string()?;
            let scopes = (0..self.unsigned()?)
                .map(|_| self.string())
                .collect::<Result<_>>()?;
            symbols.push(SymbolDesc {
                highlight,
                name,
                scopes,
            });
        }
        let count = self.unsigned()?;
        let mut types = Vec::new();
        for _ in 0..count {
            let id = self.unsigned()?;
            let name = self.string()?;
            let display_name = self.string()?;
            let generic_name = self.string()?;
            let meta = u8::try_from(self.unsigned()?).map_err(|_| "printer IR metatype")?;
            let size = self.size()?;
            let display_format = self.size()?;
            let flags = self.unsigned()?;
            let base = self.unsigned()?;
            let elements = self.size()?;
            let has_proto = self.flag()?;
            let mut fields = Vec::new();
            if meta == super::tree::meta::STRUCT {
                for _ in 0..self.unsigned()? {
                    fields.push((self.signed()?, self.signed()?, self.string()?, self.unsigned()?));
                }
            }
            let submeta = u8::try_from(self.unsigned()?).map_err(|_| "printer IR sub-metatype")?;
            let typedef = self.unsigned()?;
            let word_size = self.size()?;
            let space = self.size()?;
            let align_size = self.size()?;
            let variable_length = self.flag()?;
            types.push(TypeDesc {
                id,
                name,
                display_name,
                generic_name,
                meta,
                size,
                display_format,
                char_print: flags & 1 != 0,
                enumerated: flags & 2 != 0,
                needs_resolution: flags & 4 != 0,
                pointer_to_array: flags & 8 != 0,
                base: base.checked_sub(1).map(|base| base as usize),
                elements,
                has_proto,
                fields: fields
                    .into_iter()
                    .map(|(offset, ident, name, ty)| FieldDesc {
                        offset,
                        ident,
                        name,
                        ty: ty as usize,
                    })
                    .collect(),
                submeta,
                typedef: typedef.checked_sub(1).map(|typedef| typedef as usize),
                word_size,
                space,
                align_size,
                variable_length,
            });
        }
        for ty in &types {
            if ty.base.is_some_and(|base| base >= types.len())
                || ty.typedef.is_some_and(|typedef| typedef >= types.len())
                || ty.fields.iter().any(|field| field.ty >= types.len())
            {
                return Err("printer IR type refers past the table".into());
            }
        }
        let promote_size = self.size()?;
        let mut seeds = Vec::new();
        for _ in 0..self.unsigned()? {
            let size = self.size()?;
            let kind = u8::try_from(self.unsigned()?).map_err(|_| "printer IR seed kind")?;
            let index = self.unsigned()? as usize;
            if index >= types.len() || kind > 4 {
                return Err("printer IR seed past the table".into());
            }
            let metatype = match kind {
                0 | 4 => super::tree::meta::INT,
                1 => super::tree::meta::UINT,
                2 => super::tree::meta::UNKNOWN,
                _ => super::tree::meta::BOOL,
            };
            seeds.push(((metatype, size, kind), index));
        }
        let mut order = Vec::new();
        for _ in 0..self.unsigned()? {
            let a = self.unsigned()? as usize;
            let b = self.unsigned()? as usize;
            let sign = self.signed()?;
            if a >= types.len() || b >= types.len() || a >= b {
                return Err("printer IR type order past the table".into());
            }
            order.push(((a, b), sign.clamp(-1, 1) as i8));
        }
        self.tables = Tables {
            types,
            symbols,
            seeds,
            order,
            promote_size,
        };
        Ok(())
    }

    /// A leaf (`PT_CONST`, `PT_ATOM`, `PT_SYMBOL`, `PT_PARTIAL`) after its tag.
    fn pleaf(&mut self, tag: u64) -> Result<PNode> {
        Ok(match tag {
            1 => {
                let vn = self.unsigned()?;
                let size = self.size()?;
                let value = self.unsigned()?;
                let ty = self.type_index()?;
                let flags = self.unsigned()?;
                let symbol_format = self.size()?;
                let kind = match self.unsigned()? {
                    0 => ConstKind::Integer,
                    1 => ConstKind::Char,
                    2 => ConstKind::Default,
                    other => return Err(format!("printer IR constant kind {other}")),
                };
                PNode::Const(PConst {
                    vn,
                    size,
                    value,
                    ty,
                    unsigned_print: flags & 1 != 0,
                    long_print: flags & 2 != 0,
                    symbol_format,
                    kind,
                })
            }
            2 => {
                let size = self.size()?;
                let mut events = self.fragment()?.0;
                if events.len() != 1 {
                    return Err("printer IR atom is not a single token".into());
                }
                PNode::Atom {
                    size,
                    event: events.remove(0),
                }
            }
            3 => PNode::Symbol {
                vn: self.optional()?,
                size: self.size()?,
                sym: self.symbol_index()?,
            },
            4 => {
                let vn = self.optional()?;
                let sym = self.symbol_index()?;
                let offset = self.signed()?;
                let size = self.signed()?;
                let sym_type = self.type_index()?;
                let high_type = self.type_index()?;
                let flags = self.unsigned()?;
                PNode::Partial(PPartial {
                    vn,
                    sym,
                    offset,
                    size,
                    sym_type,
                    high_type,
                    read: flags & 1 != 0,
                    big_endian: flags & 2 != 0,
                })
            }
            other => return Err(format!("printer IR leaf tag {other}")),
        })
    }

    /// The per-opcode data after an op node's head (`opNode`'s switch).
    fn pextra(&mut self, code: u32) -> Result<Extra> {
        Ok(match code {
            render::opc::INT_ZEXT | render::opc::INT_SEXT => Extra::Ext {
                out: self.type_index()?,
                input: self.type_index()?,
                implied: self.flag()?,
                address_of: self.flag()?,
            },
            render::opc::SUBPIECE => {
                let out = self.type_index()?;
                let input = self.type_index()?;
                let offset = self.unsigned()?;
                let address_of = self.flag()?;
                let special = match self.unsigned()? {
                    0 => PieceKind::None,
                    1 => {
                        let tag = self.unsigned()?;
                        if tag != 4 {
                            return Err("printer IR piece leaf".into());
                        }
                        PieceKind::Partial(Box::new(self.pleaf(tag)?))
                    }
                    2 => PieceKind::Member {
                        container: self.type_index()?,
                        name: self.string()?,
                        ident: self.signed()?,
                    },
                    other => return Err(format!("printer IR piece kind {other}")),
                };
                Extra::Subpiece {
                    out,
                    input,
                    offset,
                    address_of,
                    special,
                }
            }
            render::opc::CAST | render::opc::FLOAT_FLOAT2FLOAT | render::opc::FLOAT_TRUNC => {
                Extra::Cast {
                    out: self.type_index()?,
                    address_of: self.flag()?,
                }
            }
            render::opc::FLOAT_INT2FLOAT => Extra::Int2Float {
                out: self.type_index()?,
            },
            render::opc::CBRANCH => Extra::Cbranch {
                flip: self.flag()?,
            },
            render::opc::CALL => {
                let name = self.string()?;
                let scopes = (0..self.unsigned()?)
                    .map(|_| self.string())
                    .collect::<Result<_>>()?;
                Extra::Call { name, scopes }
            }
            render::opc::CALLIND => Extra::CallInd {
                hidden_this: self.signed()?,
            },
            render::opc::CALLOTHER => Extra::CallOther {
                display: self.unsigned()?,
                name: self.string()?,
            },
            render::opc::RETURN => Extra::Return {
                halt: u8::try_from(self.unsigned()?).map_err(|_| "printer IR halt kind")?,
            },
            render::opc::PTRSUB => Extra::Ptrsub(match self.unsigned()? {
                0 => PtrsubKind::No(self.string()?),
                1 => PtrsubKind::Struct {
                    container: self.type_index()?,
                    field: self.string()?,
                    id: self.signed()?,
                    array: self.flag()?,
                },
                2 => {
                    let symbol_kind =
                        u8::try_from(self.unsigned()?).map_err(|_| "printer IR symbol kind")?;
                    let tag = self.unsigned()?;
                    if !(2..=4).contains(&tag) {
                        return Err("printer IR spacebase leaf".into());
                    }
                    PtrsubKind::Spacebase {
                        symbol_kind,
                        leaf: Box::new(self.pleaf(tag)?),
                    }
                }
                3 => PtrsubKind::Array,
                other => return Err(format!("printer IR ptrsub kind {other}")),
            }),
            _ => Extra::None,
        })
    }

    /// Version 6, casts pending: after a leaf its types and flags.
    fn info(&mut self) -> Result<Info> {
        Ok(Info {
            ty: self.type_index()?,
            own: self.type_index()?,
            flags: u32::try_from(self.unsigned()?).map_err(|_| "printer IR node flags")?,
        })
    }

    /// A pre-cast print node (casts pending).
    fn cnode(&mut self, depth: usize) -> Result<CNode> {
        if depth > 2000 {
            return Err("printer IR print tree too deep".into());
        }
        let tag = self.unsigned()?;
        match tag {
            0 => {
                return Ok(CNode::Leaf(CLeaf {
                    node: PNode::No(self.string()?),
                    info: Info::default(),
                }));
            }
            1..=4 => {
                let node = self.pleaf(tag)?;
                let info = self.info()?;
                return Ok(CNode::Leaf(CLeaf { node, info }));
            }
            5 => {}
            other => return Err(format!("printer IR print tree tag {other}")),
        }
        let code = self.size()?;
        let time = self.unsigned()?;
        let out_size = self.size()?;
        let count = self.unsigned()? as usize;
        let extra = self.pextra(code)?;
        let out = if self.flag()? {
            let ty = self.type_index()?;
            let own = self.type_index()?;
            let flags = u32::try_from(self.unsigned()?).map_err(|_| "printer IR node flags")?;
            let local = self.type_index()?;
            Some(COut {
                info: Info { ty, own, flags },
                local,
            })
        } else {
            None
        };
        let absorbed = self.flag()?;
        let bool_out = self.flag()?;
        let call = self.flag()?;
        let mut word = 0;
        let mut call_locked = (true, true);
        let mut ptradd_size = 0;
        let mut ptrsub_offset = 0;
        let mut ptrsub_matching = true;
        let mut token = None;
        match code {
            render::opc::LOAD | render::opc::STORE => word = self.size()?,
            render::opc::CALL => call_locked = (self.flag()?, self.flag()?),
            render::opc::PTRADD => ptradd_size = self.unsigned()?,
            render::opc::PTRSUB => {
                ptrsub_offset = self.unsigned()?;
                ptrsub_matching = self.flag()?;
                token = Some(self.type_index()?);
            }
            render::opc::SUBPIECE => token = Some(self.type_index()?),
            _ => {}
        }
        let mut slots = Vec::with_capacity(count);
        let mut locals = Vec::with_capacity(count);
        for _ in 0..count {
            slots.push(self.unsigned()? as usize);
            locals.push(self.type_index()?);
        }
        let mut kids = Vec::with_capacity(count);
        for _ in 0..count {
            kids.push(self.cnode(depth + 1)?);
        }
        Ok(CNode::Op(Box::new(COp {
            head: POp {
                code,
                time,
                out_size,
                extra,
                kids: Vec::new(),
            },
            out,
            absorbed,
            bool_out,
            call,
            word,
            ptradd_size,
            ptrsub_offset,
            ptrsub_matching,
            token,
            slots,
            locals,
            kids,
            ptrsub_cast: false,
            call_locked,
        })))
    }

    fn ctree(&mut self) -> Result<CTree> {
        let out = if self.flag()? {
            let tag = self.unsigned()?;
            Some(if tag == 0 {
                CLeaf {
                    node: PNode::No(self.string()?),
                    info: Info::default(),
                }
            } else {
                let node = self.pleaf(tag)?;
                let info = self.info()?;
                CLeaf { node, info }
            })
        } else {
            None
        };
        Ok(CTree {
            out,
            root: self.cnode(0)?,
        })
    }

    /// Casts one statement the way `ActionSetCasts` would have.
    fn cast_statement(&mut self, tree: CTree) -> Result<PrintTree> {
        casts::check_tree(&tree)?;
        let mut pass = casts::Pass::new(&mut self.tables, &self.options, &self.rules);
        pass.next_time = self.cast_time;
        let cast = pass.statement(tree)?;
        let printed = pass.finish(cast)?;
        self.cast_time = pass.next_time;
        self.cast_stats.add(&pass.stats);
        self.cast_warnings.extend(pass.warnings);
        self.cast_type_ids.extend(pass.cast_types);
        for call in pass.call_types {
            self.call_types.insert(call.time, call);
        }
        self.cast_edits.extend(pass.edits);
        Ok(printed)
    }

    fn pnode(&mut self, depth: usize) -> Result<PNode> {
        if depth > 2000 {
            return Err("printer IR print tree too deep".into());
        }
        let tag = self.unsigned()?;
        match tag {
            0 => return Ok(PNode::No(self.string()?)),
            1..=4 => return self.pleaf(tag),
            5 => {}
            other => return Err(format!("printer IR print tree tag {other}")),
        }
        let code = self.size()?;
        let time = self.unsigned()?;
        let out_size = self.size()?;
        let count = self.unsigned()?;
        if code == render::opc::CAST {
            self.expressions.native_cast_ops += 1;
        }
        let extra = self.pextra(code)?;
        let mut kids = Vec::new();
        for _ in 0..count {
            kids.push(self.pnode(depth + 1)?);
        }
        Ok(PNode::Op(Box::new(POp {
            code,
            time,
            out_size,
            extra,
            kids,
        })))
    }

    fn print_tree(&mut self) -> Result<PrintTree> {
        if self.pending {
            let tree = self.ctree()?;
            return self.cast_statement(tree);
        }
        let out = if self.flag()? {
            let tag = self.unsigned()?;
            Some(if tag == 0 {
                PNode::No(self.string()?)
            } else {
                self.pleaf(tag)?
            })
        } else {
            None
        };
        Ok(PrintTree {
            out,
            root: self.pnode(0)?,
        })
    }

    /// Replaces an expression's fragments by the worker's own rendering of
    /// its print tree when it prints it (`context`: where the expression is
    /// used; `flip`: the CBRANCH's negation).
    fn rendered(
        &mut self,
        expression: Expression,
        tree: &PrintTree,
        context: &'static str,
        flip: bool,
    ) -> Expression {
        let render::Outcome::Rendered { normal, comma } = render::attempt(
            &mut self.expressions,
            self.mode,
            &self.options,
            &self.tables,
            tree,
            context,
            flip,
            &expression.normal,
            expression.comma.as_ref(),
        ) else {
            if self.pending && self.cast_error.is_none() {
                self.cast_error = Some(format!("printed statement {context} refused after casting"));
            }
            return expression;
        };
        Expression {
            normal,
            comma,
            source: Source::Rust,
        }
    }

    /// A for-loop header's expression (`comma_separate` rendering only).
    fn rendered_loop(
        &mut self,
        fragment: Fragment,
        tree: &PrintTree,
        context: &'static str,
    ) -> (Fragment, Source) {
        let expression = Expression {
            normal: fragment.clone(),
            comma: Some(fragment),
            source: Source::Fragments,
        };
        let rendered = self.rendered(expression, tree, context, false);
        match rendered.source {
            Source::Rust => (rendered.comma.unwrap_or(rendered.normal), Source::Rust),
            Source::Fragments => (rendered.normal, Source::Fragments),
        }
    }

    fn expr(&mut self, depth: usize) -> Result<Expr> {
        if depth > 64 {
            return Err("printer IR expression too deep".into());
        }
        Ok(match self.unsigned()? {
            0 => Expr::Opaque,
            1 => Expr::Const {
                size: self.size()?,
                value: self.unsigned()?,
            },
            2 => {
                let size = self.size()?;
                let ssa = self.unsigned()?;
                let high = self.size()?;
                let packed = self.unsigned()?;
                Expr::Var {
                    size,
                    ssa,
                    high,
                    storage: Storage {
                        class: (packed & 3) as u8,
                        aliased: packed >> 2 != 0,
                    },
                }
            }
            3 => {
                let code = self.size()?;
                let count = self.unsigned()?;
                let args = (0..count)
                    .map(|_| self.expr(depth + 1))
                    .collect::<Result<_>>()?;
                Expr::Op { code, args }
            }
            other => return Err(format!("printer IR expression tag {other}")),
        })
    }

    fn size(&mut self) -> Result<u32> {
        u32::try_from(self.unsigned()?).map_err(|_| "printer IR size".into())
    }

    fn effect(&mut self) -> Result<Effect> {
        let code = self.size()?;
        let calls = self.flag()?;
        let stores = self.flag()?;
        let out = if self.flag()? {
            Some(self.expr(0)?)
        } else {
            None
        };
        let flip = self.flag()?;
        let count = self.unsigned()?;
        let args = (0..count)
            .map(|_| self.expr(0))
            .collect::<Result<_>>()?;
        Ok(Effect {
            code,
            calls,
            stores,
            out,
            flip,
            args,
        })
    }

    fn basic(&mut self, index: i64) -> Result<Basic> {
        let count = self.unsigned()?;
        let mut comments = Vec::new();
        for position in 0..count as usize {
            let printable = self.flag()?;
            let line = self.fragment()?;
            let next = self.comment_slots.len();
            let slot = *self.comment_slots.entry((index, position)).or_insert(next);
            comments.push(Comment {
                slot,
                printable,
                line,
            });
        }
        let count = self.unsigned()?;
        let mut statements = Vec::new();
        let mut trees = Vec::new();
        for _ in 0..count {
            let op = self.unsigned()?;
            let is_branch = self.flag()?;
            let comment_bound =
                usize::try_from(self.unsigned()?).map_err(|_| "printer IR bound")?;
            if comment_bound > comments.len() {
                return Err("printer IR comment bound past the block's comments".into());
            }
            let expression = self.expression()?;
            let effect = self.effect()?;
            let tree = self.print_tree()?;
            let expression = self.rendered(expression, &tree, "statement", false);
            trees.push(tree);
            statements.push(Statement {
                op,
                is_branch,
                comment_bound,
                expression,
                effect,
            });
        }
        let mut branch_tree = None;
        let branch = if self.flag()? {
            let expression = self.expression()?;
            let tree = if self.flag()? {
                let shared = self.index(trees.len(), "branch statement")?;
                trees.swap_remove(shared)
            } else {
                
                    self.print_tree()?
            };
            let expression = self.rendered(expression, &tree, "branch", false);
            branch_tree = Some(tree);
            Some(expression)
        } else {
            None
        };
        let successors = (0..self.unsigned()?)
            .map(|_| self.signed())
            .collect::<Result<_>>()?;
        let negated = if self.flag()? {
            let expression = self.expression()?;
            Some(match &branch_tree {
                Some(tree) => self.rendered(expression, tree, "negated", true),
                None => return Err("printer IR negation without a branch".into()),
            })
        } else {
            None
        };
        let holds_loop_op = self.flag()?;
        Ok(Basic {
            comments,
            statements,
            branch,
            successors,
            negated,
            holds_loop_op,
            threaded: Vec::new(),
        })
    }

    /// A for-loop initializer or iterator: its op time (when there is one),
    /// the comma-separated fragment and the print tree.
    fn loop_op(&mut self, context: &'static str) -> Result<Option<(u64, Fragment, Source)>> {
        match self.optional()? {
            Some(op) => {
                let fragment = self.fragment()?;
                let tree = self.print_tree()?;
                let (fragment, source) = self.rendered_loop(fragment, &tree, context);
                Ok(Some((op, fragment, source)))
            }
            None => Ok(None),
        }
    }

    /// One block's shape record: the facts the structurer reads (flags, last
    /// op, edges); `count` is the number of blocks, which bounds the edges.
    fn shape(&mut self, count: usize) -> Result<CfgBlock> {
        let flags = u32::try_from(self.unsigned()?).map_err(|_| "printer IR block flags")?;
        let last = match self.unsigned()? {
            0 => Last::None,
            1 => Last::Return,
            2 => Last::Cbranch,
            3 => Last::Other,
            other => return Err(format!("printer IR last-op kind {other}")),
        };
        let last_time = self.optional()?;
        let fallthru_true = self.flag()?;
        let complex = self.flag()?;
        let flipped = self.flag()?;
        let mut edges = [Vec::new(), Vec::new()];
        for list in &mut edges {
            for _ in 0..self.unsigned()? {
                let block = usize::try_from(self.signed()?).map_err(|_| "printer IR edge block")?;
                let rev = usize::try_from(self.unsigned()?).map_err(|_| "printer IR edge slot")?;
                let label = u32::try_from(self.unsigned()?).map_err(|_| "printer IR edge label")?;
                if block >= count {
                    return Err("printer IR edge past the last block".into());
                }
                list.push(CfgEdge { block, rev, label });
            }
        }
        let [ins, outs] = edges;
        Ok(CfgBlock {
            ins,
            outs,
            flags,
            last,
            last_time,
            fallthru_true,
            complex,
            flipped,
            label: Fragment::default(),
            switch_edges: Vec::new(),
            basic: None,
        })
    }

    /// The unstructured graph (version 5): per basic block its edges and the
    /// facts the structurer reads, its label, the case labels of a switch,
    /// and the block's statements; then the for-loops the decompiler found.
    fn cfg(&mut self) -> Result<Cfg> {
        let count = usize::try_from(self.unsigned()?).map_err(|_| "printer IR block count")?;
        let mut cfg = Cfg::default();
        for index in 0..count {
            let mut block = self.shape(count)?;
            block.label = self.fragment()?;
            for _ in 0..self.unsigned()? {
                if self.flag()? {
                    let labels = (0..self.unsigned()?)
                        .map(|_| self.unsigned())
                        .collect::<Result<Vec<_>>>()?;
                    block.switch_edges.push(Some(SwitchEdge {
                        labels,
                        fragment: self.fragment()?,
                    }));
                } else {
                    block.switch_edges.push(None);
                }
            }
            block.basic = Some(self.basic(index as i64)?);
            cfg.blocks.push(block);
        }
        for _ in 0..self.unsigned()? {
            let head = usize::try_from(self.signed()?).map_err(|_| "printer IR loop head")?;
            let tail = usize::try_from(self.signed()?).map_err(|_| "printer IR loop tail")?;
            let initialize = self.loop_op("loop-init")?;
            let iterate = self.loop_op("loop-iterate")?;
            cfg.loops.push(LoopRecord {
                head,
                tail,
                initialize,
                iterate,
            });
        }
        for _ in 0..self.unsigned()? {
            cfg.prefer
                .push(usize::try_from(self.unsigned()?).map_err(|_| "printer IR complemented if")?);
        }
        Ok(cfg)
    }

    fn node(&mut self, depth: usize) -> Result<Node> {
        if depth > 4096 {
            return Err("printer IR block tree too deep".into());
        }
        let block_kind = self.unsigned()?;
        let index = self.signed()?;
        let last_op = self.optional()?;
        let label = self.optional_fragment()?;
        let mut node = Node {
            kind: block_kind,
            index,
            last_op,
            label,
            children: Vec::new(),
            detail: Detail::None,
        };
        match block_kind {
            kind::BASIC => {
                node.detail = Detail::Basic(self.basic(index)?);
                return Ok(node);
            }
            kind::PLAIN => return Ok(node),
            kind::GRAPH..=kind::INFINITE_LOOP => {}
            other => return Err(format!("printer IR block kind {other}")),
        }
        let count = self.unsigned()?;
        for _ in 0..count {
            node.children.push(self.node(depth + 1)?);
        }
        let size = node.children.len();
        node.detail = match block_kind {
            kind::COPY => Detail::Copy {
                label: self.fragment()?,
            },
            kind::GOTO => Detail::Goto {
                prints: self.flag()?,
                goto_kind: self.unsigned()?,
                target: self.target()?,
            },
            kind::LIST => Detail::List {
                flow_breaks: (0..size.saturating_sub(1))
                    .map(|_| self.flag())
                    .collect::<Result<_>>()?,
            },
            kind::CONDITION => Detail::Condition { and: self.flag()? },
            kind::IF => Detail::If {
                goto_kind: self.unsigned()?,
                target: self.target()?,
            },
            kind::WHILE_DO => {
                let overflow = self.flag()?;
                let initialize = self.loop_op("loop-init")?;
                let iterate = self.loop_op("loop-iterate")?;
                Detail::WhileDo {
                    overflow,
                    initialize,
                    iterate,
                }
            }
            kind::SWITCH => {
                let count = self.unsigned()?;
                let mut cases = Vec::new();
                for _ in 0..count {
                    let labels = vec![self.fragment()?];
                    let goto_kind = self.unsigned()?;
                    let exit = self.flag()?;
                    let body = if goto_kind != 0 {
                        CaseBody::Goto {
                            goto_kind,
                            target: self.target()?,
                        }
                    } else if self.flag()? {
                        let child =
                            usize::try_from(self.unsigned()?).map_err(|_| "printer IR case")?;
                        if child >= size {
                            return Err("printer IR case block out of range".into());
                        }
                        CaseBody::Child(child)
                    } else {
                        CaseBody::Block(Box::new(self.node(depth + 1)?))
                    };
                    cases.push(Case { labels, exit, body });
                }
                Detail::Switch { cases }
            }
            _ => Detail::None,
        };
        let expected = match block_kind {
            kind::COPY | kind::GOTO | kind::MULTIGOTO | kind::DO_WHILE | kind::INFINITE_LOOP => {
                Some(1)
            }
            kind::CONDITION | kind::WHILE_DO => Some(2),
            kind::SWITCH => Some(1),
            _ => None,
        };
        // An if with an unstructured edge (`if (c) goto L;`) has only its
        // condition; otherwise it has a body and maybe an else.
        let if_shape = match &node.detail {
            Detail::If {
                target: Some(_), ..
            } => (1..=3).contains(&size),
            Detail::If { target: None, .. } => (2..=3).contains(&size),
            _ => true,
        };
        if expected.is_some_and(|expected| size < expected) || !if_shape {
            return Err(format!(
                "printer IR block kind {block_kind} has {size} children"
            ));
        }
        Ok(node)
    }
}

/// Decodes the blob carried by `<romwright_printir>`.
pub fn decode(blob: &[u8]) -> Result<PrinterIr> {
    let mut reader = Reader::new(blob);
    if blob.get(..4) != Some(b"RWPI".as_slice()) {
        return Err("printer IR has no RWPI magic".into());
    }
    reader.position = 4;
    let version = reader.unsigned()?;
    if version != 7 {
        return Err(format!("printer IR version {version} is not 7"));
    }
    let max_line_size = reader.int()?;
    let indent_increment = reader.int()?;
    let brace_function = reader.brace()?;
    let brace_if_else = reader.brace()?;
    let brace_loop = reader.brace()?;
    let brace_switch = reader.brace()?;
    let count_after = reader.int()?;
    reader.options = reader.options()?;
    reader.pending = reader.flag()?;
    if reader.pending {
        reader.mode = ExprMode::On;
    }
    // Version 7: the worker decided the function's merge (printc/merge).
    let merge_owned = reader.flag()?;
    let header = reader.fragment()?;
    let declaration = reader.fragment()?;
    let locals = reader.fragment()?;
    reader.tables()?;
    if reader.pending {
        casts::check_supported(&reader.tables, &reader.options)?;
    }
    let mut body = Vec::new();
    if reader.flag()? {
        let count = reader.unsigned()?;
        for _ in 0..count {
            body.push(reader.node(0)?);
        }
    }
    let cfg = Some(reader.cfg()?);
    if reader.position != blob.len() {
        return Err("printer IR has trailing bytes".into());
    }
    if let Some(reason) = reader.cast_error.take() {
        return Err(reason);
    }
    reader.expressions.cast_functions[usize::from(!reader.pending)] += 1;
    reader.expressions.merge_functions[usize::from(!merge_owned)] += 1;
    reader.expressions.casts.add(&reader.cast_stats);
    Ok(PrinterIr {
        max_line_size,
        indent_increment,
        brace_function,
        brace_if_else,
        brace_loop,
        brace_switch,
        count_after,
        header,
        declaration,
        locals,
        native_tree: !body.is_empty(),
        body,
        cfg,
        comment_slots: reader.comment_slots.len(),
        expressions: reader.expressions,
        cast_edits: std::mem::take(&mut reader.cast_edits),
        cast_types: reader
            .cast_type_ids
            .iter()
            .map(|&index| casts::describe(&reader.tables, index, 0))
            .collect(),
        call_types: reader
            .call_types
            .values()
            .map(|call| CallPrototypeTypes {
                time: call.time,
                params: (!call.input_locked).then(|| {
                    call.params
                        .iter()
                        .map(|&index| casts::describe(&reader.tables, index, 0))
                        .collect()
                }),
                ret: if call.output_locked {
                    None
                } else {
                    call.ret.map(|index| casts::describe(&reader.tables, index, 0))
                },
            })
            .collect(),
    })
}

/// Decodes a structuring query (`native/romwright_structure.hh`): the shape
/// of the basic-block graph `ActionBlockStructure` would structure.
pub fn decode_structure_query(blob: &[u8]) -> Result<Cfg> {
    let mut reader = Reader::new(blob);
    let count = usize::try_from(reader.unsigned()?).map_err(|_| "structuring query block count")?;
    let mut cfg = Cfg::default();
    for _ in 0..count {
        cfg.blocks.push(reader.shape(count)?);
    }
    if reader.position != blob.len() {
        return Err("structuring query has trailing bytes".into());
    }
    Ok(cfg)
}

/// A cast query (`romwrightFinishCasts`): the options, the type tables and
/// every statement's pre-cast print tree, block by block.
pub struct CastQuery {
    /// 0: decide the function's casts; 1: the decompiler's own casts of a
    /// function the worker decided (verify mode).
    pub marker: u64,
    pub tables: Tables,
    pub options: Options,
    pub statements: Vec<CTree>,
    /// The for-loop candidates' initializer and iterator statements.
    pub loop_ops: Vec<CTree>,
}

pub fn decode_cast_query(blob: &[u8]) -> Result<CastQuery> {
    let mut reader = Reader::new(blob);
    reader.pending = true;
    if reader.unsigned()? != 0 {
        return Err("cast query marker".into());
    }
    let marker = reader.unsigned()?;
    if marker > 1 {
        return Err("cast query kind".into());
    }
    reader.options = reader.options()?;
    reader.tables()?;
    let mut statements = Vec::new();
    for _ in 0..reader.unsigned()? {
        for _ in 0..reader.unsigned()? {
            statements.push(reader.ctree()?);
        }
        if reader.flag()? {
            statements.push(reader.ctree()?);
        }
    }
    let mut loop_ops = Vec::new();
    for _ in 0..reader.unsigned()? {
        for _ in 0..2 {
            if reader.flag()? {
                loop_ops.push(reader.ctree()?);
            }
        }
    }
    if reader.position != blob.len() {
        return Err("cast query has trailing bytes".into());
    }
    Ok(CastQuery {
        marker,
        tables: reader.tables,
        options: reader.options,
        statements,
        loop_ops,
    })
}

/// A merge query (`native/romwright_merge.hh`): the function's p-code after
/// `ActionAssignHigh`, for the worker's stage-3 decisions
/// (`merge::Func::decide`).
pub struct MergeQuery {
    pub func: super::merge::model::Func,
    pub multi_entry: bool,
    pub dynamic: bool,
    pub initial_ops: usize,
}

pub fn decode_merge_query(blob: &[u8]) -> Result<MergeQuery> {
    use super::merge::cover::Cover;
    use super::merge::model::{
        Addr, Affecting, Block, Func, High, LoopCandidate, NO_HIGH, Op, Space, Symbol, Vn, vf,
    };
    let mut r = Reader::new(blob);
    if r.unsigned()? != 0 {
        return Err("merge query marker".into());
    }
    if r.unsigned()? != 2 {
        return Err("merge query kind".into());
    }
    let mut f = Func::default();
    f.address = r.unsigned()?;
    f.max_implied_ref = u32::try_from(r.unsigned()?).map_err(|_| "merge query value")?;
    f.max_term_dup = u32::try_from(r.unsigned()?).map_err(|_| "merge query value")?;
    f.analyze_loops = r.flag()?;
    f.next_time = r.unsigned()?;
    f.next_create = u32::try_from(r.unsigned()?).map_err(|_| "merge query value")?;
    f.next_unique = r.unsigned()?;
    f.unique_space = u32::try_from(r.unsigned()?).map_err(|_| "merge query value")?;
    let multi_entry = r.flag()?;
    let dynamic = r.flag()?;
    r.tables()?;
    f.tables = std::mem::take(&mut r.tables);
    let types = f.tables.types.len();
    let n = r.unsigned()? as usize;
    if n != types {
        return Err("merge query stripped table".into());
    }
    for _ in 0..n {
        let s = r.unsigned()?;
        f.stripped.push(s.checked_sub(1).map(|s| s as usize));
    }
    for _ in 0..r.unsigned()? {
        let index = r.unsigned()? as usize;
        let kind = r.unsigned()? as u8;
        let big_endian = r.flag()?;
        if f.spaces.len() <= index {
            f.spaces.resize(index + 1, None);
        }
        f.spaces[index] = Some(Space { kind, big_endian });
    }
    for _ in 0..r.unsigned()? {
        f.symbols.push(Symbol { isolated: r.flag()?, meta: u8::try_from(r.unsigned()?).map_err(|_| "merge query metatype")? });
    }
    let nblocks = r.unsigned()? as usize;
    let addr = |r: &mut Reader| -> Result<Addr> {
        Ok(Addr { space: u32::try_from(r.unsigned()?).map_err(|_| "merge query space")?, offset: r.unsigned()? })
    };
    for _ in 0..nblocks {
        let mut b = Block::default();
        for _ in 0..r.unsigned()? {
            b.ins.push(r.index(nblocks, "block")?);
        }
        for _ in 0..r.unsigned()? {
            b.outs.push(r.index(nblocks, "block")?);
            b.out_rev.push(r.unsigned()? as usize);
        }
        b.idom = r.unsigned()?.checked_sub(1).map(|x| x as usize);
        b.start = addr(&mut r)?;
        b.stop = addr(&mut r)?;
        for _ in 0..r.unsigned()? {
            b.ops.push(r.unsigned()? as usize);
        }
        f.blocks.push(b);
    }
    let nops = r.unsigned()? as usize;
    let nvns_hint = blob.len();
    let _ = nvns_hint;
    for i in 0..nops {
        let mut op = Op {
            time: r.unsigned()?,
            pc: addr(&mut r)?,
            code: u32::try_from(r.unsigned()?).map_err(|_| "merge query opcode")?,
            block: r.unsigned()?.checked_sub(1).map(|x| x as usize),
            order: u32::try_from(r.unsigned()?).map_err(|_| "merge query order")?,
            flags: u32::try_from(r.unsigned()?).map_err(|_| "merge query flags")?,
            addl: u32::try_from(r.unsigned()?).map_err(|_| "merge query flags")?,
            ..Default::default()
        };
        for _ in 0..r.unsigned()? {
            op.ins.push(r.unsigned()? as usize);
        }
        op.out = r.unsigned()?.checked_sub(1).map(|x| x as usize);
        op.target = r.unsigned()?.checked_sub(1).map(|x| x as usize);
        for _ in 0..r.unsigned()? {
            op.same_local.push(u32::try_from(r.unsigned()?).map_err(|_| "merge query mask")?);
        }
        op.alive_at = Some(i);
        f.alive.push(Some(i));
        f.ops.push(op);
    }
    let nvns = r.unsigned()? as usize;
    for _ in 0..nvns {
        let mut vn = Vn {
            create: u32::try_from(r.unsigned()?).map_err(|_| "merge query create index")?,
            size: u32::try_from(r.unsigned()?).map_err(|_| "merge query size")?,
            addr: addr(&mut r)?,
            flags: u32::try_from(r.unsigned()?).map_err(|_| "merge query flags")? & !(vf::MARK | 0x1000000),
            ty: r.index(types, "type")?,
            def: r.unsigned()?.checked_sub(1).map(|x| x as usize),
            ..Default::default()
        };
        for _ in 0..r.unsigned()? {
            vn.desc.push(r.unsigned()? as usize);
        }
        vn.symbol = r.unsigned()?.checked_sub(1).map(|x| x as usize);
        let symoff = r.int()?;
        vn.entry = r.unsigned()?.checked_sub(1).map(|x| x as usize);
        vn.entry_offset = r.int()?;
        vn.high = NO_HIGH;
        vn.has_cover_obj = vn.has_cover();
        vn.cover_dirty = vn.has_cover_obj;
        vn.cover = Cover::default();
        f.vns.push(vn);
        // The high-level variable assignHigh gave it.
        if f.vns.last().unwrap().flags & vf::ANNOTATION == 0 {
            let id = f.highs.len();
            let v = f.vns.len() - 1;
            let mut high = High::default();
            high.inst = vec![v];
            high.merge_classes = 1;
            high.symbol = f.vns[v].symbol;
            high.symoff = if high.symbol.is_some() { symoff } else { -1 };
            high.cover_dirty = true;
            f.highs.push(high);
            f.vns[v].high = id;
        }
    }
    for _ in 0..r.unsigned()? {
        f.calls.push(r.unsigned()? as usize);
    }
    for _ in 0..r.unsigned()? {
        let op = r.unsigned()? as usize;
        let guard = if r.flag()? {
            Some((u32::try_from(r.unsigned()?).map_err(|_| "merge query space")?, r.unsigned()?, r.unsigned()?))
        } else {
            None
        };
        f.affecting.push(Affecting { op, guard });
    }
    for _ in 0..r.unsigned()? {
        f.loop_candidates.push(LoopCandidate {
            head: r.unsigned()? as usize,
            test: r.unsigned()? as usize,
            tail: r.unsigned()? as usize,
        });
    }
    for _ in 0..r.unsigned()? {
        f.proto_partial.push(r.unsigned()? as usize);
    }
    if r.position != blob.len() {
        return Err("merge query has trailing bytes".into());
    }
    // Consistency the replay relies on.
    for (i, op) in f.ops.iter().enumerate() {
        if op.ins.iter().any(|&v| v >= f.vns.len()) || op.out.is_some_and(|v| v >= f.vns.len()) {
            return Err(format!("merge query op {i} names a missing varnode"));
        }
    }
    for vn in &f.vns {
        if vn.def.is_some_and(|d| d >= f.ops.len()) || vn.desc.iter().any(|&d| d >= f.ops.len()) {
            return Err("merge query varnode names a missing op".into());
        }
    }
    let initial_ops = f.ops.len();
    Ok(MergeQuery { func: f, multi_entry, dynamic, initial_ops })
}

/// The decompiler's final state after its own stage-3 actions (verify mode).
pub fn decode_merge_dump(blob: &[u8]) -> Result<super::merge::Dump> {
    use super::merge::DumpOp;
    let mut r = Reader::new(blob);
    if r.unsigned()? != 0 || r.unsigned()? != 4 {
        return Err("merge dump marker".into());
    }
    let _address = r.unsigned()?;
    let mut blocks = Vec::new();
    for _ in 0..r.unsigned()? {
        let mut ops = Vec::new();
        for _ in 0..r.unsigned()? {
            let time = r.unsigned()?;
            let code = r.unsigned()? as u32;
            let non_printing = r.flag()?;
            let special_print = r.flag()?;
            let out = r.unsigned()?.checked_sub(1).map(|x| x as u32);
            let mut ins = Vec::new();
            for _ in 0..r.unsigned()? {
                ins.push(r.unsigned()? as u32);
            }
            ops.push(DumpOp { time, code, non_printing, special_print, out, ins });
        }
        blocks.push(ops);
    }
    let mut vns = Vec::new();
    for _ in 0..r.unsigned()? {
        vns.push((r.unsigned()? as u32, r.unsigned()? as u32, r.flag()?, r.flag()?, r.flag()?));
    }
    let mut loops = Vec::new();
    for _ in 0..r.unsigned()? {
        loops.push((
            r.unsigned()? as usize,
            r.unsigned()? as usize,
            r.unsigned()?.checked_sub(1),
            r.unsigned()?.checked_sub(1),
        ));
    }
    if r.position != blob.len() {
        return Err("merge dump has trailing bytes".into());
    }
    Ok(super::merge::Dump { blocks, vns, loops })
}

/// A naming query (marker 3, `native/romwright_merge.hh`).
pub fn decode_names_query(blob: &[u8]) -> Result<super::merge::names::NamesQuery> {
    use super::merge::names::{NameEntry, NamesQuery};
    let mut r = Reader::new(blob);
    if r.unsigned()? != 0 || r.unsigned()? != 3 {
        return Err("names query marker".into());
    }
    let address = r.unsigned()?;
    let base = r.int()?;
    let mut local_names = Vec::new();
    for _ in 0..r.unsigned()? {
        local_names.push(r.string()?);
    }
    let mut entries = Vec::new();
    for _ in 0..r.unsigned()? {
        let e = NameEntry {
            flags: u32::try_from(r.unsigned()?).map_err(|_| "names query flags")?,
            index: r.int()?,
            has_type: r.flag()?,
            type_base: r.string()?,
            type_size: u32::try_from(r.unsigned()?).map_err(|_| "names query size")?,
            space_name: r.string()?,
            offset: r.unsigned()?,
            addr_size: u32::try_from(r.unsigned()?).map_err(|_| "names query size")?,
            word_offset: r.unsigned()?,
            register: r.string()?,
            stack_local: r.flag()?,
            stack_start: r.signed()?,
            stack_unusual: r.flag()?,
        };
        entries.push(e);
    }
    if r.position != blob.len() {
        return Err("names query has trailing bytes".into());
    }
    Ok(NamesQuery { address, base, local_names, entries })
}
