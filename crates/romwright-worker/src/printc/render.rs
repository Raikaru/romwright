//! PrintC's expression emission, ported from the pinned
//! `third_party/ghidra/decompiler/{printlanguage.cc,printc.cc,typeop.hh,cast.cc}`
//! (Apache-2.0) to run over the exported print trees (`super::tree`).
//!
//! What is ported: the reverse-polish stack (`pushOp`, `pushAtom`, `recurse`,
//! `parentheses`, `emitOp`), operator tokens with their precedence and
//! associativity, the op handlers (`opBinary`, `opLoad`/`opStore` and array
//! notation, `opPtradd`, `opPtrsub`, calls, casts through the cast
//! strategy's `isZextCast`/`isSextCast`/`isSubpieceCast`, `opBoolNegate` and
//! the negation of comparison tokens), integer, boolean and character
//! constants (`push_integer`, `pushCharConstant`, the default cast-and-hex
//! form), symbols with their namespace path and partial symbols
//! (`pushPartialSymbol` over primitive and array types), and the type
//! expressions casts print (`pushTypeStart`, `pushTypeEnd`).
//!
//! The output is the sequence of `Emit` calls PrintC makes, as a
//! [`Fragment`], so the pretty printer replays it exactly like a fragment the
//! C++ recorded. Whatever is not ported is marked in the tree by the
//! exporter, or refused here with a reason; the caller then keeps PrintC's
//! fragment.

use super::ir::{Event, Fragment};
use super::pretty::{CONST_COLOR, FieldRef, KEYWORD_COLOR, NO_COLOR};
use super::tree::{
    ConstKind, Extra, Options, PConst, PNode, POp, PPartial, PieceKind, PrintTree, PtrsubKind,
    SymbolDesc, Tables, TypeDesc, meta,
};
use std::collections::BTreeMap;

type Result<T, E = String> = std::result::Result<T, E>;

/// `OpCode` values (opcodes.hh).
pub mod opc {
    pub const COPY: u32 = 1;
    pub const LOAD: u32 = 2;
    pub const STORE: u32 = 3;
    pub const BRANCH: u32 = 4;
    pub const CBRANCH: u32 = 5;
    pub const BRANCHIND: u32 = 6;
    pub const CALL: u32 = 7;
    pub const CALLIND: u32 = 8;
    pub const CALLOTHER: u32 = 9;
    pub const RETURN: u32 = 10;
    pub const INT_EQUAL: u32 = 11;
    pub const INT_NOTEQUAL: u32 = 12;
    pub const INT_SLESS: u32 = 13;
    pub const INT_SLESSEQUAL: u32 = 14;
    pub const INT_LESS: u32 = 15;
    pub const INT_LESSEQUAL: u32 = 16;
    pub const INT_ZEXT: u32 = 17;
    pub const INT_SEXT: u32 = 18;
    pub const INT_ADD: u32 = 19;
    pub const INT_SUB: u32 = 20;
    pub const INT_CARRY: u32 = 21;
    pub const INT_SCARRY: u32 = 22;
    pub const INT_SBORROW: u32 = 23;
    pub const INT_2COMP: u32 = 24;
    pub const INT_NEGATE: u32 = 25;
    pub const INT_XOR: u32 = 26;
    pub const INT_AND: u32 = 27;
    pub const INT_OR: u32 = 28;
    pub const INT_LEFT: u32 = 29;
    pub const INT_RIGHT: u32 = 30;
    pub const INT_SRIGHT: u32 = 31;
    pub const INT_MULT: u32 = 32;
    pub const INT_DIV: u32 = 33;
    pub const INT_SDIV: u32 = 34;
    pub const INT_REM: u32 = 35;
    pub const INT_SREM: u32 = 36;
    pub const BOOL_NEGATE: u32 = 37;
    pub const BOOL_XOR: u32 = 38;
    pub const BOOL_AND: u32 = 39;
    pub const BOOL_OR: u32 = 40;
    pub const FLOAT_EQUAL: u32 = 41;
    pub const FLOAT_NOTEQUAL: u32 = 42;
    pub const FLOAT_LESS: u32 = 43;
    pub const FLOAT_LESSEQUAL: u32 = 44;
    pub const FLOAT_NAN: u32 = 46;
    pub const FLOAT_ADD: u32 = 47;
    pub const FLOAT_DIV: u32 = 48;
    pub const FLOAT_MULT: u32 = 49;
    pub const FLOAT_SUB: u32 = 50;
    pub const FLOAT_NEG: u32 = 51;
    pub const FLOAT_ABS: u32 = 52;
    pub const FLOAT_SQRT: u32 = 53;
    pub const FLOAT_INT2FLOAT: u32 = 54;
    pub const FLOAT_FLOAT2FLOAT: u32 = 55;
    pub const FLOAT_TRUNC: u32 = 56;
    pub const FLOAT_CEIL: u32 = 57;
    pub const FLOAT_FLOOR: u32 = 58;
    pub const FLOAT_ROUND: u32 = 59;
    pub const MULTIEQUAL: u32 = 60;
    pub const INDIRECT: u32 = 61;
    pub const PIECE: u32 = 62;
    pub const SUBPIECE: u32 = 63;
    pub const CAST: u32 = 64;
    pub const PTRADD: u32 = 65;
    pub const PTRSUB: u32 = 66;
    pub const SEGMENTOP: u32 = 67;
    pub const POPCOUNT: u32 = 72;
    pub const LZCOUNT: u32 = 73;
}

// PrintLanguage::modifiers.
const FORCE_HEX: u32 = 0x1;
const FORCE_DEC: u32 = 0x2;
const FORCE_POINTER: u32 = 0x10;
const PRINT_LOAD_VALUE: u32 = 0x20;
const PRINT_STORE_VALUE: u32 = 0x40;
const COMMA_SEPARATE: u32 = 0x200;
const NEGATE_TOKEN: u32 = 0x2000;

// Emit::syntax_highlight.
const TYPE_COLOR: u8 = 2;
const FUNCNAME_COLOR: u8 = 3;
const GLOBAL_COLOR: u8 = 7;

// Symbol::display formats.
const FORMAT_HEX: u32 = 1;
const FORMAT_DEC: u32 = 2;
const FORMAT_OCT: u32 = 3;
const FORMAT_CHAR: u32 = 5;

/// `OpToken::tagtype`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Binary,
    Space,
    UnaryPrefix,
    PostSurround,
    PreSurround,
    Hidden,
}

/// The operator tokens of `PrintC` (one value per `OpToken` instance: the
/// parenthesis rule compares instances).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Hidden,
    Scope,
    ObjectMember,
    PointerMember,
    Subscript,
    FunctionCall,
    BitwiseNot,
    BooleanNot,
    UnaryMinus,
    AddressOf,
    Dereference,
    Typecast,
    Multiply,
    Divide,
    Modulo,
    BinaryPlus,
    BinaryMinus,
    ShiftLeft,
    ShiftRight,
    ShiftSRight,
    LessThan,
    LessEqual,
    GreaterThan,
    GreaterEqual,
    Equal,
    NotEqual,
    BitwiseAnd,
    BitwiseXor,
    BitwiseOr,
    BooleanAnd,
    BooleanXor,
    BooleanOr,
    Assignment,
    Comma,
    TypeExprSpace,
    TypeExprNoSpace,
    PtrExpr,
    ArrayExpr,
}

struct Def {
    print1: &'static str,
    print2: &'static str,
    stage: i32,
    precedence: i32,
    associative: bool,
    class: Class,
    spacing: i32,
    bump: i32,
}

// One field per argument: this is the operator table's row constructor.
#[allow(clippy::too_many_arguments)]
const fn def(
    print1: &'static str,
    print2: &'static str,
    stage: i32,
    precedence: i32,
    associative: bool,
    class: Class,
    spacing: i32,
    bump: i32,
) -> Def {
    Def {
        print1,
        print2,
        stage,
        precedence,
        associative,
        class,
        spacing,
        bump,
    }
}

impl Tok {
    /// `printc.cc`'s `OpToken` table.
    fn def(self) -> Def {
        use Class::*;
        match self {
            Tok::Hidden => def("", "", 1, 70, false, Hidden, 0, 0),
            Tok::Scope => def("::", "", 2, 70, true, Binary, 0, 0),
            Tok::ObjectMember => def(".", "", 2, 66, true, Binary, 0, 0),
            Tok::PointerMember => def("->", "", 2, 66, true, Binary, 0, 0),
            Tok::Subscript => def("[", "]", 2, 66, false, PostSurround, 0, 0),
            Tok::FunctionCall => def("(", ")", 2, 66, false, PostSurround, 0, 10),
            Tok::BitwiseNot => def("~", "", 1, 62, false, UnaryPrefix, 0, 0),
            Tok::BooleanNot => def("!", "", 1, 62, false, UnaryPrefix, 0, 0),
            Tok::UnaryMinus => def("-", "", 1, 62, false, UnaryPrefix, 0, 0),
            Tok::AddressOf => def("&", "", 1, 62, false, UnaryPrefix, 0, 0),
            Tok::Dereference => def("*", "", 1, 62, false, UnaryPrefix, 0, 0),
            Tok::Typecast => def("(", ")", 2, 62, false, PreSurround, 0, 0),
            Tok::Multiply => def("*", "", 2, 54, true, Binary, 1, 0),
            Tok::Divide => def("/", "", 2, 54, false, Binary, 1, 0),
            Tok::Modulo => def("%", "", 2, 54, false, Binary, 1, 0),
            Tok::BinaryPlus => def("+", "", 2, 50, true, Binary, 1, 0),
            Tok::BinaryMinus => def("-", "", 2, 50, false, Binary, 1, 0),
            Tok::ShiftLeft => def("<<", "", 2, 46, false, Binary, 1, 0),
            Tok::ShiftRight => def(">>", "", 2, 46, false, Binary, 1, 0),
            Tok::ShiftSRight => def(">>", "", 2, 46, false, Binary, 1, 0),
            Tok::LessThan => def("<", "", 2, 42, false, Binary, 1, 0),
            Tok::LessEqual => def("<=", "", 2, 42, false, Binary, 1, 0),
            Tok::GreaterThan => def(">", "", 2, 42, false, Binary, 1, 0),
            Tok::GreaterEqual => def(">=", "", 2, 42, false, Binary, 1, 0),
            Tok::Equal => def("==", "", 2, 38, false, Binary, 1, 0),
            Tok::NotEqual => def("!=", "", 2, 38, false, Binary, 1, 0),
            Tok::BitwiseAnd => def("&", "", 2, 34, true, Binary, 1, 0),
            Tok::BitwiseXor => def("^", "", 2, 30, true, Binary, 1, 0),
            Tok::BitwiseOr => def("|", "", 2, 26, true, Binary, 1, 0),
            Tok::BooleanAnd => def("&&", "", 2, 22, false, Binary, 1, 0),
            Tok::BooleanXor => def("^^", "", 2, 20, false, Binary, 1, 0),
            Tok::BooleanOr => def("||", "", 2, 18, false, Binary, 1, 0),
            Tok::Assignment => def("=", "", 2, 14, false, Binary, 1, 5),
            Tok::Comma => def(",", "", 2, 2, true, Binary, 0, 0),
            Tok::TypeExprSpace => def("", "", 2, 10, false, Space, 1, 0),
            Tok::TypeExprNoSpace => def("", "", 2, 10, false, Space, 0, 0),
            Tok::PtrExpr => def("*", "", 1, 62, false, UnaryPrefix, 0, 0),
            Tok::ArrayExpr => def("[", "]", 2, 66, false, PostSurround, 1, 0),
        }
    }

    /// `OpToken::negate`: the token of the negated comparison.
    fn negate(self) -> Option<Tok> {
        Some(match self {
            Tok::LessThan => Tok::GreaterEqual,
            Tok::LessEqual => Tok::GreaterThan,
            Tok::GreaterThan => Tok::LessEqual,
            Tok::GreaterEqual => Tok::LessThan,
            Tok::Equal => Tok::NotEqual,
            Tok::NotEqual => Tok::Equal,
            _ => return None,
        })
    }
}

/// `get_booleanflip(code) != CPUI_MAX`: the ops whose token PrintC flips
/// instead of printing `!`.
fn flips_as_token(code: u32) -> bool {
    matches!(
        code,
        opc::INT_EQUAL
            | opc::INT_NOTEQUAL
            | opc::INT_SLESS
            | opc::INT_SLESSEQUAL
            | opc::INT_LESS
            | opc::INT_LESSEQUAL
            | opc::BOOL_NEGATE
            | opc::FLOAT_EQUAL
            | opc::FLOAT_NOTEQUAL
            | opc::FLOAT_LESS
            | opc::FLOAT_LESSEQUAL
    )
}

/// The binary token an op prints as (`opBinary`), if it is one.
fn binary_token(code: u32) -> Option<Tok> {
    Some(match code {
        opc::INT_EQUAL | opc::FLOAT_EQUAL => Tok::Equal,
        opc::INT_NOTEQUAL | opc::FLOAT_NOTEQUAL => Tok::NotEqual,
        opc::INT_SLESS | opc::INT_LESS | opc::FLOAT_LESS => Tok::LessThan,
        opc::INT_SLESSEQUAL | opc::INT_LESSEQUAL | opc::FLOAT_LESSEQUAL => Tok::LessEqual,
        opc::INT_ADD | opc::FLOAT_ADD => Tok::BinaryPlus,
        opc::INT_SUB | opc::FLOAT_SUB => Tok::BinaryMinus,
        opc::INT_XOR => Tok::BitwiseXor,
        opc::INT_AND => Tok::BitwiseAnd,
        opc::INT_OR => Tok::BitwiseOr,
        opc::INT_LEFT => Tok::ShiftLeft,
        opc::INT_RIGHT => Tok::ShiftRight,
        opc::INT_SRIGHT => Tok::ShiftSRight,
        opc::INT_MULT | opc::FLOAT_MULT => Tok::Multiply,
        opc::INT_DIV | opc::INT_SDIV | opc::FLOAT_DIV => Tok::Divide,
        opc::INT_REM | opc::INT_SREM => Tok::Modulo,
        opc::BOOL_XOR => Tok::BooleanXor,
        opc::BOOL_AND => Tok::BooleanAnd,
        opc::BOOL_OR => Tok::BooleanOr,
        _ => return None,
    })
}

/// `TypeOp::getOperatorName` of the ops that print in function syntax;
/// sizes are the byte sizes of the input and output varnodes.
fn function_name(op: &POp) -> Option<String> {
    let size = |slot: usize| op.kids.get(slot).map(PNode::size).unwrap_or(0);
    Some(match op.code {
        opc::INT_ZEXT => format!("ZEXT{}{}", size(0), op.out_size),
        opc::INT_SEXT => format!("SEXT{}{}", size(0), op.out_size),
        opc::INT_CARRY => format!("CARRY{}", size(0)),
        opc::INT_SCARRY => format!("SCARRY{}", size(0)),
        opc::INT_SBORROW => format!("SBORROW{}", size(0)),
        opc::FLOAT_NAN => "NAN".into(),
        opc::FLOAT_ABS => "ABS".into(),
        opc::FLOAT_SQRT => "SQRT".into(),
        opc::FLOAT_CEIL => "CEIL".into(),
        opc::FLOAT_FLOOR => "FLOOR".into(),
        opc::FLOAT_ROUND => "ROUND".into(),
        opc::PIECE => format!("CONCAT{}{}", size(0), size(1)),
        opc::SUBPIECE => format!("SUB{}{}", size(0), op.out_size),
        opc::POPCOUNT => "POPCOUNT".into(),
        opc::LZCOUNT => "LZCOUNT".into(),
        _ => return None,
    })
}

struct Entry {
    tok: Tok,
    visited: i32,
    paren: bool,
    op: Option<u64>,
    id: u64,
    id2: u64,
}

struct Pending<'a> {
    node: &'a PNode,
    /// The op reading the node (`PcodeOp::getTime`).
    reader: u64,
    mods: u32,
}

/// A token pushed by [`Engine::push_atom`]: an event to emit, or the blank
/// token that prints nothing.
enum Atom {
    Event(Event),
    Blank,
}

struct Engine<'a> {
    tables: &'a Tables,
    options: &'a Options,
    /// `PrintLanguage::mods`.
    mods: u32,
    mod_stack: Vec<u32>,
    revpol: Vec<Entry>,
    nodepend: Vec<Pending<'a>>,
    pending: usize,
    events: Vec<Event>,
    next_id: u64,
    /// Print the negation of a root CBRANCH's condition.
    invert: bool,
}

fn calc_mask(size: u32) -> u64 {
    match size {
        0 => 0,
        1..=7 => (1u64 << (8 * size)) - 1,
        _ => u64::MAX,
    }
}

/// `PrintLanguage::mostNaturalBase`.
fn most_natural_base(val: u64) -> u32 {
    if val == 0 {
        return 10;
    }
    let mut count_dec = 0;
    let mut tmp = val;
    let set_dec = tmp % 10;
    if set_dec == 0 || set_dec == 9 {
        count_dec += 1;
        tmp /= 10;
        while tmp != 0 {
            if tmp % 10 == set_dec {
                count_dec += 1;
            } else {
                break;
            }
            tmp /= 10;
        }
    }
    match count_dec {
        0 => return 16,
        1 => {
            if tmp > 1 || set_dec == 9 {
                return 16;
            }
        }
        2 => {
            if tmp > 10 {
                return 16;
            }
        }
        3 | 4 => {
            if tmp > 100 {
                return 16;
            }
        }
        _ => {
            if tmp > 1000 {
                return 16;
            }
        }
    }
    let mut count_hex = 0;
    tmp = val;
    let set_hex = tmp & 0xf;
    if set_hex == 0 || set_hex == 0xf {
        count_hex += 1;
        tmp >>= 4;
        while tmp != 0 {
            if tmp & 0xf == set_hex {
                count_hex += 1;
            } else {
                break;
            }
            tmp >>= 4;
        }
    }
    if count_dec > count_hex { 10 } else { 16 }
}

/// `PrintLanguage::formatBinary`.
fn format_binary(val: u64) -> String {
    if val == 0 {
        return "0".into();
    }
    let top = 63 - val.leading_zeros() as i32;
    let pos = match top {
        0..=7 => 7,
        8..=15 => 15,
        16..=31 => 31,
        _ => 63,
    };
    (0..=pos)
        .rev()
        .map(|bit| if val >> bit & 1 != 0 { '1' } else { '0' })
        .collect()
}

/// `PrintC::printCharHexEscape`.
fn char_hex_escape(val: u32) -> String {
    if val < 256 {
        format!("\\x{val:02x}")
    } else if val < 65536 {
        format!("\\x{val:04x}")
    } else {
        format!("\\x{val:08x}")
    }
}

/// `PrintC::printUnicode` for the ASCII range; larger code points need the
/// Unicode tables of `unicodeNeedsEscape` and are refused.
fn print_unicode(val: u32) -> Result<String> {
    if val >= 0x80 {
        return Err("char:unicode".into());
    }
    Ok(match val {
        0 => "\\0".into(),
        7 => "\\a".into(),
        8 => "\\b".into(),
        9 => "\\t".into(),
        10 => "\\n".into(),
        11 => "\\v".into(),
        12 => "\\f".into(),
        13 => "\\r".into(),
        92 => "\\\\".into(),
        34 => "\\\"".into(),
        39 => "\\'".into(),
        0x20..=0x7e => char::from(val as u8).to_string(),
        _ => char_hex_escape(val),
    })
}

/// `CastStrategyC::isSubpieceCast`.
fn is_subpiece_cast(out: &TypeDesc, input: &TypeDesc, offset: u32) -> bool {
    if offset != 0 {
        return false;
    }
    let in_meta = input.meta;
    if !matches!(
        in_meta,
        meta::INT | meta::UINT | meta::UNKNOWN | meta::PTR | meta::PARTIALSTRUCT | meta::PARTIALUNION
    ) {
        return false;
    }
    let out_meta = out.meta;
    if !matches!(
        out_meta,
        meta::INT | meta::UINT | meta::UNKNOWN | meta::PTR | meta::FLOAT
    ) {
        return false;
    }
    if in_meta == meta::PTR {
        if out_meta == meta::PTR && out.size < input.size {
            return true;
        }
        if out_meta != meta::INT && out_meta != meta::UINT {
            return false;
        }
    }
    true
}

/// `CastStrategyC::isSubpieceCastEndian`.
fn is_subpiece_cast_endian(out: &TypeDesc, input: &TypeDesc, offset: u32, big_endian: bool) -> bool {
    let tmp = if big_endian {
        input.size.wrapping_sub(1).wrapping_sub(offset)
    } else {
        offset
    };
    is_subpiece_cast(out, input, tmp)
}

/// `CastStrategyC::isSextCast`.
fn is_sext_cast(out: &TypeDesc, input: &TypeDesc) -> bool {
    matches!(out.meta, meta::UINT | meta::INT) && matches!(input.meta, meta::INT | meta::BOOL)
}

/// `CastStrategyC::isZextCast`.
fn is_zext_cast(out: &TypeDesc, input: &TypeDesc) -> bool {
    matches!(out.meta, meta::UINT | meta::INT) && matches!(input.meta, meta::UINT | meta::BOOL)
}

/// `PrintC::checkArrayDeref`: the pointer expression is a PTRSUB or PTRADD
/// (looking through a SEGMENTOP).
fn check_array_deref(node: &PNode) -> bool {
    let PNode::Op(def) = node else {
        return false;
    };
    let mut def = def;
    if def.code == opc::SEGMENTOP {
        match def.kids.first() {
            Some(PNode::Op(inner)) => def = inner,
            _ => return false,
        }
    }
    def.code == opc::PTRSUB || def.code == opc::PTRADD
}

/// `PrintC::isValueFlexible`.
fn value_flexible(node: &PNode) -> bool {
    let PNode::Op(def) = node else {
        return false;
    };
    let mut code = def.code;
    if code == opc::COPY {
        match def.kids.first() {
            Some(PNode::Op(inner)) => code = inner.code,
            _ => return false,
        }
    }
    code == opc::PTRSUB || code == opc::PTRADD
}

/// `PrintC::checkPrintNegation`.
fn check_print_negation(node: &PNode) -> bool {
    matches!(node, PNode::Op(def) if flips_as_token(def.code))
}

struct StackEntry {
    tok: Tok,
    /// Array element index or byte offset of an artificial field.
    offset: i64,
    size: i64,
    subscript: bool,
    /// A structure field: the structure and the field's index in it.
    field: Option<(usize, usize)>,
}

/// `TypeStruct::findTruncation`: the field holding `off .. off + size`, and
/// the offset within it.
fn find_truncation(ct: &TypeDesc, off: i64, size: i64, tables: &Tables) -> Option<(usize, i64)> {
    let index = ct.fields.iter().position(|field| {
        field.offset <= off && field.offset + i64::from(tables.types[field.ty].size) > off
    })?;
    let field = &ct.fields[index];
    let inner = off - field.offset;
    if inner + size > i64::from(tables.types[field.ty].size) {
        return None;
    }
    Some((index, inner))
}

impl<'a> Engine<'a> {
    fn new(tables: &'a Tables, options: &'a Options, comma: bool, invert: bool) -> Self {
        Engine {
            tables,
            options,
            mods: options.base_mods | if comma { COMMA_SEPARATE } else { 0 },
            mod_stack: Vec::new(),
            revpol: Vec::new(),
            nodepend: Vec::new(),
            pending: 0,
            events: Vec::new(),
            next_id: 1,
            invert,
        }
    }

    fn is_set(&self, mods: u32) -> bool {
        self.mods & mods != 0
    }

    fn ty(&self, index: usize) -> &'a TypeDesc {
        &self.tables.types[index]
    }

    // ---- Emit -----------------------------------------------------------

    fn open_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn open_group(&mut self) -> u64 {
        let id = self.open_id();
        self.events.push(Event::OpenGroup(id));
        id
    }

    fn open_paren(&mut self, text: &str) -> u64 {
        let id = self.open_id();
        self.events.push(Event::OpenParen(id, text.to_string()));
        id
    }

    fn spaces(&mut self, count: i32, bump: i32) {
        self.events.push(Event::Spaces(count, bump));
    }

    fn tag_op(&mut self, name: &str, highlight: u8, op: Option<u64>) {
        self.events.push(Event::Op {
            name: name.to_string(),
            highlight,
            op,
        });
    }

    // ---- The reverse-polish stack (printlanguage.cc) ---------------------

    fn push_mod(&mut self) {
        self.mod_stack.push(self.mods);
    }

    fn pop_mod(&mut self) {
        if let Some(mods) = self.mod_stack.pop() {
            self.mods = mods;
        }
    }

    /// `PrintLanguage::pushOp`.
    fn push_op(&mut self, tok: Tok, op: Option<u64>) -> Result<()> {
        if self.pending < self.nodepend.len() {
            self.recurse()?;
        }
        let paren;
        let id;
        if self.revpol.is_empty() {
            paren = false;
            id = self.open_group();
        } else {
            let top = self.revpol.len() - 1;
            self.emit_op(top);
            paren = self.parentheses(tok);
            id = if paren {
                self.open_paren("(")
            } else {
                self.open_group()
            };
        }
        self.revpol.push(Entry {
            tok,
            visited: 0,
            paren,
            op,
            id,
            id2: 0,
        });
        Ok(())
    }

    /// `PrintLanguage::pushAtom`.
    fn push_atom(&mut self, atom: Atom) -> Result<()> {
        if self.pending < self.nodepend.len() {
            self.recurse()?;
        }
        if self.revpol.is_empty() {
            self.emit_atom(atom);
            return Ok(());
        }
        let top = self.revpol.len() - 1;
        self.emit_op(top);
        self.emit_atom(atom);
        loop {
            let top = self.revpol.len() - 1;
            self.revpol[top].visited += 1;
            if self.revpol[top].visited == self.revpol[top].tok.def().stage {
                self.emit_op(top);
                let entry = self.revpol.pop().expect("entry just visited");
                if entry.paren {
                    self.events.push(Event::CloseParen(entry.id, ")".into()));
                } else {
                    self.events.push(Event::CloseGroup(entry.id));
                }
            } else {
                break;
            }
            if self.revpol.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// `PrintLanguage::parentheses`.
    fn parentheses(&self, op2: Tok) -> bool {
        let top = self.revpol.last().expect("a token to compare with");
        let top_def = top.tok.def();
        let op2_def = op2.def();
        let stage = top.visited;
        match top_def.class {
            Class::Space | Class::Binary => {
                // native/ghidra-opt-sleigh.patch (printlanguage.cc): mixed
                // arithmetic/bitwise grouping is always explicit.
                if top_def.class == Class::Binary && op2_def.class == Class::Binary {
                    let (parent, child) = (top_def.print1, op2_def.print1);
                    if matches!(parent, "&" | "^" | "|")
                        && (matches!(
                            child,
                            "+" | "-"
                                | "*"
                                | "/"
                                | "%"
                                | "<<"
                                | ">>"
                                | "=="
                                | "!="
                                | "<"
                                | "<="
                                | ">"
                                | ">="
                                | "&&"
                                | "||"
                        ) || (matches!(child, "&" | "^" | "|") && child != parent))
                    {
                        return true;
                    }
                    if (matches!(parent, "<<" | ">>") && matches!(child, "+" | "-"))
                        || (parent == "||" && child == "&&")
                    {
                        return true;
                    }
                }
                if top_def.precedence > op2_def.precedence {
                    return true;
                }
                if top_def.precedence < op2_def.precedence {
                    return false;
                }
                if top_def.associative && top.tok == op2 {
                    return false;
                }
                if op2_def.class == Class::PostSurround && stage == 0 {
                    return false;
                }
                true
            }
            Class::UnaryPrefix => {
                if top_def.precedence > op2_def.precedence {
                    return true;
                }
                if top_def.precedence < op2_def.precedence {
                    return false;
                }
                !matches!(op2_def.class, Class::UnaryPrefix | Class::PreSurround)
            }
            Class::PostSurround => {
                if stage == 1 {
                    return false;
                }
                if top_def.precedence > op2_def.precedence {
                    return true;
                }
                if top_def.precedence < op2_def.precedence {
                    return false;
                }
                !matches!(op2_def.class, Class::PostSurround | Class::Binary)
            }
            Class::PreSurround => {
                if stage == 0 {
                    return false;
                }
                if top_def.precedence > op2_def.precedence {
                    return true;
                }
                if top_def.precedence < op2_def.precedence {
                    return false;
                }
                !matches!(op2_def.class, Class::UnaryPrefix | Class::PreSurround)
            }
            Class::Hidden => {
                if stage == 0 && self.revpol.len() > 1 {
                    let previous = &self.revpol[self.revpol.len() - 2];
                    let previous_def = previous.tok.def();
                    if !matches!(previous_def.class, Class::Binary | Class::UnaryPrefix) {
                        return false;
                    }
                    if previous_def.precedence < op2_def.precedence {
                        return false;
                    }
                }
                true
            }
        }
    }

    /// `PrintLanguage::emitOp`.
    fn emit_op(&mut self, index: usize) {
        let (tok, visited, op) = {
            let entry = &self.revpol[index];
            (entry.tok, entry.visited, entry.op)
        };
        let def = tok.def();
        match def.class {
            Class::Binary => {
                if visited != 1 {
                    return;
                }
                self.spaces(def.spacing, def.bump);
                self.tag_op(def.print1, NO_COLOR, op);
                self.spaces(def.spacing, def.bump);
            }
            Class::UnaryPrefix => {
                if visited != 0 {
                    return;
                }
                self.tag_op(def.print1, NO_COLOR, op);
                self.spaces(def.spacing, def.bump);
            }
            Class::PostSurround => {
                if visited == 0 {
                    return;
                }
                if visited == 1 {
                    self.spaces(def.spacing, def.bump);
                    let id = self.open_paren(def.print1);
                    self.revpol[index].id2 = id;
                    self.spaces(0, def.bump);
                } else {
                    let id = self.revpol[index].id2;
                    self.events.push(Event::CloseParen(id, def.print2.into()));
                }
            }
            Class::PreSurround => {
                if visited == 2 {
                    return;
                }
                if visited == 0 {
                    let id = self.open_paren(def.print1);
                    self.revpol[index].id2 = id;
                } else {
                    let id = self.revpol[index].id2;
                    self.events.push(Event::CloseParen(id, def.print2.into()));
                    self.spaces(def.spacing, def.bump);
                }
            }
            Class::Space => {
                if visited != 1 {
                    return;
                }
                self.spaces(def.spacing, def.bump);
            }
            Class::Hidden => {}
        }
    }

    /// `PrintLanguage::emitAtom`.
    fn emit_atom(&mut self, atom: Atom) {
        if let Atom::Event(event) = atom {
            self.events.push(event);
        }
    }

    /// `PrintLanguage::pushVn`: the node waits until the stack needs it.
    fn push_vn(&mut self, node: &'a PNode, reader: u64, mods: u32) {
        self.nodepend.push(Pending {
            node,
            reader,
            mods,
        });
    }

    /// `PrintLanguage::recurse`: pushes the nodes waiting on the stack.
    fn recurse(&mut self) -> Result<()> {
        let saved = self.mods;
        let last_pending = self.pending;
        self.pending = self.nodepend.len();
        while last_pending < self.pending {
            let waiting = self.nodepend.pop().expect("pending node");
            self.mods = waiting.mods;
            self.pending -= 1;
            self.visit(waiting.node, waiting.reader)?;
            self.pending = self.nodepend.len();
        }
        self.mods = saved;
        Ok(())
    }

    /// An implied varnode pushes its defining op, an explicit one its leaf.
    fn visit(&mut self, node: &'a PNode, reader: u64) -> Result<()> {
        match node {
            PNode::Op(op) => self.op(op),
            PNode::No(reason) => Err(reason.clone()),
            leaf => self.leaf(leaf, reader),
        }
    }

    // ---- Leaves -------------------------------------------------------------

    fn variable(name: String, highlight: u8, varnode: Option<u64>, op: Option<u64>) -> Atom {
        Atom::Event(Event::Variable {
            name,
            highlight,
            varnode,
            op,
        })
    }

    fn syntax(text: String, highlight: u8) -> Atom {
        Atom::Event(Event::Print { text, highlight })
    }

    /// `PrintC::pushSymbol`, including `pushSymbolScope`.
    fn push_symbol(&mut self, sym: &'a SymbolDesc, vn: Option<u64>, op: Option<u64>) -> Result<()> {
        for _ in &sym.scopes {
            self.push_op(Tok::Scope, None)?;
        }
        for scope in &sym.scopes {
            self.push_atom(Self::syntax(scope.clone(), GLOBAL_COLOR))?;
        }
        self.push_atom(Self::variable(sym.name.clone(), sym.highlight, vn, op))
    }

    /// `PrintC::push_integer`.
    #[allow(clippy::too_many_arguments)]
    fn push_integer(
        &mut self,
        mut val: u64,
        size: u32,
        sign: bool,
        var: bool,
        constant: Option<&PConst>,
        op: Option<u64>,
        mut display_format: u32,
    ) -> Result<()> {
        let mut force_unsigned = false;
        let mut force_sized = false;
        if let Some(constant) = constant {
            if constant.symbol_format > 0 {
                display_format = constant.symbol_format - 1;
            }
            force_unsigned = constant.unsigned_print;
            force_sized = constant.long_print;
        }
        let negative;
        if sign && display_format != FORMAT_CHAR {
            let mask = calc_mask(size);
            let flip = val ^ mask;
            negative = flip < val;
            if negative {
                val = flip.wrapping_add(1);
            }
            force_unsigned = false;
        } else {
            negative = false;
        }
        if display_format != 0 {
        } else if self.is_set(FORCE_HEX) {
            display_format = FORMAT_HEX;
        } else if val <= 10 || self.is_set(FORCE_DEC) {
            display_format = FORMAT_DEC;
        } else {
            display_format = if most_natural_base(val) == 16 {
                FORMAT_HEX
            } else {
                FORMAT_DEC
            };
        }
        let mut text = String::new();
        if negative {
            text.push('-');
        }
        match display_format {
            FORMAT_HEX => text.push_str(&format!("0x{val:x}")),
            FORMAT_DEC => text.push_str(&val.to_string()),
            FORMAT_OCT => text.push_str(&format!("0{val:o}")),
            FORMAT_CHAR => {
                if size > 1 {
                    text.push('L');
                }
                text.push('\'');
                if size == 1 && val >= 0x80 {
                    text.push_str(&char_hex_escape(val as u32));
                } else {
                    text.push_str(&print_unicode(u32::try_from(val).map_err(|_| "char:unicode")?)?);
                }
                text.push('\'');
            }
            _ => {
                text.push_str("0b");
                text.push_str(&format_binary(val));
            }
        }
        if force_unsigned {
            text.push('U');
        }
        if force_sized {
            text.push_str(&self.options.size_suffix);
        }
        if var {
            self.push_atom(Self::variable(
                text,
                CONST_COLOR,
                constant.map(|constant| constant.vn),
                op,
            ))
        } else {
            self.push_atom(Self::syntax(text, CONST_COLOR))
        }
    }

    /// `PrintC::pushTypeStart`, the part that pushes the type name and the
    /// prefix operators.
    fn push_type_start(&mut self, ct: usize, no_ident: bool) -> Result<()> {
        let mut stack = Vec::new();
        let mut current = ct;
        loop {
            stack.push(current);
            let ty = self.ty(current);
            if ty.has_proto {
                return Err("type:function".into());
            }
            if !ty.name.is_empty() {
                break;
            }
            match (ty.meta, ty.base) {
                (meta::PTR | meta::ARRAY | meta::CODE, Some(base)) => current = base,
                _ => break,
            }
        }
        let base = self.ty(*stack.last().expect("one type"));
        let tok = if no_ident && stack.len() == 1 {
            Tok::TypeExprNoSpace
        } else {
            Tok::TypeExprSpace
        };
        let name = if base.name.is_empty() {
            base.generic_name.clone()
        } else {
            base.display_name.clone()
        };
        self.push_op(tok, None)?;
        self.push_atom(Atom::Event(Event::Type {
            name,
            highlight: TYPE_COLOR,
            id: base.id,
        }))?;
        for &index in stack[..stack.len() - 1].iter().rev() {
            match self.ty(index).meta {
                meta::PTR => self.push_op(Tok::PtrExpr, None)?,
                meta::ARRAY => self.push_op(Tok::ArrayExpr, None)?,
                meta::CODE => self.push_op(Tok::FunctionCall, None)?,
                _ => return Err("type:bad-expression".into()),
            }
        }
        Ok(())
    }

    /// `PrintC::pushTypeEnd`.
    fn push_type_end(&mut self, ct: usize) -> Result<()> {
        self.push_mod();
        self.mods |= FORCE_DEC;
        let mut current = ct;
        loop {
            let ty = self.ty(current);
            if !ty.name.is_empty() {
                break;
            }
            match (ty.meta, ty.base) {
                (meta::PTR, Some(base)) => current = base,
                (meta::ARRAY, Some(base)) => {
                    current = base;
                    self.push_integer(u64::from(ty.elements), 4, false, false, None, None, 0)?;
                }
                (meta::CODE, _) => return Err("type:function".into()),
                _ => break,
            }
        }
        self.pop_mod();
        Ok(())
    }

    /// `PrintC::pushType`.
    fn push_type(&mut self, ct: usize) -> Result<()> {
        self.push_type_start(ct, true)?;
        self.push_atom(Atom::Blank)?;
        self.push_type_end(ct)
    }

    /// `PrintC::pushConstant`, for the types the exporter leaves to us.
    fn push_constant(&mut self, constant: &'a PConst, reader: u64) -> Result<()> {
        let ty = self.ty(constant.ty);
        let op = Some(reader);
        match constant.kind {
            ConstKind::Integer => match ty.meta {
                meta::UINT | meta::UNKNOWN => self.push_integer(
                    constant.value,
                    ty.size,
                    false,
                    true,
                    Some(constant),
                    op,
                    ty.display_format,
                ),
                meta::INT => self.push_integer(
                    constant.value,
                    ty.size,
                    true,
                    true,
                    Some(constant),
                    op,
                    ty.display_format,
                ),
                meta::BOOL => {
                    let text = if constant.value != 0 { "true" } else { "false" };
                    self.push_atom(Self::variable(
                        text.into(),
                        CONST_COLOR,
                        Some(constant.vn),
                        op,
                    ))
                }
                _ => Err("const:integer-type".into()),
            },
            ConstKind::Char => {
                // pushCharConstant with no symbol format and no type format.
                let mut text = String::new();
                if ty.size > 1 {
                    text.push('L');
                }
                text.push('\'');
                text.push_str(&print_unicode(
                    u32::try_from(constant.value).map_err(|_| "char:unicode")?,
                )?);
                text.push('\'');
                self.push_atom(Self::variable(text, CONST_COLOR, Some(constant.vn), op))
            }
            ConstKind::Default | ConstKind::Bare => {
                if !self.options.no_casts && constant.kind == ConstKind::Default {
                    self.push_op(Tok::Typecast, op)?;
                    self.push_type(constant.ty)?;
                }
                self.push_mod();
                if !self.is_set(FORCE_DEC) {
                    self.mods |= FORCE_HEX;
                }
                let result = self.push_integer(
                    constant.value,
                    ty.size,
                    false,
                    true,
                    Some(constant),
                    op,
                    ty.display_format,
                );
                self.pop_mod();
                result
            }
        }
    }

    /// `PrintC::pushPartialSymbol` over primitive and array symbol types.
    fn push_partial(&mut self, partial: &'a PPartial, reader: u64) -> Result<()> {
        let op = Some(reader);
        let sym = &self.tables.symbols[partial.sym];
        let mut off = partial.offset;
        let mut size = partial.size;
        let mut stack: Vec<StackEntry> = Vec::new();
        let mut final_cast = None;
        let mut current = Some(partial.sym_type);
        while let Some(index) = current {
            let ct = self.ty(index);
            if off == 0
                && (size == 0
                    || (size == i64::from(ct.size) && (!ct.needs_resolution || ct.meta == meta::PTR)))
            {
                break;
            }
            let mut succeeded = false;
            match ct.meta {
                meta::STRUCT => {
                    if ct.needs_resolution {
                        return Err("partial:resolution".into());
                    }
                    if let Some((field, inner)) = find_truncation(ct, off, size, self.tables) {
                        off = inner;
                        stack.push(StackEntry {
                            tok: Tok::ObjectMember,
                            offset: 0,
                            size: 0,
                            subscript: false,
                            field: Some((index, field)),
                        });
                        current = Some(ct.fields[field].ty);
                        succeeded = true;
                    }
                }
                meta::UNION => return Err("partial:union".into()),
                meta::ARRAY => {
                    let element = ct.base.ok_or("partial:array")?;
                    let align = i64::from(self.ty(element).size);
                    if align <= 0 || self.ty(element).meta == meta::STRUCT {
                        return Err("partial:array-element".into());
                    }
                    let new_off = off % align;
                    let el = off / align;
                    if new_off + size <= align {
                        off = new_off;
                        stack.push(StackEntry {
                            tok: Tok::Subscript,
                            offset: el,
                            size: 0,
                            subscript: true,
                            field: None,
                        });
                        current = Some(element);
                        succeeded = true;
                    }
                }
                _ if partial.read => {
                    let out_type = self.ty(partial.high_type);
                    if is_subpiece_cast_endian(out_type, ct, off as u32, partial.big_endian) {
                        final_cast = Some(partial.high_type);
                        current = None;
                        succeeded = true;
                    }
                }
                _ => {}
            }
            if !succeeded {
                if size == 0 {
                    size = i64::from(ct.size) - off;
                }
                stack.push(StackEntry {
                    tok: Tok::ObjectMember,
                    offset: off,
                    size,
                    subscript: false,
                    field: None,
                });
                current = None;
            }
        }
        if let Some(cast) = final_cast
            && !self.options.no_casts
        {
            self.push_op(Tok::Typecast, op)?;
            self.push_type(cast)?;
        }
        for entry in stack.iter().rev() {
            self.push_op(entry.tok, op)?;
        }
        self.push_symbol(sym, partial.vn, op)?;
        for entry in &stack {
            if let Some((container, field)) = entry.field {
                let field = &self.ty(container).fields[field];
                self.push_atom(self.field_atom(container, &field.name, field.ident, reader))?;
            } else if entry.subscript || entry.size <= 0 {
                self.push_integer(
                    entry.offset as u64,
                    entry.size.max(0) as u32,
                    entry.offset < 0,
                    false,
                    None,
                    op,
                    0,
                )?;
            } else {
                self.push_atom(Self::syntax(
                    format!("_{}_{}_", entry.offset, entry.size),
                    NO_COLOR,
                ))?;
            }
        }
        Ok(())
    }

    /// `PrintLanguage::pushVnExplicit` / `pushSymbolDetail`.
    fn leaf(&mut self, node: &'a PNode, reader: u64) -> Result<()> {
        match node {
            PNode::Const(constant) => self.push_constant(constant, reader),
            PNode::Atom { event, .. } => self.push_atom(Atom::Event(event.clone())),
            PNode::Symbol { vn, sym, .. } => {
                self.push_symbol(&self.tables.symbols[*sym], *vn, Some(reader))
            }
            PNode::Partial(partial) => self.push_partial(partial, reader),
            PNode::No(reason) => Err(reason.clone()),
            PNode::Op(_) => Err("leaf:op".into()),
        }
    }

    // ---- Ops (printc.cc) ----------------------------------------------------

    /// `PrintLanguage::opBinary`.
    fn op_binary(&mut self, mut tok: Tok, op: &'a POp) -> Result<()> {
        if self.is_set(NEGATE_TOKEN) {
            tok = tok.negate().ok_or("Could not find fliptoken")?;
            self.mods &= !NEGATE_TOKEN;
        }
        let [first, second] = op.kids.as_slice() else {
            return Err("op:binary-arity".into());
        };
        self.push_op(tok, Some(op.time))?;
        self.push_vn(second, op.time, self.mods);
        self.push_vn(first, op.time, self.mods);
        Ok(())
    }

    /// `PrintLanguage::opUnary`.
    fn op_unary(&mut self, tok: Tok, op: &'a POp) -> Result<()> {
        let [first] = op.kids.as_slice() else {
            return Err("op:unary-arity".into());
        };
        self.push_op(tok, Some(op.time))?;
        self.push_vn(first, op.time, self.mods);
        Ok(())
    }

    fn comma_list(&mut self, op: &'a POp, kids: &'a [PNode]) -> Result<()> {
        for _ in 1..kids.len() {
            self.push_op(Tok::Comma, Some(op.time))?;
        }
        for kid in kids.iter().rev() {
            self.push_vn(kid, op.time, self.mods);
        }
        Ok(())
    }

    /// `PrintC::opFunc`.
    fn op_func(&mut self, op: &'a POp) -> Result<()> {
        let name = function_name(op).ok_or("op:function-name")?;
        self.push_op(Tok::FunctionCall, Some(op.time))?;
        self.push_atom(Atom::Event(Event::Op {
            name,
            highlight: NO_COLOR,
            op: Some(op.time),
        }))?;
        if op.kids.is_empty() {
            self.push_atom(Atom::Blank)
        } else {
            self.comma_list(op, &op.kids)
        }
    }

    /// `PrintC::opTypeCast`.
    fn op_type_cast(&mut self, op: &'a POp, out: usize, address_of: bool) -> Result<()> {
        let first = op.kids.first().ok_or("op:cast-arity")?;
        if self.ty(out).pointer_to_array && address_of {
            self.push_op(Tok::AddressOf, Some(op.time))?;
            self.push_vn(first, op.time, self.mods);
            return Ok(());
        }
        if !self.options.no_casts {
            self.push_op(Tok::Typecast, Some(op.time))?;
            self.push_type(out)?;
        }
        self.push_vn(first, op.time, self.mods);
        Ok(())
    }

    /// `PrintC::opHiddenFunc`.
    fn op_hidden(&mut self, op: &'a POp) -> Result<()> {
        let first = op.kids.first().ok_or("op:hidden-arity")?;
        self.push_op(Tok::Hidden, Some(op.time))?;
        self.push_vn(first, op.time, self.mods);
        Ok(())
    }

    /// `PrintC::opPtradd`.
    fn op_ptradd(&mut self, op: &'a POp) -> Result<()> {
        let [base, index] = op.kids.as_slice() else {
            return Err("op:ptradd-arity".into());
        };
        let print_value = self.is_set(PRINT_LOAD_VALUE | PRINT_STORE_VALUE);
        let m = self.mods & !(PRINT_LOAD_VALUE | PRINT_STORE_VALUE);
        self.push_op(
            if print_value {
                Tok::Subscript
            } else {
                Tok::BinaryPlus
            },
            Some(op.time),
        )?;
        self.push_vn(index, op.time, m);
        self.push_vn(base, op.time, m);
        Ok(())
    }

    fn field_atom(&self, container: usize, name: &str, id: i64, op: u64) -> Atom {
        let ty = self.ty(container);
        Atom::Event(Event::Field {
            name: name.to_string(),
            highlight: NO_COLOR,
            field: Some(FieldRef {
                type_name: ty.name.clone(),
                type_id: ty.id,
                offset: id,
                op: Some(op),
            }),
        })
    }

    /// `PrintC::opPtrsub`.
    fn op_ptrsub(&mut self, op: &'a POp, kind: &'a PtrsubKind) -> Result<()> {
        let in0 = op.kids.first().ok_or("op:ptrsub-arity")?;
        let time = Some(op.time);
        let m = self.mods & !(PRINT_LOAD_VALUE | PRINT_STORE_VALUE);
        let mut value_on = self.is_set(PRINT_LOAD_VALUE | PRINT_STORE_VALUE);
        let flex = value_flexible(in0);
        match kind {
            PtrsubKind::No(reason) => Err(reason.clone()),
            PtrsubKind::Struct {
                container,
                field,
                id,
                array,
            } => {
                let mut array_value = false;
                if *array {
                    array_value = value_on;
                    value_on = true;
                }
                let (member, load) = if flex {
                    (Tok::ObjectMember, PRINT_LOAD_VALUE)
                } else {
                    (Tok::PointerMember, 0)
                };
                if !value_on {
                    self.push_op(Tok::AddressOf, time)?;
                    self.push_op(member, time)?;
                    self.push_vn(in0, op.time, m | load);
                    self.push_atom(self.field_atom(*container, field, *id, op.time))?;
                } else {
                    if array_value {
                        self.push_op(Tok::Subscript, time)?;
                    }
                    self.push_op(member, time)?;
                    self.push_vn(in0, op.time, m | load);
                    self.push_atom(self.field_atom(*container, field, *id, op.time))?;
                    if array_value {
                        self.push_integer(0, 4, false, false, None, time, 0)?;
                    }
                }
                Ok(())
            }
            PtrsubKind::Spacebase { symbol_kind, leaf } => {
                let mut array_value = false;
                match symbol_kind {
                    1 => {
                        array_value = value_on;
                        value_on = true;
                    }
                    2 => value_on = true,
                    _ => {}
                }
                if !value_on {
                    self.push_op(Tok::AddressOf, time)?;
                } else if array_value {
                    self.push_op(Tok::Subscript, time)?;
                }
                self.leaf(leaf, op.time)?;
                if array_value {
                    self.push_integer(0, 4, false, false, None, time, 0)?;
                }
                Ok(())
            }
            PtrsubKind::Array => {
                if !value_on {
                    if flex {
                        self.push_vn(in0, op.time, m | PRINT_LOAD_VALUE);
                    } else {
                        self.push_op(Tok::Dereference, time)?;
                        self.push_vn(in0, op.time, m);
                    }
                } else if flex {
                    self.push_op(Tok::Subscript, time)?;
                    self.push_vn(in0, op.time, m | PRINT_LOAD_VALUE);
                    self.push_integer(0, 4, false, false, None, time, 0)?;
                } else {
                    self.push_op(Tok::Subscript, time)?;
                    self.push_op(Tok::Dereference, time)?;
                    self.push_vn(in0, op.time, m);
                    self.push_integer(0, 4, false, false, None, time, 0)?;
                }
                Ok(())
            }
        }
    }

    /// The handler `TypeOp::push` dispatches to.
    fn op(&mut self, op: &'a POp) -> Result<()> {
        let time = Some(op.time);
        match op.code {
            opc::COPY => {
                let first = op.kids.first().ok_or("op:copy-arity")?;
                self.push_vn(first, op.time, self.mods);
                Ok(())
            }
            opc::LOAD => {
                let pointer = op.kids.first().ok_or("op:load-arity")?;
                let use_array = check_array_deref(pointer);
                let mut m = self.mods;
                if use_array && !self.is_set(FORCE_POINTER) {
                    m |= PRINT_LOAD_VALUE;
                } else {
                    self.push_op(Tok::Dereference, time)?;
                }
                self.push_vn(pointer, op.time, m);
                Ok(())
            }
            opc::STORE => {
                let [pointer, value] = op.kids.as_slice() else {
                    return Err("op:store-arity".into());
                };
                let mut m = self.mods;
                self.push_op(Tok::Assignment, time)?;
                let use_array = check_array_deref(pointer);
                if use_array && !self.is_set(FORCE_POINTER) {
                    m |= PRINT_STORE_VALUE;
                } else {
                    self.push_op(Tok::Dereference, time)?;
                }
                self.push_vn(value, op.time, self.mods);
                self.push_vn(pointer, op.time, m);
                Ok(())
            }
            opc::BRANCH | opc::MULTIEQUAL | opc::INDIRECT => Ok(()),
            opc::CBRANCH => self.op_cbranch(op),
            opc::BRANCHIND => {
                let target = op.kids.first().ok_or("op:branchind-arity")?;
                self.tag_op("switch", KEYWORD_COLOR, time);
                let id = self.open_paren("(");
                self.push_vn(target, op.time, self.mods);
                self.recurse()?;
                self.events.push(Event::CloseParen(id, ")".into()));
                Ok(())
            }
            opc::CALL => {
                let Extra::Call { name, scopes } = &op.extra else {
                    return Err("op:call-extra".into());
                };
                self.push_op(Tok::FunctionCall, time)?;
                for _ in scopes {
                    self.push_op(Tok::Scope, None)?;
                }
                for scope in scopes {
                    self.push_atom(Self::syntax(scope.clone(), GLOBAL_COLOR))?;
                }
                self.push_atom(Atom::Event(Event::FuncName {
                    name: name.clone(),
                    highlight: FUNCNAME_COLOR,
                    op: time,
                }))?;
                if op.kids.is_empty() {
                    self.push_atom(Atom::Blank)
                } else {
                    self.comma_list(op, &op.kids)
                }
            }
            opc::CALLIND => {
                let Extra::CallInd { hidden_this } = &op.extra else {
                    return Err("op:callind-extra".into());
                };
                if *hidden_this >= 0 {
                    return Err("call:hidden-this".into());
                }
                let (target, args) = op.kids.split_first().ok_or("op:callind-arity")?;
                self.push_op(Tok::FunctionCall, time)?;
                self.push_op(Tok::Dereference, time)?;
                match args.len() {
                    0 => {
                        self.push_vn(target, op.time, self.mods);
                        self.push_atom(Atom::Blank)?;
                    }
                    1 => {
                        self.push_vn(&args[0], op.time, self.mods);
                        self.push_vn(target, op.time, self.mods);
                    }
                    count => {
                        self.push_vn(target, op.time, self.mods);
                        for _ in 0..count - 1 {
                            self.push_op(Tok::Comma, time)?;
                        }
                        for arg in args.iter().rev() {
                            self.push_vn(arg, op.time, self.mods);
                        }
                    }
                }
                Ok(())
            }
            opc::CALLOTHER => {
                let Extra::CallOther { display, name } = &op.extra else {
                    return Err("op:callother-extra".into());
                };
                match display {
                    0 => {
                        self.push_op(Tok::FunctionCall, time)?;
                        self.push_atom(Atom::Event(Event::Op {
                            name: name.clone(),
                            highlight: FUNCNAME_COLOR,
                            op: time,
                        }))?;
                        if op.kids.is_empty() {
                            self.push_atom(Atom::Blank)
                        } else {
                            self.comma_list(op, &op.kids)
                        }
                    }
                    2 => {
                        let first = op.kids.first().ok_or("op:callother-arity")?;
                        self.push_vn(first, op.time, self.mods);
                        Ok(())
                    }
                    _ => Err("callother:display".into()),
                }
            }
            opc::RETURN => {
                let Extra::Return { halt } = &op.extra else {
                    return Err("op:return-extra".into());
                };
                let name = match halt {
                    0 => {
                        self.tag_op("return", KEYWORD_COLOR, time);
                        if let Some(value) = op.kids.first() {
                            self.spaces(1, 0);
                            self.push_vn(value, op.time, self.mods);
                        }
                        return Ok(());
                    }
                    1 => "halt",
                    2 => "halt_baddata",
                    3 => "halt_unimplemented",
                    _ => "halt_missing",
                };
                self.push_op(Tok::FunctionCall, time)?;
                self.push_atom(Atom::Event(Event::Op {
                    name: name.into(),
                    highlight: FUNCNAME_COLOR,
                    op: time,
                }))?;
                self.push_atom(Atom::Blank)
            }
            opc::INT_ZEXT | opc::INT_SEXT => {
                let Extra::Ext {
                    out,
                    input,
                    implied,
                    address_of,
                } = &op.extra
                else {
                    return Err("op:extension-extra".into());
                };
                let is_cast = if op.code == opc::INT_ZEXT {
                    is_zext_cast(self.ty(*out), self.ty(*input))
                } else {
                    is_sext_cast(self.ty(*out), self.ty(*input))
                };
                if !is_cast {
                    self.op_func(op)
                } else if self.options.hide_exts && *implied {
                    self.op_hidden(op)
                } else {
                    self.op_type_cast(op, *out, *address_of)
                }
            }
            opc::INT_2COMP | opc::FLOAT_NEG => self.op_unary(Tok::UnaryMinus, op),
            opc::INT_NEGATE => self.op_unary(Tok::BitwiseNot, op),
            opc::BOOL_NEGATE => {
                let first = op.kids.first().ok_or("op:negate-arity")?;
                if self.is_set(NEGATE_TOKEN) {
                    self.mods &= !NEGATE_TOKEN;
                    self.push_vn(first, op.time, self.mods);
                } else if check_print_negation(first) {
                    self.push_vn(first, op.time, self.mods | NEGATE_TOKEN);
                } else {
                    self.push_op(Tok::BooleanNot, time)?;
                    self.push_vn(first, op.time, self.mods);
                }
                Ok(())
            }
            opc::FLOAT_INT2FLOAT => {
                let Extra::Int2Float { out } = &op.extra else {
                    return Err("op:int2float-extra".into());
                };
                let first = op.kids.first().ok_or("op:int2float-arity")?;
                if !self.options.no_casts {
                    self.push_op(Tok::Typecast, time)?;
                    self.push_type(*out)?;
                }
                self.push_vn(first, op.time, self.mods);
                Ok(())
            }
            opc::FLOAT_FLOAT2FLOAT | opc::FLOAT_TRUNC | opc::CAST => {
                let Extra::Cast { out, address_of } = &op.extra else {
                    return Err("op:cast-extra".into());
                };
                self.op_type_cast(op, *out, *address_of)
            }
            opc::SUBPIECE => {
                let Extra::Subpiece {
                    out,
                    input,
                    offset,
                    address_of,
                    special,
                } = &op.extra
                else {
                    return Err("op:subpiece-extra".into());
                };
                match special {
                    PieceKind::Partial(leaf) => return self.leaf(leaf, op.time),
                    PieceKind::Member {
                        container,
                        name,
                        ident,
                    } => {
                        let first = op.kids.first().ok_or("op:subpiece-arity")?;
                        self.push_op(Tok::ObjectMember, time)?;
                        self.push_vn(first, op.time, self.mods);
                        return self.push_atom(self.field_atom(*container, name, *ident, op.time));
                    }
                    PieceKind::None => {}
                }
                let offset = u32::try_from(*offset).unwrap_or(u32::MAX);
                if is_subpiece_cast(self.ty(*out), self.ty(*input), offset) {
                    self.op_type_cast(op, *out, *address_of)
                } else {
                    self.op_func(op)
                }
            }
            opc::PTRADD => self.op_ptradd(op),
            opc::PTRSUB => {
                let Extra::Ptrsub(kind) = &op.extra else {
                    return Err("op:ptrsub-extra".into());
                };
                self.op_ptrsub(op, kind)
            }
            opc::SEGMENTOP => {
                let first = op.kids.first().ok_or("op:segmentop-arity")?;
                self.push_vn(first, op.time, self.mods);
                Ok(())
            }
            opc::INT_CARRY
            | opc::INT_SCARRY
            | opc::INT_SBORROW
            | opc::FLOAT_NAN
            | opc::FLOAT_ABS
            | opc::FLOAT_SQRT
            | opc::FLOAT_CEIL
            | opc::FLOAT_FLOOR
            | opc::FLOAT_ROUND
            | opc::PIECE
            | opc::POPCOUNT
            | opc::LZCOUNT => self.op_func(op),
            code => match binary_token(code) {
                Some(tok) => self.op_binary(tok, op),
                None => Err(format!("op:{code}")),
            },
        }
    }

    /// `PrintC::opCbranch` in structured mode.
    fn op_cbranch(&mut self, op: &'a POp) -> Result<()> {
        let Extra::Cbranch { flip } = &op.extra else {
            return Err("op:cbranch-extra".into());
        };
        let condition = op.kids.first().ok_or("op:cbranch-arity")?;
        let mut boolean_flip = *flip ^ self.invert;
        let mut m = self.mods;
        let paren = !self.is_set(COMMA_SEPARATE);
        let id = if paren {
            self.open_paren("(")
        } else {
            self.open_group()
        };
        if boolean_flip && check_print_negation(condition) {
            m |= NEGATE_TOKEN;
            boolean_flip = false;
        }
        if boolean_flip {
            self.push_op(Tok::BooleanNot, Some(op.time))?;
        }
        self.push_vn(condition, op.time, m);
        self.recurse()?;
        if paren {
            self.events.push(Event::CloseParen(id, ")".into()));
        } else {
            self.events.push(Event::CloseGroup(id));
        }
        Ok(())
    }
}

/// `PrintC::emitExpression` over a print tree: the Emit calls of one
/// statement. `invert` prints a CBRANCH's negation (the exporter's
/// `negated`); `comma` is the `comma_separate` rendering.
pub fn render(
    tables: &Tables,
    options: &Options,
    tree: &PrintTree,
    comma: bool,
    invert: bool,
) -> Result<Fragment> {
    let PNode::Op(root) = &tree.root else {
        return match &tree.root {
            PNode::No(reason) => Err(reason.clone()),
            _ => Err("tree:root".into()),
        };
    };
    let mut engine = Engine::new(tables, options, comma, invert);
    if let Some(out) = &tree.out {
        engine.push_op(Tok::Assignment, Some(root.time))?;
        match out {
            PNode::No(reason) => return Err(reason.clone()),
            leaf => engine.leaf(leaf, root.time)?,
        }
    }
    engine.op(root)?;
    engine.recurse()?;
    if !engine.revpol.is_empty() || !engine.nodepend.is_empty() || !engine.mod_stack.is_empty() {
        return Err("tree:unbalanced".into());
    }
    Ok(Fragment(engine.events))
}

/// How the worker treats print trees (`ROMWRIGHT_RUST_EXPRESSIONS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExprMode {
    /// Keep every PrintC fragment (the differential's reference).
    Off,
    /// Print the expressions the worker supports (default).
    On,
    /// Render every supported expression, compare it with PrintC's fragment,
    /// count the differences and keep the fragment.
    Verify,
}

impl ExprMode {
    pub fn from_env() -> Self {
        match std::env::var("ROMWRIGHT_RUST_EXPRESSIONS").as_deref() {
            Ok("off" | "fragments" | "0" | "none") => ExprMode::Off,
            Ok("verify") => ExprMode::Verify,
            _ => ExprMode::On,
        }
    }
}

/// The visible text of a fragment, the way the pretty printer lays out one line.
pub fn fragment_text(fragment: &Fragment) -> String {
    let mut out = String::new();
    for event in &fragment.0 {
        match event {
            Event::Variable { name, .. }
            | Event::Op { name, .. }
            | Event::Type { name, .. }
            | Event::FuncName { name, .. } => out.push_str(name),
            Event::Print { text, .. } => out.push_str(text),
            Event::OpenParen(_, paren) | Event::CloseParen(_, paren) => out.push_str(paren),
            Event::Spaces(count, _) => out.push_str(&" ".repeat(*count as usize)),
            _ => {}
        }
    }
    out
}

/// What happened to the expressions of one function: per context and kind
/// (`rust`, `fragments`), why the others kept their fragment, and in
/// `verify` mode how many renderings differ from PrintC's.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ExprStats {
    /// `context.kind` -> [printed by the worker, kept as PrintC fragments].
    #[serde(serialize_with = "serialize_kinds")]
    pub by_kind: BTreeMap<(&'static str, &'static str), [u64; 2]>,
    /// Why expressions kept their fragment.
    pub reasons: BTreeMap<String, u64>,
    /// `verify` mode: renderings equal to PrintC's.
    pub verified: u64,
    /// `verify` mode: renderings that differ (the first few are listed).
    pub mismatched: u64,
    pub mismatches: Vec<String>,
    /// Microseconds spent rendering print trees (the cost of printing
    /// expressions here instead of replaying a fragment).
    pub render_micros: u64,
    /// Functions whose casts the worker decided / the decompiler did
    /// (`ActionSetCasts`), and what the worker's cast pass did.
    pub cast_functions: [u64; 2],
    /// Functions whose merge, explicit/implied marking and for-loop moves the worker decided / the decompiler did.
    pub merge_functions: [u64; 2],
    pub casts: super::casts::CastStats,
    /// `CAST` operators the decompiler's `ActionSetCasts` inserted in the statements the worker printed
    /// (the functions it declined, or every function under `ROMWRIGHT_NATIVE_CASTS=1`).
    pub native_cast_ops: u64,
}

fn serialize_kinds<S: serde::Serializer>(
    kinds: &BTreeMap<(&'static str, &'static str), [u64; 2]>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(kinds.len()))?;
    for ((context, kind), counts) in kinds {
        map.serialize_entry(&format!("{context}.{kind}"), counts)?;
    }
    map.end()
}

impl ExprStats {
    pub fn add(&mut self, other: &ExprStats) {
        for (key, counts) in &other.by_kind {
            let entry = self.by_kind.entry(*key).or_default();
            entry[0] += counts[0];
            entry[1] += counts[1];
        }
        for (reason, count) in &other.reasons {
            *self.reasons.entry(reason.clone()).or_default() += count;
        }
        self.verified += other.verified;
        self.mismatched += other.mismatched;
        self.render_micros += other.render_micros;
        self.cast_functions[0] += other.cast_functions[0];
        self.cast_functions[1] += other.cast_functions[1];
        self.merge_functions[0] += other.merge_functions[0];
        self.merge_functions[1] += other.merge_functions[1];
        self.casts.add(&other.casts);
        self.native_cast_ops += other.native_cast_ops;
        for example in &other.mismatches {
            if self.mismatches.len() < 8 {
                self.mismatches.push(example.clone());
            }
        }
    }
}

/// The kind an expression counts as, by its root op.
fn kind_of(tree: &PrintTree) -> &'static str {
    match &tree.root {
        PNode::Op(op) => match op.code {
            opc::STORE => "store",
            opc::CALL | opc::CALLIND | opc::CALLOTHER => "call",
            opc::RETURN => "return",
            opc::CBRANCH => "cbranch",
            opc::BRANCHIND => "branchind",
            opc::BRANCH => "branch",
            _ if tree.out.is_some() => "assign",
            _ => "other",
        },
        _ => "unsupported",
    }
}

pub enum Outcome {
    Rendered {
        normal: Fragment,
        comma: Option<Fragment>,
    },
    Fragments,
}

/// Renders one expression when the worker supports it, counting the result.
#[allow(clippy::too_many_arguments)]
pub fn attempt(
    stats: &mut ExprStats,
    mode: ExprMode,
    options: &Options,
    tables: &Tables,
    tree: &PrintTree,
    context: &'static str,
    invert: bool,
    normal: &Fragment,
    comma: Option<&Fragment>,
) -> Outcome {
    let key = (context, kind_of(tree));
    let reason = if mode == ExprMode::Off {
        Some("disabled".to_string())
    } else {
        options
            .unsupported()
            .map(str::to_string)
            .or_else(|| tree.unsupported().map(str::to_string))
    };
    let started = std::time::Instant::now();
    let result = match reason {
        Some(reason) => Err(reason),
        None => render(tables, options, tree, false, invert).and_then(|normal| {
            let comma = if comma.is_some() {
                Some(render(tables, options, tree, true, invert)?)
            } else {
                None
            };
            Ok((normal, comma))
        }),
    };
    stats.render_micros += started.elapsed().as_micros() as u64;
    let (rendered_normal, rendered_comma) = match result {
        Ok(rendered) => rendered,
        Err(reason) => {
            stats.by_kind.entry(key).or_default()[1] += 1;
            *stats.reasons.entry(reason).or_default() += 1;
            return Outcome::Fragments;
        }
    };
    if mode == ExprMode::Verify {
        stats.by_kind.entry(key).or_default()[1] += 1;
        if rendered_normal == *normal && rendered_comma.as_ref() == comma {
            stats.verified += 1;
        } else {
            stats.mismatched += 1;
            if std::env::var_os("ROMWRIGHT_RUST_EXPRESSIONS_LOG").is_some() {
                eprintln!(
                    "{}",
                    serde_json::json!({"expression_mismatch": {
                        "context": context,
                        "kind": kind_of(tree),
                        "rust": format!("{:?}", rendered_normal.0),
                        "printc": format!("{:?}", normal.0),
                    }})
                );
            }
            if stats.mismatches.len() < 8 {
                stats.mismatches.push(format!(
                    "{context} {}: rust {:?} / fragment {:?}",
                    kind_of(tree),
                    rendered_normal.0,
                    normal.0
                ));
            }
        }
        return Outcome::Fragments;
    }
    stats.by_kind.entry(key).or_default()[0] += 1;
    Outcome::Rendered {
        normal: rendered_normal,
        comma: rendered_comma,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::printc::tree::{PtrsubKind, TypeDesc};

    fn ty(name: &str, meta: u8, size: u32, base: Option<usize>) -> TypeDesc {
        TypeDesc {
            id: 1,
            name: name.into(),
            display_name: name.into(),
            generic_name: String::new(),
            meta,
            size,
            display_format: 0,
            char_print: false,
            enumerated: false,
            needs_resolution: false,
            pointer_to_array: false,
            base,
            elements: 0,
            has_proto: false,
            fields: Vec::new(),
            ..TypeDesc::default()
        }
    }

    fn tables() -> Tables {
        let symbol = |name: &str| SymbolDesc {
            highlight: 4,
            name: name.into(),
            scopes: Vec::new(),
        };
        Tables {
            // 0 uint, 1 int, 2 uint *, 3 undefined8
            types: vec![
                ty("uint", meta::UINT, 4, None),
                ty("int", meta::INT, 4, None),
                ty("", meta::PTR, 4, Some(0)),
                ty("undefined8", meta::UNKNOWN, 8, None),
            ],
            symbols: vec![symbol("x"), symbol("a"), symbol("b"), symbol("c"), symbol("p")],
            ..Tables::default()
        }
    }

    fn sym(index: usize) -> PNode {
        PNode::Symbol {
            vn: Some(index as u64),
            size: 4,
            sym: index,
        }
    }

    fn constant(value: u64, ty: usize) -> PNode {
        PNode::Const(PConst {
            vn: 99,
            size: 4,
            value,
            ty,
            unsigned_print: false,
            long_print: false,
            symbol_format: 0,
            kind: ConstKind::Integer,
        })
    }

    fn op(code: u32, time: u64, kids: Vec<PNode>) -> PNode {
        op_with(code, time, Extra::None, kids)
    }

    fn op_with(code: u32, time: u64, extra: Extra, kids: Vec<PNode>) -> PNode {
        PNode::Op(Box::new(POp {
            code,
            time,
            out_size: 4,
            extra,
            kids,
        }))
    }

    fn options() -> Options {
        Options {
            hide_exts: true,
            size_suffix: "L".into(),
            ..Options::default()
        }
    }

    /// The visible text of a fragment, the way the pretty printer lays out
    /// one line.
    fn text(fragment: &Fragment) -> String {
        let mut out = String::new();
        for event in &fragment.0 {
            match event {
                Event::Variable { name, .. }
                | Event::Op { name, .. }
                | Event::Type { name, .. }
                | Event::FuncName { name, .. } => out.push_str(name),
                Event::Print { text, .. } => out.push_str(text),
                Event::OpenParen(_, paren) | Event::CloseParen(_, paren) => out.push_str(paren),
                Event::Spaces(count, _) => out.push_str(&" ".repeat(*count as usize)),
                _ => {}
            }
        }
        out
    }

    fn render_text(tree: &PrintTree, comma: bool, invert: bool) -> String {
        text(&render(&tables(), &options(), tree, comma, invert).unwrap())
    }

    fn statement(out: Option<PNode>, root: PNode) -> PrintTree {
        PrintTree { out, root }
    }

    #[test]
    fn parenthesizes_by_precedence() {
        // x = (a + b) * c
        let sum = op(opc::INT_ADD, 2, vec![sym(1), sym(2)]);
        let root = op(opc::INT_MULT, 3, vec![sum, sym(3)]);
        assert_eq!(
            render_text(&statement(Some(sym(0)), root), false, false),
            "x = (a + b) * c"
        );
        // x = a + b * c
        let product = op(opc::INT_MULT, 2, vec![sym(2), sym(3)]);
        let root = op(opc::INT_ADD, 3, vec![sym(1), product]);
        assert_eq!(
            render_text(&statement(Some(sym(0)), root), false, false),
            "x = a + b * c"
        );
    }

    #[test]
    fn mixed_bitwise_grouping_is_explicit() {
        // The patch's rule: x = (a + b) & c, though & binds looser than +.
        let sum = op(opc::INT_ADD, 2, vec![sym(1), sym(2)]);
        let root = op(opc::INT_AND, 3, vec![sum, sym(3)]);
        assert_eq!(
            render_text(&statement(Some(sym(0)), root), false, false),
            "x = (a + b) & c"
        );
        // Associative and equal tokens stay flat.
        let inner = op(opc::INT_AND, 2, vec![sym(1), sym(2)]);
        let root = op(opc::INT_AND, 3, vec![inner, sym(3)]);
        assert_eq!(
            render_text(&statement(Some(sym(0)), root), false, false),
            "x = a & b & c"
        );
    }

    #[test]
    fn integers_follow_push_integer() {
        let assign = |value: u64, ty: usize| {
            render_text(
                &statement(Some(sym(0)), op(opc::COPY, 1, vec![constant(value, ty)])),
                false,
                false,
            )
        };
        assert_eq!(assign(5, 0), "x = 5");
        assert_eq!(assign(0x10, 0), "x = 0x10");
        assert_eq!(assign(100, 0), "x = 100");
        assert_eq!(assign(0xffff_ffff, 0), "x = 0xffffffff");
        assert_eq!(assign(0xffff_ffff, 1), "x = -1");
        assert_eq!(assign(0x8000_0000, 1), "x = -0x80000000");
    }

    #[test]
    fn casts_print_their_type() {
        let cast = op_with(
            opc::CAST,
            2,
            Extra::Cast {
                out: 0,
                address_of: false,
            },
            vec![sym(1)],
        );
        assert_eq!(
            render_text(&statement(Some(sym(0)), cast), false, false),
            "x = (uint)a"
        );
        let pointer = op_with(
            opc::CAST,
            2,
            Extra::Cast {
                out: 2,
                address_of: false,
            },
            vec![sym(1)],
        );
        assert_eq!(
            render_text(&statement(Some(sym(0)), pointer), false, false),
            "x = (uint *)a"
        );
    }

    #[test]
    fn conditions_negate_their_token() {
        let condition = op(opc::INT_LESS, 2, vec![sym(1), constant(4, 0)]);
        let branch = op_with(
            opc::CBRANCH,
            3,
            Extra::Cbranch { flip: false },
            vec![condition],
        );
        let tree = statement(None, branch);
        assert_eq!(render_text(&tree, false, false), "(a < 4)");
        assert_eq!(render_text(&tree, true, false), "a < 4");
        assert_eq!(render_text(&tree, false, true), "(a >= 4)");
        assert_eq!(render_text(&tree, true, true), "a >= 4");
    }

    #[test]
    fn boolean_negation_wraps_what_cannot_flip() {
        let call = op_with(
            opc::CALL,
            2,
            Extra::Call {
                name: "f".into(),
                scopes: Vec::new(),
            },
            vec![sym(1)],
        );
        let branch = op_with(opc::CBRANCH, 3, Extra::Cbranch { flip: true }, vec![call]);
        assert_eq!(
            render_text(&statement(None, branch), false, false),
            "(!f(a))"
        );
    }

    #[test]
    fn array_notation_absorbs_the_dereference() {
        // x = p[a]
        let add = op(opc::PTRADD, 2, vec![sym(4), sym(1)]);
        let load = op(opc::LOAD, 3, vec![add]);
        assert_eq!(
            render_text(&statement(Some(sym(0)), load), false, false),
            "x = p[a]"
        );
        // *(p + a) = x
        let add = op(opc::PTRADD, 2, vec![sym(4), sym(1)]);
        let store = op(opc::STORE, 3, vec![add, sym(0)]);
        assert_eq!(render_text(&statement(None, store), false, false), "p[a] = x");
        // x = *p
        let load = op(opc::LOAD, 3, vec![sym(4)]);
        assert_eq!(
            render_text(&statement(Some(sym(0)), load), false, false),
            "x = *p"
        );
    }

    #[test]
    fn calls_list_their_arguments() {
        let call = op_with(
            opc::CALL,
            2,
            Extra::Call {
                name: "f".into(),
                scopes: vec!["ns".into()],
            },
            vec![sym(1), sym(2), constant(7, 0)],
        );
        assert_eq!(
            render_text(&statement(Some(sym(0)), call), false, false),
            "x = ns::f(a,b,7)"
        );
        let void = op_with(
            opc::CALL,
            2,
            Extra::Call {
                name: "f".into(),
                scopes: Vec::new(),
            },
            Vec::new(),
        );
        assert_eq!(render_text(&statement(None, void), false, false), "f()");
    }

    #[test]
    fn partial_symbols_use_artificial_field_names() {
        // x = a._4_4_
        let partial = PNode::Partial(PPartial {
            vn: Some(1),
            sym: 1,
            offset: 4,
            size: 4,
            sym_type: 3,
            high_type: 3,
            read: true,
            big_endian: false,
        });
        assert_eq!(
            render_text(
                &statement(Some(sym(0)), op(opc::COPY, 1, vec![partial])),
                false,
                false
            ),
            "x = a._4_4_"
        );
    }

    #[test]
    fn spacebase_ptrsub_takes_the_address() {
        let ptrsub = op_with(
            opc::PTRSUB,
            2,
            Extra::Ptrsub(PtrsubKind::Spacebase {
                symbol_kind: 0,
                leaf: Box::new(sym(1)),
            }),
            vec![constant(0, 0)],
        );
        assert_eq!(
            render_text(&statement(Some(sym(0)), ptrsub), false, false),
            "x = &a"
        );
    }

    #[test]
    fn unsupported_nodes_refuse() {
        let tree = statement(
            Some(sym(0)),
            op(opc::COPY, 1, vec![PNode::No("const:float".into())]),
        );
        assert_eq!(tree.unsupported(), Some("const:float"));
        assert!(render(&tables(), &options(), &tree, false, false).is_err());
    }

    #[test]
    fn ids_open_in_the_order_printc_counts_them() {
        let sum = op(opc::INT_ADD, 2, vec![sym(1), sym(2)]);
        let root = op(opc::INT_MULT, 3, vec![sum, sym(3)]);
        let fragment = render(
            &tables(),
            &options(),
            &statement(Some(sym(0)), root),
            false,
            false,
        )
        .unwrap();
        let opened: Vec<u64> = fragment
            .0
            .iter()
            .filter_map(|event| match event {
                Event::OpenGroup(id) | Event::OpenParen(id, _) => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(opened, (1..=opened.len() as u64).collect::<Vec<_>>());
    }
}
