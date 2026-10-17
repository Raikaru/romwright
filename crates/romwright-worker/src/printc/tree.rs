//! Print trees (printer IR version 4): what PrintC's expression emission
//! reads for one statement, exported by `native/romwright_printir.hh` so
//! [`super::render`] can print the expression itself.
//!
//! A tree is what PrintC pushes onto its reverse-polish stack, structurally:
//! an op node holds the inputs the op prints, in p-code order (an implied
//! varnode is the op that defines it, an explicit one a leaf). The choices
//! PrintC makes from the data-type system and the symbol table are carried
//! as data: which cast an extension prints as, the type a cast names, a
//! symbol's name, colour and namespace path. A leaf PrintC would print as one
//! token that the worker does not format itself (a string literal, a float,
//! a function name) travels as that token. Whatever the worker cannot print
//! yet is a [`PNode::No`] naming why; the statement then keeps its fragment.

use super::ir::Event;

/// `type_metatype` (type.hh).
pub mod meta {
    pub const VOID: u8 = 17;
    pub const SPACEBASE: u8 = 16;
    pub const UNKNOWN: u8 = 15;
    pub const INT: u8 = 14;
    pub const UINT: u8 = 13;
    pub const BOOL: u8 = 12;
    pub const CODE: u8 = 11;
    pub const FLOAT: u8 = 10;
    pub const PTR: u8 = 9;
    pub const PTRREL: u8 = 8;
    pub const ARRAY: u8 = 7;
    pub const STRUCT: u8 = 4;
    pub const UNION: u8 = 3;
    pub const PARTIALSTRUCT: u8 = 1;
    pub const PARTIALUNION: u8 = 0;
}

/// The options of PrintC's expression emission, as exported.
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub no_casts: bool,
    pub hide_exts: bool,
    pub null_keyword: bool,
    pub inplace_ops: bool,
    pub hide_this: bool,
    /// `PrintLanguage::mods` bits that persist (`force_hex`, `force_dec`, ...).
    pub base_mods: u32,
    /// `PrintC::sizeSuffix`.
    pub size_suffix: String,
}

impl Options {
    /// The options whose effect the worker's expression printer does not
    /// model; with any of them set every expression keeps its fragment.
    pub fn unsupported(&self) -> Option<&'static str> {
        if self.null_keyword {
            Some("option:NULL")
        } else if self.inplace_ops {
            Some("option:inplace")
        } else if self.hide_this {
            Some("option:hide-this")
        } else {
            None
        }
    }
}

/// `Datatype` as the printer reads it.
#[derive(Clone, Debug, Default)]
pub struct TypeDesc {
    /// `Datatype::getUnsizedId`, the type id markup carries.
    pub id: u64,
    pub name: String,
    pub display_name: String,
    /// `PrintC::genericTypeName` when the type is anonymous.
    pub generic_name: String,
    pub meta: u8,
    pub size: u32,
    /// `Datatype::getDisplayFormat`.
    pub display_format: u32,
    pub char_print: bool,
    pub enumerated: bool,
    pub needs_resolution: bool,
    pub pointer_to_array: bool,
    /// Pointer: pointed-to type. Array: element type. Code without a
    /// prototype: `void`.
    pub base: Option<usize>,
    pub elements: u32,
    /// A function type with a prototype (its parameter list prints too).
    pub has_proto: bool,
    /// Structure fields, by offset.
    pub fields: Vec<FieldDesc>,
    /// `Datatype::getSubMeta` (version 6: what the cast strategy orders by).
    pub submeta: u8,
    /// `Datatype::getTypedef`: the type this one is a typedef of.
    pub typedef: Option<usize>,
    /// Pointer: `getWordSize`.
    pub word_size: u32,
    /// Pointer: 1 + the index of its address space, 0 for none.
    pub space: u32,
    /// `Datatype::getAlignSize`.
    pub align_size: u32,
    pub variable_length: bool,
}

/// A structure field (`TypeField`).
#[derive(Clone, Debug)]
pub struct FieldDesc {
    pub offset: i64,
    pub ident: i64,
    pub name: String,
    pub ty: usize,
}

/// `PrintC::pushSymbol`'s token: colour, name and namespace path.
#[derive(Clone, Debug)]
pub struct SymbolDesc {
    pub highlight: u8,
    pub name: String,
    /// Outermost scope first.
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Tables {
    pub types: Vec<TypeDesc>,
    pub symbols: Vec<SymbolDesc>,
    /// Version 6, casts pending: the core types by (metatype, size, kind) as
    /// `TypeFactory::getBase` returns them; kind 0..3 `getBase` with INT,
    /// UINT, UNKNOWN, BOOL, 4 `getBaseNoChar(1, INT)`.
    pub seeds: Vec<((u8, u32, u8), usize)>,
    /// Version 6: `Datatype::typeOrder` of the pairs of types the cast pass
    /// cannot order itself, with the lower index first.
    pub order: Vec<((usize, usize), i8)>,
    /// Version 6: `TypeFactory::getSizeOfInt`.
    pub promote_size: u32,
}

/// A constant leaf: `PrintC::pushConstant`'s input.
#[derive(Clone, Debug)]
pub struct PConst {
    /// `Varnode::getCreateIndex`.
    pub vn: u64,
    pub size: u32,
    pub value: u64,
    /// The type the reading op sees (`getHighTypeReadFacing`).
    pub ty: usize,
    pub unsigned_print: bool,
    pub long_print: bool,
    /// 0: the varnode's variable has no symbol; else 1 + its display format.
    pub symbol_format: u32,
    pub kind: ConstKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstKind {
    /// Integer, unknown or boolean type: `push_integer`, `true`/`false`.
    Integer,
    /// A printable character constant below 0x80.
    Char,
    /// Any other type: a cast and a hexadecimal integer.
    Default,
    /// Default printing without the cast: the type is an aggregate, which has
    /// no C cast from an integer (the worker's cast pass decides this).
    Bare,
}

/// `PrintC::pushPartialSymbol`'s input: a symbol read or written at an
/// offset and size within it.
#[derive(Clone, Debug)]
pub struct PPartial {
    pub vn: Option<u64>,
    pub sym: usize,
    pub offset: i64,
    pub size: i64,
    pub sym_type: usize,
    /// `HighVariable::getType` of the varnode.
    pub high_type: usize,
    pub read: bool,
    pub big_endian: bool,
}

/// What `PrintC::opPtrsub` decides from the pointed-to type.
#[derive(Clone, Debug)]
pub enum PtrsubKind {
    No(String),
    Struct {
        container: usize,
        field: String,
        id: i64,
        array: bool,
    },
    /// `symbol_kind`: 0 other, 1 array, 2 code.
    Spacebase { symbol_kind: u8, leaf: Box<PNode> },
    Array,
}

/// `PrintC::opSubpiece`'s special printing of a piece of a structured
/// variable.
#[derive(Clone, Debug)]
pub enum PieceKind {
    /// A cast or `SUB` function.
    None,
    /// The element or field of the symbol the piece is, as a partial symbol
    /// (no inputs print).
    Partial(Box<PNode>),
    /// A field of the input (`in.field`).
    Member {
        container: usize,
        name: String,
        ident: i64,
    },
}

/// The per-opcode data an op node carries beyond its inputs.
#[derive(Clone, Debug)]
pub enum Extra {
    None,
    /// `INT_ZEXT`, `INT_SEXT`: output and input types, whether the
    /// extension is implied by its reader, whether it is an address-of cast.
    Ext {
        out: usize,
        input: usize,
        implied: bool,
        address_of: bool,
    },
    Subpiece {
        out: usize,
        input: usize,
        offset: u64,
        address_of: bool,
        special: PieceKind,
    },
    Cast {
        out: usize,
        address_of: bool,
    },
    Int2Float {
        out: usize,
    },
    Cbranch {
        flip: bool,
    },
    Call {
        name: String,
        scopes: Vec<String>,
    },
    CallInd {
        hidden_this: i64,
    },
    CallOther {
        display: u64,
        name: String,
    },
    Return {
        halt: u8,
    },
    Ptrsub(PtrsubKind),
}

#[derive(Clone, Debug)]
pub struct POp {
    /// `OpCode`.
    pub code: u32,
    /// `PcodeOp::getTime`, the `opref` of the op's tokens.
    pub time: u64,
    /// Size of the output varnode (0 without one).
    pub out_size: u32,
    pub extra: Extra,
    pub kids: Vec<PNode>,
}

#[derive(Clone, Debug)]
pub enum PNode {
    /// The worker does not print this yet, and why.
    No(String),
    Const(PConst),
    /// One token PrintC produced for the leaf.
    Atom {
        size: u32,
        event: Event,
    },
    Symbol {
        vn: Option<u64>,
        size: u32,
        sym: usize,
    },
    Partial(PPartial),
    Op(Box<POp>),
}

impl PNode {
    /// The size of the varnode the node stands for, where known.
    pub fn size(&self) -> u32 {
        match self {
            PNode::Const(constant) => constant.size,
            PNode::Atom { size, .. } | PNode::Symbol { size, .. } => *size,
            PNode::Partial(partial) => partial.size.max(0) as u32,
            PNode::Op(op) => op.out_size,
            PNode::No(_) => 0,
        }
    }
}

/// A statement: the variable it assigns (if any) and the op.
#[derive(Clone, Debug)]
pub struct PrintTree {
    pub out: Option<PNode>,
    pub root: PNode,
}

impl PrintTree {
    /// The first reason a node of the tree cannot be printed.
    pub fn unsupported(&self) -> Option<&str> {
        fn walk(node: &PNode) -> Option<&str> {
            match node {
                PNode::No(reason) => Some(reason),
                PNode::Op(op) => {
                    if let Extra::Ptrsub(kind) = &op.extra {
                        match kind {
                            PtrsubKind::No(reason) => return Some(reason),
                            PtrsubKind::Spacebase { leaf, .. } => {
                                if let Some(reason) = walk(leaf) {
                                    return Some(reason);
                                }
                            }
                            _ => {}
                        }
                    }
                    op.kids.iter().find_map(walk)
                }
                _ => None,
            }
        }
        self.out
            .as_ref()
            .and_then(walk)
            .or_else(|| walk(&self.root))
    }
}
