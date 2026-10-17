//! Metrowerks DWARF 1 ("MW MIPS C Compiler"): the whole debug stream, not
//! only the procedure table.
//!
//! The grammar, from the DWARF 1.1.0 draft (UNIX International, 1992), with
//! the Metrowerks dialect this stream uses. Every tag, attribute and
//! fundamental-type number below was checked against SLUS_209.50 itself
//! (names, sibling chains, struct layouts); no GPL source was consulted:
//!
//! * a flat run of DIEs, each `length:u32` (including itself), `tag:u16`,
//!   then attributes whose 16-bit code packs `(attribute << 4) | form`;
//! * forms: 1 addr, 2 ref (a section offset), 3 block2, 4 block4, 5 data2,
//!   6 data4, 7 data8, 8 NUL-terminated string;
//! * a record shorter than a tag is a null entry. DWARF 1 has no
//!   "has children" flag: a DIE owns the entries up to its `AT_sibling`
//!   offset exactly when that offset lies beyond the DIE's own end, and the
//!   child list closes with a null entry;
//! * types are an attribute, not a DIE: `fund_type` (a 16-bit `FT_*`),
//!   `mod_fund_type` (modifier bytes then an `FT_*`), `user_def_type` (a
//!   ref to a type DIE) and `mod_u_d_type` (modifier bytes then a ref).
//!   Modifiers are `01` pointer, `02` reference, `03` const, `04`
//!   volatile, outermost first;
//! * member offsets, parameter and variable locations are small stack
//!   programs: `01 reg4` (register), `02 reg4` (register as base, optionally
//!   followed by `04 const4 07`, i.e. plus a constant), `03 addr4`, and
//!   `04 const4 07` for a member's offset in its aggregate.
//!
//! Metrowerks widths DWARF 1 does not state are measured, not assumed: in
//! SLUS_209.50, every `signed_long`/`unsigned_long` struct member advances
//! the next member's offset by 8 (191 and 112 cases, none by 4), so `long`
//! is 64-bit on this toolchain. `FT 0xa510` is the 16-byte `I128`/`UI128`
//! multimedia member type; it states no signedness and is `unknown`.
//!
//! The importer consumes the prototypes. The rest of what the stream states
//! (locals, locations, the type graph, scoring classes) is recovered and
//! exercised by the tests and by the differential against the independent
//! Python reader (`benchmarks/dwarf1_diff.py`), so it is not dead code even
//! where no import path reads it yet.
#![allow(dead_code)]

use super::super::NativeFunction;
use romwright_model::type_evidence::Class;
use romwright_model::structs::{DEBUG_SOURCE, StructField, StructLayout};
use std::collections::BTreeMap;

pub(super) const TAG_ARRAY: u16 = 0x01;
pub(super) const TAG_ENUMERATION: u16 = 0x04;
pub(super) const TAG_FORMAL_PARAMETER: u16 = 0x05;
pub(super) const TAG_GLOBAL_SUBROUTINE: u16 = 0x06;
pub(super) const TAG_LEXICAL_BLOCK: u16 = 0x0b;
pub(super) const TAG_LOCAL_VARIABLE: u16 = 0x0c;
pub(super) const TAG_MEMBER: u16 = 0x0d;
pub(super) const TAG_POINTER: u16 = 0x0f;
pub(super) const TAG_REFERENCE: u16 = 0x10;
pub(super) const TAG_COMPILE_UNIT: u16 = 0x11;
pub(super) const TAG_STRUCTURE: u16 = 0x13;
pub(super) const TAG_SUBROUTINE: u16 = 0x14;
pub(super) const TAG_SUBROUTINE_TYPE: u16 = 0x15;
pub(super) const TAG_TYPEDEF: u16 = 0x16;
pub(super) const TAG_UNION: u16 = 0x17;
pub(super) const TAG_UNSPECIFIED_PARAMETERS: u16 = 0x18;
pub(super) const TAG_INLINED_SUBROUTINE: u16 = 0x1f;
const TAG_CLASS: u16 = 0x02;

const AT_SIBLING: u16 = 0x001;
const AT_LOCATION: u16 = 0x002;
const AT_NAME: u16 = 0x003;
const AT_FUND_TYPE: u16 = 0x005;
const AT_MOD_FUND_TYPE: u16 = 0x006;
const AT_USER_DEF_TYPE: u16 = 0x007;
const AT_MOD_U_D_TYPE: u16 = 0x008;
const AT_SUBSCR_DATA: u16 = 0x00a;
const AT_BYTE_SIZE: u16 = 0x00b;
const AT_BIT_OFFSET: u16 = 0x00c;
const AT_BIT_SIZE: u16 = 0x00d;
const AT_ELEMENT_LIST: u16 = 0x00f;
const AT_LOW_PC: u16 = 0x011;
const AT_HIGH_PC: u16 = 0x012;

const FORM_ADDR: u16 = 1;
const FORM_REF: u16 = 2;
const FORM_BLOCK2: u16 = 3;
const FORM_BLOCK4: u16 = 4;
const FORM_DATA2: u16 = 5;
const FORM_DATA4: u16 = 6;
const FORM_DATA8: u16 = 7;
const FORM_STRING: u16 = 8;

const MOD_POINTER_TO: u8 = 0x01;
const MOD_REFERENCE_TO: u8 = 0x02;
const MOD_CONST: u8 = 0x03;
const MOD_VOLATILE: u8 = 0x04;

const OP_REG: u8 = 0x01;
const OP_BASEREG: u8 = 0x02;
const OP_ADDR: u8 = 0x03;
const OP_CONST: u8 = 0x04;
const OP_ADD: u8 = 0x07;

/// Width of `long`/`unsigned long` in bytes on the Metrowerks MIPS
/// toolchain; see the module comment for the measurement.
const LONG_BYTES: u32 = 8;

/// Pointer width of the 32-bit Metrowerks MIPS target.
const POINTER_BYTES: u64 = 4;

/// The MIPS stack pointer in the compiler's register numbering (the
/// `OP_BASEREG` of every stack local in SLUS_209.50 names it).
const MIPS_SP: u32 = 29;

/// One attribute's value, borrowed from the stream.
#[derive(Clone, Copy, Debug)]
enum Value<'a> {
    Addr(u64),
    Ref(u32),
    Data(u64),
    Str(&'a [u8]),
    Block(&'a [u8]),
}

impl Value<'_> {
    fn number(self) -> Option<u64> {
        match self {
            Value::Addr(v) | Value::Data(v) => Some(v),
            Value::Ref(v) => Some(u64::from(v)),
            _ => None,
        }
    }
}

/// One DIE: where it starts, its tag, its raw attribute bytes, and the
/// index one past its last descendant (so `index + 1 == subtree_end` is a
/// leaf).
struct Die<'a> {
    offset: u32,
    tag: u16,
    body: &'a [u8],
    subtree_end: usize,
}

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// The attributes of one DIE body, in order; ends at the first malformed
/// one (the record's own length still frames the stream).
struct Attributes<'a> {
    body: &'a [u8],
    at: usize,
}

impl<'a> Iterator for Attributes<'a> {
    type Item = (u16, Value<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let code = le16(self.body, self.at)?;
        let attribute = code >> 4;
        let form = code & 0xf;
        let mut p = self.at + 2;
        let value = match form {
            FORM_ADDR => {
                let v = le32(self.body, p)?;
                p += 4;
                Value::Addr(u64::from(v))
            }
            FORM_REF => {
                let v = le32(self.body, p)?;
                p += 4;
                Value::Ref(v)
            }
            FORM_DATA2 => {
                let v = le16(self.body, p)?;
                p += 2;
                Value::Data(u64::from(v))
            }
            FORM_DATA4 => {
                let v = le32(self.body, p)?;
                p += 4;
                Value::Data(u64::from(v))
            }
            FORM_DATA8 => {
                let v = u64::from_le_bytes(self.body.get(p..p + 8)?.try_into().ok()?);
                p += 8;
                Value::Data(v)
            }
            FORM_BLOCK2 => {
                let n = usize::from(le16(self.body, p)?);
                let block = self.body.get(p + 2..p + 2 + n)?;
                p += 2 + n;
                Value::Block(block)
            }
            FORM_BLOCK4 => {
                let n = le32(self.body, p)? as usize;
                let block = self.body.get(p + 4..p.checked_add(4)?.checked_add(n)?)?;
                p += 4 + n;
                Value::Block(block)
            }
            FORM_STRING => {
                let rest = self.body.get(p..)?;
                let nul = rest.iter().position(|c| *c == 0)?;
                p += nul + 1;
                Value::Str(&rest[..nul])
            }
            // An unknown form makes the tail unreadable.
            _ => return None,
        };
        self.at = p;
        Some((attribute, value))
    }
}

fn attributes(body: &[u8]) -> Attributes<'_> {
    Attributes { body, at: 0 }
}

/// A reference to a type, as an attribute states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TypeRef {
    /// The attribute is absent.
    Absent,
    /// An `FT_*` fundamental type code.
    Fundamental(u16),
    /// A type DIE, by section offset.
    Die(u32),
    /// Modifier bytes (outermost first) applied to a base.
    Modified { modifiers: Vec<u8>, base: Box<TypeRef> },
}

/// What a type is once qualifiers and typedefs are looked through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Resolved {
    Void,
    Int { signed: bool, bits: u32 },
    Float(u32),
    Bool,
    /// A pointer or reference; the target keeps its own spelling.
    Pointer(TypeRef),
    /// A subroutine type by value (what a pointer to code points at).
    Subroutine,
    Aggregate,
    /// A value of this many bits whose kind the stream does not state.
    Opaque(u32),
    Unknown,
}

impl Resolved {
    /// The class name `benchmarks/dwarf_types.py` uses for the same type,
    /// given how to resolve a pointer's target.
    fn class_name(&self, graph: &TypeGraph) -> String {
        match self {
            Resolved::Void => "void".into(),
            Resolved::Int { signed: true, bits } => Class::Int(*bits).name(),
            Resolved::Int { signed: false, bits } => Class::Uint(*bits).name(),
            Resolved::Float(bits) => Class::Float(*bits).name(),
            Resolved::Bool => "bool".into(),
            Resolved::Pointer(target) => {
                if graph.resolve(target) == Resolved::Subroutine {
                    "code".into()
                } else {
                    "ptr".into()
                }
            }
            Resolved::Subroutine => "code".into(),
            Resolved::Aggregate => "aggregate".into(),
            Resolved::Opaque(_) | Resolved::Unknown => "unknown".into(),
        }
    }
}

/// How a variable or parameter is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Location {
    /// Lives in this register (the compiler's numbering).
    Register(u32),
    /// At `base register + offset`.
    Based { register: u32, offset: i64 },
    /// At a fixed address (a function-local `static`).
    Address(u64),
    /// A program this reader does not interpret.
    Other(Vec<u8>),
}

fn decode_location(block: &[u8]) -> Location {
    match block {
        [OP_REG, r @ ..] if r.len() == 4 => Location::Register(le32(r, 0).unwrap_or(0)),
        [OP_ADDR, a @ ..] if a.len() == 4 => Location::Address(u64::from(le32(a, 0).unwrap_or(0))),
        [OP_BASEREG, r @ ..] if r.len() == 4 => Location::Based {
            register: le32(r, 0).unwrap_or(0),
            offset: 0,
        },
        [OP_BASEREG, r0, r1, r2, r3, OP_CONST, c0, c1, c2, c3, OP_ADD] => Location::Based {
            register: u32::from_le_bytes([*r0, *r1, *r2, *r3]),
            offset: i64::from(i32::from_le_bytes([*c0, *c1, *c2, *c3])),
        },
        other => Location::Other(other.to_vec()),
    }
}

/// A member's offset: `04 const4 07`, constant plus the aggregate's base.
fn member_offset(block: &[u8]) -> Option<u32> {
    match block {
        [OP_CONST, c0, c1, c2, c3, OP_ADD] => Some(u32::from_le_bytes([*c0, *c1, *c2, *c3])),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Member {
    pub name: String,
    pub ty: TypeRef,
    /// Byte offset in the aggregate.
    pub offset: Option<u32>,
    pub bit_offset: Option<u16>,
    pub bit_size: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Aggregate {
    pub name: Option<String>,
    pub size: Option<u32>,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Enumerator {
    pub name: String,
    pub value: i32,
}

/// One array dimension. A bound the stream states as a location expression
/// rather than a constant is `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Dimension {
    pub index: TypeRef,
    pub low: Option<i64>,
    pub high: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TypeDie {
    Structure(Aggregate),
    Union(Aggregate),
    Enumeration { name: Option<String>, size: Option<u32>, enumerators: Vec<Enumerator> },
    Array { element: TypeRef, dimensions: Vec<Dimension> },
    Typedef { name: String, target: TypeRef },
    Pointer { target: TypeRef, reference: bool },
    Subroutine { returns: TypeRef, parameters: Vec<TypeRef>, variadic: bool },
}

/// Every type DIE in the stream, by section offset.
#[derive(Debug, Default)]
pub(crate) struct TypeGraph {
    pub types: BTreeMap<u32, TypeDie>,
}

const RESOLVE_DEPTH: usize = 32;

impl TypeGraph {
    pub(crate) fn resolve(&self, ty: &TypeRef) -> Resolved {
        self.resolve_at(ty, 0)
    }

    fn resolve_at(&self, ty: &TypeRef, depth: usize) -> Resolved {
        if depth > RESOLVE_DEPTH {
            return Resolved::Unknown;
        }
        match ty {
            TypeRef::Absent => Resolved::Unknown,
            TypeRef::Fundamental(ft) => fundamental(*ft),
            TypeRef::Modified { modifiers, base } => {
                let skip = modifiers
                    .iter()
                    .take_while(|m| matches!(**m, MOD_CONST | MOD_VOLATILE))
                    .count();
                match modifiers.get(skip) {
                    None => self.resolve_at(base, depth + 1),
                    Some(&(MOD_POINTER_TO | MOD_REFERENCE_TO)) => {
                        let rest = &modifiers[skip + 1..];
                        Resolved::Pointer(if rest.is_empty() {
                            (**base).clone()
                        } else {
                            TypeRef::Modified { modifiers: rest.to_vec(), base: base.clone() }
                        })
                    }
                    Some(_) => Resolved::Unknown,
                }
            }
            TypeRef::Die(offset) => match self.types.get(offset) {
                None => Resolved::Unknown,
                Some(TypeDie::Structure(_) | TypeDie::Union(_) | TypeDie::Array { .. }) => {
                    Resolved::Aggregate
                }
                Some(TypeDie::Enumeration { size, .. }) => match size {
                    Some(size) if *size > 0 => Resolved::Int { signed: true, bits: size * 8 },
                    _ => Resolved::Unknown,
                },
                Some(TypeDie::Typedef { target, .. }) => self.resolve_at(target, depth + 1),
                Some(TypeDie::Pointer { target, .. }) => Resolved::Pointer(target.clone()),
                Some(TypeDie::Subroutine { .. }) => Resolved::Subroutine,
            },
        }
    }

    /// The scoring class of a type.
    pub(crate) fn class_name(&self, ty: &TypeRef) -> String {
        self.resolve(ty).class_name(self)
    }

    /// The C spelling the decompiler's parser accepts for a value of this
    /// type, or `None` when it has none (aggregates by value, unknown
    /// kinds). Pointers whose target has no such spelling are `void *`;
    /// pointers to code are `code *`.
    pub(crate) fn c_type(&self, ty: &TypeRef) -> Option<String> {
        self.c_type_at(ty, 0)
    }

    fn c_type_at(&self, ty: &TypeRef, depth: usize) -> Option<String> {
        if depth > RESOLVE_DEPTH {
            return None;
        }
        Some(match self.resolve(ty) {
            Resolved::Void => "void".into(),
            Resolved::Int { signed, bits } => match (signed, bits) {
                (true, 8) => "char",
                (false, 8) => "byte",
                (true, 16) => "short",
                (false, 16) => "ushort",
                (true, 32) => "int",
                (false, 32) => "uint",
                (true, 64) => "longlong",
                (false, 64) => "ulonglong",
                _ => return None,
            }
            .into(),
            Resolved::Float(32) => "float".into(),
            Resolved::Float(64) => "double".into(),
            Resolved::Float(_) => return None,
            Resolved::Bool => "bool".into(),
            Resolved::Pointer(target) => match self.resolve(&target) {
                Resolved::Subroutine => "code *".into(),
                Resolved::Aggregate | Resolved::Opaque(_) | Resolved::Unknown => "void *".into(),
                _ => format!("{} *", self.c_type_at(&target, depth + 1)?),
            },
            Resolved::Subroutine | Resolved::Aggregate | Resolved::Opaque(_) | Resolved::Unknown => {
                return None;
            }
        })
    }
}

impl TypeGraph {
    /// Bytes a value of this type occupies on the 32-bit Metrowerks MIPS
    /// target, or `None` when the stream does not say (a function type, an
    /// unknown reference, an array with a non-constant bound).
    pub(crate) fn size_of(&self, ty: &TypeRef) -> Option<u64> {
        self.size_at(ty, 0)
    }

    fn size_at(&self, ty: &TypeRef, depth: usize) -> Option<u64> {
        if depth > RESOLVE_DEPTH {
            return None;
        }
        match ty {
            TypeRef::Absent => None,
            TypeRef::Fundamental(ft) => match fundamental(*ft) {
                Resolved::Int { bits, .. } | Resolved::Float(bits) | Resolved::Opaque(bits) => {
                    Some(u64::from(bits / 8))
                }
                Resolved::Bool => Some(1),
                Resolved::Pointer(_) => Some(POINTER_BYTES),
                Resolved::Void => Some(0),
                _ => None,
            },
            TypeRef::Modified { modifiers, base } => {
                let skip = modifiers
                    .iter()
                    .take_while(|m| matches!(**m, MOD_CONST | MOD_VOLATILE))
                    .count();
                match modifiers.get(skip) {
                    None => self.size_at(base, depth + 1),
                    Some(&(MOD_POINTER_TO | MOD_REFERENCE_TO)) => Some(POINTER_BYTES),
                    Some(_) => None,
                }
            }
            TypeRef::Die(offset) => match self.types.get(offset)? {
                TypeDie::Structure(a) | TypeDie::Union(a) => a.size.map(u64::from),
                TypeDie::Enumeration { size, .. } => size.map(u64::from),
                TypeDie::Typedef { target, .. } => self.size_at(target, depth + 1),
                TypeDie::Pointer { .. } => Some(POINTER_BYTES),
                TypeDie::Array { element, dimensions } => {
                    let mut total = self.size_at(element, depth + 1)?;
                    for d in dimensions {
                        let count = d.high?.checked_sub(d.low?)?.checked_add(1)?;
                        total = total.checked_mul(u64::try_from(count).ok()?)?;
                    }
                    Some(total)
                }
                TypeDie::Subroutine { .. } => None,
            },
        }
    }
}

/// An `FT_*` code. Widths that depend on the toolchain follow `LONG_BYTES`.
fn fundamental(ft: u16) -> Resolved {
    let long_bits = LONG_BYTES * 8;
    match ft {
        0x01 | 0x02 => Resolved::Int { signed: true, bits: 8 },
        0x03 => Resolved::Int { signed: false, bits: 8 },
        0x04 | 0x05 => Resolved::Int { signed: true, bits: 16 },
        0x06 => Resolved::Int { signed: false, bits: 16 },
        0x07 | 0x08 => Resolved::Int { signed: true, bits: 32 },
        0x09 => Resolved::Int { signed: false, bits: 32 },
        0x0a | 0x0b => Resolved::Int { signed: true, bits: long_bits },
        0x0c => Resolved::Int { signed: false, bits: long_bits },
        0x0d => Resolved::Pointer(TypeRef::Fundamental(0x14)),
        0x0e => Resolved::Float(32),
        0x0f => Resolved::Float(64),
        0x14 => Resolved::Void,
        0x15 => Resolved::Bool,
        0xa510 => Resolved::Opaque(128),
        _ => Resolved::Unknown,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Variable {
    pub name: String,
    pub ty: TypeRef,
    pub location: Option<Location>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Subprogram {
    pub entry: u64,
    pub high_pc: Option<u64>,
    /// Empty when the DIE carries no name.
    pub name: String,
    /// `TAG_global_subroutine`: externally visible.
    pub external: bool,
    pub returns: TypeRef,
    pub parameters: Vec<Variable>,
    /// Locals of the function and of every lexical block inside it.
    pub locals: Vec<Variable>,
    /// A `TAG_unspecified_parameters` child ends the parameter list.
    pub variadic: bool,
}

/// The recovered debug stream.
#[derive(Debug, Default)]
pub(crate) struct Dwarf1 {
    pub types: TypeGraph,
    pub subprograms: Vec<Subprogram>,
}

/// A prototype in the C spelling the decompiler's parser takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugPrototype {
    pub entry: u64,
    pub name: String,
    pub return_type: String,
    /// `(name, C type)`; the name is empty when the DIE has none.
    pub parameters: Vec<(String, String)>,
    pub variadic: bool,
}

fn string(value: Value<'_>) -> Option<String> {
    match value {
        Value::Str(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        _ => None,
    }
}

impl Dwarf1 {
    /// Parses a stream. Anything after a malformed record is dropped; what
    /// came before is kept.
    pub(crate) fn parse(blob: &[u8]) -> Dwarf1 {
        let dies = read_dies(blob);
        let mut types = TypeGraph::default();
        for (index, die) in dies.iter().enumerate() {
            if let Some(ty) = type_die(&dies, index, die) {
                types.types.insert(die.offset, ty);
            }
        }
        let mut subprograms = Vec::new();
        for (index, die) in dies.iter().enumerate() {
            if matches!(
                die.tag,
                TAG_GLOBAL_SUBROUTINE | TAG_SUBROUTINE | TAG_INLINED_SUBROUTINE
            )
                && let Some(subprogram) = subprogram(&dies, index, die) {
                    subprograms.push(subprogram);
                }
        }
        Dwarf1 { types, subprograms }
    }

    /// The functions the stream declares, sized by `high_pc - low_pc`.
    pub(crate) fn functions(&self) -> Vec<NativeFunction> {
        self.subprograms
            .iter()
            .map(|s| NativeFunction {
                entry: s.entry,
                name: if s.name.is_empty() {
                    format!("FUN_{:08x}", s.entry)
                } else {
                    s.name.clone()
                },
                size: s.high_pc.and_then(|high| high.checked_sub(s.entry)).unwrap_or(0),
            })
            .collect()
    }

    /// Per function: return class and parameter classes, in the vocabulary
    /// the research harness scores (`benchmarks/dwarf_types.py`).
    pub(crate) fn classes(&self, subprogram: &Subprogram) -> (String, Vec<String>) {
        let returns = self.types.class_name(&subprogram.returns);
        let parameters = subprogram
            .parameters
            .iter()
            .map(|p| self.types.class_name(&p.ty))
            .collect();
        (returns, parameters)
    }

    /// The prototype of one subprogram, or `None` when any type in it has
    /// no C spelling (a struct by value, a 128-bit value).
    pub(crate) fn prototype(&self, subprogram: &Subprogram) -> Option<DebugPrototype> {
        let return_type = self.types.c_type(&subprogram.returns)?;
        let parameters = subprogram
            .parameters
            .iter()
            .map(|p| Some((p.name.clone(), self.types.c_type(&p.ty)?)))
            .collect::<Option<Vec<_>>>()?;
        Some(DebugPrototype {
            entry: subprogram.entry,
            name: subprogram.name.clone(),
            return_type,
            parameters,
            variadic: subprogram.variadic,
        })
    }

    /// Prototypes for every subprogram that has one, in stream order.
    pub(crate) fn prototypes(&self) -> Vec<DebugPrototype> {
        self.subprograms.iter().filter_map(|s| self.prototype(s)).collect()
    }
}

/// A local the stream puts on the stack, placed relative to the stack
/// pointer at function entry (negative: below it), as Ghidra's stack
/// space counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugLocal {
    pub entry: u64,
    pub name: String,
    /// The C spelling of its type when it has one.
    pub c_type: Option<String>,
    pub size: u64,
    pub offset: i64,
}

impl Dwarf1 {
    /// The scalar locals of one subprogram that live on the stack, given
    /// how far its prologue moves the stack pointer. DWARF 1 states a
    /// stack local's address as `sp + c` after the prologue, so its
    /// entry-relative offset is `c - frame`. A local that would sit at or
    /// above the entry stack pointer (the outgoing-argument area, or a
    /// parameter's home) is not a local.
    pub(crate) fn stack_locals(&self, subprogram: &Subprogram, frame: u64) -> Vec<DebugLocal> {
        let frame = i64::try_from(frame).unwrap_or(i64::MAX);
        subprogram
            .locals
            .iter()
            .filter_map(|local| {
                let Some(Location::Based { register: MIPS_SP, offset }) = local.location else {
                    return None;
                };
                let size = self.types.size_of(&local.ty).filter(|size| (1..=8).contains(size))?;
                let entry_relative = offset.checked_sub(frame)?;
                if entry_relative >= 0 || entry_relative + i64::try_from(size).ok()? > 0 {
                    return None;
                }
                Some(DebugLocal {
                    entry: subprogram.entry,
                    name: local.name.clone(),
                    c_type: self.types.c_type(&local.ty),
                    size,
                    offset: entry_relative,
                })
            })
            .collect()
    }
}

/// Reads every DIE and nests them by sibling offsets.
fn read_dies(blob: &[u8]) -> Vec<Die<'_>> {
    let mut dies: Vec<Die<'_>> = Vec::new();
    // (die index, offset where its children end)
    let mut open: Vec<(usize, u32)> = Vec::new();
    let mut off = 0usize;
    while let Some(length) = le32(blob, off).map(|n| n as usize) {
        let here = off as u32;
        while let Some(&(index, end)) = open.last() {
            if end > here {
                break;
            }
            dies[index].subtree_end = dies.len();
            open.pop();
        }
        if length < 6 {
            // A null entry closes the innermost child list.
            if let Some((index, _)) = open.pop() {
                dies[index].subtree_end = dies.len();
            }
            off += length.max(4);
            continue;
        }
        let Some(end) = off.checked_add(length).filter(|end| *end <= blob.len()) else {
            break;
        };
        let Some(tag) = le16(blob, off + 4) else { break };
        let body = &blob[off + 6..end];
        let index = dies.len();
        dies.push(Die { offset: here, tag, body, subtree_end: index + 1 });
        let sibling = attributes(body).find_map(|(a, v)| match (a, v) {
            (AT_SIBLING, Value::Ref(r)) => Some(r),
            _ => None,
        });
        if let Some(sibling) = sibling.filter(|s| *s as usize > end) {
            open.push((index, sibling));
        }
        off = end;
    }
    for (index, _) in open {
        dies[index].subtree_end = dies.len();
    }
    dies
}

fn children<'d>(dies: &'d [Die<'_>], index: usize) -> impl Iterator<Item = usize> + 'd {
    let end = dies[index].subtree_end;
    let mut next = index + 1;
    std::iter::from_fn(move || {
        if next >= end {
            return None;
        }
        let this = next;
        next = dies[this].subtree_end.max(this + 1);
        Some(this)
    })
}

fn attr<'a>(die: &Die<'a>, code: u16) -> Option<Value<'a>> {
    attributes(die.body).find(|(a, _)| *a == code).map(|(_, v)| v)
}

fn name_of(die: &Die<'_>) -> Option<String> {
    attr(die, AT_NAME).and_then(string)
}

/// The type an attribute set states, in whichever of the four forms.
fn type_of(die: &Die<'_>) -> TypeRef {
    for (attribute, value) in attributes(die.body) {
        match (attribute, value) {
            (AT_FUND_TYPE, Value::Data(ft)) => return TypeRef::Fundamental(ft as u16),
            (AT_USER_DEF_TYPE, Value::Ref(r)) => return TypeRef::Die(r),
            (AT_MOD_FUND_TYPE, Value::Block(block)) if block.len() >= 2 => {
                let (mods, ft) = block.split_at(block.len() - 2);
                return modified(mods, TypeRef::Fundamental(le16(ft, 0).unwrap_or(0)));
            }
            (AT_MOD_U_D_TYPE, Value::Block(block)) if block.len() >= 4 => {
                let (mods, r) = block.split_at(block.len() - 4);
                return modified(mods, TypeRef::Die(le32(r, 0).unwrap_or(0)));
            }
            _ => {}
        }
    }
    TypeRef::Absent
}

fn modified(modifiers: &[u8], base: TypeRef) -> TypeRef {
    if modifiers.is_empty() {
        base
    } else {
        TypeRef::Modified { modifiers: modifiers.to_vec(), base: Box::new(base) }
    }
}

fn aggregate(dies: &[Die<'_>], index: usize, die: &Die<'_>) -> Aggregate {
    let members = children(dies, index)
        .filter(|c| dies[*c].tag == TAG_MEMBER)
        .map(|c| {
            let member = &dies[c];
            Member {
                name: name_of(member).unwrap_or_default(),
                ty: type_of(member),
                offset: match attr(member, AT_LOCATION) {
                    Some(Value::Block(block)) => member_offset(block),
                    _ => None,
                },
                bit_offset: attr(member, AT_BIT_OFFSET).and_then(Value::number).map(|v| v as u16),
                bit_size: attr(member, AT_BIT_SIZE).and_then(Value::number).map(|v| v as u32),
            }
        })
        .collect();
    Aggregate {
        name: name_of(die),
        size: attr(die, AT_BYTE_SIZE).and_then(Value::number).map(|v| v as u32),
        members,
    }
}

fn type_die(dies: &[Die<'_>], index: usize, die: &Die<'_>) -> Option<TypeDie> {
    Some(match die.tag {
        TAG_STRUCTURE | TAG_CLASS => TypeDie::Structure(aggregate(dies, index, die)),
        TAG_UNION => TypeDie::Union(aggregate(dies, index, die)),
        TAG_ENUMERATION => TypeDie::Enumeration {
            name: name_of(die),
            size: attr(die, AT_BYTE_SIZE).and_then(Value::number).map(|v| v as u32),
            enumerators: match attr(die, AT_ELEMENT_LIST) {
                Some(Value::Block(block)) => enumerators(block),
                _ => Vec::new(),
            },
        },
        TAG_ARRAY => {
            let (element, dimensions) = match attr(die, AT_SUBSCR_DATA) {
                Some(Value::Block(block)) => subscripts(block),
                _ => (TypeRef::Absent, Vec::new()),
            };
            TypeDie::Array { element, dimensions }
        }
        TAG_TYPEDEF => TypeDie::Typedef {
            name: name_of(die).unwrap_or_default(),
            target: type_of(die),
        },
        TAG_POINTER | TAG_REFERENCE => TypeDie::Pointer {
            target: type_of(die),
            reference: die.tag == TAG_REFERENCE,
        },
        TAG_SUBROUTINE_TYPE => {
            let mut parameters = Vec::new();
            let mut variadic = false;
            for c in children(dies, index) {
                match dies[c].tag {
                    TAG_FORMAL_PARAMETER => parameters.push(type_of(&dies[c])),
                    TAG_UNSPECIFIED_PARAMETERS => variadic = true,
                    _ => {}
                }
            }
            TypeDie::Subroutine { returns: subroutine_return(die), parameters, variadic }
        }
        _ => return None,
    })
}

/// A function (or function type) with no type attribute returns `void`.
fn subroutine_return(die: &Die<'_>) -> TypeRef {
    match type_of(die) {
        TypeRef::Absent => TypeRef::Fundamental(0x14),
        ty => ty,
    }
}

/// `AT_element_list`: `(value:i32, name\0)` pairs.
fn enumerators(block: &[u8]) -> Vec<Enumerator> {
    let mut out = Vec::new();
    let mut p = 0;
    while let Some(value) = le32(block, p) {
        let Some(rest) = block.get(p + 4..) else { break };
        let Some(nul) = rest.iter().position(|c| *c == 0) else { break };
        out.push(Enumerator {
            name: String::from_utf8_lossy(&rest[..nul]).into_owned(),
            value: value as i32,
        });
        p += 4 + nul + 1;
    }
    out
}

/// A type attribute embedded in a subscript block (`FMT_ET`): its own
/// attribute code, then a value of that form. Returns the type and the
/// bytes consumed.
fn embedded_type(block: &[u8]) -> Option<(TypeRef, usize)> {
    let code = le16(block, 0)?;
    let rest = block.get(2..)?;
    match (code >> 4, code & 0xf) {
        (AT_FUND_TYPE, FORM_DATA2) => Some((TypeRef::Fundamental(le16(rest, 0)?), 4)),
        (AT_USER_DEF_TYPE, FORM_REF) => Some((TypeRef::Die(le32(rest, 0)?), 6)),
        (AT_MOD_FUND_TYPE, FORM_BLOCK2) => {
            let n = usize::from(le16(rest, 0)?);
            let body = rest.get(2..2 + n)?;
            if n < 2 {
                return None;
            }
            let (mods, ft) = body.split_at(n - 2);
            Some((modified(mods, TypeRef::Fundamental(le16(ft, 0)?)), 4 + n))
        }
        (AT_MOD_U_D_TYPE, FORM_BLOCK2) => {
            let n = usize::from(le16(rest, 0)?);
            let body = rest.get(2..2 + n)?;
            if n < 4 {
                return None;
            }
            let (mods, r) = body.split_at(n - 4);
            Some((modified(mods, TypeRef::Die(le32(r, 0)?)), 4 + n))
        }
        _ => None,
    }
}

/// `AT_subscr_data`: a run of dimension descriptors closed by an element
/// type (`FMT_ET`, 0x08). Descriptor formats `FMT_FT_*` (index type is a
/// fundamental type) and `FMT_UT_*` (a ref) each carry a low and a high
/// bound that is either a 4-byte constant (`C`) or a length-prefixed
/// location expression (`X`).
fn subscripts(block: &[u8]) -> (TypeRef, Vec<Dimension>) {
    let mut dimensions = Vec::new();
    let mut p = 0usize;
    let mut element = TypeRef::Absent;
    while let Some(&format) = block.get(p) {
        p += 1;
        if format == 0x08 {
            if let Some((ty, _)) = block.get(p..).and_then(embedded_type) {
                element = ty;
            }
            break;
        }
        if format > 0x07 {
            break;
        }
        let user_defined = format >= 4;
        let index = if user_defined {
            let Some(r) = le32(block, p) else { break };
            p += 4;
            TypeRef::Die(r)
        } else {
            let Some(ft) = le16(block, p) else { break };
            p += 2;
            TypeRef::Fundamental(ft)
        };
        let mut bounds = [None, None];
        let mut ok = true;
        // Formats 0..3 / 4..7 differ only in the index type; within each,
        // bit 1 makes the low bound an expression and bit 0 the high one.
        let low_is_expression = matches!(format & 3, 2 | 3);
        let high_is_expression = matches!(format & 3, 1 | 3);
        for (slot, expression) in bounds.iter_mut().zip([low_is_expression, high_is_expression]) {
            if expression {
                let Some(n) = le16(block, p).map(usize::from) else {
                    ok = false;
                    break;
                };
                p += 2 + n;
            } else {
                let Some(v) = le32(block, p) else {
                    ok = false;
                    break;
                };
                p += 4;
                *slot = Some(i64::from(v as i32));
            }
        }
        if !ok {
            break;
        }
        dimensions.push(Dimension { index, low: bounds[0], high: bounds[1] });
    }
    (element, dimensions)
}

fn variable(die: &Die<'_>) -> Variable {
    Variable {
        name: name_of(die).unwrap_or_default(),
        ty: type_of(die),
        location: match attr(die, AT_LOCATION) {
            Some(Value::Block(block)) => Some(decode_location(block)),
            _ => None,
        },
    }
}

/// Collects local variables below a function, through lexical blocks.
fn collect_locals(dies: &[Die<'_>], index: usize, out: &mut Vec<Variable>) {
    for c in children(dies, index) {
        match dies[c].tag {
            TAG_LOCAL_VARIABLE => out.push(variable(&dies[c])),
            TAG_LEXICAL_BLOCK => collect_locals(dies, c, out),
            _ => {}
        }
    }
}

fn subprogram(dies: &[Die<'_>], index: usize, die: &Die<'_>) -> Option<Subprogram> {
    let entry = attr(die, AT_LOW_PC).and_then(Value::number)?;
    if entry == 0 {
        return None;
    }
    let mut parameters = Vec::new();
    let mut variadic = false;
    for c in children(dies, index) {
        match dies[c].tag {
            TAG_FORMAL_PARAMETER => parameters.push(variable(&dies[c])),
            TAG_UNSPECIFIED_PARAMETERS => variadic = true,
            _ => {}
        }
    }
    let mut locals = Vec::new();
    collect_locals(dies, index, &mut locals);
    Some(Subprogram {
        entry,
        high_pc: attr(die, AT_HIGH_PC).and_then(Value::number),
        name: name_of(die).unwrap_or_default(),
        external: die.tag == TAG_GLOBAL_SUBROUTINE,
        returns: subroutine_return(die),
        parameters,
        locals,
        variadic,
    })
}

/// Type names the decompiler's languages declare. A struct that took one would
/// shadow it for every function that uses the primitive.
const RESERVED_TYPE_NAMES: &[&str] = &[
    "void", "bool", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "byte",
    "sbyte", "ushort", "uint", "ulong", "longlong", "ulonglong", "longdouble", "code", "wchar_t",
    "wchar16", "wchar32", "pointer", "struct", "union", "enum", "const", "volatile", "sizeof",
    "typedef", "static", "extern", "register", "auto", "return", "if", "else", "for", "while", "do",
    "switch", "case", "default", "break", "continue", "goto", "inline",
];

/// The struct layouts a stream states, and the name each exported struct DIE
/// answers to (the name its prototypes spell).
#[derive(Debug, Default)]
pub(crate) struct DebugStructs {
    pub layouts: Vec<StructLayout>,
    pub names: BTreeMap<u32, String>,
}

fn c_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    matches!(bytes.next(), Some(b'_' | b'a'..=b'z' | b'A'..=b'Z'))
        && bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
}

/// `T *`, with the second star of `T **` attached to the first.
fn pointer_to(inner: &str) -> String {
    if inner.ends_with('*') {
        format!("{inner}*")
    } else {
        format!("{inner} *")
    }
}

/// The core type of a value of `size` bytes whose kind the stream does not
/// state: what a field of no known type is.
fn opaque_spelling(size: u64) -> String {
    match size {
        1 | 2 | 4 | 8 => format!("undefined{size}"),
        _ => format!("byte[{size}]"),
    }
}

impl TypeGraph {
    /// The struct DIE a type reaches through typedefs and qualifiers.
    fn struct_die(&self, ty: &TypeRef, depth: usize) -> Option<u32> {
        if depth > RESOLVE_DEPTH {
            return None;
        }
        match ty {
            TypeRef::Die(offset) => match self.types.get(offset)? {
                TypeDie::Structure(_) => Some(*offset),
                TypeDie::Typedef { target, .. } => self.struct_die(target, depth + 1),
                _ => None,
            },
            TypeRef::Modified { modifiers, base }
                if modifiers.iter().all(|m| matches!(*m, MOD_CONST | MOD_VOLATILE)) =>
            {
                self.struct_die(base, depth + 1)
            }
            _ => None,
        }
    }

    /// [`c_type`](Self::c_type), naming the structs `names` exports instead
    /// of erasing a pointer to one to `void *`.
    pub(crate) fn c_type_named(&self, ty: &TypeRef, names: &BTreeMap<u32, String>) -> Option<String> {
        self.c_type_named_at(ty, names, 0)
    }

    fn c_type_named_at(&self, ty: &TypeRef, names: &BTreeMap<u32, String>, depth: usize) -> Option<String> {
        if depth > RESOLVE_DEPTH {
            return None;
        }
        if let Resolved::Pointer(target) = self.resolve(ty) {
            return Some(match self.resolve(&target) {
                Resolved::Subroutine => "code *".into(),
                Resolved::Aggregate => match self.struct_die(&target, 0).and_then(|die| names.get(&die)) {
                    Some(name) => format!("{name} *"),
                    None => "void *".into(),
                },
                Resolved::Opaque(_) | Resolved::Unknown => "void *".into(),
                _ => format!("{} *", self.c_type_named_at(&target, names, depth + 1)?),
            });
        }
        self.c_type_at(ty, depth)
    }

    /// The `type_ref` spelling of a member's type, or `None` when the stream
    /// gives it no spelling a field can carry (a union, a function, an
    /// unbounded array).
    fn field_spelling(&self, ty: &TypeRef, names: &BTreeMap<u32, String>, depth: usize) -> Option<String> {
        if depth > RESOLVE_DEPTH {
            return None;
        }
        let scalar = |resolved: Resolved| -> Option<String> {
            Some(
                match resolved {
                    Resolved::Int { signed: true, bits: 8 } => "char",
                    Resolved::Int { signed: false, bits: 8 } => "byte",
                    Resolved::Int { signed: true, bits: 16 } => "short",
                    Resolved::Int { signed: false, bits: 16 } => "ushort",
                    Resolved::Int { signed: true, bits: 32 } => "int",
                    Resolved::Int { signed: false, bits: 32 } => "uint",
                    Resolved::Int { signed: true, bits: 64 } => "longlong",
                    Resolved::Int { signed: false, bits: 64 } => "ulonglong",
                    Resolved::Float(32) => "float",
                    Resolved::Float(64) => "double",
                    Resolved::Bool => "bool",
                    _ => return None,
                }
                .into(),
            )
        };
        match self.resolve(ty) {
            Resolved::Pointer(_) => self.c_type_named(ty, names),
            Resolved::Opaque(bits) => Some(opaque_spelling(u64::from(bits / 8))),
            Resolved::Aggregate => {
                if let Some(die) = self.struct_die(ty, 0) {
                    return names.get(&die).cloned();
                }
                // An array of something the member spells, or a union.
                let mut ty = ty;
                let mut hops = 0;
                loop {
                    hops += 1;
                    match ty {
                        TypeRef::Die(offset) => match self.types.get(offset)? {
                            TypeDie::Typedef { target, .. } => ty = target,
                            TypeDie::Array { element, dimensions } => {
                                let mut text = self.field_spelling(element, names, depth + 1)?;
                                for dimension in dimensions {
                                    let count = dimension.high?.checked_sub(dimension.low?)?.checked_add(1)?;
                                    if count <= 0 {
                                        return None;
                                    }
                                    text.push_str(&format!("[{count}]"));
                                }
                                return Some(text);
                            }
                            _ => return None,
                        },
                        TypeRef::Modified { modifiers, base }
                            if modifiers.iter().all(|m| matches!(*m, MOD_CONST | MOD_VOLATILE)) =>
                        {
                            ty = base
                        }
                        _ => return None,
                    }
                    if hops > RESOLVE_DEPTH {
                        return None;
                    }
                }
            }
            other => scalar(other),
        }
    }
}

impl Dwarf1 {
    /// The struct layouts this stream states. `taken` are names a struct must
    /// not take (the program's functions).
    ///
    /// A struct is exported when it is complete, its name is a C identifier
    /// no primitive or function holds, and it has a member the stream
    /// places. Compile units repeat a type's DIE; identical layouts under one
    /// name are one struct, and a name two units use for different layouts
    /// names the first and `Name_2`, `Name_3`... the others, so each
    /// parameter keeps the layout its own unit declared. A forward
    /// declaration answers to the name's first layout.
    pub(crate) fn structs(&self, taken: &std::collections::BTreeSet<&str>) -> DebugStructs {
        let types = &self.types;
        // The name a struct DIE is known by: its tag, else the typedef that
        // names it.
        let mut alias: BTreeMap<u32, &str> = BTreeMap::new();
        for ty in types.types.values() {
            if let TypeDie::Typedef { name, target: TypeRef::Die(target) } = ty {
                alias.entry(*target).or_insert(name.as_str());
            }
        }
        let mut tag: BTreeMap<u32, String> = BTreeMap::new();
        for (offset, ty) in &types.types {
            let TypeDie::Structure(aggregate) = ty else { continue };
            let name = aggregate.name.as_deref().or_else(|| alias.get(offset).copied());
            if let Some(name) = name.filter(|name| {
                c_identifier(name)
                    && !RESERVED_TYPE_NAMES.contains(name)
                    && !name.starts_with("undefined")
                    && !taken.contains(name)
            }) {
                tag.insert(*offset, name.to_string());
            }
        }
        // What a member's type spells, in tag names only: two DIEs are one
        // layout when these agree.
        let key_names: BTreeMap<u32, String> = tag.clone();
        let complete = |offset: u32| -> Option<&Aggregate> {
            match types.types.get(&offset)? {
                TypeDie::Structure(a) if a.size.is_some_and(|size| size > 0) && !a.members.is_empty() => Some(a),
                _ => None,
            }
        };
        let key_of = |a: &Aggregate| -> String {
            let mut key = format!("{}", a.size.unwrap_or(0));
            for member in &a.members {
                let spelling = types
                    .field_spelling(&member.ty, &key_names, 0)
                    .unwrap_or_else(|| "?".into());
                key.push_str(&format!(
                    "|{}:{}:{}:{}",
                    member.offset.map_or(-1, i64::from),
                    member.name,
                    spelling,
                    member.bit_size.unwrap_or(0)
                ));
            }
            key
        };
        // name -> variants in first-seen order: (layout key, representative).
        let mut variants: BTreeMap<String, Vec<(String, u32)>> = BTreeMap::new();
        let mut variant_of: BTreeMap<u32, (String, usize)> = BTreeMap::new();
        for (offset, name) in &tag {
            let Some(aggregate) = complete(*offset) else { continue };
            let key = key_of(aggregate);
            let list = variants.entry(name.clone()).or_default();
            let index = match list.iter().position(|(existing, _)| *existing == key) {
                Some(index) => index,
                None => {
                    list.push((key, *offset));
                    list.len() - 1
                }
            };
            variant_of.insert(*offset, (name.clone(), index));
        }
        // Final names: the first variant keeps the tag.
        let mut final_name: BTreeMap<(String, usize), String> = BTreeMap::new();
        let mut used: std::collections::BTreeSet<String> = variants.keys().cloned().collect();
        for (name, list) in &variants {
            for index in 0..list.len() {
                let chosen = if index == 0 {
                    name.clone()
                } else {
                    let mut serial = index + 1;
                    loop {
                        let candidate = format!("{name}_{serial}");
                        if !used.contains(&candidate) && !taken.contains(candidate.as_str()) {
                            used.insert(candidate.clone());
                            break candidate;
                        }
                        serial += 1;
                    }
                };
                final_name.insert((name.clone(), index), chosen);
            }
        }
        let mut names: BTreeMap<u32, String> = BTreeMap::new();
        for (offset, (name, index)) in &variant_of {
            names.insert(*offset, final_name[&(name.clone(), *index)].clone());
        }
        // A forward declaration answers to the tag's first layout.
        for (offset, name) in &tag {
            if !names.contains_key(offset)
                && let Some(first) = final_name.get(&(name.clone(), 0))
            {
                names.insert(*offset, first.clone());
            }
        }
        let mut layouts = Vec::new();
        for (name, list) in &variants {
            for (index, (_, offset)) in list.iter().enumerate() {
                let Some(aggregate) = complete(*offset) else { continue };
                let mut fields: Vec<StructField> = Vec::new();
                let mut taken_names: std::collections::BTreeSet<String> = Default::default();
                let mut members: Vec<&Member> = aggregate.members.iter().filter(|m| m.offset.is_some()).collect();
                members.sort_by_key(|member| member.offset);
                for member in members {
                    let at = u64::from(member.offset.unwrap_or(0));
                    // A bit-field's container is the member's own width; later
                    // bit-fields in it share the offset.
                    if fields.last().is_some_and(|last| last.offset == at) {
                        continue;
                    }
                    let Some(size) = types.size_of(&member.ty).filter(|size| *size > 0) else { continue };
                    let type_ref = types
                        .field_spelling(&member.ty, &names, 0)
                        .unwrap_or_else(|| opaque_spelling(size));
                    let mut field_name = if c_identifier(&member.name) {
                        member.name.clone()
                    } else {
                        format!("field_0x{at:x}")
                    };
                    if !taken_names.insert(field_name.clone()) {
                        field_name = format!("{field_name}_0x{at:x}");
                        taken_names.insert(field_name.clone());
                    }
                    fields.push(StructField { name: field_name, offset: at, size, type_ref });
                }
                if fields.is_empty() {
                    continue;
                }
                layouts.push(StructLayout {
                    name: final_name[&(name.clone(), index)].clone(),
                    size: u64::from(aggregate.size.unwrap_or(0)),
                    provenance: DEBUG_SOURCE.into(),
                    fields,
                });
            }
        }
        // A struct that kept no field is not exported, and neither is a name
        // that points at it.
        let exported: std::collections::BTreeSet<&str> = layouts.iter().map(|l| l.name.as_str()).collect();
        names.retain(|_, name| exported.contains(name.as_str()));
        DebugStructs { layouts, names }
    }

    /// The prototype of one subprogram with its struct pointers named.
    pub(crate) fn prototype_named(
        &self,
        subprogram: &Subprogram,
        names: &BTreeMap<u32, String>,
    ) -> Option<DebugPrototype> {
        let return_type = self.types.c_type_named(&subprogram.returns, names)?;
        let parameters = subprogram
            .parameters
            .iter()
            .map(|p| Some((p.name.clone(), self.types.c_type_named(&p.ty, names)?)))
            .collect::<Option<Vec<_>>>()?;
        Some(DebugPrototype {
            entry: subprogram.entry,
            name: subprogram.name.clone(),
            return_type,
            parameters,
            variadic: subprogram.variadic,
        })
    }

    /// Prototypes for every subprogram that has one, struct pointers named.
    pub(crate) fn prototypes_named(&self, names: &BTreeMap<u32, String>) -> Vec<DebugPrototype> {
        self.subprograms.iter().filter_map(|s| self.prototype_named(s, names)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a DWARF 1 stream with real sibling offsets, so nesting is
    /// the one the reader has to recover from them.
    #[derive(Default)]
    struct Stream {
        b: Vec<u8>,
    }

    fn name(text: &str) -> Vec<u8> {
        let mut v = 0x0038u16.to_le_bytes().to_vec();
        v.extend_from_slice(text.as_bytes());
        v.push(0);
        v
    }
    fn data2(code: u16, v: u16) -> Vec<u8> {
        [code.to_le_bytes().as_slice(), v.to_le_bytes().as_slice()].concat()
    }
    fn four(code: u16, v: u32) -> Vec<u8> {
        [code.to_le_bytes().as_slice(), v.to_le_bytes().as_slice()].concat()
    }
    fn block2(code: u16, bytes: &[u8]) -> Vec<u8> {
        [code.to_le_bytes().as_slice(), (bytes.len() as u16).to_le_bytes().as_slice(), bytes]
            .concat()
    }
    fn ft(v: u16) -> Vec<u8> {
        data2(0x0055, v)
    }
    fn mft(mods: &[u8], v: u16) -> Vec<u8> {
        block2(0x0063, &[mods, v.to_le_bytes().as_slice()].concat())
    }
    fn udt(offset: u32) -> Vec<u8> {
        four(0x0072, offset)
    }
    fn mudt(mods: &[u8], offset: u32) -> Vec<u8> {
        block2(0x0083, &[mods, offset.to_le_bytes().as_slice()].concat())
    }
    fn loc(bytes: &[u8]) -> Vec<u8> {
        block2(0x0023, bytes)
    }
    fn reg(r: u32) -> Vec<u8> {
        loc(&[&[OP_REG][..], &r.to_le_bytes()].concat())
    }
    fn member_at(offset: u32) -> Vec<u8> {
        loc(&[&[OP_CONST][..], &offset.to_le_bytes(), &[OP_ADD]].concat())
    }
    fn size(v: u32) -> Vec<u8> {
        four(0x00b6, v)
    }
    fn pc(low: u32, high: u32) -> Vec<u8> {
        [four(0x0111, low), four(0x0121, high)].concat()
    }

    impl Stream {
        fn open(&mut self, tag: u16, attrs: &[Vec<u8>]) -> usize {
            let at = self.b.len();
            let mut body = tag.to_le_bytes().to_vec();
            body.extend_from_slice(&four(0x0012, 0));
            for a in attrs {
                body.extend_from_slice(a);
            }
            self.b.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
            self.b.extend_from_slice(&body);
            at
        }
        /// A DIE with no children: its sibling is the next record.
        fn leaf(&mut self, tag: u16, attrs: &[Vec<u8>]) -> u32 {
            let at = self.open(tag, attrs);
            self.patch(at);
            at as u32
        }
        fn patch(&mut self, at: usize) {
            let next = self.b.len() as u32;
            self.b[at + 8..at + 12].copy_from_slice(&next.to_le_bytes());
        }
        /// Ends a DIE's child list: the null entry, then the sibling.
        fn close(&mut self, at: usize) -> u32 {
            self.b.extend_from_slice(&4u32.to_le_bytes());
            self.patch(at);
            at as u32
        }
    }

    const POINTER: &[u8] = &[MOD_POINTER_TO];

    /// One compile unit holding a struct, an enum, a union, an array, a
    /// typedef, a function type, and four functions that use them.
    fn stream() -> (Vec<u8>, BTreeMap<&'static str, u32>) {
        let mut s = Stream::default();
        let mut at = BTreeMap::new();
        let unit = s.open(TAG_COMPILE_UNIT, &[name("unit.c")]);

        let record = s.open(TAG_STRUCTURE, &[size(12), name("Rec")]);
        s.leaf(TAG_MEMBER, &[ft(0x08), member_at(0), name("count")]);
        s.leaf(TAG_MEMBER, &[mft(POINTER, 0x01), member_at(4), name("text")]);
        s.leaf(
            TAG_MEMBER,
            &[ft(0x09), member_at(8), data2(0x00c5, 3), four(0x00d6, 5), name("flags")],
        );
        at.insert("Rec", s.close(record));

        let colour = s.leaf(
            TAG_ENUMERATION,
            &[
                size(4),
                name("Colour"),
                {
                    let mut v = 0x00f4u16.to_le_bytes().to_vec();
                    let body = [
                        &0i32.to_le_bytes()[..], b"RED\0", &7i32.to_le_bytes(), b"BLUE\0",
                    ]
                    .concat();
                    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
                    v.extend_from_slice(&body);
                    v
                },
            ],
        );
        at.insert("Colour", colour);

        let either = s.open(TAG_UNION, &[size(4), name("Either")]);
        s.leaf(TAG_MEMBER, &[ft(0x08), member_at(0), name("i")]);
        s.leaf(TAG_MEMBER, &[ft(0x0e), member_at(0), name("f")]);
        at.insert("Either", s.close(either));

        // int grid[3][4]: two FMT_FT_C_C descriptors, then FMT_ET.
        let subscripts = {
            let mut v = Vec::new();
            for high in [2u32, 3] {
                v.push(0x00);
                v.extend_from_slice(&0x0008u16.to_le_bytes());
                v.extend_from_slice(&0u32.to_le_bytes());
                v.extend_from_slice(&high.to_le_bytes());
            }
            v.push(0x08);
            v.extend_from_slice(&0x0055u16.to_le_bytes());
            v.extend_from_slice(&0x0008u16.to_le_bytes());
            v
        };
        at.insert("grid", s.leaf(TAG_ARRAY, &[block2(0x00a3, &subscripts)]));

        at.insert("Handle", s.leaf(TAG_TYPEDEF, &[mudt(POINTER, at["Rec"]), name("Handle")]));

        let callback = s.open(TAG_SUBROUTINE_TYPE, &[ft(0x14)]);
        s.leaf(TAG_FORMAL_PARAMETER, &[ft(0x08)]);
        at.insert("callback", s.close(callback));

        // unsigned long f1(char *p, Handle h, float x): register parameters.
        let f1 = s.open(
            TAG_GLOBAL_SUBROUTINE,
            &[pc(0x1000, 0x1040), ft(0x0c), name("f1")],
        );
        s.leaf(TAG_FORMAL_PARAMETER, &[mft(POINTER, 0x01), reg(16), name("p")]);
        s.leaf(TAG_FORMAL_PARAMETER, &[udt(at["Handle"]), reg(17), name("h")]);
        s.leaf(TAG_FORMAL_PARAMETER, &[ft(0x0e), reg(18), name("x")]);
        s.close(f1);

        // Rec f2(void): an aggregate by value has no C spelling.
        let f2 = s.open(TAG_SUBROUTINE, &[pc(0x1040, 0x1080), udt(at["Rec"]), name("f2")]);
        s.close(f2);

        // void f3(void (*cb)(int), enum Colour c, ...): a block with a
        // register local and a frame local, a static, and a varargs marker.
        let f3 = s.open(
            TAG_GLOBAL_SUBROUTINE,
            &[pc(0x1080, 0x1100), ft(0x14), name("f3")],
        );
        s.leaf(TAG_FORMAL_PARAMETER, &[mudt(POINTER, at["callback"]), reg(16), name("cb")]);
        s.leaf(
            TAG_FORMAL_PARAMETER,
            &[udt(at["Colour"]), loc(&[&[OP_BASEREG][..], &29u32.to_le_bytes(), &[OP_CONST], &0x20u32.to_le_bytes(), &[OP_ADD]].concat()), name("c")],
        );
        s.leaf(TAG_UNSPECIFIED_PARAMETERS, &[]);
        let block = s.open(TAG_LEXICAL_BLOCK, &[pc(0x1080, 0x1100)]);
        s.leaf(TAG_LOCAL_VARIABLE, &[ft(0x08), reg(2), name("tmp")]);
        s.leaf(
            TAG_LOCAL_VARIABLE,
            &[udt(at["grid"]), loc(&[&[OP_ADDR][..], &0x2b2920u32.to_le_bytes()].concat()), name("table")],
        );
        s.close(block);
        s.close(f3);

        // int f4(unsigned char a, Either u): a union by value; found only
        // to prove f3's children did not leak into the next sibling.
        let f4 = s.open(TAG_GLOBAL_SUBROUTINE, &[pc(0x1100, 0x1140), ft(0x08), name("f4")]);
        s.leaf(TAG_FORMAL_PARAMETER, &[ft(0x03), reg(16), name("a")]);
        s.leaf(TAG_FORMAL_PARAMETER, &[udt(at["Either"]), reg(17), name("u")]);
        s.close(f4);

        // short *f5(long long *wide, I128 v): a 128-bit value has no spelling.
        let f5 = s.open(TAG_GLOBAL_SUBROUTINE, &[pc(0x1140, 0x1180), mft(POINTER, 0x05), name("f5")]);
        s.leaf(TAG_FORMAL_PARAMETER, &[ft(0xa510), reg(16), name("v")]);
        s.close(f5);

        at.insert("end", s.close(unit));
        (s.b, at)
    }

    fn parsed() -> (Dwarf1, BTreeMap<&'static str, u32>) {
        let (blob, at) = stream();
        (Dwarf1::parse(&blob), at)
    }

    fn by_name<'a>(d: &'a Dwarf1, name: &str) -> &'a Subprogram {
        d.subprograms.iter().find(|s| s.name == name).unwrap()
    }

    #[test]
    fn a_struct_becomes_a_layout_and_the_pointers_to_it_name_it() {
        let (d, at) = parsed();
        let none = std::collections::BTreeSet::new();
        let structs = d.structs(&none);
        let rec = structs.layouts.iter().find(|l| l.name == "Rec").expect("Rec is exported");
        assert_eq!(rec.size, 12);
        assert_eq!(rec.provenance, DEBUG_SOURCE);
        let fields: Vec<_> = rec.fields.iter().map(|f| (f.name.as_str(), f.offset, f.size, f.type_ref.as_str())).collect();
        // The bit-field takes its container's width; `char *` keeps its pointee.
        assert_eq!(fields, [("count", 0, 4, "int"), ("text", 4, 4, "char *"), ("flags", 8, 4, "uint")]);
        assert_eq!(structs.names.get(&at["Rec"]).map(String::as_str), Some("Rec"));
        // A union is not a struct, an enum is not exported.
        assert!(structs.layouts.iter().all(|l| l.name != "Either" && l.name != "Colour"));
        // `Handle h` (a typedef of `Rec *`) is `Rec *`; `char *p` stays `char *`.
        let f1 = d.prototype_named(by_name(&d, "f1"), &structs.names).expect("f1 has a prototype");
        assert_eq!(f1.parameters[0].1, "char *");
        assert_eq!(f1.parameters[1].1, "Rec *");
        // Without the struct table the same prototype erases it.
        assert_eq!(d.prototype(by_name(&d, "f1")).unwrap().parameters[1].1, "void *");
        // A struct sharing a function's name is not exported: its pointers stay `void *`.
        let taken = std::collections::BTreeSet::from(["Rec"]);
        let renamed = d.structs(&taken);
        assert!(renamed.layouts.is_empty() && renamed.names.is_empty());
        assert_eq!(d.prototype_named(by_name(&d, "f1"), &renamed.names).unwrap().parameters[1].1, "void *");
    }

    #[test]
    fn structures_unions_and_bit_fields_keep_member_offsets() {
        let (d, at) = parsed();
        let TypeDie::Structure(record) = &d.types.types[&at["Rec"]] else { panic!() };
        assert_eq!(record.name.as_deref(), Some("Rec"));
        assert_eq!(record.size, Some(12));
        let members: Vec<_> = record
            .members
            .iter()
            .map(|m| (m.name.as_str(), m.offset, m.bit_offset, m.bit_size))
            .collect();
        assert_eq!(
            members,
            [
                ("count", Some(0), None, None),
                ("text", Some(4), None, None),
                ("flags", Some(8), Some(3), Some(5)),
            ]
        );
        assert_eq!(
            record.members[1].ty,
            TypeRef::Modified { modifiers: vec![1], base: Box::new(TypeRef::Fundamental(1)) }
        );
        let TypeDie::Union(either) = &d.types.types[&at["Either"]] else { panic!() };
        assert_eq!(either.members.iter().map(|m| m.offset).collect::<Vec<_>>(), [Some(0), Some(0)]);
    }

    #[test]
    fn enumerators_arrays_typedefs_and_function_types_decode() {
        let (d, at) = parsed();
        let TypeDie::Enumeration { name, size, enumerators } = &d.types.types[&at["Colour"]] else {
            panic!()
        };
        assert_eq!((name.as_deref(), *size), (Some("Colour"), Some(4)));
        assert_eq!(
            enumerators,
            &[
                Enumerator { name: "RED".into(), value: 0 },
                Enumerator { name: "BLUE".into(), value: 7 },
            ]
        );
        let TypeDie::Array { element, dimensions } = &d.types.types[&at["grid"]] else { panic!() };
        assert_eq!(*element, TypeRef::Fundamental(0x08));
        assert_eq!(
            dimensions.iter().map(|x| (x.low, x.high)).collect::<Vec<_>>(),
            [(Some(0), Some(2)), (Some(0), Some(3))]
        );
        let TypeDie::Typedef { name, target } = &d.types.types[&at["Handle"]] else { panic!() };
        assert_eq!(name, "Handle");
        assert_eq!(d.types.resolve(target), Resolved::Pointer(TypeRef::Die(at["Rec"])));
        let TypeDie::Subroutine { returns, parameters, variadic } = &d.types.types[&at["callback"]]
        else {
            panic!()
        };
        assert_eq!(*returns, TypeRef::Fundamental(0x14));
        assert_eq!(parameters, &[TypeRef::Fundamental(0x08)]);
        assert!(!variadic);
    }

    #[test]
    fn subprograms_nest_by_sibling_offsets() {
        let (d, _) = parsed();
        let names: Vec<_> = d.subprograms.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["f1", "f2", "f3", "f4", "f5"]);
        let arities: Vec<_> = d.subprograms.iter().map(|s| s.parameters.len()).collect();
        assert_eq!(arities, [3, 0, 2, 2, 1]);
        // f3's block locals belong to f3 alone.
        let locals = |n: &str| by_name(&d, n).locals.iter().map(|l| l.name.clone()).collect::<Vec<_>>();
        assert_eq!(locals("f3"), ["tmp", "table"]);
        assert!(locals("f1").is_empty() && locals("f4").is_empty());
        assert!(by_name(&d, "f1").external && !by_name(&d, "f2").external);
        assert_eq!(by_name(&d, "f1").high_pc, Some(0x1040));
    }

    #[test]
    fn locations_decode_registers_frame_offsets_and_statics() {
        let (d, _) = parsed();
        let f1 = by_name(&d, "f1");
        assert_eq!(f1.parameters[0].location, Some(Location::Register(16)));
        let f3 = by_name(&d, "f3");
        assert_eq!(
            f3.parameters[1].location,
            Some(Location::Based { register: 29, offset: 0x20 })
        );
        assert_eq!(f3.locals[0].location, Some(Location::Register(2)));
        assert_eq!(f3.locals[1].location, Some(Location::Address(0x2b2920)));
        assert!(f3.variadic && !f1.variadic);
    }

    #[test]
    fn classes_follow_the_scoring_vocabulary() {
        let (d, _) = parsed();
        let class = |n: &str| d.classes(by_name(&d, n));
        // `unsigned long` is 64-bit on this toolchain; a typedef'd pointer
        // is `ptr`; `float` keeps its width.
        assert_eq!(class("f1"), ("uint64".to_string(), vec!["ptr".into(), "ptr".into(), "float32".into()]));
        assert_eq!(class("f2"), ("aggregate".to_string(), vec![]));
        // A pointer to a function type is `code`; an enum is its width.
        assert_eq!(class("f3"), ("void".to_string(), vec!["code".into(), "int32".into()]));
        assert_eq!(class("f4"), ("int32".to_string(), vec!["uint8".into(), "aggregate".into()]));
        assert_eq!(class("f5"), ("ptr".to_string(), vec!["unknown".into()]));
    }

    #[test]
    fn prototypes_exist_only_where_every_type_has_a_c_spelling() {
        let (d, _) = parsed();
        let protos = d.prototypes();
        let names: Vec<_> = protos.iter().map(|p| p.name.as_str()).collect();
        // f2 returns a struct, f4 takes a union, f5 takes a 128-bit value.
        assert_eq!(names, ["f1", "f3"]);
        let f1 = &protos[0];
        assert_eq!((f1.entry, f1.return_type.as_str()), (0x1000, "ulonglong"));
        assert_eq!(
            f1.parameters,
            [
                ("p".to_string(), "char *".to_string()),
                ("h".to_string(), "void *".to_string()),
                ("x".to_string(), "float".to_string()),
            ]
        );
        let f3 = &protos[1];
        assert_eq!(f3.return_type, "void");
        assert_eq!(f3.parameters[0].1, "code *");
        assert_eq!(f3.parameters[1].1, "int");
        assert!(f3.variadic && !f1.variadic);
    }

    #[test]
    fn pointer_chains_and_qualifiers_resolve_outermost_first() {
        let g = TypeGraph::default();
        let two = TypeRef::Modified { modifiers: vec![1, 1], base: Box::new(TypeRef::Fundamental(0x03)) };
        assert_eq!(g.c_type(&two).as_deref(), Some("byte * *"));
        assert_eq!(g.class_name(&two), "ptr");
        // const pointer to char: the pointer is the outer type.
        let cp = TypeRef::Modified { modifiers: vec![MOD_CONST, 1], base: Box::new(TypeRef::Fundamental(0x01)) };
        assert_eq!(g.c_type(&cp).as_deref(), Some("char *"));
        // pointer to const char: still a pointer to char.
        let pc = TypeRef::Modified { modifiers: vec![1, MOD_CONST], base: Box::new(TypeRef::Fundamental(0x01)) };
        assert_eq!(g.c_type(&pc).as_deref(), Some("char *"));
        assert_eq!(g.class_name(&TypeRef::Fundamental(0x0f)), "float64");
        assert_eq!(g.class_name(&TypeRef::Fundamental(0x15)), "bool");
        assert_eq!(g.class_name(&TypeRef::Fundamental(0x0a)), "int64");
        assert_eq!(g.class_name(&TypeRef::Die(1)), "unknown");
    }

    fn sp_based(offset: u32) -> Vec<u8> {
        loc(&[&[OP_BASEREG][..], &29u32.to_le_bytes(), &[OP_CONST], &offset.to_le_bytes(), &[OP_ADD]].concat())
    }

    #[test]
    fn stack_locals_are_entry_relative_scalars_below_the_entry_stack_pointer() {
        let mut s = Stream::default();
        let unit = s.open(TAG_COMPILE_UNIT, &[name("unit.c")]);
        let record = s.open(TAG_STRUCTURE, &[size(12), name("Rec")]);
        s.leaf(TAG_MEMBER, &[ft(0x08), member_at(0), name("count")]);
        let record = s.close(record);
        let f = s.open(TAG_GLOBAL_SUBROUTINE, &[pc(0x2000, 0x2040), ft(0x14), name("f")]);
        // int at sp+0x10, a pointer at sp+0x18, a 12-byte struct, a double at
        // sp+0x28, a register local, a static, and an outgoing-argument slot
        // at sp+0 whose entry-relative offset is still negative but which is
        // not scalar-sized.
        s.leaf(TAG_LOCAL_VARIABLE, &[ft(0x08), sp_based(0x10), name("count")]);
        s.leaf(TAG_LOCAL_VARIABLE, &[mft(POINTER, 0x01), sp_based(0x18), name("text")]);
        s.leaf(TAG_LOCAL_VARIABLE, &[udt(record), sp_based(0x20), name("rec")]);
        s.leaf(TAG_LOCAL_VARIABLE, &[ft(0x0f), sp_based(0x28), name("ratio")]);
        s.leaf(TAG_LOCAL_VARIABLE, &[ft(0x08), reg(2), name("fast")]);
        s.leaf(TAG_LOCAL_VARIABLE, &[ft(0x08), loc(&[&[OP_ADDR][..], &0x2b2920u32.to_le_bytes()].concat()), name("kept")]);
        // sp+0x40 is the entry stack pointer for a 0x40 frame: not a local.
        s.leaf(TAG_LOCAL_VARIABLE, &[ft(0x08), sp_based(0x40), name("home")]);
        s.close(f);
        s.close(unit);
        let d = Dwarf1::parse(&s.b);
        let found = d.stack_locals(&d.subprograms[0], 0x40);
        let summary: Vec<_> = found.iter().map(|l| (l.name.as_str(), l.offset, l.size, l.c_type.as_deref())).collect();
        assert_eq!(
            summary,
            [
                ("count", -0x30, 4, Some("int")),
                ("text", -0x28, 4, Some("char *")),
                ("ratio", -0x18, 8, Some("double")),
            ]
        );
        assert!(found.iter().all(|l| l.entry == 0x2000));
    }

    #[test]
    fn sizes_follow_the_target_layout() {
        let (d, at) = parsed();
        let size = |ty: TypeRef| d.types.size_of(&ty);
        assert_eq!(size(TypeRef::Fundamental(0x03)), Some(1));
        assert_eq!(size(TypeRef::Fundamental(0x0c)), Some(8));
        assert_eq!(size(TypeRef::Die(at["Rec"])), Some(12));
        assert_eq!(size(TypeRef::Die(at["Colour"])), Some(4));
        // int grid[3][4]
        assert_eq!(size(TypeRef::Die(at["grid"])), Some(4 * 3 * 4));
        assert_eq!(size(TypeRef::Die(at["Handle"])), Some(4));
        assert_eq!(size(TypeRef::Die(at["callback"])), None);
    }

    #[test]
    fn a_truncated_stream_keeps_what_came_before() {
        let (blob, _) = stream();
        let cut = &blob[..blob.len() - 60];
        let d = Dwarf1::parse(cut);
        assert!(d.subprograms.len() >= 4);
        assert_eq!(d.subprograms[0].name, "f1");
    }

    /// The real image, when the corpus is present: the differential
    /// harness (`benchmarks/dwarf1_diff.py`) reads the JSON this writes.
    #[test]
    #[ignore = "reads ROMWRIGHT_DWARF1_ELF; writes ROMWRIGHT_DWARF1_OUT"]
    fn dump_dwarf1_classes_for_the_differential() {
        let (Ok(path), Ok(out)) = (
            std::env::var("ROMWRIGHT_DWARF1_ELF"),
            std::env::var("ROMWRIGHT_DWARF1_OUT"),
        ) else {
            return;
        };
        let data = std::fs::read(path).unwrap();
        let (off, size) = debug_section(&data);
        let d = Dwarf1::parse(&data[off..off + size]);
        let mut rows = serde_json::Map::new();
        for s in &d.subprograms {
            let (returns, parameters) = d.classes(s);
            let proto = d.prototype(s);
            rows.insert(
                format!("{:08x}", s.entry),
                serde_json::json!({
                    "name": s.name, "returns": returns, "parameters": parameters,
                    "locals": s.locals.len(),
                    "prototype": proto.map(|p| serde_json::json!({
                        "returns": p.return_type, "variadic": p.variadic,
                        "parameters": p.parameters.iter().map(|(n, t)| [n, t]).collect::<Vec<_>>(),
                    })),
                }),
            );
        }
        let stats = serde_json::json!({
            "types": d.types.types.len(), "subprograms": d.subprograms.len(),
            "with_prototype": d.prototypes().len(), "functions": rows,
        });
        std::fs::write(out, serde_json::to_string(&stats).unwrap()).unwrap();
    }

    /// The `.debug` section of a little-endian ELF32, by section name.
    fn debug_section(data: &[u8]) -> (usize, usize) {
        let shoff = le32(data, 0x20).unwrap() as usize;
        let shentsize = le16(data, 0x2e).unwrap() as usize;
        let shnum = le16(data, 0x30).unwrap() as usize;
        let shstrndx = le16(data, 0x32).unwrap() as usize;
        let strtab = le32(data, shoff + shstrndx * shentsize + 16).unwrap() as usize;
        for i in 0..shnum {
            let h = shoff + i * shentsize;
            let n = strtab + le32(data, h).unwrap() as usize;
            if data[n..].starts_with(b".debug\0") {
                return (le32(data, h + 16).unwrap() as usize, le32(data, h + 20).unwrap() as usize);
            }
        }
        panic!("no .debug section");
    }
}
