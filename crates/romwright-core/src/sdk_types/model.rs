//! The C type model a header declares: what the declaration parser builds and
//! the layout engine measures. Names are the decompiler's: a struct, union or
//! enum is known by its tag alone, the way Ghidra's own C grammar looks one up
//! (`CParse::oldStruct` calls `findByName(ident)` on the bare tag,
//! grammar.cc:2652-2659), and a primitive by the core-type name the
//! decompiler holds or derives (`uchar`, `ulonglong`, ...).

use std::collections::BTreeMap;

/// A C arithmetic or void type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Prim {
    Char,
    SChar,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
    Float,
    Double,
    LongDouble,
    Bool,
    Void,
}

impl Prim {
    /// The decompiler's name for the type. `char`, `short`, `ushort`, `int`,
    /// `uint`, `longlong`, `ulonglong`, `float`, `double`, `bool` and `void`
    /// are core types of every 32-bit language (`coretypes.xml`); `long`,
    /// `ulong` and `longdouble` are the names `library_types::language_base_types`
    /// answers from the compiler spec; `schar`/`uchar` are the names of
    /// Ghidra's `SignedCharDataType`/`UnsignedCharDataType`, which its client
    /// encodes as a one-byte char type (`encodeCharDataType`,
    /// PcodeDataTypeManager.java:607-625).
    pub fn name(self) -> &'static str {
        match self {
            Self::Char => "char",
            Self::SChar => "schar",
            Self::UChar => "uchar",
            Self::Short => "short",
            Self::UShort => "ushort",
            Self::Int => "int",
            Self::UInt => "uint",
            Self::Long => "long",
            Self::ULong => "ulong",
            Self::LongLong => "longlong",
            Self::ULongLong => "ulonglong",
            Self::Float => "float",
            Self::Double => "double",
            Self::LongDouble => "longdouble",
            Self::Bool => "bool",
            Self::Void => "void",
        }
    }

    pub fn is_integer(self) -> bool {
        !matches!(self, Self::Float | Self::Double | Self::LongDouble | Self::Void)
    }

    /// Signedness as C defines it; plain `char` follows the target.
    pub fn is_signed(self, char_signed: bool) -> bool {
        match self {
            Self::Char => char_signed,
            Self::SChar | Self::Short | Self::Int | Self::Long | Self::LongLong => true,
            _ => false,
        }
    }

    /// Resolves the keyword multiset of a C type specifier (`unsigned long
    /// int`, `signed char`, ...) the way C11 6.7.2p2 lists the valid sets.
    pub fn from_keywords(words: &[&str]) -> Option<Self> {
        let count = |word: &str| words.iter().filter(|w| **w == word).count();
        let unsigned = count("unsigned") > 0;
        let signed = count("signed") > 0;
        let longs = count("long");
        let base = words
            .iter()
            .copied()
            .find(|w| !matches!(*w, "unsigned" | "signed" | "long" | "short"));
        if unsigned && signed {
            return None;
        }
        Some(match base {
            Some("void") => Self::Void,
            Some("_Bool") | Some("bool") => Self::Bool,
            Some("float") => Self::Float,
            Some("double") if longs == 1 => Self::LongDouble,
            Some("double") => Self::Double,
            Some("char") if unsigned => Self::UChar,
            Some("char") if signed => Self::SChar,
            Some("char") => Self::Char,
            Some("int") | None => {
                if count("short") > 0 {
                    if unsigned { Self::UShort } else { Self::Short }
                } else if longs >= 2 {
                    if unsigned { Self::ULongLong } else { Self::LongLong }
                } else if longs == 1 {
                    if unsigned { Self::ULong } else { Self::Long }
                } else if unsigned {
                    Self::UInt
                } else {
                    Self::Int
                }
            }
            _ => return None,
        })
    }
}

/// A C type as a declaration spells it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CType {
    Prim(Prim),
    /// A typedef name.
    Named(String),
    Struct(String),
    Union(String),
    Enum(String),
    Pointer(Box<CType>),
    /// Element type and length; `None` is `[]`, a flexible array member.
    Array(Box<CType>, Option<u64>),
    Function(Box<FunctionType>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionType {
    pub ret: CType,
    pub params: Vec<(Option<String>, CType)>,
    pub variadic: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositeKind {
    Struct,
    Union,
}

/// A member of a struct or union as declared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// `None` for an anonymous member or an unnamed bit-field.
    pub name: Option<String>,
    pub ty: CType,
    /// Declared width of a bit-field.
    pub bits: Option<u64>,
    /// `__attribute__((aligned(N)))` on the member, in bytes.
    pub aligned: Option<u64>,
    /// `__attribute__((packed))` on the member.
    pub packed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Composite {
    pub kind: CompositeKind,
    pub name: String,
    /// `None` until a body is seen: a forward declaration only.
    pub members: Option<Vec<Member>>,
    pub packed: bool,
    pub aligned: Option<u64>,
    /// Where the definition was read, for the report.
    pub origin: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumDef {
    pub name: String,
    /// Enumerators in declaration order, `None` until a body is seen.
    pub values: Option<Vec<(String, i64)>>,
    pub packed: bool,
    pub origin: String,
}

/// A typedef: its target and any alignment the typedef itself asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Typedef {
    pub ty: CType,
    pub aligned: Option<u64>,
    pub origin: String,
}

/// Every type a set of headers declares.
#[derive(Clone, Debug, Default)]
pub struct TypeTable {
    pub typedefs: BTreeMap<String, Typedef>,
    pub composites: BTreeMap<String, Composite>,
    pub enums: BTreeMap<String, EnumDef>,
}

impl TypeTable {
    /// Follows typedef names to the type they stand for. A cycle or an
    /// unknown name yields `None`.
    pub fn resolve<'a>(&'a self, mut ty: &'a CType) -> Option<&'a CType> {
        for _ in 0..64 {
            match ty {
                CType::Named(name) => ty = &self.typedefs.get(name)?.ty,
                other => return Some(other),
            }
        }
        None
    }
}
