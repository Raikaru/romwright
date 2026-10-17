//! The cast phase, ported from the pinned `third_party/ghidra/decompiler`
//! (`coreaction.cc` `ActionSetCasts`, `cast.cc` `CastStrategyC`, the cast
//! methods of `typeop.cc`; Apache-2.0) to run over the statements' print trees
//! (docs/types-port.md, stage 2a).
//!
//! `ghidra_opt` no longer runs `ActionSetCasts` for a function this pass
//! accepts: it exports each statement's *pre-cast* tree (`CNode`: the print
//! tree plus what the cast methods read -- types, local requirement types,
//! flags) and this pass puts the casts in: a `CAST` around an input or an
//! output, a `PTRSUB #0` into a structure's first field, the types of
//! constants and implied results, the unsigned/long print flags of constants.
//! The result is the print tree `render.rs` prints, exactly as it would have
//! been had `ActionSetCasts` run.
//!
//! Every place the port is not exact (unions, partial types, variable-length
//! structures, address spaces on pointers, a constant retyped to a string or
//! code pointer, ...) is a [`Err`] naming why; the caller then has
//! `ghidra_opt` run `ActionSetCasts` for that function.

use super::render::opc;
use super::tree::{
    ConstKind, Extra, Options, PConst, PNode, POp, PrintTree, PtrsubKind, Tables, TypeDesc, meta,
};

type Result<T, E = String> = std::result::Result<T, E>;

/// `Varnode` flags the exporter packs (`RomwrightPrintIrExport::nodeFlags`).
pub const F_TYPELOCK: u32 = 1;
pub const F_NZHIGH: u32 = 2;
pub const F_CONST: u32 = 4;
pub const F_WRITTEN: u32 = 8;
pub const F_LONE_RETURN: u32 = 16;
pub const F_IMPLIED: u32 = 32;
/// The varnode has no sole reader (`loneDescend` is null): several ops read it.
pub const F_MULTI: u32 = 64;

/// `CastStrategy::IntPromotionCode`.
const NO_PROMOTION: i32 = -1;
const UNKNOWN_PROMOTION: i32 = 0;
const UNSIGNED_EXTENSION: i32 = 1;
const SIGNED_EXTENSION: i32 = 2;
const EITHER_EXTENSION: i32 = 3;

/// Switches of the cast decisions that are not C++ parity.
#[derive(Clone, Debug, Default)]
pub struct CastRules {
    /// A constant of an aggregate type (an array or a structure, whose C cast
    /// from an integer does not exist) prints as the bare integer.
    /// `ROMWRIGHT_RUST_CASTS_AGGREGATE=off` keeps the decompiler's `(type)0x...`.
    pub bare_aggregate_constants: bool,
    /// Stage 4: a null pointer constant passed to a call prints as the bare `0x0`, not `(char **)0x0`. The cast
    /// names a pointer type the decompiler inferred for the callee's parameter; where the project declares the
    /// callee otherwise (a `char`, an `int`) the cast is the compile error, and `0` converts to every pointer type
    /// and to every integer one. `ROMWRIGHT_RUST_TYPES_NULL_ARGS=off` and `ROMWRIGHT_NATIVE_TYPES=1` keep the cast.
    pub null_call_arguments: bool,
}

pub fn current_rules() -> CastRules {
    let native = std::env::var("ROMWRIGHT_NATIVE_TYPES").is_ok_and(|mode| mode == "1");
    CastRules {
        bare_aggregate_constants: std::env::var("ROMWRIGHT_RUST_CASTS_AGGREGATE").map_or(true, |mode| mode != "off"),
        null_call_arguments: !native && std::env::var("ROMWRIGHT_RUST_TYPES_NULL_ARGS").map_or(true, |mode| mode != "off"),
    }
}

/// What the pass did, for the ownership log and the differential.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct CastStats {
    pub casts: u64,
    pub ptrsubs: u64,
    pub constants_retyped: u64,
    pub unsigned_marked: u64,
    pub long_marked: u64,
    pub casts_replaced: u64,
    pub warnings: u64,
    /// Constants of an aggregate type printed without the cast.
    pub bare_constants: u64,
}

impl CastStats {
    pub fn add(&mut self, other: &CastStats) {
        self.casts += other.casts;
        self.ptrsubs += other.ptrsubs;
        self.constants_retyped += other.constants_retyped;
        self.unsigned_marked += other.unsigned_marked;
        self.long_marked += other.long_marked;
        self.casts_replaced += other.casts_replaced;
        self.warnings += other.warnings;
        self.bare_constants += other.bare_constants;
    }
}

/// Types and flags of a leaf or of an op's output.
#[derive(Clone, Debug, Default)]
pub struct Info {
    /// `getHighTypeReadFacing` (leaf) / `getHighTypeDefFacing` (output).
    pub ty: usize,
    /// The varnode's own type.
    pub own: usize,
    pub flags: u32,
}

#[derive(Clone, Debug)]
pub struct CLeaf {
    pub node: PNode,
    pub info: Info,
}

#[derive(Clone, Debug)]
pub struct COut {
    pub info: Info,
    /// `PcodeOp::outputTypeLocal`.
    pub local: usize,
}

#[derive(Clone, Debug)]
pub struct COp {
    /// Opcode, time, output size and per-opcode extras; `kids` stays empty.
    pub head: POp,
    pub out: Option<COut>,
    pub absorbed: bool,
    pub bool_out: bool,
    pub call: bool,
    /// LOAD/STORE: the word size of the space.
    pub word: u32,
    /// PTRADD: the element size in its third input.
    pub ptradd_size: u64,
    /// PTRSUB: the offset in its second input, whether its pointer type still
    /// fits it, and the output type the decompiler computed before any cast.
    pub ptrsub_offset: u64,
    pub ptrsub_matching: bool,
    /// PTRSUB, SUBPIECE: `getOutputToken` before any cast.
    pub token: Option<usize>,
    /// The p-code input slot of each kid, and the type the slot requires
    /// locally (`inputTypeLocal`).
    pub slots: Vec<usize>,
    pub locals: Vec<usize>,
    pub kids: Vec<CNode>,
    /// A cast went in front of the first input of a PTRSUB.
    pub ptrsub_cast: bool,
    /// CALL: whether the callee's parameter types / return type are declared
    /// (`FuncCallSpecs::isInputLocked`, `isOutputLocked`).
    pub call_locked: (bool, bool),
}

#[derive(Clone, Debug)]
pub enum CNode {
    Leaf(CLeaf),
    Op(Box<COp>),
}

#[derive(Clone, Debug)]
pub struct CTree {
    pub out: Option<CLeaf>,
    pub root: CNode,
}

impl CNode {
    fn ty(&self) -> usize {
        match self {
            CNode::Leaf(leaf) => leaf.info.ty,
            CNode::Op(op) => op.out.as_ref().map_or(0, |out| out.info.ty),
        }
    }

    fn own(&self) -> usize {
        match self {
            CNode::Leaf(leaf) => leaf.info.own,
            CNode::Op(op) => op.out.as_ref().map_or(0, |out| out.info.own),
        }
    }

    fn size(&self) -> u32 {
        match self {
            CNode::Leaf(leaf) => leaf.node.size(),
            CNode::Op(op) => op.head.out_size,
        }
    }

    fn is_const(&self) -> bool {
        matches!(self, CNode::Leaf(leaf) if leaf.info.flags & F_CONST != 0)
    }

    /// `Varnode::isExplicit` for a non-constant.
    fn is_explicit(&self) -> bool {
        matches!(self, CNode::Leaf(leaf) if leaf.info.flags & F_CONST == 0)
    }

    #[allow(dead_code)]
    fn is_written(&self) -> bool {
        match self {
            CNode::Leaf(leaf) => leaf.info.flags & F_WRITTEN != 0,
            CNode::Op(_) => true,
        }
    }

    fn typelock(&self) -> bool {
        match self {
            CNode::Leaf(leaf) => leaf.info.flags & F_TYPELOCK != 0,
            CNode::Op(op) => op.out.as_ref().is_some_and(|out| out.info.flags & F_TYPELOCK != 0),
        }
    }

    fn const_value(&self) -> Option<(u64, u32)> {
        match self {
            CNode::Leaf(CLeaf {
                node: PNode::Const(c),
                ..
            }) => Some((c.value, c.size)),
            _ => None,
        }
    }

    fn info_mut(&mut self) -> Option<&mut Info> {
        match self {
            CNode::Leaf(leaf) => Some(&mut leaf.info),
            CNode::Op(op) => op.out.as_mut().map(|out| &mut out.info),
        }
    }
}

impl COp {
    fn code(&self) -> u32 {
        self.head.code
    }

    fn kid_at(&self, slot: usize) -> Option<&CNode> {
        self.slots
            .iter()
            .position(|&s| s == slot)
            .map(|index| &self.kids[index])
    }
}

/// `TypeOp::inheritsSign`.
fn inherits_sign(code: u32) -> bool {
    matches!(
        code,
        opc::INT_EQUAL
            | opc::INT_NOTEQUAL
            | opc::INT_SLESS
            | opc::INT_SLESSEQUAL
            | opc::INT_LESS
            | opc::INT_LESSEQUAL
            | opc::INT_ADD
            | opc::INT_SUB
            | opc::INT_2COMP
            | opc::INT_NEGATE
            | opc::INT_XOR
            | opc::INT_AND
            | opc::INT_OR
            | opc::INT_LEFT
            | opc::INT_RIGHT
            | opc::INT_SRIGHT
            | opc::INT_MULT
            | opc::INT_DIV
            | opc::INT_SDIV
            | opc::INT_REM
            | opc::INT_SREM
    )
}

/// `TypeOp::inheritsSignFirstParamOnly`.
fn inherits_sign_first_only(code: u32) -> bool {
    matches!(
        code,
        opc::INT_LEFT | opc::INT_RIGHT | opc::INT_SRIGHT | opc::INT_REM | opc::INT_SREM
    )
}

fn is_shift(code: u32) -> bool {
    matches!(code, opc::INT_LEFT | opc::INT_RIGHT | opc::INT_SRIGHT)
}

/// The number of inputs of the opcodes that inherit a sign.
fn num_input(code: u32) -> usize {
    match code {
        opc::INT_2COMP | opc::INT_NEGATE => 1,
        _ => 2,
    }
}

fn signbit_negative(value: u64, size: u32) -> bool {
    if size == 0 || size > 8 {
        return false;
    }
    (value >> (size * 8 - 1)) & 1 != 0
}

fn mostsigbit_set(value: u64) -> i32 {
    if value == 0 {
        -1
    } else {
        63 - value.leading_zeros() as i32
    }
}

fn negate(value: u64, size: u32) -> u64 {
    let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
    value.wrapping_neg() & mask
}

pub struct Pass<'a> {
    t: &'a mut Tables,
    #[allow(dead_code)]
    options: &'a Options,
    #[allow(dead_code)]
    rules: &'a CastRules,
    pub next_time: u64,
    pub stats: CastStats,
    /// `ActionSetCasts::checkPointerIssues`' warnings: (op time, opcode).
    pub warnings: Vec<(u64, u32)>,
    /// Types of the casts the pass inserted (the printed type tokens).
    pub cast_types: std::collections::BTreeSet<usize>,
    /// The calls of unlocked callees as they print after the casts: the types
    /// the call's prototype is read off (`romwrightEncodeCallPrototypes`).
    pub call_types: Vec<CallType>,
    /// What the pass did to the p-code, in order (`FunctionIr` mirrors it).
    pub edits: Vec<IrEdit>,
}

/// One change `ActionSetCasts` makes to the p-code. The document's semantic IR
/// is built from the p-code the decompiler exports; with the casts decided by
/// the worker it has to be given the same CAST operations, or the type
/// evidence read off it differs (a cast is where a value changes type).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrEdit {
    /// `castOutput`: the op writes a fresh value and a CAST (`cast`) writes the original one after it.
    Output { op: u64, cast: u64 },
    /// `castInput`: a CAST (`cast`) before `op` reads the input of `slot`; `op` reads the cast's output.
    Input { op: u64, slot: usize, cast: u64 },
    /// `castInput` found a cast already in place and put the cast's own input in its place.
    Replace { op: u64, slot: usize },
}

/// One call whose callee prototype is not declared, after the casts.
#[derive(Clone, Debug)]
pub struct CallType {
    pub time: u64,
    pub input_locked: bool,
    pub output_locked: bool,
    /// The type of each argument (high type as the call reads it).
    pub params: Vec<usize>,
    /// The type of the call's result (definition-facing), when it has one.
    pub ret: Option<usize>,
}

/// Synthetic op times start here: past any `PcodeOp::getTime` of a function.
const SYNTHETIC_TIME: u64 = 1 << 40;

/// `Datatype::isComplex`-style ordering classes (types the exporter orders pairwise).
fn is_complex(t: &Tables, index: usize) -> bool {
    let ty = &t.types[index];
    matches!(
        ty.meta,
        meta::STRUCT
            | meta::UNION
            | meta::CODE
            | meta::PTRREL
            | meta::SPACEBASE
            | meta::PARTIALSTRUCT
            | meta::PARTIALUNION
    ) || ty.enumerated
}

/// `Datatype::compare(op, level)`.
pub fn type_compare(t: &Tables, a: usize, b: usize, level: i32) -> Result<i32> {
    if a == b {
        return Ok(0);
    }
    let (x, y) = (&t.types[a], &t.types[b]);
    if x.submeta != y.submeta {
        return Ok(if x.submeta < y.submeta { -1 } else { 1 });
    }
    if x.size != y.size {
        return Ok(y.size as i32 - x.size as i32);
    }
    if is_complex(t, a) || is_complex(t, b) {
        let key = if a < b { (a, b) } else { (b, a) };
        let sign = if a < b { 1 } else { -1 };
        return t
            .order
            .iter()
            .find(|(pair, _)| *pair == key)
            .map(|(_, order)| i32::from(*order) * sign)
            .ok_or_else(|| "cast:type-order".to_string());
    }
    match x.meta {
        meta::PTR => {
            if x.word_size != y.word_size {
                return Ok(if x.word_size < y.word_size { -1 } else { 1 });
            }
            if x.space != y.space {
                if x.space == 0 {
                    return Ok(1);
                }
                if y.space == 0 {
                    return Ok(-1);
                }
                return Ok(if x.space < y.space { -1 } else { 1 });
            }
            if level - 1 < 0 {
                return Err("cast:type-order-depth".into());
            }
            match (x.base, y.base) {
                (Some(p), Some(q)) => type_compare(t, p, q, level - 1),
                _ => Err("cast:type-order".into()),
            }
        }
        meta::ARRAY => {
            if level - 1 < 0 {
                return Err("cast:type-order-depth".into());
            }
            match (x.base, y.base) {
                (Some(p), Some(q)) => type_compare(t, p, q, level - 1),
                _ => Err("cast:type-order".into()),
            }
        }
        _ => Ok(0),
    }
}

impl<'a> Pass<'a> {
    pub fn new(t: &'a mut Tables, options: &'a Options, rules: &'a CastRules) -> Self {
        Pass {
            t,
            options,
            rules,
            next_time: SYNTHETIC_TIME,
            stats: CastStats::default(),
            warnings: Vec::new(),
            cast_types: Default::default(),
            call_types: Vec::new(),
            edits: Vec::new(),
        }
    }

    fn ty(&self, index: usize) -> &TypeDesc {
        &self.t.types[index]
    }

    fn meta(&self, index: usize) -> u8 {
        self.t.types[index].meta
    }

    /// A partial structure or union: the decompiler strips these from the
    /// high-level type a variable reads as, which this pass does not model.
    fn partial(&self, index: usize) -> bool {
        matches!(self.meta(index), meta::PARTIALSTRUCT | meta::PARTIALUNION)
    }

    fn time(&mut self) -> u64 {
        self.next_time += 1;
        self.next_time
    }

    // ---- the type factory subset ----

    /// `TypeFactory::getBase` (kind 0..3) and `getBaseNoChar(1, INT)` (4).
    fn base(&self, size: u32, kind: u8) -> Result<usize> {
        let meta = match kind {
            0 | 4 => meta::INT,
            1 => meta::UINT,
            2 => meta::UNKNOWN,
            _ => meta::BOOL,
        };
        self.t
            .seeds
            .iter()
            .find(|(key, _)| *key == (meta, size, kind))
            .map(|(_, index)| *index)
            .ok_or_else(|| format!("cast:core-type-{size}"))
    }

    /// `TypeFactory::getTypePointer(size, pointee, wordsize)`.
    fn pointer(&mut self, size: u32, pointee: usize, word_size: u32) -> usize {
        if let Some(found) = self.t.types.iter().position(|ty| {
            ty.meta == meta::PTR
                && ty.size == size
                && ty.base == Some(pointee)
                && ty.word_size == word_size
                && ty.space == 0
                && ty.typedef.is_none()
        }) {
            return found;
        }
        let array = self.meta(pointee) == meta::ARRAY;
        self.t.types.push(TypeDesc {
            id: 0,
            name: String::new(),
            display_name: String::new(),
            generic_name: String::new(),
            meta: meta::PTR,
            size,
            base: Some(pointee),
            pointer_to_array: array,
            submeta: 6,
            word_size,
            align_size: size,
            ..TypeDesc::default()
        });
        self.t.types.len() - 1
    }

    fn strip_typedef(&self, mut index: usize) -> usize {
        while let Some(next) = self.ty(index).typedef {
            index = next;
        }
        index
    }

    /// `Datatype::compare(op, level)`.
    fn compare(&self, a: usize, b: usize, level: i32) -> Result<i32> {
        type_compare(self.t, a, b, level)
    }

    /// `Datatype::typeOrder`.
    fn type_order(&self, a: usize, b: usize) -> Result<i32> {
        if a == b {
            return Ok(0);
        }
        self.compare(a, b, 10)
    }

    // ---- CastStrategyC ----

    /// `CastStrategyC::castStandard`: the type to cast to, if a cast is needed.
    fn cast_standard(
        &self,
        reqtype: usize,
        curtype: usize,
        mut care_uint_int: bool,
        care_ptr_uint: bool,
    ) -> Result<Option<usize>> {
        if curtype == reqtype {
            return Ok(None);
        }
        if self.meta(curtype) == meta::VOID {
            return Ok(Some(reqtype));
        }
        let (mut reqbase, mut curbase) = (reqtype, curtype);
        let mut isptr = false;
        while self.meta(reqbase) == meta::PTR && self.meta(curbase) == meta::PTR {
            let (rp, cp) = (self.ty(reqbase), self.ty(curbase));
            if rp.word_size != cp.word_size {
                return Ok(Some(reqtype));
            }
            if rp.space != cp.space && rp.space != 0 && cp.space != 0 {
                return Ok(Some(reqtype));
            }
            match (rp.base, cp.base) {
                (Some(r), Some(c)) => {
                    reqbase = r;
                    curbase = c;
                }
                _ => return Err("cast:pointer-without-pointee".into()),
            }
            care_uint_int = true;
            isptr = true;
        }
        reqbase = self.strip_typedef(reqbase);
        curbase = self.strip_typedef(curbase);
        if curbase == reqbase {
            return Ok(None);
        }
        if self.meta(reqbase) == meta::VOID || self.meta(curbase) == meta::VOID {
            return Ok(None);
        }
        if self.ty(reqbase).size != self.ty(curbase).size {
            if self.ty(reqbase).variable_length && isptr {
                return Err("cast:variable-length".into());
            }
            return Ok(Some(reqtype));
        }
        let partial = |m: u8| m == meta::PARTIALSTRUCT || m == meta::PARTIALUNION;
        match self.meta(reqbase) {
            meta::UNKNOWN | meta::PARTIALSTRUCT | meta::PARTIALUNION => return Ok(None),
            meta::UINT => {
                let cm = self.meta(curbase);
                if !care_uint_int {
                    if cm == meta::UNKNOWN
                        || cm == meta::INT
                        || cm == meta::UINT
                        || cm == meta::BOOL
                        || partial(cm)
                    {
                        return Ok(None);
                    }
                } else {
                    if cm == meta::UINT || cm == meta::BOOL {
                        return Ok(None);
                    }
                    if isptr && (cm == meta::UNKNOWN || partial(cm)) {
                        return Ok(None);
                    }
                }
                if !care_ptr_uint && cm == meta::PTR {
                    return Ok(None);
                }
            }
            meta::INT => {
                let cm = self.meta(curbase);
                if !care_uint_int {
                    if cm == meta::UNKNOWN
                        || cm == meta::INT
                        || cm == meta::UINT
                        || cm == meta::BOOL
                        || partial(cm)
                    {
                        return Ok(None);
                    }
                } else {
                    if cm == meta::INT || cm == meta::BOOL {
                        return Ok(None);
                    }
                    if isptr && (cm == meta::UNKNOWN || partial(cm)) {
                        return Ok(None);
                    }
                }
            }
            meta::CODE
                if self.meta(curbase) == meta::CODE
                    && (!self.ty(reqbase).has_proto || !self.ty(curbase).has_proto)
                => {
                    return Ok(None);
                }
            _ => {}
        }
        Ok(Some(reqtype))
    }

    /// `CastStrategyC::arithmeticOutputStandard`.
    fn arithmetic_output(&self, op: &COp) -> Result<usize> {
        let mut res1 = op.kids.first().ok_or("cast:arity")?.ty();
        if self.meta(res1) == meta::BOOL {
            res1 = self.base(self.ty(res1).size, 0)?;
        }
        for kid in op.kids.iter().skip(1) {
            let res2 = kid.ty();
            if self.meta(res2) == meta::BOOL {
                continue;
            }
            if self.type_order(res2, res1)? < 0 {
                res1 = res2;
            }
        }
        Ok(res1)
    }

    /// `CastStrategyC::localExtensionType`.
    fn local_extension_type(&self, vn: &CNode) -> i32 {
        let m = self.meta(vn.ty());
        let natural = if m == meta::UINT
            || m == meta::BOOL
            || m == meta::UNKNOWN
            || m == meta::PARTIALSTRUCT
            || m == meta::PARTIALUNION
        {
            UNSIGNED_EXTENSION
        } else if m == meta::INT {
            SIGNED_EXTENSION
        } else {
            return UNKNOWN_PROMOTION;
        };
        if let Some((value, size)) = vn.const_value() {
            return if !signbit_negative(value, size) {
                EITHER_EXTENSION
            } else {
                natural
            };
        }
        if vn.is_const() {
            // A constant printed as one token: its value is not known here.
            return UNKNOWN_PROMOTION;
        }
        if vn.is_explicit() {
            return natural;
        }
        let CNode::Op(def) = vn else {
            return UNKNOWN_PROMOTION;
        };
        if def.bool_out {
            return EITHER_EXTENSION;
        }
        if def.code() == opc::CAST || def.code() == opc::LOAD || def.call {
            return natural;
        }
        if def.code() == opc::INT_AND
            && let Some(other) = def.kid_at(1)
                && let Some((value, size)) = other.const_value() {
                    return if !signbit_negative(value, size) {
                        EITHER_EXTENSION
                    } else {
                        natural
                    };
                }
        UNKNOWN_PROMOTION
    }

    /// `CastStrategyC::intPromotionType`.
    fn int_promotion_type(&self, vn: &CNode) -> i32 {
        if vn.size() >= self.t.promote_size {
            return NO_PROMOTION;
        }
        if vn.is_const() {
            return self.local_extension_type(vn);
        }
        if vn.is_explicit() {
            return NO_PROMOTION;
        }
        let CNode::Op(op) = vn else {
            return UNKNOWN_PROMOTION;
        };
        let local = |slot: usize| -> i32 {
            match op.kid_at(slot) {
                Some(other) => self.local_extension_type(other),
                None => UNKNOWN_PROMOTION,
            }
        };
        match op.code() {
            opc::INT_AND => {
                if local(1) & UNSIGNED_EXTENSION != 0 {
                    return UNSIGNED_EXTENSION;
                }
                if local(0) & UNSIGNED_EXTENSION != 0 {
                    return UNSIGNED_EXTENSION;
                }
            }
            opc::INT_RIGHT => {
                let val = local(0);
                if val & UNSIGNED_EXTENSION != 0 {
                    return val;
                }
            }
            opc::INT_SRIGHT => {
                let val = local(0);
                if val & SIGNED_EXTENSION != 0 {
                    return val;
                }
            }
            opc::INT_XOR | opc::INT_OR | opc::INT_DIV | opc::INT_REM => {
                if local(0) & UNSIGNED_EXTENSION == 0 {
                    return UNKNOWN_PROMOTION;
                }
                if local(1) & UNSIGNED_EXTENSION == 0 {
                    return UNKNOWN_PROMOTION;
                }
                return UNSIGNED_EXTENSION;
            }
            opc::INT_SDIV | opc::INT_SREM => {
                if local(0) & SIGNED_EXTENSION == 0 {
                    return UNKNOWN_PROMOTION;
                }
                if local(1) & SIGNED_EXTENSION == 0 {
                    return UNKNOWN_PROMOTION;
                }
                return SIGNED_EXTENSION;
            }
            opc::INT_NEGATE | opc::INT_2COMP => {
                if local(0) & SIGNED_EXTENSION != 0 {
                    return SIGNED_EXTENSION;
                }
            }
            opc::INT_ADD | opc::INT_SUB | opc::INT_LEFT | opc::INT_MULT => {}
            _ => return NO_PROMOTION,
        }
        UNKNOWN_PROMOTION
    }

    /// `CastStrategyC::checkIntPromotionForCompare`.
    fn check_promotion_compare(&self, op: &COp, k: usize) -> bool {
        let exttype1 = self.int_promotion_type(&op.kids[k]);
        if exttype1 == NO_PROMOTION {
            return false;
        }
        if exttype1 == UNKNOWN_PROMOTION {
            return true;
        }
        let other = op.kid_at(1 - op.slots[k].min(1));
        let exttype2 = match other {
            Some(other) => self.int_promotion_type(other),
            None => UNKNOWN_PROMOTION,
        };
        if exttype1 & exttype2 != 0 {
            return false;
        }
        if exttype2 == NO_PROMOTION {
            return false;
        }
        true
    }

    /// `CastStrategyC::checkIntPromotionForExtension`.
    fn check_promotion_extension(&self, op: &COp) -> bool {
        let Some(vn) = op.kids.first() else {
            return false;
        };
        let exttype = self.int_promotion_type(vn);
        if exttype == NO_PROMOTION {
            return false;
        }
        if exttype == UNKNOWN_PROMOTION {
            return true;
        }
        if exttype & UNSIGNED_EXTENSION != 0 && op.code() == opc::INT_ZEXT {
            return false;
        }
        if exttype & SIGNED_EXTENSION != 0 && op.code() == opc::INT_SEXT {
            return false;
        }
        true
    }

    /// `CastStrategyC::isExtensionCastImplied` for an extension whose reader
    /// is `reader` (the code, and per input slot what the extension's
    /// neighbours are).
    fn extension_implied(&self, out_type: usize, reader: &Reader) -> bool {
        let metatype = self.meta(out_type);
        match reader.code {
            opc::PTRADD => true,
            opc::INT_ADD
            | opc::INT_SUB
            | opc::INT_MULT
            | opc::INT_DIV
            | opc::INT_AND
            | opc::INT_OR
            | opc::INT_XOR
            | opc::INT_EQUAL
            | opc::INT_NOTEQUAL
            | opc::INT_LESS
            | opc::INT_LESSEQUAL
            | opc::INT_SLESS
            | opc::INT_SLESSEQUAL => {
                let Some(other) = reader.other.as_ref() else {
                    return false;
                };
                if other.constant {
                    if other.size > self.t.promote_size {
                        return false;
                    }
                } else if !other.explicit {
                    return false;
                }
                other.meta == metatype
            }
            _ => false,
        }
    }

    /// `CastStrategy::markExplicitUnsigned`.
    fn mark_explicit_unsigned(
        &mut self,
        op: &mut COp,
        k: usize,
        explicit_out: bool,
        reader_code: Option<u32>,
    ) -> bool {
        let code = op.code();
        if !inherits_sign(code) {
            return false;
        }
        let first_only = inherits_sign_first_only(code);
        let slot = op.slots[k];
        if slot == 1 && first_only {
            return false;
        }
        if !op.kids[k].is_const() {
            return false;
        }
        let dt = self.ty(op.kids[k].ty());
        let m = dt.meta;
        if m != meta::UINT && m != meta::UNKNOWN && m != meta::PARTIALSTRUCT && m != meta::PARTIALUNION
        {
            return false;
        }
        if dt.char_print || dt.enumerated {
            return false;
        }
        if num_input(code) == 2 && !first_only
            && let Some(first) = op.kid_at(1 - slot.min(1)) {
                let fm = self.meta(first.ty());
                if fm == meta::UINT
                    || fm == meta::UNKNOWN
                    || fm == meta::PARTIALSTRUCT
                    || fm == meta::PARTIALUNION
                {
                    return false;
                }
            }
        let multi_read = op.out.as_ref().is_some_and(|out| out.info.flags & F_MULTI != 0);
        if op.out.is_some() {
            if explicit_out {
                return false;
            }
            if let Some(reader) = reader_code
                && !multi_read && !inherits_sign(reader) {
                    return false;
                }
        }
        if let CNode::Leaf(CLeaf {
            node: PNode::Const(c),
            ..
        }) = &mut op.kids[k]
        {
            c.unsigned_print = true;
            self.stats.unsigned_marked += 1;
            true
        } else {
            false
        }
    }

    /// `CastStrategy::markExplicitLongSize`.
    fn mark_explicit_long(&mut self, op: &mut COp, k: usize) -> bool {
        if !is_shift(op.code()) || op.slots[k] != 0 {
            return false;
        }
        let Some((value, size)) = op.kids[k].const_value() else {
            return false;
        };
        let promote = self.t.promote_size;
        if size <= promote {
            return false;
        }
        let m = self.meta(op.kids[k].ty());
        if m != meta::UINT
            && m != meta::INT
            && m != meta::UNKNOWN
            && m != meta::PARTIALSTRUCT
            && m != meta::PARTIALUNION
        {
            return false;
        }
        let mut off = value;
        if m == meta::INT && signbit_negative(off, size) {
            off = negate(off, size);
            if mostsigbit_set(off) >= promote as i32 * 8 - 1 {
                return false;
            }
        } else if mostsigbit_set(off) >= promote as i32 * 8 {
            return false;
        }
        if let CNode::Leaf(CLeaf {
            node: PNode::Const(c),
            ..
        }) = &mut op.kids[k]
        {
            c.long_print = true;
            self.stats.long_marked += 1;
            true
        } else {
            false
        }
    }

    // ---- TypeOp::getInputCast / getOutputToken ----

    fn kid_index(op: &COp, slot: usize) -> Result<usize> {
        op.slots
            .iter()
            .position(|&s| s == slot)
            .ok_or_else(|| format!("cast:slot-{slot}"))
    }

    /// `TypeOp::getInputCast`: the type input `k` of `op` must be cast to.
    fn input_cast(&mut self, op: &COp, k: usize) -> Result<Option<usize>> {
        let slot = op.slots[k];
        let kid = &op.kids[k];
        let req = op.locals[k];
        let default = |this: &Self| -> Result<Option<usize>> {
            this.cast_standard(req, kid.ty(), false, true)
        };
        match op.code() {
            opc::COPY => {
                let reqtype = op.out.as_ref().ok_or("cast:copy-out")?.info.ty;
                self.cast_standard(reqtype, kid.ty(), false, true)
            }
            opc::LOAD => {
                if slot != 1 {
                    return Ok(None);
                }
                let reqtype = op.out.as_ref().ok_or("cast:load-out")?.info.ty;
                let mut curtype = kid.ty();
                if self.meta(curtype) == meta::PTR {
                    curtype = self.ty(curtype).base.ok_or("cast:pointer-without-pointee")?;
                } else {
                    return Ok(Some(self.pointer(kid.size(), reqtype, op.word)));
                }
                if curtype != reqtype && self.ty(curtype).size == self.ty(reqtype).size {
                    let curmeta = self.meta(curtype);
                    if curmeta != meta::STRUCT
                        && curmeta != meta::ARRAY
                        && curmeta != meta::SPACEBASE
                        && curmeta != meta::UNION
                    {
                        let is_cast = matches!(kid, CNode::Op(inner) if inner.code() == opc::CAST);
                        if !is_cast {
                            return Ok(None);
                        }
                    }
                }
                match self.cast_standard(reqtype, curtype, false, true)? {
                    None => Ok(None),
                    Some(ct) => Ok(Some(self.pointer(kid.size(), ct, op.word))),
                }
            }
            opc::STORE => {
                if slot == 0 {
                    return Ok(None);
                }
                let pointer_k = Self::kid_index(op, 1)?;
                let value_k = Self::kid_index(op, 2)?;
                let pointer_vn = &op.kids[pointer_k];
                let pointer_type = pointer_vn.ty();
                let value_type = op.kids[value_k].ty();
                let mut pointed_to = pointer_type;
                let dest_size: i64 = if self.meta(pointer_type) == meta::PTR {
                    pointed_to = self.ty(pointer_type).base.ok_or("cast:pointer-without-pointee")?;
                    i64::from(self.ty(pointed_to).size)
                } else {
                    -1
                };
                if dest_size != i64::from(self.ty(value_type).size) {
                    return if slot == 1 {
                        Ok(Some(self.pointer(pointer_vn.size(), value_type, op.word)))
                    } else {
                        Ok(None)
                    };
                }
                if slot == 1 {
                    if let CNode::Op(inner) = pointer_vn
                        && inner.code() == opc::CAST {
                            let new_type = self.pointer(pointer_vn.size(), value_type, op.word);
                            if pointer_type != new_type {
                                return Ok(Some(new_type));
                            }
                        }
                    return Ok(None);
                }
                self.cast_standard(pointed_to, value_type, false, true)
            }
            opc::INT_EQUAL | opc::INT_NOTEQUAL => {
                let k0 = Self::kid_index(op, 0)?;
                let k1 = Self::kid_index(op, 1)?;
                let mut reqtype = op.kids[k0].ty();
                let othertype = op.kids[k1].ty();
                if self.type_order(othertype, reqtype)? < 0 {
                    reqtype = othertype;
                }
                if self.check_promotion_compare(op, k) {
                    return Ok(Some(reqtype));
                }
                self.cast_standard(reqtype, kid.ty(), false, false)
            }
            opc::INT_SLESS | opc::INT_SLESSEQUAL => {
                if self.check_promotion_compare(op, k) {
                    return Ok(Some(req));
                }
                self.cast_standard(req, kid.ty(), true, true)
            }
            opc::INT_LESS | opc::INT_LESSEQUAL => {
                if self.check_promotion_compare(op, k) {
                    return Ok(Some(req));
                }
                self.cast_standard(req, kid.ty(), true, false)
            }
            opc::INT_ZEXT | opc::INT_SEXT => {
                if self.check_promotion_extension(op) {
                    return Ok(Some(req));
                }
                self.cast_standard(req, kid.ty(), true, false)
            }
            opc::INT_RIGHT => {
                if slot == 0 {
                    let promo = self.int_promotion_type(kid);
                    if promo != NO_PROMOTION && promo & UNSIGNED_EXTENSION == 0 {
                        return Ok(Some(req));
                    }
                    return self.cast_standard(req, kid.ty(), true, true);
                }
                default(self)
            }
            opc::INT_SRIGHT => {
                if slot == 0 {
                    let promo = self.int_promotion_type(kid);
                    if promo != NO_PROMOTION && promo & SIGNED_EXTENSION == 0 {
                        return Ok(Some(req));
                    }
                    return self.cast_standard(req, kid.ty(), true, true);
                }
                default(self)
            }
            opc::INT_DIV | opc::INT_REM => {
                let promo = self.int_promotion_type(kid);
                if promo != NO_PROMOTION && promo & UNSIGNED_EXTENSION == 0 {
                    return Ok(Some(req));
                }
                self.cast_standard(req, kid.ty(), true, true)
            }
            opc::INT_SDIV | opc::INT_SREM => {
                let promo = self.int_promotion_type(kid);
                if promo != NO_PROMOTION && promo & SIGNED_EXTENSION == 0 {
                    return Ok(Some(req));
                }
                self.cast_standard(req, kid.ty(), true, true)
            }
            opc::FLOAT_INT2FLOAT => {
                if op.absorbed {
                    return Ok(None);
                }
                let mut care_uint_int = true;
                if kid.size() <= 8 {
                    let nz_high = match kid {
                        CNode::Leaf(leaf) => leaf.info.flags & F_NZHIGH != 0,
                        CNode::Op(inner) => inner
                            .out
                            .as_ref()
                            .is_some_and(|out| out.info.flags & F_NZHIGH != 0),
                    };
                    care_uint_int = nz_high;
                }
                self.cast_standard(req, kid.ty(), care_uint_int, true)
            }
            opc::PIECE | opc::SUBPIECE | opc::SEGMENTOP => {
                Ok(None)
            }
            opc::PTRADD => {
                if slot == 0 {
                    let reqtype = kid.own();
                    let curtype = kid.ty();
                    if self.meta(reqtype) != meta::PTR || self.meta(curtype) != meta::PTR {
                        return Ok(Some(reqtype));
                    }
                    let reqbase = self.ty(reqtype).base.ok_or("cast:pointer-without-pointee")?;
                    let curbase = self.ty(curtype).base.ok_or("cast:pointer-without-pointee")?;
                    if self.ty(reqbase).align_size == self.ty(curbase).align_size {
                        return Ok(None);
                    }
                    return Ok(Some(reqtype));
                }
                default(self)
            }
            opc::PTRSUB => {
                if slot == 0 {
                    let reqtype = kid.own();
                    let curtype = kid.ty();
                    if curtype == reqtype {
                        return Ok(None);
                    }
                    if self.meta(reqtype) != meta::PTR || self.meta(curtype) != meta::PTR {
                        return Ok(Some(reqtype));
                    }
                    let mut reqbase = self.ty(reqtype).base.ok_or("cast:pointer-without-pointee")?;
                    let mut curbase = self.ty(curtype).base.ok_or("cast:pointer-without-pointee")?;
                    if self.meta(curbase) == meta::ARRAY && self.meta(reqbase) == meta::ARRAY {
                        curbase = self.ty(curbase).base.ok_or("cast:array-without-element")?;
                        reqbase = self.ty(reqbase).base.ok_or("cast:array-without-element")?;
                    }
                    reqbase = self.strip_typedef(reqbase);
                    curbase = self.strip_typedef(curbase);
                    if curbase == reqbase {
                        return Ok(None);
                    }
                    return Ok(Some(reqtype));
                }
                default(self)
            }
            _ => default(self),
        }
    }

    /// `TypeOp::getOutputToken`.
    fn output_token(&mut self, op: &COp) -> Result<usize> {
        let out = op.out.as_ref().ok_or("cast:no-output")?;
        let first = |this: &Self| -> Result<usize> {
            let _ = this;
            op.kids.first().map(CNode::ty).ok_or_else(|| "cast:arity".to_string())
        };
        match op.code() {
            opc::COPY => first(self),
            opc::LOAD => {
                let ct = first(self)?;
                if self.meta(ct) == meta::PTR {
                    let base = self.ty(ct).base.ok_or("cast:pointer-without-pointee")?;
                    if self.ty(base).size == op.head.out_size {
                        return Ok(base);
                    }
                }
                Ok(out.info.ty)
            }
            opc::INT_ADD
            | opc::INT_SUB
            | opc::INT_2COMP
            | opc::INT_NEGATE
            | opc::INT_XOR
            | opc::INT_AND
            | opc::INT_OR
            | opc::INT_MULT => self.arithmetic_output(op),
            opc::INT_LEFT | opc::INT_RIGHT | opc::INT_SRIGHT => {
                let res1 = first(self)?;
                if self.meta(res1) == meta::BOOL {
                    return self.base(self.ty(res1).size, 0);
                }
                Ok(res1)
            }
            opc::PIECE => {
                let dt = out.info.ty;
                let m = self.meta(dt);
                if m == meta::INT || m == meta::UINT {
                    return Ok(dt);
                }
                self.base(op.head.out_size, 1)
            }
            opc::SUBPIECE | opc::PTRSUB => op.token.ok_or_else(|| "cast:token".to_string()),
            opc::PTRADD => first(self),
            opc::SEGMENTOP => first(self),
            _ => Ok(out.local),
        }
    }

    // ---- ActionSetCasts ----

    /// `Varnode::updateType(ct)` on an input constant or an implied output:
    /// the type changes unless the varnode's type is locked.
    fn update_type(&mut self, node: &mut CNode, ct: usize) -> Result<bool> {
        if node.typelock() {
            return Ok(false);
        }
        if self.partial(ct) {
            return Err("cast:partial-type".into());
        }
        let Some(info) = node.info_mut() else {
            return Ok(false);
        };
        if info.own == ct {
            return Ok(false);
        }
        info.own = ct;
        info.ty = ct;
        if let CNode::Leaf(leaf) = node {
            match &mut leaf.node {
                PNode::Const(c) => {
                    c.ty = ct;
                    let kind = self.const_kind(ct, c)?;
                    c.kind = kind;
                    self.stats.constants_retyped += 1;
                }
                _ => return Err("cast:retype-token-constant".into()),
            }
        }
        Ok(true)
    }

    /// How `PrintC::pushConstant` prints an integer constant of type `ct`.
    fn const_kind(&self, ct: usize, c: &PConst) -> Result<ConstKind> {
        let _ = c;
        let ty = self.ty(ct);
        match ty.meta {
            meta::UINT | meta::INT => {
                if ty.char_print || ty.enumerated {
                    Err("cast:const-retype-char-enum".into())
                } else {
                    Ok(ConstKind::Integer)
                }
            }
            meta::UNKNOWN | meta::BOOL => {
                if ty.enumerated {
                    Err("cast:const-retype-char-enum".into())
                } else {
                    Ok(ConstKind::Integer)
                }
            }
            meta::PTR | meta::PTRREL => {
                let base = ty.base.ok_or("cast:pointer-without-pointee")?;
                let pointee = self.ty(base);
                if pointee.char_print || pointee.meta == meta::CODE {
                    Err("cast:const-retype-string-or-code".into())
                } else {
                    Ok(ConstKind::Default)
                }
            }
            meta::FLOAT | meta::VOID => Err("cast:const-retype-float".into()),
            _ => Ok(ConstKind::Default),
        }
    }

    /// `ActionSetCasts::isOpIdentical`.
    fn op_identical(&self, ct1: usize, ct2: usize) -> bool {
        let (mut a, mut b) = (ct1, ct2);
        while self.meta(a) == meta::PTR && self.meta(b) == meta::PTR {
            match (self.ty(a).base, self.ty(b).base) {
                (Some(x), Some(y)) => {
                    a = x;
                    b = y;
                }
                _ => break,
            }
        }
        self.strip_typedef(a) == self.strip_typedef(b)
    }

    /// `ActionSetCasts::testStructOffset0`.
    fn test_struct_offset0(&self, reqtype: usize, curtype: usize) -> Result<bool> {
        if self.meta(curtype) != meta::PTR {
            return Ok(false);
        }
        let high_ptr_to = self.ty(curtype).base.ok_or("cast:pointer-without-pointee")?;
        let (mut req, mut cur);
        match self.meta(high_ptr_to) {
            meta::STRUCT => {
                let fields = &self.ty(high_ptr_to).fields;
                let Some(first) = fields.first() else {
                    return Ok(false);
                };
                if first.offset != 0 {
                    return Ok(false);
                }
                req = self.ty(reqtype).base.ok_or("cast:pointer-without-pointee")?;
                cur = first.ty;
                if self.meta(req) == meta::ARRAY {
                    req = self.ty(req).base.ok_or("cast:array-without-element")?;
                }
                if self.meta(cur) == meta::ARRAY {
                    cur = self.ty(cur).base.ok_or("cast:array-without-element")?;
                }
            }
            meta::ARRAY => {
                req = self.ty(reqtype).base.ok_or("cast:pointer-without-pointee")?;
                cur = self.ty(high_ptr_to).base.ok_or("cast:array-without-element")?;
            }
            _ => return Ok(false),
        }
        if self.meta(req) == meta::VOID {
            return Ok(false);
        }
        Ok(self.cast_standard(req, cur, true, true)?.is_none())
    }

    fn new_cast(&mut self, input: CNode, ct: usize) -> Result<CNode> {
        if self.partial(ct) {
            return Err("cast:partial-type".into());
        }
        if self.ty(ct).pointer_to_array {
            return Err("cast:address-of".into());
        }
        let time = self.time();
        self.stats.casts += 1;
        self.cast_types.insert(ct);
        let size = input.size();
        Ok(CNode::Op(Box::new(COp {
            head: POp {
                code: opc::CAST,
                time,
                out_size: size,
                extra: Extra::Cast {
                    out: ct,
                    address_of: false,
                },
                kids: Vec::new(),
            },
            out: Some(COut {
                info: Info {
                    ty: ct,
                    own: ct,
                    flags: F_IMPLIED,
                },
                local: ct,
            }),
            absorbed: false,
            bool_out: false,
            call: false,
            word: 0,
            ptradd_size: 0,
            ptrsub_offset: 0,
            ptrsub_matching: true,
            token: None,
            slots: vec![0],
            locals: vec![ct],
            kids: vec![input],
            ptrsub_cast: false,
            call_locked: (true, true),
        })))
    }

    /// `ActionSetCasts::castInput`.
    fn cast_input(
        &mut self,
        op: &mut COp,
        k: usize,
        explicit_out: bool,
        reader_code: Option<u32>,
    ) -> Result<()> {
        let Some(ct) = self.input_cast(op, k)? else {
            let unsigned = self.mark_explicit_unsigned(op, k, explicit_out, reader_code);
            let long = self.mark_explicit_long(op, k);
            let _ = (unsigned, long);
            return Ok(());
        };
        let mut vnin = std::mem::replace(&mut op.kids[k], CNode::Leaf(placeholder()));
        let is_cast = matches!(&vnin, CNode::Op(inner) if inner.code() == opc::CAST);
        if is_cast {
            // A cast is already in place (an output cast of the op that produced it).
            let multi = matches!(&vnin, CNode::Op(inner) if inner.out.as_ref().is_some_and(|out| out.info.flags & F_MULTI != 0));
            if !multi {
                self.update_type(&mut vnin, ct)?;
                if vnin.own() == ct {
                    op.kids[k] = vnin;
                    return Ok(());
                }
            }
            let CNode::Op(mut inner) = vnin else {
                unreachable!()
            };
            let earlier = inner.kids.remove(0);
            self.stats.casts_replaced += 1;
            self.edits.push(IrEdit::Replace {
                op: op.head.time,
                slot: op.slots[k],
            });
            if earlier.own() == ct {
                op.kids[k] = earlier;
                return Ok(());
            }
            vnin = earlier;
        } else if vnin.is_const() {
            self.update_type(&mut vnin, ct)?;
            if vnin.own() == ct {
                op.kids[k] = vnin;
                return Ok(());
            }
        } else if self.meta(ct) == meta::PTR && self.test_struct_offset0(ct, vnin.ty())? {
            // A PTRSUB would need a constant and a block position the semantic IR mirror does not model.
            return Err("cast:ptrsub-insert".into());
        }
        op.kids[k] = self.new_cast(vnin, ct)?;
        if let CNode::Op(cast) = &op.kids[k] {
            self.edits.push(IrEdit::Input {
                op: op.head.time,
                slot: op.slots[k],
                cast: cast.head.time,
            });
        }
        if op.code() == opc::PTRSUB && op.slots[k] == 0 {
            op.ptrsub_cast = true;
        }
        Ok(())
    }

    /// `ActionSetCasts::castOutput`: the node, wrapped in a cast if one is needed.
    fn cast_output(&mut self, mut op: Box<COp>, explicit_out: bool) -> Result<CNode> {
        let tokenct = self.output_token(&op)?;
        if self.partial(tokenct) {
            return Err("cast:partial-type".into());
        }
        let (out_high, out_flags) = {
            let out = op.out.as_ref().ok_or("cast:no-output")?;
            (out.info.ty, out.info.flags)
        };
        if tokenct == out_high {
            return Ok(CNode::Op(op));
        }
        let mut high_resolve = out_high;
        let mut force = false;
        let implied = !explicit_out;
        if implied {
            if out_flags & F_TYPELOCK != 0 {
                if out_flags & F_LONE_RETURN == 0 {
                    force = !self.op_identical(high_resolve, tokenct);
                }
            } else if self.meta(high_resolve) != meta::PTR {
                let out = op.out.as_mut().unwrap();
                out.info.own = tokenct;
                out.info.ty = tokenct;
                high_resolve = tokenct;
            } else if self.meta(tokenct) == meta::PTR {
                let outct = self.ty(high_resolve).base.ok_or("cast:pointer-without-pointee")?;
                let m = self.meta(outct);
                if m != meta::ARRAY && m != meta::STRUCT && m != meta::UNION {
                    let out = op.out.as_mut().unwrap();
                    out.info.own = tokenct;
                    out.info.ty = tokenct;
                    high_resolve = tokenct;
                }
            }
        }
        let mut ptrsub = false;
        if !force {
            if self.meta(high_resolve) == meta::PTR && self.test_struct_offset0(high_resolve, tokenct)? {
                ptrsub = true;
            } else if self.cast_standard(high_resolve, tokenct, false, true)?.is_none() {
                return Ok(CNode::Op(op));
            }
        }
        if ptrsub {
            // The inserted PTRSUB is itself visited by the pass (its own output token).
            return Err("cast:ptrsub-output".into());
        }
        if self.ty(tokenct).pointer_to_array {
            return Err("cast:address-of".into());
        }
        // The cast produces the original output; the op now produces a fresh implied value of the token type.
        let cast_out = {
            let out = op.out.as_ref().unwrap();
            Info {
                ty: high_resolve,
                own: out.info.own,
                flags: out.info.flags,
            }
        };
        {
            let out = op.out.as_mut().unwrap();
            out.info = Info {
                ty: tokenct,
                own: tokenct,
                flags: F_IMPLIED | (out.info.flags & (F_NZHIGH | F_WRITTEN)),
            };
        }
        let size = op.head.out_size;
        let time = self.time();
        self.stats.casts += 1;
        self.cast_types.insert(high_resolve);
        self.edits.push(IrEdit::Output {
            op: op.head.time,
            cast: time,
        });
        Ok(CNode::Op(Box::new(COp {
            head: POp {
                code: opc::CAST,
                time,
                out_size: size,
                extra: Extra::Cast {
                    out: high_resolve,
                    address_of: false,
                },
                kids: Vec::new(),
            },
            out: Some(COut {
                info: cast_out,
                local: high_resolve,
            }),
            absorbed: false,
            bool_out: false,
            call: false,
            word: 0,
            ptradd_size: 0,
            ptrsub_offset: 0,
            ptrsub_matching: true,
            token: None,
            slots: vec![0],
            locals: vec![tokenct],
            kids: vec![CNode::Op(op)],
            ptrsub_cast: false,
            call_locked: (true, true),
        })))
    }

    /// One op in block order: its inputs' producers first, then its own
    /// revalidation, input casts, pointer warnings and output cast.
    fn op(
        &mut self,
        mut op: Box<COp>,
        reader_code: Option<u32>,
        explicit_out: bool,
    ) -> Result<CNode> {
        let code = op.code();
        let kids = std::mem::take(&mut op.kids);
        for kid in kids {
            op.kids.push(match kid {
                CNode::Op(inner) => self.op(inner, Some(code), false)?,
                leaf => leaf,
            });
        }
        if code == opc::CAST {
            return Ok(CNode::Op(op));
        }
        if code == opc::PTRADD {
            let k0 = Self::kid_index(&op, 0)?;
            let ct = op.kids[k0].ty();
            let fits = self.meta(ct) == meta::PTR
                && self
                    .ty(self.ty(ct).base.ok_or("cast:pointer-without-pointee")?)
                    .align_size as u64
                    == op.ptradd_size * u64::from(self.ty(ct).word_size.max(1));
            if !fits {
                return Err("cast:ptradd-undo".into());
            }
        } else if code == opc::PTRSUB && !op.ptrsub_matching {
            if op.ptrsub_offset == 0 {
                op.head.code = opc::COPY;
                op.head.extra = Extra::None;
                op.token = None;
            } else {
                return Err("cast:ptrsub-misfit".into());
            }
        }
        let code = op.code();
        for k in 0..op.kids.len() {
            self.cast_input(&mut op, k, explicit_out, reader_code)?;
        }
        if code == opc::LOAD || code == opc::STORE {
            let pointer_k = Self::kid_index(&op, 1)?;
            let ptrtype = op.kids[pointer_k].ty();
            let valsize = if code == opc::LOAD {
                op.head.out_size
            } else {
                op.kids[Self::kid_index(&op, 2)?].size()
            };
            let ok = self.meta(ptrtype) == meta::PTR
                && self
                    .ty(self.ty(ptrtype).base.ok_or("cast:pointer-without-pointee")?)
                    .size
                    == valsize;
            if !ok {
                self.warnings.push((op.head.time, code));
                self.stats.warnings += 1;
            }
        }
        if op.out.is_none() {
            return Ok(CNode::Op(op));
        }
        self.cast_output(op, explicit_out)
    }

    /// Casts one statement. `Err` names why the worker cannot decide this
    /// function's casts.
    pub fn statement(&mut self, tree: CTree) -> Result<CTree> {
        let CTree { out, root } = tree;
        let root = match root {
            CNode::Op(op) => {
                self.op(op, None, out.is_some())?
            }
            leaf => leaf,
        };
        Ok(CTree { out, root })
    }

    /// The print tree of a cast statement, with the extras that depend on
    /// the final shape (the types of extensions and pieces, whether an
    /// extension is implied).
    pub fn finish(&mut self, tree: CTree) -> Result<PrintTree> {
        let root = self.convert(tree.root, None)?;
        Ok(PrintTree {
            out: tree.out.map(|leaf| leaf.node),
            root,
        })
    }

    fn convert(&mut self, node: CNode, reader: Option<Reader>) -> Result<PNode> {
        let mut op = match node {
            CNode::Leaf(mut leaf) => {
                if self.rules.bare_aggregate_constants
                    && let PNode::Const(c) = &mut leaf.node
                        && c.kind == ConstKind::Default
                            && matches!(self.meta(c.ty), meta::ARRAY | meta::STRUCT | meta::UNION)
                        {
                            c.kind = ConstKind::Bare;
                            self.stats.bare_constants += 1;
                        }
                if self.rules.null_call_arguments && reader.as_ref().is_some_and(|r| r.code == opc::CALL)
                    && let PNode::Const(c) = &mut leaf.node
                        && c.kind == ConstKind::Default && c.value == 0 && self.meta(c.ty) == meta::PTR {
                            c.kind = ConstKind::Bare;
                            self.stats.bare_constants += 1;
                        }
                return Ok(leaf.node);
            }
            CNode::Op(op) => op,
        };
        if op.code() == opc::PTRSUB && op.ptrsub_cast {
            return Err("cast:ptrsub-input-cast".into());
        }
        let out_ty = op.out.as_ref().map(|out| out.info.ty);
        let in_ty = op.kids.first().map(CNode::ty);
        let mut extra = op.head.extra.clone();
        match &mut extra {
            Extra::Ext {
                out,
                input,
                implied,
                address_of,
            } => {
                *out = out_ty.ok_or("cast:extension-output")?;
                *input = in_ty.ok_or("cast:extension-input")?;
                if self.ty(*out).pointer_to_array {
                    return Err("cast:address-of".into());
                }
                *implied = reader
                    .as_ref()
                    .is_some_and(|reader| self.extension_implied(*out, reader));
                *address_of = false;
            }
            Extra::Subpiece {
                out,
                input,
                address_of,
                ..
            } => {
                *out = out_ty.ok_or("cast:subpiece-output")?;
                if let Some(first) = in_ty {
                    *input = first;
                }
                if self.ty(*out).pointer_to_array {
                    return Err("cast:address-of".into());
                }
                *address_of = false;
            }
            Extra::Cast { out, address_of } => {
                *out = out_ty.ok_or("cast:cast-output")?;
                if self.ty(*out).pointer_to_array {
                    return Err("cast:address-of".into());
                }
                *address_of = false;
            }
            Extra::Int2Float { out } => *out = out_ty.ok_or("cast:int2float-output")?,
            _ => {}
        }
        // What the kids' extensions see of this op.
        let summaries: Vec<(usize, Neighbour)> = op
            .slots
            .iter()
            .zip(op.kids.iter())
            .map(|(&slot, kid)| {
                (
                    slot,
                    Neighbour {
                        constant: kid.is_const(),
                        explicit: kid.is_explicit(),
                        size: kid.size(),
                        meta: self.meta(kid.ty()),
                    },
                )
            })
            .collect();
        let code = op.code();
        let slots = op.slots.clone();
        if code == opc::CALL && (!op.call_locked.0 || !op.call_locked.1) {
            self.call_types.push(CallType {
                time: op.head.time,
                input_locked: op.call_locked.0,
                output_locked: op.call_locked.1,
                params: op.kids.iter().map(CNode::ty).collect(),
                ret: op.out.as_ref().map(|out| out.info.ty),
            });
        }
        let mut kids = std::mem::take(&mut op.kids);
        if op.absorbed && code == opc::FLOAT_INT2FLOAT {
            // The extension the conversion absorbs prints as its input (after the casts of that input).
            if let Some(first) = kids.first_mut() {
                let mut node = std::mem::replace(first, CNode::Leaf(placeholder()));
                loop {
                    match node {
                        CNode::Op(mut inner) if inner.code() == opc::CAST => node = inner.kids.remove(0),
                        CNode::Op(mut inner) if inner.code() == opc::INT_ZEXT => {
                            node = inner.kids.remove(0);
                            break;
                        }
                        other => {
                            node = other;
                            break;
                        }
                    }
                }
                *first = node;
            }
        }
        let mut converted = Vec::with_capacity(kids.len());
        for (index, kid) in kids.into_iter().enumerate() {
            let slot = slots[index];
            let other = summaries
                .iter()
                .find(|(s, _)| *s == 1 - slot.min(1) && slots.len() > 1)
                .map(|(_, n)| n.clone());
            converted.push(self.convert(kid, Some(Reader { code, other }))?);
        }
        Ok(PNode::Op(Box::new(POp {
            code,
            time: op.head.time,
            out_size: op.head.out_size,
            extra,
            kids: converted,
        })))
    }
}

#[derive(Clone)]
struct Neighbour {
    constant: bool,
    explicit: bool,
    size: u32,
    meta: u8,
}

/// The op that reads a node, as `isExtensionCastImplied` looks at it.
struct Reader {
    code: u32,
    other: Option<Neighbour>,
}

fn placeholder() -> CLeaf {
    CLeaf {
        node: PNode::No("cast:placeholder".into()),
        info: Info::default(),
    }
}

/// The result of the worker's cast pass over a function.
pub struct Cast {
    pub trees: Vec<PrintTree>,
    pub stats: CastStats,
    pub warnings: Vec<(u64, u32)>,
}

/// Casts a function's statements in order.
pub fn cast_function(
    tables: &mut Tables,
    options: &Options,
    rules: &CastRules,
    statements: Vec<CTree>,
    loop_ops: Vec<CTree>,
) -> Result<Cast> {
    check_supported(tables, options)?;
    let mut pass = Pass::new(tables, options, rules);
    // The decompiler found the for-loops on the p-code before the casts. A cast around the output of an
    // initializer or iterator makes the cast the loop's statement, which is what is printed
    // (`piVar2 = (int *)piVar2[0xc]`); declining such a function would let `ActionSetCasts` cast it after the
    // loop was chosen, which prints the loop header wrong. The loop statements are cast here only so that a
    // function with one the pass cannot cast is declined as a whole.
    for tree in loop_ops {
        check_tree(&tree)?;
        pass.statement(tree)?;
    }
    pass.warnings.clear();
    pass.stats = CastStats::default();
    pass.cast_types.clear();
    let mut trees = Vec::with_capacity(statements.len());
    for statement in statements {
        check_tree(&statement)?;
        let cast = pass.statement(statement)?;
        trees.push(pass.finish(cast)?);
    }
    Ok(Cast {
        trees,
        stats: pass.stats,
        warnings: pass.warnings,
    })
}

/// Types the pass declines to decide about: unions and types that need a
/// resolution, partial structures, address spaces on pointers.
pub fn check_supported(tables: &Tables, options: &Options) -> Result<()> {
    if let Some(reason) = options.unsupported() {
        return Err(reason.to_string());
    }
    if options.no_casts {
        return Err("option:nocasts".into());
    }
    for ty in &tables.types {
        if ty.needs_resolution {
            return Err("cast:needs-resolution".into());
        }
        if ty.space != 0 {
            return Err("cast:pointer-space".into());
        }
    }
    Ok(())
}

/// Nodes the printer refuses are un-castable: PrintC's fragment of them
/// would not have its casts.
pub fn check_tree(tree: &CTree) -> Result<()> {
    fn walk(node: &CNode) -> Result<()> {
        match node {
            CNode::Leaf(leaf) => match &leaf.node {
                PNode::No(reason) => Err(reason.clone()),
                _ => Ok(()),
            },
            CNode::Op(op) => {
                if let Extra::Ptrsub(kind) = &op.head.extra {
                    match kind {
                        PtrsubKind::No(reason) => return Err(reason.clone()),
                        PtrsubKind::Spacebase { leaf, .. } => {
                            if let PNode::No(reason) = &**leaf {
                                return Err(reason.clone());
                            }
                        }
                        _ => {}
                    }
                }
                op.kids.iter().try_for_each(walk)
            }
        }
    }
    if let Some(leaf) = &tree.out {
        walk(&CNode::Leaf(leaf.clone()))?;
    }
    walk(&tree.root)
}

/// A readable one-line form of a pre-cast tree, for `ROMWRIGHT_RUST_CASTS_DEBUG`.
pub fn debug_text(tables: &Tables, tree: &CTree) -> String {
    fn ty(tables: &Tables, index: usize, depth: usize) -> String {
        let t = &tables.types[index];
        if depth > 4 {
            return "..".into();
        }
        match (t.meta, t.base) {
            (meta::PTR | meta::PTRREL, Some(base)) => format!("*{}", ty(tables, base, depth + 1)),
            _ if t.name.is_empty() => format!("<m{}s{}>", t.meta, t.size),
            _ => t.name.clone(),
        }
    }
    fn info(tables: &Tables, info: &Info) -> String {
        let mut text = ty(tables, info.ty, 0).to_string();
        if info.own != info.ty {
            text.push_str(&format!("/own={}", ty(tables, info.own, 0)));
        }
        if info.flags & F_TYPELOCK != 0 {
            text.push_str("/lock");
        }
        if info.flags & F_NZHIGH != 0 {
            text.push_str("/nz");
        }
        text
    }
    fn node(tables: &Tables, n: &CNode, out: &mut String) {
        match n {
            CNode::Leaf(leaf) => {
                match &leaf.node {
                    PNode::Const(c) => out.push_str(&format!("#{:x}", c.value)),
                    PNode::Symbol { sym, .. } => out.push_str(&tables.symbols[*sym].name),
                    PNode::Partial(p) => out.push_str(&format!("{}@{}", tables.symbols[p.sym].name, p.offset)),
                    other => out.push_str(&format!("{other:?}").chars().take(30).collect::<String>()),
                }
                out.push_str(&format!(":{}", info(tables, &leaf.info)));
            }
            CNode::Op(op) => {
                out.push_str(&format!("({}", op.head.code));
                if let Some(o) = &op.out {
                    out.push_str(&format!("[{}|loc={}]", info(tables, &o.info), ty(tables, o.local, 0)));
                }
                if op.absorbed {
                    out.push_str("{absorbed}");
                }
                for (slot, kid) in op.slots.iter().zip(op.kids.iter()) {
                    out.push_str(&format!(" s{slot}="));
                    node(tables, kid, out);
                }
                out.push(')');
            }
        }
    }
    let mut out = String::new();
    if let Some(leaf) = &tree.out {
        node(tables, &CNode::Leaf(leaf.clone()), &mut out);
        out.push_str(" = ");
    }
    node(tables, &tree.root, &mut out);
    out
}

/// A type table entry as the document's type model (`DecompType`), for the
/// spelling pass: name and id for named types, the pointee for pointers.
pub fn describe(tables: &Tables, index: usize, depth: usize) -> romwright_model::DecompType {
    let ty = &tables.types[index];
    let metatype = match ty.meta {
        meta::VOID => "void",
        meta::SPACEBASE => "spacebase",
        meta::UNKNOWN => "unknown",
        meta::INT => "int",
        meta::UINT => "uint",
        meta::BOOL => "bool",
        meta::CODE => "code",
        meta::FLOAT => "float",
        meta::PTR => "ptr",
        meta::PTRREL => "ptrrel",
        meta::ARRAY => "array",
        meta::STRUCT => "struct",
        meta::UNION => "union",
        meta::PARTIALSTRUCT => "partialstruct",
        _ => "partialunion",
    };
    romwright_model::DecompType {
        name: (!ty.name.is_empty()).then(|| ty.name.clone()),
        id: (ty.id != 0).then_some(ty.id),
        size: Some(u64::from(ty.size)),
        metatype: Some(metatype.to_string()),
        element_count: (ty.meta == meta::ARRAY).then_some(u64::from(ty.elements)),
        target: match ty.base {
            Some(base) if depth < 8 && matches!(ty.meta, meta::PTR | meta::PTRREL | meta::ARRAY) => {
                Some(Box::new(describe(tables, base, depth + 1)))
            }
            _ => None,
        },
        prototype: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::printc::tree::SymbolDesc;

    /// 0 int, 1 uint, 2 undefined4, 3 undefined4 *.
    fn tables() -> Tables {
        let base = |name: &str, meta: u8, submeta: u8| TypeDesc {
            id: 1,
            name: name.into(),
            display_name: name.into(),
            meta,
            size: 4,
            submeta,
            align_size: 4,
            ..TypeDesc::default()
        };
        Tables {
            types: vec![
                base("int", meta::INT, 17),
                base("uint", meta::UINT, 16),
                base("undefined4", meta::UNKNOWN, 21),
                TypeDesc {
                    meta: meta::PTR,
                    base: Some(2),
                    submeta: 6,
                    word_size: 1,
                    ..base("", meta::PTR, 6)
                },
            ],
            symbols: vec![SymbolDesc {
                highlight: 4,
                name: "x".into(),
                scopes: Vec::new(),
            }],
            promote_size: 4,
            ..Tables::default()
        }
    }

    fn leaf(ty: usize) -> CNode {
        CNode::Leaf(CLeaf {
            node: PNode::Symbol {
                vn: Some(1),
                size: 4,
                sym: 0,
            },
            info: Info {
                ty,
                own: ty,
                flags: F_WRITTEN,
            },
        })
    }

    fn op(code: u32, ty: usize, flags: u32, slots: Vec<usize>, locals: Vec<usize>, kids: Vec<CNode>) -> CNode {
        CNode::Op(Box::new(COp {
            head: POp {
                code,
                time: 7,
                out_size: 4,
                extra: if code == opc::CAST {
                    Extra::Cast {
                        out: ty,
                        address_of: false,
                    }
                } else {
                    Extra::None
                },
                kids: Vec::new(),
            },
            out: Some(COut {
                info: Info {
                    ty,
                    own: ty,
                    flags: flags | F_IMPLIED,
                },
                local: 0,
            }),
            absorbed: false,
            bool_out: false,
            call: false,
            word: 0,
            ptradd_size: 0,
            ptrsub_offset: 0,
            ptrsub_matching: true,
            token: None,
            slots,
            locals,
            kids,
            ptrsub_cast: false,
            call_locked: (true, true),
        }))
    }

    /// `x + (T *)(x + x)`: the inner sum's output is a pointer, read by a second addition that needs an integer.
    fn sum_of_a_cast(multi: bool) -> CNode {
        let inner = op(opc::INT_ADD, 0, 0, vec![0, 1], vec![0, 0], vec![leaf(0), leaf(0)]);
        let cast = op(opc::CAST, 3, if multi { F_MULTI } else { 0 }, vec![0], vec![3], vec![inner]);
        op(opc::INT_ADD, 0, 0, vec![0, 1], vec![0, 0], vec![leaf(0), cast])
    }

    fn second_input(node: CNode) -> (u32, usize) {
        let CNode::Op(outer) = node else { panic!("not an op") };
        let CNode::Op(kid) = &outer.kids[1] else { panic!("not an op") };
        (kid.code(), kid.out.as_ref().unwrap().info.ty)
    }

    #[test]
    fn a_cast_read_by_one_op_takes_the_type_that_op_needs() {
        let mut tables = tables();
        let (options, rules) = (Options::default(), CastRules::default());
        let mut pass = Pass::new(&mut tables, &options, &rules);
        let CNode::Op(root) = sum_of_a_cast(false) else { unreachable!() };
        let node = pass.op(root, None, true).unwrap();
        // `castInput` retypes the cast in place: `(int)(x + x)`.
        assert_eq!(second_input(node), (opc::CAST, 0));
    }

    #[test]
    fn a_cast_read_by_several_ops_is_not_retyped_for_one_of_them() {
        let mut tables = tables();
        let (options, rules) = (Options::default(), CastRules::default());
        let mut pass = Pass::new(&mut tables, &options, &rules);
        let CNode::Op(root) = sum_of_a_cast(true) else { unreachable!() };
        let node = pass.op(root, None, true).unwrap();
        // `loneDescend() != op`: the reader goes to the cast's input, which already has the type it needs.
        assert_eq!(second_input(node), (opc::INT_ADD, 0));
    }

    #[test]
    fn cast_standard_only_casts_what_c_will_not_convert() {
        let mut tables = tables();
        let (options, rules) = (Options::default(), CastRules::default());
        let pass = Pass::new(&mut tables, &options, &rules);
        // int <- uint and uint <- int need no cast when signedness does not matter; a pointer into an integer does.
        assert_eq!(pass.cast_standard(0, 1, false, true).unwrap(), None);
        assert_eq!(pass.cast_standard(0, 3, false, true).unwrap(), Some(0));
        assert_eq!(pass.cast_standard(3, 0, true, true).unwrap(), Some(3));
        assert_eq!(pass.cast_standard(3, 3, true, true).unwrap(), None);
    }
}
