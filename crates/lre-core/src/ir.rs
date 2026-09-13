//! The IR handoff: a typed mid-level form between raw p-code and the
//! analyses that consume it.
//!
//! Raw p-code arrives as `PcodeOp { opcode: String, … }` — an untyped opcode
//! string and untyped space strings, so every consumer re-parses the same
//! `match op.opcode.as_str()` and a typo (`"INT_SLESS"` vs `"INT_SLES"`) is a
//! silent fallthrough to the default arm. This module is the normalization
//! layer the architecture calls for: `lift` turns a `PcodeInstruction` into
//! an `IrInstruction` whose ops carry a typed `Opcode`, and consumers match
//! on the enum — exhaustive, checked, and free of string compares.
//!
//! The opcode set is Ghidra's `OpCode` (`third_party/ghidra/decompiler/
//! opcodes.hh`, CPUI_COPY=1 … CPUI_SPULL=74), keyed by the *string* the
//! translator emits (`opcodes.cc` `opcode_name[]`) — note the names differ
//! from the enum: `CPUI_PTRADD`→`"LABEL"`, `CPUI_PTRSUB`→`"CROSSBUILD"`,
//! `CPUI_SPULL`→`"EXTRACT"`. `Opcode::Other` keeps a name this build does
//! not know rather than dropping the op.

use crate::native_runtime::{PcodeInstruction, PcodeOp, PcodeVarnode};
use std::str::FromStr;

/// A typed p-code opcode — the `opcode_name[]` strings of `opcodes.cc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Opcode {
    Copy,
    Load,
    Store,
    Branch,
    CBranch,
    BranchInd,
    Call,
    CallInd,
    CallOther,
    Return,
    IntEqual,
    IntNotEqual,
    IntSLess,
    IntSLessEqual,
    IntLess,
    IntLessEqual,
    IntZExt,
    IntSExt,
    IntAdd,
    IntSub,
    IntCarry,
    IntSCarry,
    IntSBorrow,
    Int2Comp,
    IntNegate,
    IntXor,
    IntAnd,
    IntOr,
    IntLeft,
    IntRight,
    IntSRight,
    IntMult,
    IntDiv,
    IntSDiv,
    IntRem,
    IntSRem,
    BoolNegate,
    BoolXor,
    BoolAnd,
    BoolOr,
    FloatEqual,
    FloatNotEqual,
    FloatLess,
    FloatLessEqual,
    FloatNan,
    FloatAdd,
    FloatDiv,
    FloatMult,
    FloatSub,
    FloatNeg,
    FloatAbs,
    FloatSqrt,
    Int2Float,
    Float2Float,
    Trunc,
    Ceil,
    Floor,
    Round,
    /// `BUILD` — CPUI_PTRADD, array index.
    Build,
    /// `DELAY_SLOT` — CPUI_PTRSUB, sub-field.
    DelaySlot,
    Piece,
    Subpiece,
    Cast,
    /// `LABEL` — CPUI_PTRADD's emitted name.
    Label,
    /// `CROSSBUILD` — CPUI_PTRSUB's emitted name.
    CrossBuild,
    SegmentOp,
    CPoolRef,
    New,
    Insert,
    /// `EXTRACT` — CPUI_ZPULL's emitted name.
    Extract,
    PopCount,
    LzCount,
    /// `SPULL` — CPUI_SPULL's emitted name (signed bit-range extract).
    SPull,
    /// A name this build does not know; the op is kept, not dropped.
    Other,
}

impl Opcode {
    /// The string the translator emits for this opcode (`opcode_name[]`).
    pub fn name(self) -> &'static str {
        match self {
            Opcode::Copy => "COPY",
            Opcode::Load => "LOAD",
            Opcode::Store => "STORE",
            Opcode::Branch => "BRANCH",
            Opcode::CBranch => "CBRANCH",
            Opcode::BranchInd => "BRANCHIND",
            Opcode::Call => "CALL",
            Opcode::CallInd => "CALLIND",
            Opcode::CallOther => "CALLOTHER",
            Opcode::Return => "RETURN",
            Opcode::IntEqual => "INT_EQUAL",
            Opcode::IntNotEqual => "INT_NOTEQUAL",
            Opcode::IntSLess => "INT_SLESS",
            Opcode::IntSLessEqual => "INT_SLESSEQUAL",
            Opcode::IntLess => "INT_LESS",
            Opcode::IntLessEqual => "INT_LESSEQUAL",
            Opcode::IntZExt => "INT_ZEXT",
            Opcode::IntSExt => "INT_SEXT",
            Opcode::IntAdd => "INT_ADD",
            Opcode::IntSub => "INT_SUB",
            Opcode::IntCarry => "INT_CARRY",
            Opcode::IntSCarry => "INT_SCARRY",
            Opcode::IntSBorrow => "INT_SBORROW",
            Opcode::Int2Comp => "INT_2COMP",
            Opcode::IntNegate => "INT_NEGATE",
            Opcode::IntXor => "INT_XOR",
            Opcode::IntAnd => "INT_AND",
            Opcode::IntOr => "INT_OR",
            Opcode::IntLeft => "INT_LEFT",
            Opcode::IntRight => "INT_RIGHT",
            Opcode::IntSRight => "INT_SRIGHT",
            Opcode::IntMult => "INT_MULT",
            Opcode::IntDiv => "INT_DIV",
            Opcode::IntSDiv => "INT_SDIV",
            Opcode::IntRem => "INT_REM",
            Opcode::IntSRem => "INT_SREM",
            Opcode::BoolNegate => "BOOL_NEGATE",
            Opcode::BoolXor => "BOOL_XOR",
            Opcode::BoolAnd => "BOOL_AND",
            Opcode::BoolOr => "BOOL_OR",
            Opcode::FloatEqual => "FLOAT_EQUAL",
            Opcode::FloatNotEqual => "FLOAT_NOTEQUAL",
            Opcode::FloatLess => "FLOAT_LESS",
            Opcode::FloatLessEqual => "FLOAT_LESSEQUAL",
            Opcode::FloatNan => "FLOAT_NAN",
            Opcode::FloatAdd => "FLOAT_ADD",
            Opcode::FloatDiv => "FLOAT_DIV",
            Opcode::FloatMult => "FLOAT_MULT",
            Opcode::FloatSub => "FLOAT_SUB",
            Opcode::FloatNeg => "FLOAT_NEG",
            Opcode::FloatAbs => "FLOAT_ABS",
            Opcode::FloatSqrt => "FLOAT_SQRT",
            Opcode::Int2Float => "INT2FLOAT",
            Opcode::Float2Float => "FLOAT2FLOAT",
            Opcode::Trunc => "TRUNC",
            Opcode::Ceil => "CEIL",
            Opcode::Floor => "FLOOR",
            Opcode::Round => "ROUND",
            Opcode::Build => "BUILD",
            Opcode::DelaySlot => "DELAY_SLOT",
            Opcode::Piece => "PIECE",
            Opcode::Subpiece => "SUBPIECE",
            Opcode::Cast => "CAST",
            Opcode::Label => "LABEL",
            Opcode::CrossBuild => "CROSSBUILD",
            Opcode::SegmentOp => "SEGMENTOP",
            Opcode::CPoolRef => "CPOOLREF",
            Opcode::New => "NEW",
            Opcode::Insert => "INSERT",
            Opcode::Extract => "EXTRACT",
            Opcode::PopCount => "POPCOUNT",
            Opcode::LzCount => "LZCOUNT",
            Opcode::SPull => "SPULL",
            Opcode::Other => "OTHER",
        }
    }

    /// The broad class a consumer usually wants, so a match need not name
    /// every member of a family.
    pub fn kind(self) -> OpKind {
        use Opcode::*;
        match self {
            Copy | Cast => OpKind::Copy,
            Load | Store => OpKind::Memory,
            Branch | CBranch | BranchInd | Call | CallInd | CallOther | Return => OpKind::Control,
            IntEqual | IntNotEqual | IntSLess | IntSLessEqual | IntLess | IntLessEqual => {
                OpKind::IntCompare
            }
            IntAdd | IntSub | IntMult | IntDiv | IntSDiv | IntRem | IntSRem | IntCarry
            | IntSCarry | IntSBorrow | Int2Comp | IntNegate | IntXor | IntAnd | IntOr | IntLeft
            | IntRight | IntSRight | IntZExt | IntSExt | PopCount | LzCount => OpKind::IntArith,
            BoolNegate | BoolXor | BoolAnd | BoolOr => OpKind::Bool,
            FloatEqual | FloatNotEqual | FloatLess | FloatLessEqual | FloatNan | FloatAdd
            | FloatDiv | FloatMult | FloatSub | FloatNeg | FloatAbs | FloatSqrt | Int2Float
            | Float2Float | Trunc | Ceil | Floor | Round => OpKind::Float,
            Piece | Subpiece | Insert | Extract | SPull => OpKind::BitField,
            _ => OpKind::Other,
        }
    }
}

/// The broad semantic class of an `Opcode` — what an abstract interpreter
/// dispatches on when it does not need the exact operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Copy,
    Memory,
    Control,
    IntCompare,
    IntArith,
    Bool,
    Float,
    BitField,
    Other,
}

impl FromStr for Opcode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        use Opcode::*;
        Ok(match s {
            "COPY" => Copy,
            "LOAD" => Load,
            "STORE" => Store,
            "BRANCH" => Branch,
            "CBRANCH" => CBranch,
            "BRANCHIND" => BranchInd,
            "CALL" => Call,
            "CALLIND" => CallInd,
            "CALLOTHER" => CallOther,
            "RETURN" => Return,
            "INT_EQUAL" => IntEqual,
            "INT_NOTEQUAL" => IntNotEqual,
            "INT_SLESS" => IntSLess,
            "INT_SLESSEQUAL" => IntSLessEqual,
            "INT_LESS" => IntLess,
            "INT_LESSEQUAL" => IntLessEqual,
            "INT_ZEXT" => IntZExt,
            "INT_SEXT" => IntSExt,
            "INT_ADD" => IntAdd,
            "INT_SUB" => IntSub,
            "INT_CARRY" => IntCarry,
            "INT_SCARRY" => IntSCarry,
            "INT_SBORROW" => IntSBorrow,
            "INT_2COMP" => Int2Comp,
            "INT_NEGATE" => IntNegate,
            "INT_XOR" => IntXor,
            "INT_AND" => IntAnd,
            "INT_OR" => IntOr,
            "INT_LEFT" => IntLeft,
            "INT_RIGHT" => IntRight,
            "INT_SRIGHT" => IntSRight,
            "INT_MULT" => IntMult,
            "INT_DIV" => IntDiv,
            "INT_SDIV" => IntSDiv,
            "INT_REM" => IntRem,
            "INT_SREM" => IntSRem,
            "BOOL_NEGATE" => BoolNegate,
            "BOOL_XOR" => BoolXor,
            "BOOL_AND" => BoolAnd,
            "BOOL_OR" => BoolOr,
            "FLOAT_EQUAL" => FloatEqual,
            "FLOAT_NOTEQUAL" => FloatNotEqual,
            "FLOAT_LESS" => FloatLess,
            "FLOAT_LESSEQUAL" => FloatLessEqual,
            "FLOAT_NAN" => FloatNan,
            "FLOAT_ADD" => FloatAdd,
            "FLOAT_DIV" => FloatDiv,
            "FLOAT_MULT" => FloatMult,
            "FLOAT_SUB" => FloatSub,
            "FLOAT_NEG" => FloatNeg,
            "FLOAT_ABS" => FloatAbs,
            "FLOAT_SQRT" => FloatSqrt,
            "INT2FLOAT" => Int2Float,
            "FLOAT2FLOAT" => Float2Float,
            "TRUNC" => Trunc,
            "CEIL" => Ceil,
            "FLOOR" => Floor,
            "ROUND" => Round,
            "BUILD" => Build,
            "DELAY_SLOT" => DelaySlot,
            "PIECE" => Piece,
            "SUBPIECE" => Subpiece,
            "CAST" => Cast,
            "LABEL" => Label,
            "CROSSBUILD" => CrossBuild,
            "SEGMENTOP" => SegmentOp,
            "CPOOLREF" => CPoolRef,
            "NEW" => New,
            "INSERT" => Insert,
            "EXTRACT" => Extract,
            "POPCOUNT" => PopCount,
            "LZCOUNT" => LzCount,
            "SPULL" => SPull,
            _ => Other,
        })
    }
}

/// One IR operation: a typed opcode over the same varnodes the p-code named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrOp {
    pub opcode: Opcode,
    pub output: Option<PcodeVarnode>,
    pub inputs: Vec<PcodeVarnode>,
}

/// The IR of one machine instruction — the normalized form analyses consume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrInstruction {
    pub address: u64,
    pub length: u8,
    pub ops: Vec<IrOp>,
    /// `BAD` or `UNIMPL` when SLEIGH could not decode the address.
    pub error: Option<String>,
}

impl IrOp {
    /// Lift one raw p-code op, typing its opcode.
    pub fn from_pcode(op: &PcodeOp) -> Self {
        Self {
            opcode: Opcode::from_str(&op.opcode).unwrap_or(Opcode::Other),
            output: op.output.clone(),
            inputs: op.inputs.clone(),
        }
    }
}

/// Lift one machine instruction's p-code into the IR.
pub fn lift(instruction: &PcodeInstruction) -> IrInstruction {
    IrInstruction {
        address: instruction.address,
        length: instruction.length,
        ops: instruction.ops.iter().map(IrOp::from_pcode).collect(),
        error: instruction.error.clone(),
    }
}

/// Lift a slice of instructions.
pub fn lift_all(instructions: &[PcodeInstruction]) -> Vec<IrInstruction> {
    instructions.iter().map(lift).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_round_trips_every_known_name() {
        // Every name in opcodes.cc opcode_name[] maps to a typed opcode and
        // back to the same string.
        for (name, opc) in [
            ("COPY", Opcode::Copy),
            ("INT_SLESS", Opcode::IntSLess),
            ("SUBPIECE", Opcode::Subpiece),
            ("LABEL", Opcode::Label),
            ("CROSSBUILD", Opcode::CrossBuild),
            ("EXTRACT", Opcode::Extract),
            ("SPULL", Opcode::SPull),
            ("POPCOUNT", Opcode::PopCount),
        ] {
            assert_eq!(Opcode::from_str(name), Ok(opc), "{name}");
            assert_eq!(opc.name(), name, "{name}");
        }
        assert_eq!(Opcode::from_str("NOT_A_REAL_OP"), Ok(Opcode::Other));
    }

    #[test]
    fn lift_types_the_opcode() {
        let instruction = PcodeInstruction {
            address: 0x1000,
            length: 4,
            ops: vec![PcodeOp {
                opcode: "INT_ADD".into(),
                output: Some(PcodeVarnode {
                    space: "register".into(),
                    offset: 0x20,
                    size: 4,
                }),
                inputs: vec![],
            }],
            error: None,
        };
        let ir = lift(&instruction);
        assert_eq!(ir.ops[0].opcode, Opcode::IntAdd);
        assert_eq!(ir.ops[0].opcode.kind(), OpKind::IntArith);
    }
}
