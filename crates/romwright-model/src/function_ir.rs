//! Native SSA identities, ordered control flow, and recovered types.
//!
//! Operation IDs are Ghidra SeqNum::getTime() (the wire `uniq` attribute and
//! token `opref`). Value IDs are Varnode::getCreateIndex(), not storage offsets.
//! Block IDs name basic blocks, not instruction addresses. A phi input's slot
//! indexes its block's predecessor list; a conditional's successors are false,
//! then true. Presentation tokens are not a semantic input to this model.
use crate::{Address, DecompType};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

macro_rules! identity {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub u64);
    };
}
identity!(ValueId);
identity!(OperationId);
identity!(BlockId);

macro_rules! opcodes {
    ($($name:ident = $value:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[allow(non_camel_case_types)]
        #[repr(u8)]
        pub enum Opcode { $($name = $value),+ }
        impl TryFrom<u64> for Opcode {
            type Error = String;
            fn try_from(value: u64) -> Result<Self, String> {
                match value { $($value => Ok(Self::$name),)+ _ => Err(format!("unknown p-code opcode {value}")) }
            }
        }
    };
}
// Pinned decompiler/opcodes.hh. Slot 45 is reserved, not an operation.
opcodes! {
    COPY=1, LOAD=2, STORE=3, BRANCH=4, CBRANCH=5, BRANCHIND=6,
    CALL=7, CALLIND=8, CALLOTHER=9, RETURN=10,
    INT_EQUAL=11, INT_NOTEQUAL=12, INT_SLESS=13, INT_SLESSEQUAL=14,
    INT_LESS=15, INT_LESSEQUAL=16, INT_ZEXT=17, INT_SEXT=18,
    INT_ADD=19, INT_SUB=20, INT_CARRY=21, INT_SCARRY=22, INT_SBORROW=23,
    INT_2COMP=24, INT_NEGATE=25, INT_XOR=26, INT_AND=27, INT_OR=28,
    INT_LEFT=29, INT_RIGHT=30, INT_SRIGHT=31, INT_MULT=32,
    INT_DIV=33, INT_SDIV=34, INT_REM=35, INT_SREM=36,
    BOOL_NEGATE=37, BOOL_XOR=38, BOOL_AND=39, BOOL_OR=40,
    FLOAT_EQUAL=41, FLOAT_NOTEQUAL=42, FLOAT_LESS=43, FLOAT_LESSEQUAL=44,
    FLOAT_NAN=46, FLOAT_ADD=47, FLOAT_DIV=48, FLOAT_MULT=49, FLOAT_SUB=50,
    FLOAT_NEG=51, FLOAT_ABS=52, FLOAT_SQRT=53, FLOAT_INT2FLOAT=54,
    FLOAT_FLOAT2FLOAT=55, FLOAT_TRUNC=56, FLOAT_CEIL=57, FLOAT_FLOOR=58,
    FLOAT_ROUND=59, MULTIEQUAL=60, INDIRECT=61, PIECE=62, SUBPIECE=63,
    CAST=64, PTRADD=65, PTRSUB=66, SEGMENTOP=67, CPOOLREF=68,
    NEW=69, INSERT=70, ZPULL=71, POPCOUNT=72, LZCOUNT=73, SPULL=74,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum IrSpace {
    Index(u64),
    Special(u8),
    Named(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePiece {
    pub space: String,
    pub offset: u64,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrValue {
    pub id: ValueId,
    pub space: IrSpace,
    /// Absent for joined storage and unresolved call-spec annotations.
    pub offset: Option<u64>,
    pub size: Option<u32>,
    /// Most significant piece first, independent of target byte order.
    pub pieces: Vec<StoragePiece>,
    pub input: bool,
    pub persistent: bool,
    pub address_tied: bool,
    pub unaffected: bool,
    pub volatile: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Operand {
    Value(ValueId),
    Operation(OperationId),
    Space(IrSpace),
    Void,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Pure,
    ReadMemory,
    WriteMemory,
    Call,
    Control,
    Indirect,
    Opaque,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrOperation {
    pub id: OperationId,
    pub address: Address,
    pub opcode: Opcode,
    pub output: Option<ValueId>,
    pub inputs: Vec<Operand>,
}
impl IrOperation {
    /// Conservative effect class. Unknown intrinsics and indirect effects may
    /// not be treated as arithmetic merely because their output is unused.
    pub fn effect(&self) -> Effect {
        match self.opcode {
            Opcode::LOAD => Effect::ReadMemory,
            Opcode::STORE => Effect::WriteMemory,
            Opcode::CALL | Opcode::CALLIND => Effect::Call,
            Opcode::BRANCH | Opcode::CBRANCH | Opcode::BRANCHIND | Opcode::RETURN => {
                Effect::Control
            }
            Opcode::INDIRECT => Effect::Indirect,
            Opcode::CALLOTHER | Opcode::NEW | Opcode::CPOOLREF | Opcode::SEGMENTOP => {
                Effect::Opaque
            }
            _ => Effect::Pure,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrBlock {
    pub id: BlockId,
    pub operations: Vec<IrOperation>,
    pub predecessors: Vec<BlockId>,
    pub successors: Vec<BlockId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrSymbol {
    pub id: u64,
    pub name: String,
    pub data_type: DecompType,
    pub volatile: bool,
    pub global: bool,
    pub address: Option<Address>,
    /// Physical pieces when the symbol spans registers or stack locations.
    /// Such storage has no single `address`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pieces: Vec<StoragePiece>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighVariable {
    pub representative: ValueId,
    pub class: String,
    pub symbol: Option<IrSymbol>,
    pub symbol_offset: Option<i64>,
    pub type_locked: bool,
    pub data_type: DecompType,
    pub members: Vec<ValueId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PassRole {
    Analyze,
    Transform,
    Structure,
    Diagnostic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassReport {
    pub name: String,
    pub role: PassRole,
    /// Facts, edits, cut edges, or diagnostics produced by this role.
    pub items: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrDiagnostic {
    pub pass: String,
    pub message: String,
    pub operation: Option<OperationId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowCut {
    pub source: BlockId,
    pub successor_slot: usize,
    pub target: BlockId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionIr {
    pub values: BTreeMap<ValueId, IrValue>,
    pub blocks: Vec<IrBlock>,
    pub high_variables: Vec<HighVariable>,
    #[serde(default)]
    pub type_evidence: BTreeMap<ValueId, crate::type_evidence::Class>,
    #[serde(default)]
    pub control_flow_cuts: Vec<ControlFlowCut>,
    #[serde(default)]
    pub passes: Vec<PassReport>,
    #[serde(default)]
    pub diagnostics: Vec<IrDiagnostic>,
    /// Types the worker's cast pass named in the printed C that no variable
    /// or prototype of the function carries (the decompiler no longer casts,
    /// so its document does not list them): what the C spelling pass needs
    /// to rename them like any other.
    #[serde(default)]
    pub cast_types: Vec<crate::DecompType>,
}

impl FunctionIr {
    /// SSA evidence describes the exact value, not a physical register slot
    /// that may be read at several widths before normalization.
    pub fn validate_evidence(
        &self,
        evidence: &BTreeMap<ValueId, crate::type_evidence::Class>,
    ) -> Result<(), String> {
        use crate::type_evidence::Class;
        for (id, class) in evidence {
            let value = self
                .values
                .get(id)
                .ok_or("type evidence references an unknown value")?;
            let bits = match class {
                Class::Opaque(bits)
                | Class::Num(bits)
                | Class::Int(bits)
                | Class::Uint(bits)
                | Class::IntOrUint(bits)
                | Class::Float(bits) => Some(*bits),
                _ => None,
            };
            if bits.is_some() && value.size.and_then(|bytes| bytes.checked_mul(8)) != bits {
                return Err(format!("type evidence changes the width of {id:?}"));
            }
        }
        Ok(())
    }

    /// Reject dangling identities, duplicate definitions, and edge/phi order
    /// corruption at the process boundary, before a semantic pass can run.
    pub fn validate(&self) -> Result<(), String> {
        let mut blocks = BTreeMap::new();
        let mut operations = BTreeSet::new();
        let mut definitions = BTreeSet::new();
        for block in &self.blocks {
            if blocks.insert(block.id, block).is_some() {
                return Err(format!("duplicate basic block {:?}", block.id));
            }
            for op in &block.operations {
                if !operations.insert(op.id) {
                    return Err(format!("duplicate operation {:?}", op.id));
                }
                if let Some(output) = op.output {
                    if !self.values.contains_key(&output) || !definitions.insert(output) {
                        return Err(format!("invalid SSA definition {output:?}"));
                    }
                }
                if op.opcode == Opcode::MULTIEQUAL && op.inputs.len() != block.predecessors.len() {
                    return Err(format!(
                        "phi {:?} has no input for every predecessor",
                        op.id
                    ));
                }
            }
        }
        for (id, value) in &self.values {
            if *id != value.id {
                return Err(format!("value key does not match {id:?}"));
            }
        }
        let mut forward = BTreeMap::new();
        let mut reverse = BTreeMap::new();
        for block in &self.blocks {
            for target in &block.successors {
                if !blocks.contains_key(target) {
                    return Err(format!("missing successor {target:?}"));
                }
                *forward.entry((block.id, *target)).or_insert(0usize) += 1;
            }
            for source in &block.predecessors {
                if !blocks.contains_key(source) {
                    return Err(format!("missing predecessor {source:?}"));
                }
                *reverse.entry((*source, block.id)).or_insert(0usize) += 1;
            }
            for op in &block.operations {
                for input in &op.inputs {
                    let valid = match input {
                        Operand::Value(id) => self.values.contains_key(id),
                        Operand::Operation(id) => operations.contains(id),
                        Operand::Space(_) | Operand::Void => true,
                    };
                    if !valid {
                        return Err(format!("dangling operand in {:?}", op.id));
                    }
                }
            }
        }
        if forward != reverse {
            return Err("inconsistent predecessor/successor edges".into());
        }
        let mut members = BTreeSet::new();
        for high in &self.high_variables {
            if !high.members.contains(&high.representative) {
                return Err("high variable omits its representative".into());
            }
            for member in &high.members {
                if !self.values.contains_key(member) || !members.insert(*member) {
                    return Err(format!("invalid high-variable member {member:?}"));
                }
            }
        }
        self.validate_evidence(&self.type_evidence)?;
        let mut cuts = BTreeSet::new();
        for cut in &self.control_flow_cuts {
            if blocks
                .get(&cut.source)
                .and_then(|block| block.successors.get(cut.successor_slot))
                != Some(&cut.target)
                || !cuts.insert((cut.source, cut.successor_slot))
            {
                return Err("invalid original control-flow cut".into());
            }
        }
        if self.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .operation
                .is_some_and(|operation| !operations.contains(&operation))
        }) {
            return Err("diagnostic references an unknown operation".into());
        }
        Ok(())
    }
}
