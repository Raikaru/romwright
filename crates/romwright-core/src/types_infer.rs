//! Type inference over p-code, scored against the compiler's own DWARF.
//!
//! The shape is TIE's: every operation an operand takes part in is a
//! constraint on what that operand can be, constraints are joined over a
//! small lattice, and the answer is the join -- never a guess where nothing
//! constrained it. What p-code makes observable is exactly what an
//! instruction set commits to:
//!
//! * an address operand of `LOAD`/`STORE` holds a pointer;
//! * the target of `CALLIND` holds a code pointer;
//! * `INT_SLESS`, `INT_SBORROW`, `INT_SRIGHT` and `INT_SEXT` read their
//!   operand as signed; `INT_LESS`, `INT_CARRY`, `INT_RIGHT` and `INT_ZEXT`
//!   read it as unsigned;
//! * every `FLOAT_*` operation reads its operands as floating point;
//! * width comes from the varnode, which SLEIGH already sized.
//!
//! Nothing here invents a struct: an aggregate passed by value is
//! indistinguishable from the integers it is passed in, and claiming
//! otherwise would be a guess with no evidence behind it. `Unknown` is a
//! real answer and is scored as one.
//!
//! The lattice is a join semilattice with `Unknown` at the bottom and
//! `Top` where two irreconcilable facts meet -- an operand read as both a
//! pointer and a float is a union in the source or a defect here, and
//! either way the honest answer is that the evidence disagrees.
use std::collections::{BTreeMap, BTreeSet};

use crate::native_runtime::{PcodeInstruction, PcodeVarnode};

/// What one operand can be, as a class an inference can be scored on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// No operation constrained it.
    Unknown,
    /// A number of this width, with no evidence of sign.
    Num(u32),
    Int(u32),
    Uint(u32),
    Float(u32),
    /// A pointer to data.
    Ptr,
    /// A pointer to code, which an indirect call proves.
    Code,
    /// Two facts that cannot both hold.
    Top,
}

impl Default for Class {
    fn default() -> Self {
        Class::Unknown
    }
}

impl Class {
    /// The name the DWARF truth uses, so the two are directly comparable.
    pub fn name(self) -> String {
        match self {
            Class::Unknown => "unknown".into(),
            Class::Num(bits) => format!("num{bits}"),
            Class::Int(bits) => format!("int{bits}"),
            Class::Uint(bits) => format!("uint{bits}"),
            Class::Float(bits) => format!("float{bits}"),
            Class::Ptr => "ptr".into(),
            Class::Code => "code".into(),
            Class::Top => "top".into(),
        }
    }

    /// The bit width a sized class carries; pointer-ish and unknown
    /// classes have no meaningful width, so they report a word.
    pub fn width(self) -> u32 {
        match self {
            Class::Num(b) | Class::Int(b) | Class::Uint(b) | Class::Float(b) => b,
            _ => 64,
        }
    }

    /// The least class above both. A width joins with a width of the same
    /// size; two different widths keep the wider, because the narrower use
    /// is a truncation of the same storage.
    pub fn join(self, other: Class) -> Class {
        use Class::*;
        match (self, other) {
            (Unknown, value) | (value, Unknown) => value,
            (left, right) if left == right => left,
            (Top, _) | (_, Top) => Top,
            // A number with no sign evidence yields to one that has it, and
            // the width is the wider of the two: one storage location is
            // read at several widths on any machine with subregisters --
            // `EDI` and `RDI` are the same bytes, and treating a 32-bit
            // signed read of a 64-bit slot as a contradiction reported every
            // x86-64 first parameter as conflicting evidence.
            //
            // The width kept is the *narrowest* read, not the widest: a
            // 32-bit parameter arrives in a 64-bit slot and every ABI
            // permits the callee to use the whole register, so the wide use
            // is the slot and the narrow one is the type. Measured on the
            // type fixture, `max` reported `int64` where the source said
            // `int32` on every 32-bit parameter.
            (Num(left), Int(right)) | (Int(right), Num(left)) => Int(left.min(right)),
            (Num(left), Uint(right)) | (Uint(right), Num(left)) => Uint(left.min(right)),
            (Num(left), Float(right)) | (Float(right), Num(left)) => Float(left.min(right)),
            // A pointer read as an integer of pointer width is a pointer:
            // address arithmetic is integer arithmetic on every machine.
            (Ptr, Num(_)) | (Num(_), Ptr) => Ptr,
            (Code, Num(_)) | (Num(_), Code) => Code,
            // Address arithmetic is unsigned arithmetic: a slot read as an
            // unsigned 64-bit value and dereferenced is a pointer, and the
            // dereference is the stronger fact.
            (Ptr, Uint(64)) | (Uint(64), Ptr) => Ptr,
            (Code, Uint(64)) | (Uint(64), Code) => Code,
            (Code, Ptr) | (Ptr, Code) => Code,
            (Num(left), Num(right)) => Num(left.min(right)),
            (Int(left), Int(right)) => Int(left.min(right)),
            (Uint(left), Uint(right)) => Uint(left.min(right)),
            (Float(left), Float(right)) => Float(left.min(right)),
            // Signed and unsigned readings of one storage location disagree
            // about the sign and agree about everything else. Without SSA
            // the two readings may belong to different values in the same
            // register -- a compiler implements signed division by a
            // constant with unsigned multiplies and shifts -- so the honest
            // answer is the width, not a contradiction.
            (Int(left), Uint(right)) | (Uint(right), Int(left)) => Num(left.min(right)),
            // Anything else really is evidence in conflict.
            _ => Top,
        }
    }
}

/// A field recovered at one offset of a struct: the access width and the
/// scalar class the value's first use proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Field {
    pub offset: i64,
    pub size: u32,
    pub class: Class,
}

/// A structural type — the TRex layer over the flat `Class` lattice. It
/// describes observed behavior (`*struct{+0x34: float32}`), not a lost
/// source type: a register that is only ever dereferenced at two offsets is
/// a pointer to a two-field struct whether or not the source declared one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ty {
    Unknown,
    Scalar(Class),
    Ptr(Box<Ty>),
    /// offset -> field; the layout the accesses proved.
    Struct(BTreeMap<i64, Field>),
    /// `base[index]` with a constant stride.
    Array { elem: Box<Ty>, stride: u64 },
}

impl Ty {
    /// C-ish rendering for reports: `*struct{+0x34: float32}`.
    pub fn name(&self) -> String {
        match self {
            Ty::Unknown => "unknown".into(),
            Ty::Scalar(class) => class.name(),
            Ty::Ptr(inner) => format!("*{}", inner.name()),
            Ty::Struct(fields) => {
                let body: Vec<String> = fields
                    .values()
                    .map(|f| format!("+{:#x}: {}", f.offset, f.class.name()))
                    .collect();
                format!("struct{{{}}}", body.join(", "))
            }
            Ty::Array { elem, stride } => format!("{}[stride {}]", elem.name(), stride),
        }
    }
}

impl Ty {
    /// The least type above both — the join a caller's observed argument
    /// type makes with a callee's inferred parameter type. Scalars join on
    /// their class; structs union their fields (a field either side saw is
    /// evidence); pointers join their pointees; a conflict falls back to
    /// the wider claim rather than collapsing to Top.
    pub fn join(&self, other: &Ty) -> Ty {
        match (self, other) {
            (Ty::Unknown, t) | (t, Ty::Unknown) => t.clone(),
            (Ty::Scalar(a), Ty::Scalar(b)) => Ty::Scalar(a.join(*b)),
            (Ty::Ptr(a), Ty::Ptr(b)) => Ty::Ptr(Box::new(a.join(b))),
            (Ty::Struct(a), Ty::Struct(b)) => {
                let mut fields = a.clone();
                for (off, f) in b {
                    fields
                        .entry(*off)
                        .and_modify(|e| {
                            e.class = e.class.join(f.class);
                            e.size = e.size.max(f.size);
                        })
                        .or_insert(*f);
                }
                Ty::Struct(fields)
            }
            (
                Ty::Array { elem: ae, stride: as_ },
                Ty::Array { elem: be, stride: bs },
            ) => Ty::Array {
                elem: Box::new(ae.join(be)),
                stride: (*as_).max(*bs),
            },
            // A pointer and a scalar disagree: the pointer is the more
            // informative claim (a scalar use of a pointer is a width, not
            // a refutation).
            (Ty::Ptr(_), _) | (_, Ty::Ptr(_)) => {
                if matches!(self, Ty::Ptr(_)) { self.clone() } else { other.clone() }
            }
            (Ty::Struct(_), _) | (_, Ty::Struct(_)) => {
                if matches!(self, Ty::Struct(_)) { self.clone() } else { other.clone() }
            }
            (Ty::Array { .. }, _) | (_, Ty::Array { .. }) => {
                if matches!(self, Ty::Array { .. }) { self.clone() } else { other.clone() }
            }
        }
    }
}

/// A storage location an inference tracks: a register, by its offset and
/// size in the register space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Register {
    pub offset: u64,
    pub size: u32,
}

/// Constraints collected over one function's p-code.
#[derive(Debug, Default, Clone)]
pub struct Facts {
    registers: BTreeMap<u64, Class>,
    /// The class of the last value written to each register: what a return
    /// type is read from, since the value a function returns is produced in
    /// the body rather than arriving in it.
    writes: BTreeMap<u64, Class>,
    /// Registers read before any write defines them: the function's actual
    /// parameters, since a register the body only ever stores is not one.
    read_before_write: BTreeSet<u64>,
    /// Registers currently holding another varnode's value: register offset
    /// to the parameter register it was carried from and the carried width.
    /// A register holding its *own* entry value reloaded itself (a spill
    /// shuffle); one holding another register, or nothing, computed or
    /// carries the call's argument.
    aliases: BTreeMap<u64, (u64, u32)>,
    /// The structural type each parameter register's accesses prove —
    /// `*struct{…}` for a register dereferenced at several offsets. This is
    /// the TRex layer: behavior-describing, built from LOAD/STORE evidence.
    structural: BTreeMap<u64, Ty>,
}

impl Facts {
    fn constrain(&mut self, varnode: &PcodeVarnode, class: Class) {
        if varnode.space != "register" {
            return;
        }
        let slot = self.registers.entry(varnode.offset).or_insert(Class::Unknown);
        *slot = slot.join(class);
    }

    /// What is known about the register at `offset`.
    pub fn get(&self, offset: u64) -> Class {
        self.registers.get(&offset).copied().unwrap_or(Class::Unknown)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, Class)> + '_ {
        self.registers.iter().map(|(offset, class)| (*offset, *class))
    }

    /// The class last written to the register at `offset`.
    pub fn written(&self, offset: u64) -> Class {
        self.writes.get(&offset).copied().unwrap_or(Class::Unknown)
    }

    /// Whether the register at `offset` was read before any write defined
    /// it: a function's actual parameter, not a caller-saved leftover.
    pub fn read_before_write(&self, offset: u64) -> bool {
        self.read_before_write.contains(&offset)
    }

    /// The structural type the register at `offset` proved, if any.
    pub fn structural(&self, offset: u64) -> Option<&Ty> {
        self.structural.get(&offset)
    }

    /// The parameter register whose value the register at `offset`
    /// currently holds, if any: a spill reload or a carried copy.
    pub fn alias_origin(&self, offset: u64) -> Option<(u64, u32)> {
        self.aliases.get(&offset).copied()
    }
}

/// Collects the constraints one function's p-code puts on its registers.
///
/// Only the *entry* value of a register is a parameter, so a register that
/// is written before it is read carries no constraint from later uses: the
/// walk tracks which registers have been defined and stops constraining one
/// once it has been.
/// The condition varnodes that some `CBRANCH` reads, and everything that
/// feeds them.
///
/// One machine comparison emits every flag its instruction set defines:
/// x86's `CMP` produces a signed test *and* an unsigned one, and only the
/// branch that follows says which was meant. Taking sign evidence from both
/// reports every compared operand as contradictory -- which is exactly what
/// the first measurement of this pass did, on twelve of thirteen fixture
/// functions. So a comparison is evidence only when its result reaches a
/// branch.
fn branch_relevant(instructions: &[PcodeInstruction]) -> std::collections::BTreeSet<(String, u64)> {
    let mut wanted: std::collections::BTreeSet<(String, u64)> = std::collections::BTreeSet::new();
    for instruction in instructions {
        for op in &instruction.ops {
            if op.opcode == "CBRANCH"
                && let Some(condition) = op.inputs.get(1)
            {
                wanted.insert((condition.space.clone(), condition.offset));
            }
        }
    }
    // Walk definitions backwards until nothing new joins: a flag is often
    // combined (`SF != OF`) before the branch reads it.
    loop {
        let mut grew = false;
        for instruction in instructions {
            for op in &instruction.ops {
                let Some(output) = &op.output else { continue };
                if !wanted.contains(&(output.space.clone(), output.offset)) {
                    continue;
                }
                for input in &op.inputs {
                    if input.space == "const" {
                        continue;
                    }
                    if wanted.insert((input.space.clone(), input.offset)) {
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    wanted
}

pub fn infer(instructions: &[PcodeInstruction]) -> Facts {
    let mut facts = Facts::default();
    let relevant = branch_relevant(instructions);
    let signed_evidence = |op: &crate::native_runtime::PcodeOp| {
        op.output
            .as_ref()
            .is_some_and(|output| relevant.contains(&(output.space.clone(), output.offset)))
    };
    let mut defined: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    // A unique or register holding a value copied from a parameter carries
    // that parameter's constraints; one level of copy covers the prologue
    // moves every ABI makes.
    let mut alias: BTreeMap<(String, u64), (u64, u32)> = BTreeMap::new();
    // An unoptimised build spills every parameter to its frame before using
    // it, so the entry register is only ever stored and the uses are loads
    // from the slot. Addresses computed as `base + displacement` are
    // tracked by that pair, which is what a frame slot is, and a slot that
    // received a parameter carries the parameter's identity.
    // Structural evidence: (base register, displacement) -> the field the
    // access proved. A LOAD's field type is the class its loaded value's
    // first use commits to, so a load records a pending read keyed by the
    // output temporary and the first consuming op resolves it.
    let mut fields: BTreeMap<(u64, i64), Field> = BTreeMap::new();
    let mut pending: BTreeMap<(String, u64), (u64, i64, u32)> = BTreeMap::new();
    // `base[index]` with a constant stride: base register -> (stride, elem).
    let mut arrays: BTreeMap<u64, (u64, Class)> = BTreeMap::new();
    // Registers established as a struct base — used as the address of a
    // field access. A parameter stored into `*(base+disp)` on one of these
    // is a field write, not a frame spill.
    let mut struct_bases: BTreeSet<u64> = BTreeSet::new();
    // `t = index * stride` or `t = index << shift`: the scaled index of an
    // array access, temp -> stride in bytes.
    let mut scaled: BTreeMap<(String, u64), u64> = BTreeMap::new();
    // `t = a + b` where b is not a constant: a base-plus-index sum, temp ->
    // (base, index) so a LOAD through it is an array access on the base.
    let mut sum_of: BTreeMap<(String, u64), ((String, u64), (String, u64))> = BTreeMap::new();
    let mut address_of: BTreeMap<(String, u64), (u64, i64)> = BTreeMap::new();
    let mut spilled: BTreeMap<(u64, i64), u64> = BTreeMap::new();
    // Registers that went into computing a temporary. When the temporary
    // turns out to be an address, whatever pointer-width value it was built
    // from is the pointer -- `values[index]` is `LOAD(values + index * 4)`,
    // and without this the pointer parameter is only ever an addend.
    let mut built_from: BTreeMap<(String, u64), Vec<u64>> = BTreeMap::new();
    for instruction in instructions {
        for op in &instruction.ops {
            let opcode = op.opcode.as_str();
            let mut spill_alias: Option<(u64, u32)> = None;
            let mut live = |facts: &mut Facts, input: &PcodeVarnode, class: Class| {
                if input.space == "register" && !defined.contains(&input.offset) {
                    facts.read_before_write.insert(input.offset);
                    facts.constrain(input, class);
                } else if let Some((origin, size)) =
                    alias.get(&(input.space.clone(), input.offset)).copied()
                    && input.size >= size
                {
                    // A spill or copy origin is only ever recorded from an
                    // entry value, so it is always a parameter -- even when
                    // the register itself has been redefined since. The
                    // size guard keeps a narrower read from claiming the
                    // whole register.
                    facts.read_before_write.insert(origin);
                    facts.constrain(
                        &PcodeVarnode {
                            space: "register".into(),
                            offset: origin,
                            size: input.size,
                        },
                        class,
                    );
                }
            };
            // What each temporary was computed from, one level at a time.
            if let Some(output) = &op.output
                && matches!(
                    opcode,
                    "INT_ADD" | "INT_SUB" | "INT_MULT" | "COPY" | "INT_ZEXT" | "INT_SEXT"
                )
            {
                let mut sources: Vec<u64> = Vec::new();
                for input in &op.inputs {
                    if let Some((origin, _)) =
                        alias.get(&(input.space.clone(), input.offset)).copied()
                    {
                        // A parameter reloaded from its frame slot is still
                        // that parameter: without this an unoptimised build
                        // hides every pointer behind its own spill.
                        sources.push(origin);
                    } else if input.space == "register" && input.size == 8 {
                        sources.push(input.offset);
                    } else if let Some(more) =
                        built_from.get(&(input.space.clone(), input.offset))
                    {
                        sources.extend(more.iter().copied());
                    }
                }
                sources.sort_unstable();
                sources.dedup();
                if !sources.is_empty() {
                    built_from.insert((output.space.clone(), output.offset), sources);
                }
            }
            // Frame arithmetic: `base ± displacement` into a temporary. The
            // base may itself be a temporary already resolved to
            // `(register, disp)`, so `lea 0x10(%rax)` after `lea -0x8(%rax)`
            // composes to `rax + 8` rather than losing the register.
            if matches!(opcode, "INT_ADD" | "INT_SUB")
                && let Some(output) = &op.output
                && let (Some(base), Some(offset)) = (op.inputs.first(), op.inputs.get(1))
                && offset.space == "const"
            {
                let disp = offset.offset as i64;
                let disp = if opcode == "INT_SUB" { -disp } else { disp };
                let resolved = if base.space == "register" {
                    Some((base.offset, disp))
                } else {
                    address_of
                        .get(&(base.space.clone(), base.offset))
                        .map(|(reg, d)| (*reg, d + disp))
                };
                if let Some(pair) = resolved {
                    address_of.insert((output.space.clone(), output.offset), pair);
                }
            }
            // `t = index * stride` or `t = index << shift`: the scaled index
            // of an array access.
            if let Some(output) = &op.output {
                let key = (output.space.clone(), output.offset);
                if opcode == "INT_MULT"
                    && let (Some(a), Some(b)) = (op.inputs.first(), op.inputs.get(1))
                {
                    let stride = if b.space == "const" { Some(b.offset) }
                        else if a.space == "const" { Some(a.offset) } else { None };
                    if let Some(stride) = stride {
                        scaled.insert(key.clone(), stride);
                    }
                } else if opcode == "INT_LEFT"
                    && let (Some(_), Some(shift)) = (op.inputs.first(), op.inputs.get(1))
                    && shift.space == "const"
                {
                    scaled.insert(key.clone(), 1u64 << shift.offset.min(63));
                }
                // `t = a + b` with no constant: a base-plus-index sum.
                if opcode == "INT_ADD"
                    && let (Some(a), Some(b)) = (op.inputs.first(), op.inputs.get(1))
                    && a.space != "const" && b.space != "const"
                {
                    sum_of.insert(
                        key,
                        ((a.space.clone(), a.offset), (b.space.clone(), b.offset)),
                    );
                }
            }
            // A loaded value's first use resolves the field's class: the
            // read itself only proved a width.
            for input in &op.inputs {
                if let Some((base, disp, size)) =
                    pending.get(&(input.space.clone(), input.offset)).copied()
                {
                    let class = match opcode {
                        "INT_SLESS" | "INT_SLESSEQUAL" | "INT_SBORROW" | "INT_SRIGHT"
                        | "INT_SDIV" | "INT_SREM" | "INT_SEXT" => Class::Int(size * 8),
                        "INT_LESS" | "INT_LESSEQUAL" | "INT_CARRY" | "INT_RIGHT"
                        | "INT_DIV" | "INT_REM" | "INT_ZEXT" => Class::Uint(size * 8),
                        _ if opcode.starts_with("FLOAT_") => Class::Float(size * 8),
                        "COPY" | "INT_ADD" | "INT_SUB" | "INT_MULT" | "INT_AND"
                        | "INT_OR" | "INT_XOR" | "INT_LEFT" | "INT_EQUAL"
                        | "INT_NOTEQUAL" => Class::Num(size * 8),
                        _ => Class::Unknown,
                    };
                    if class != Class::Unknown {
                        let entry = fields.entry((base, disp)).or_insert(Field {
                            offset: disp,
                            size,
                            class: Class::Unknown,
                        });
                        entry.class = entry.class.join(class);
                        // The widest access is the field's width; a narrower
                        // read is a partial one.
                        entry.size = entry.size.max(size);
                    }
                }
            }
            match opcode {
                // The address operand of a memory access is a pointer, and
                // a frame slot is not: a stack address is the frame, which
                // says nothing about the type of anything.
                "LOAD" => {
                    if let Some(address) = op.inputs.get(1) {
                        let slot = address_of.get(&(address.space.clone(), address.offset));
                        match slot.and_then(|key| spilled.get(key)).copied() {
                            Some(origin) => {
                                // The loaded value is the parameter that was
                                // spilled here: later uses of the temporary
                                // constrain the parameter. The insert is
                                // deferred to the tail block so the output's
                                // clear runs first.
                                if let Some(output) = &op.output {
                                    spill_alias = Some((origin, output.size));
                                }
                            }
                            None if slot.is_none() => {
                                live(&mut facts, address, Class::Ptr);
                                for origin in built_from
                                    .get(&(address.space.clone(), address.offset))
                                    .cloned()
                                    .unwrap_or_default()
                                {
                                    if !defined.contains(&origin) {
                                        facts.constrain(
                                            &PcodeVarnode {
                                                space: "register".into(),
                                                offset: origin,
                                                size: 8,
                                            },
                                            Class::Ptr,
                                        );
                                    }
                                }
                                // `base[index]` with a constant stride is an
                                // array access on the base register.
                                if let Some((a, b)) = sum_of
                                    .get(&(address.space.clone(), address.offset))
                                    .cloned()
                                {
                                    let pair = if scaled.contains_key(&b) {
                                        Some((a, b))
                                    } else if scaled.contains_key(&a) {
                                        Some((b, a))
                                    } else {
                                        None
                                    };
                                    if let Some((base_key, idx_key)) = pair
                                        && let Some(stride) = scaled.get(&idx_key).copied()
                                    {
                                        let bases: Vec<u64> = if base_key.0 == "register" {
                                            vec![base_key.1]
                                        } else {
                                            built_from.get(&base_key).cloned().unwrap_or_default()
                                        };
                                        let elem = op
                                            .output
                                            .as_ref()
                                            .map(|o| Class::Num(o.size * 8))
                                            .unwrap_or(Class::Unknown);
                                        for base in bases {
                                            if !defined.contains(&base) {
                                                arrays.insert(base, (stride, elem));
                                            }
                                        }
                                    }
                                }
                            }
                            None => {
                                // `*(base + disp)` through a resolved
                                // address that is not a spill slot: a field
                                // read. The class is whatever the loaded
                                // value's first use commits to, so the read
                                // is recorded pending and resolved when the
                                // output temporary is consumed.
                                if let Some(&(base, disp)) = slot
                                    && let Some(output) = &op.output
                                {
                                    struct_bases.insert(base);
                                    pending.insert(
                                        (output.space.clone(), output.offset),
                                        (base, disp, output.size),
                                    );
                                    if !defined.contains(&base) {
                                        facts.constrain(
                                            &PcodeVarnode {
                                                space: "register".into(),
                                                offset: base,
                                                size: 8,
                                            },
                                            Class::Ptr,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                "STORE" => {
                    if let Some(address) = op.inputs.get(1) {
                        let key = address_of.get(&(address.space.clone(), address.offset)).copied();
                        match key {
                            Some(key) => {
                                // A store into `*(base+disp)` where `base`
                                // is an established struct base is a field
                                // write, never a spill — even when the value
                                // is a parameter register.
                                let is_struct_base = struct_bases.contains(&key.0);
                                // Remember which parameter landed in this
                                // slot, if any — but only for a real frame
                                // slot, not a struct field.
                                if let Some(value) = op.inputs.get(2) {
                                    let origin = if value.space == "register"
                                        && !defined.contains(&value.offset)
                                    {
                                        Some(value.offset)
                                    } else {
                                        alias
                                            .get(&(value.space.clone(), value.offset))
                                            .map(|(origin, _)| *origin)
                                    };
                                    if !is_struct_base {
                                        match origin {
                                            Some(origin) => {
                                                spilled.insert(key, origin);
                                            }
                                            None => {
                                                spilled.remove(&key);
                                            }
                                        }
                                    }
                                    // A store into a resolved address that
                                    // is not a spill slot is a field write:
                                    // `*(base + disp) = value`. The field's
                                    // class is the stored value's own.
                                    if is_struct_base || !spilled.contains_key(&key) {
                                        let (base, disp) = key;
                                        struct_bases.insert(base);
                                        let class = if value.space == "const" {
                                            Class::Num(value.size * 8)
                                        } else if value.space == "register" {
                                            let known = facts.get(value.offset);
                                            if known == Class::Unknown {
                                                Class::Num(value.size * 8)
                                            } else {
                                                known
                                            }
                                        } else {
                                            Class::Num(value.size * 8)
                                        };
                                        let entry = fields
                                            .entry((base, disp))
                                            .or_insert(Field {
                                                offset: disp,
                                                size: value.size,
                                                class: Class::Unknown,
                                            });
                                        entry.class = entry.class.join(class);
                                        entry.size = entry.size.max(value.size);
                                        if !defined.contains(&base) {
                                            facts.constrain(
                                                &PcodeVarnode {
                                                    space: "register".into(),
                                                    offset: base,
                                                    size: 8,
                                                },
                                                Class::Ptr,
                                            );
                                        }
                                    }
                                }
                            }
                            None => {
                                live(&mut facts, address, Class::Ptr);
                                for origin in built_from
                                    .get(&(address.space.clone(), address.offset))
                                    .cloned()
                                    .unwrap_or_default()
                                {
                                    if !defined.contains(&origin) {
                                        facts.constrain(
                                            &PcodeVarnode {
                                                space: "register".into(),
                                                offset: origin,
                                                size: 8,
                                            },
                                            Class::Ptr,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                "CALLIND" | "BRANCHIND" => {
                    if let Some(target) = op.inputs.first() {
                        live(&mut facts, target, Class::Code);
                    }
                }
                "INT_SLESS" | "INT_SLESSEQUAL" | "INT_SBORROW"
                    if !signed_evidence(op) =>
                {
                    // A flag nothing branches on is not evidence.
                    for input in &op.inputs {
                        let class = Class::Num(input.size * 8);
                        live(&mut facts, input, class);
                    }
                }
                "INT_LESS" | "INT_LESSEQUAL" | "INT_CARRY" if !signed_evidence(op) => {
                    for input in &op.inputs {
                        let class = Class::Num(input.size * 8);
                        live(&mut facts, input, class);
                    }
                }
                "INT_SLESS" | "INT_SLESSEQUAL" | "INT_SBORROW" | "INT_SRIGHT" | "INT_SDIV"
                | "INT_SREM" => {
                    for input in &op.inputs {
                        let class = Class::Int(input.size * 8);
                        live(&mut facts, input, class);
                    }
                }
                "INT_SEXT" => {
                    if let Some(input) = op.inputs.first() {
                        let class = Class::Int(input.size * 8);
                        live(&mut facts, input, class);
                    }
                }
                "INT_LESS" | "INT_LESSEQUAL" | "INT_CARRY" | "INT_RIGHT" | "INT_DIV"
                | "INT_REM" => {
                    for input in &op.inputs {
                        let class = Class::Uint(input.size * 8);
                        live(&mut facts, input, class);
                    }
                }
                "INT_ZEXT" => {
                    // Same on the reading side: widening an operand says
                    // how wide it is, not how it is signed.
                    if let Some(input) = op.inputs.first() {
                        let class = Class::Num(input.size * 8);
                        live(&mut facts, input, class);
                    }
                }
                _ if opcode.starts_with("FLOAT_") => {
                    for input in &op.inputs {
                        if input.size == 4 || input.size == 8 || input.size == 10 {
                            let class = Class::Float(input.size * 8);
                            live(&mut facts, input, class);
                        }
                    }
                }
                // Plain arithmetic says the operand is a number of that
                // width and nothing more.
                "INT_ADD" | "INT_SUB" | "INT_MULT" | "INT_AND" | "INT_OR" | "INT_XOR"
                | "INT_LEFT" | "INT_EQUAL" | "INT_NOTEQUAL" => {
                    for input in &op.inputs {
                        let class = Class::Num(input.size * 8);
                        live(&mut facts, input, class);
                    }
                }
                _ => {}
            }
            // What this operation produces, for whoever reads the result
            // later -- a return register above all.
            if let Some(output) = &op.output
                && output.space == "register"
            {
                let produced = match opcode {
                    "LOAD" => Class::Unknown,
                    "INT_EQUAL" | "INT_NOTEQUAL" | "INT_LESS" | "INT_LESSEQUAL"
                    | "INT_SLESS" | "INT_SLESSEQUAL" | "BOOL_AND" | "BOOL_OR" | "BOOL_NEGATE"
                    | "FLOAT_EQUAL" | "FLOAT_NOTEQUAL" | "FLOAT_LESS" | "FLOAT_LESSEQUAL" => {
                        Class::Num(output.size * 8)
                    }
                    "INT_SDIV" | "INT_SREM" | "INT_SRIGHT" => Class::Int(output.size * 8),
                    "INT_DIV" | "INT_REM" | "INT_RIGHT" => Class::Uint(output.size * 8),
                    // Widening into a register is the machine's, not the
                    // type's: `mov eax, ...` zero-extends into RAX on every
                    // x86-64, and reading that as `uint64` made every
                    // 32-bit return contradict the compiler. The value is
                    // what was widened, at the width it was widened from.
                    "INT_ZEXT" | "INT_SEXT" => {
                        let source = op.inputs.first();
                        let bits = source.map_or(output.size * 8, |input| input.size * 8);
                        let carried = source
                            .filter(|input| input.space == "register")
                            .map(|input| self_written(&facts, input.offset))
                            .unwrap_or(Class::Unknown);
                        match carried {
                            // Zero-extension is how a machine fills a wide
                            // register with a narrow value; it is not a
                            // claim about sign, and reading it as one made
                            // every `int32` return come back `uint32`.
                            Class::Unknown | Class::Num(_) if opcode == "INT_ZEXT" => {
                                Class::Num(bits)
                            }
                            // Sign-extension is emitted for signed values.
                            Class::Unknown | Class::Num(_) => Class::Int(bits),
                            known => known,
                        }
                    }
                    _ if opcode.starts_with("FLOAT_") => Class::Float(output.size * 8),
                    "COPY" | "INT_ADD" | "INT_SUB" | "INT_MULT" | "INT_AND" | "INT_OR"
                    | "INT_XOR" | "INT_LEFT" | "INT_2COMP" | "INT_NEGATE" => {
                        // A copy of a pointer is a pointer; otherwise the
                        // operation says only how wide the result is.
                        // The result of arithmetic is the kind of what it
                        // was computed from: adding to a pointer gives a
                        // pointer, and multiplying a signed value gives a
                        // signed value. Where the operands disagree the
                        // join already degrades to a width.
                        let carried = op
                            .inputs
                            .iter()
                            .filter(|input| input.space == "register")
                            .map(|input| self_written(&facts, input.offset))
                            .filter(|class| *class != Class::Unknown)
                            .fold(Class::Unknown, Class::join);
                        match carried {
                            Class::Unknown | Class::Top => Class::Num(output.size * 8),
                            Class::Ptr | Class::Code => carried,
                            // The result is as wide as the operation says,
                            // with the kind its operands had.
                            Class::Int(_) => Class::Int(output.size * 8),
                            Class::Uint(_) => Class::Uint(output.size * 8),
                            Class::Float(_) => Class::Float(output.size * 8),
                            Class::Num(_) => Class::Num(output.size * 8),
                        }
                    }
                    _ => Class::Unknown,
                };
                if produced != Class::Unknown {
                    facts.writes.insert(output.offset, produced);
                } else {
                    facts.writes.remove(&output.offset);
                }
            }
            // A copy carries the source's identity forward, then the output
            // counts as defined: its later uses are not the entry value.
            if let Some(output) = &op.output {
                // Consult the input's alias *before* the output's write
                // clears it: `add rax,rdx` reads rax's alias to record rdx
                // as a source, and `INT_ZEXT RCX←ECX` reads ECX's alias to
                // carry the parameter's identity.
                let carried = if opcode == "COPY"
                    && let Some(input) = op.inputs.first()
                {
                    if input.space == "register" && !defined.contains(&input.offset) {
                        Some((input.offset, input.size))
                    } else {
                        alias.get(&(input.space.clone(), input.offset)).copied()
                    }
                } else if opcode == "INT_ZEXT"
                    && let Some(input) = op.inputs.first()
                    && output.space == input.space
                    && output.offset == input.offset
                {
                    // The x86 `mov ecx,[m]` idiom emits `RCX = zext(ECX)`:
                    // the extension is the machine's, and the value is the
                    // parameter's.
                    alias.get(&(input.space.clone(), input.offset)).copied()
                } else {
                    None
                };
                let held = spill_alias.or(carried);
                let key = (output.space.clone(), output.offset);
                alias.remove(&key);
                if let Some(a) = held {
                    alias.insert(key, a);
                }
                if output.space == "register" {
                    defined.insert(output.offset);
                    facts.aliases.remove(&output.offset);
                    if let Some(a) = held {
                        facts.aliases.insert(output.offset, a);
                    }
                }
            }
        }
    }
    // Fold the field accesses and array strides into a structural type per
    // base register. A register dereferenced at several offsets is a
    // `*struct{…}`; one dereferenced only at offset 0 is a `*T`; one indexed
    // by a scaled value is an array.
    let mut by_base: BTreeMap<u64, BTreeMap<i64, Field>> = BTreeMap::new();
    for ((base, disp), field) in fields {
        by_base.entry(base).or_default().insert(disp, field);
    }
    for (base, map) in by_base {
        let ty = if map.len() == 1 && map.contains_key(&0) {
            let field = map[&0];
            Ty::Ptr(Box::new(Ty::Scalar(field.class)))
        } else {
            Ty::Ptr(Box::new(Ty::Struct(map)))
        };
        facts.structural.insert(base, ty);
    }
    for (base, (stride, elem)) in arrays {
        facts
            .structural
            .entry(base)
            .or_insert(Ty::Array { elem: Box::new(Ty::Scalar(elem)), stride });
    }
    facts
}

/// The class already written to a register, without borrowing `facts`
/// mutably at the call site.
fn self_written(facts: &Facts, offset: u64) -> Class {
    facts.written(offset).join(facts.get(offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varnode(space: &str, offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: space.to_string(),
            offset,
            size,
        }
    }

    fn instruction(ops: Vec<crate::native_runtime::PcodeOp>) -> PcodeInstruction {
        PcodeInstruction {
            address: 0x1000,
            length: 4,
            ops,
            error: None,
        }
    }

    fn op(
        opcode: &str,
        output: Option<PcodeVarnode>,
        inputs: Vec<PcodeVarnode>,
    ) -> crate::native_runtime::PcodeOp {
        crate::native_runtime::PcodeOp {
            opcode: opcode.to_string(),
            output,
            inputs,
        }
    }

    #[test]
    fn a_dereferenced_parameter_is_a_pointer() {
        let facts = infer(&[instruction(vec![op(
            "LOAD",
            Some(varnode("unique", 0x100, 8)),
            vec![varnode("const", 0x1b1, 4), varnode("register", 0x38, 8)],
        )])]);
        assert_eq!(facts.get(0x38), Class::Ptr);
    }

    #[test]
    fn a_parameter_dereferenced_at_two_offsets_is_a_struct_pointer() {
        // `*(rdi + 0x34) = 1.0f` then `*(rdi + 0x10) = x`: the register is a
        // pointer to a struct with a float at +0x34 and a number at +0x10.
        let facts = infer(&[
            // t0 = rdi + 0x34
            instruction(vec![op(
                "INT_ADD",
                Some(varnode("unique", 0x100, 8)),
                vec![varnode("register", 0x38, 8), varnode("const", 0x34, 8)],
            )]),
            // *(t0) = 1.0f  (a float constant store)
            instruction(vec![op(
                "STORE",
                None,
                vec![
                    varnode("const", 0x1b1, 4),
                    varnode("unique", 0x100, 8),
                    varnode("const", 0x3f800000, 4),
                ],
            )]),
            // t1 = rdi + 0x10
            instruction(vec![op(
                "INT_ADD",
                Some(varnode("unique", 0x108, 8)),
                vec![varnode("register", 0x38, 8), varnode("const", 0x10, 8)],
            )]),
            // *(t1) = rsi
            instruction(vec![op(
                "STORE",
                None,
                vec![
                    varnode("const", 0x1b1, 4),
                    varnode("unique", 0x108, 8),
                    varnode("register", 0x30, 8),
                ],
            )]),
        ]);
        let ty = facts.structural(0x38).expect("a structural type for rdi");
        match ty {
            Ty::Ptr(inner) => match inner.as_ref() {
                Ty::Struct(fields) => {
                    assert!(fields.contains_key(&0x34), "field at +0x34: {fields:?}");
                    assert!(fields.contains_key(&0x10), "field at +0x10: {fields:?}");
                }
                other => panic!("expected a struct, got {other:?}"),
            },
            other => panic!("expected a pointer, got {other:?}"),
        }
    }

    /// A comparison plus the branch that reads it: only then is the
    /// comparison evidence, because one machine instruction emits every
    /// flag and the branch says which one was meant.
    fn compare_and_branch(opcode: &str, size: u32) -> Vec<PcodeInstruction> {
        vec![instruction(vec![
            op(
                opcode,
                Some(varnode("unique", 0x200, 1)),
                vec![varnode("register", 0x38, size), varnode("const", 10, size)],
            ),
            op(
                "CBRANCH",
                None,
                vec![varnode("ram", 0x1100, 8), varnode("unique", 0x200, 1)],
            ),
        ])]
    }

    #[test]
    fn a_signed_comparison_a_branch_reads_makes_it_signed() {
        let facts = infer(&compare_and_branch("INT_SLESS", 4));
        assert_eq!(facts.get(0x38), Class::Int(32));
    }

    #[test]
    fn a_flag_nothing_branches_on_is_not_evidence() {
        // x86 `CMP` emits a signed test and an unsigned one; taking both as
        // evidence makes every compared operand contradictory.
        let facts = infer(&[instruction(vec![
            op(
                "INT_SLESS",
                Some(varnode("unique", 0x200, 1)),
                vec![varnode("register", 0x38, 4), varnode("const", 10, 4)],
            ),
            op(
                "INT_LESS",
                Some(varnode("unique", 0x201, 1)),
                vec![varnode("register", 0x38, 4), varnode("const", 10, 4)],
            ),
            op(
                "CBRANCH",
                None,
                vec![varnode("ram", 0x1100, 8), varnode("unique", 0x201, 1)],
            ),
        ])]);
        assert_eq!(facts.get(0x38), Class::Uint(32));
    }

    #[test]
    fn arithmetic_alone_proves_only_a_width() {
        let facts = infer(&[instruction(vec![op(
            "INT_ADD",
            Some(varnode("unique", 0x200, 8)),
            vec![varnode("register", 0x38, 8), varnode("const", 1, 8)],
        )])]);
        assert_eq!(facts.get(0x38), Class::Num(64));
    }

    #[test]
    fn a_value_written_before_it_is_read_is_not_a_parameter() {
        // The register is set from a constant, then dereferenced: the
        // dereference says nothing about what came in.
        let facts = infer(&[instruction(vec![
            op(
                "COPY",
                Some(varnode("register", 0x38, 8)),
                vec![varnode("const", 0x4000, 8)],
            ),
            op(
                "LOAD",
                Some(varnode("unique", 0x100, 8)),
                vec![varnode("const", 0x1b1, 4), varnode("register", 0x38, 8)],
            ),
        ])]);
        assert_eq!(facts.get(0x38), Class::Unknown);
    }

    #[test]
    fn a_parameter_copied_into_a_temporary_keeps_its_constraints() {
        let facts = infer(&[instruction(vec![
            op(
                "COPY",
                Some(varnode("unique", 0x100, 8)),
                vec![varnode("register", 0x38, 8)],
            ),
            op(
                "LOAD",
                Some(varnode("unique", 0x200, 8)),
                vec![varnode("const", 0x1b1, 4), varnode("unique", 0x100, 8)],
            ),
        ])]);
        assert_eq!(facts.get(0x38), Class::Ptr);
    }

    #[test]
    fn one_slot_read_at_two_widths_is_not_a_conflict() {
        // `EDI` and `RDI` are the same storage: a 32-bit signed compare and
        // 64-bit arithmetic on it agree that it is signed, and the type is
        // the narrower read -- the wide one is the register, not the value.
        let mut ops = compare_and_branch("INT_SLESS", 4);
        ops[0].ops.push(op(
            "INT_ADD",
            Some(varnode("unique", 0x208, 8)),
            vec![varnode("register", 0x38, 8), varnode("const", 1, 8)],
        ));
        let facts = infer(&ops);
        assert_eq!(facts.get(0x38), Class::Int(32));
    }

    #[test]
    fn a_disputed_sign_degrades_to_a_width() {
        // Two branches, one on a signed test and one on an unsigned test of
        // the same storage: without SSA these may be different values in
        // one register, so the answer is the width they agree on.
        let facts = infer(&[instruction(vec![
            op(
                "INT_SLESS",
                Some(varnode("unique", 0x200, 1)),
                vec![varnode("register", 0x38, 4), varnode("const", 10, 4)],
            ),
            op(
                "CBRANCH",
                None,
                vec![varnode("ram", 0x1100, 8), varnode("unique", 0x200, 1)],
            ),
            op(
                "INT_LESS",
                Some(varnode("unique", 0x201, 1)),
                vec![varnode("register", 0x38, 4), varnode("const", 10, 4)],
            ),
            op(
                "CBRANCH",
                None,
                vec![varnode("ram", 0x1200, 8), varnode("unique", 0x201, 1)],
            ),
        ])]);
        assert_eq!(facts.get(0x38), Class::Num(32));
    }

    #[test]
    fn an_indirect_call_through_a_parameter_makes_it_a_code_pointer() {
        let facts = infer(&[instruction(vec![op(
            "CALLIND",
            None,
            vec![varnode("register", 0x38, 8)],
        )])]);
        assert_eq!(facts.get(0x38), Class::Code);
    }

    #[test]
    fn a_float_parameter_spilled_and_reloaded_is_still_a_float() {
        // `movsd %xmm0, -0x8(%rbp)` stores the parameter; `movsd
        // -0x8(%rbp), %xmm0` loads it back into the same register; the
        // comparison reads it. The constraint must reach the entry value
        // even though the register was redefined in between.
        let facts = infer(&[instruction(vec![
            // The frame slot's address: rbp + (-8).
            op(
                "INT_ADD",
                Some(varnode("unique", 0x300, 8)),
                vec![varnode("register", 0x28, 8), varnode("const", 0xfffffff8, 8)],
            ),
            // Store xmm0 to the slot.
            op(
                "STORE",
                None,
                vec![
                    varnode("const", 0x1b1, 4),
                    varnode("unique", 0x300, 8),
                    varnode("register", 0x200, 8),
                ],
            ),
            // Redefine xmm0 before the reload -- the register is defined,
            // but the entry value is still the parameter.
            op(
                "COPY",
                Some(varnode("register", 0x200, 8)),
                vec![varnode("const", 0, 8)],
            ),
            // Load the spill back into xmm0.
            op(
                "LOAD",
                Some(varnode("register", 0x200, 8)),
                vec![varnode("const", 0x1b1, 4), varnode("unique", 0x300, 8)],
            ),
            // Compare it as a float.
            op(
                "FLOAT_LESS",
                Some(varnode("unique", 0x500, 1)),
                vec![varnode("register", 0x200, 8), varnode("const", 0, 8)],
            ),
            op(
                "CBRANCH",
                None,
                vec![varnode("ram", 0x1100, 8), varnode("unique", 0x500, 1)],
            ),
        ])]);
        assert_eq!(facts.get(0x200), Class::Float(64));
        assert!(facts.read_before_write(0x200));
    }
}
