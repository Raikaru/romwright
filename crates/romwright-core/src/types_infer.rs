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
use romwright_model::type_evidence::Class;

/// What the inference needs to know about the target machine, read from
/// its compiler spec (`register_params::Conventions::machine`). Nothing
/// here is x86-64's: a GBA's pointers are four bytes in four-byte
/// registers, a PS2's are four bytes in registers SLEIGH sizes wider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Machine {
    /// Bytes in a data pointer. A register narrower than this cannot hold
    /// one, so it never becomes a pointer by being part of an address.
    pub pointer_size: u32,
    /// The stack pointer's offset in the register space. An address built
    /// from it is a frame slot: a spill, a local, or an incoming stack
    /// argument — never a field of a struct the function was handed.
    pub stack_pointer: Option<u64>,
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
    Array {
        elem: Box<Ty>,
        stride: u64,
    },
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

    /// The C type a prototype renders. A proven struct or array pointer is
    /// still a pointer to a reader — `struct Point *` is recoverable from
    /// the layout, so the signature spells it `void *` and keeps the
    /// structural detail in the analysis fields.
    pub fn c_name(&self) -> String {
        match self {
            Ty::Unknown => "int".into(),
            Ty::Scalar(class) => class.c_name(),
            Ty::Ptr(_) | Ty::Struct(_) | Ty::Array { .. } => "void *".into(),
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
                Ty::Array {
                    elem: ae,
                    stride: as_,
                },
                Ty::Array {
                    elem: be,
                    stride: bs,
                },
            ) => Ty::Array {
                elem: Box::new(ae.join(be)),
                stride: (*as_).max(*bs),
            },
            // A pointer and a scalar disagree: the pointer is the more
            // informative claim (a scalar use of a pointer is a width, not
            // a refutation).
            (Ty::Ptr(_), _) | (_, Ty::Ptr(_)) => {
                if matches!(self, Ty::Ptr(_)) {
                    self.clone()
                } else {
                    other.clone()
                }
            }
            (Ty::Struct(_), _) | (_, Ty::Struct(_)) => {
                if matches!(self, Ty::Struct(_)) {
                    self.clone()
                } else {
                    other.clone()
                }
            }
            (Ty::Array { .. }, _) | (_, Ty::Array { .. }) => {
                if matches!(self, Ty::Array { .. }) {
                    self.clone()
                } else {
                    other.clone()
                }
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
    /// Every register the body wrote, whatever the class — including a
    /// `LOAD` whose value's class is unproven. A return register in this
    /// set carries a value; one absent returns `void`.
    touched: BTreeSet<u64>,
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
        self.constrain_register(varnode.offset, class);
    }

    /// Constrains the register at `offset`; the class carries any width.
    fn constrain_register(&mut self, offset: u64, class: Class) {
        let slot = self.registers.entry(offset).or_insert(Class::Unknown);
        *slot = slot.join(class);
    }

    /// What is known about the register at `offset`.
    pub fn get(&self, offset: u64) -> Class {
        self.registers
            .get(&offset)
            .copied()
            .unwrap_or(Class::Unknown)
    }

    /// Whether the body wrote the register at `offset` at all — the
    /// difference between a `void` return (never written) and a value
    /// return whose class is unproven (written, e.g. by a `LOAD`).
    pub fn touched(&self, offset: u64) -> bool {
        self.touched.contains(&offset)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, Class)> + '_ {
        self.registers
            .iter()
            .map(|(offset, class)| (*offset, *class))
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

/// A varnode by space and offset: what the maps of this pass are keyed by.
type VarKey = (String, u64);

/// The varnodes a `POPCOUNT` reads: x86 computes its parity flag as
/// `popcount(value & 0xff) & 1`, and the mask there is the flag's, not the
/// program's.
fn parity_inputs(instructions: &[PcodeInstruction]) -> std::collections::BTreeSet<(String, u64)> {
    instructions
        .iter()
        .flat_map(|instruction| &instruction.ops)
        .filter(|op| op.opcode == "POPCOUNT")
        .flat_map(|op| &op.inputs)
        .map(|input| (input.space.clone(), input.offset))
        .collect()
}

pub fn infer(instructions: &[PcodeInstruction], machine: &Machine) -> Facts {
    let mut facts = Facts::default();
    let relevant = branch_relevant(instructions);
    let signed_evidence = |op: &crate::native_runtime::PcodeOp| {
        op.output
            .as_ref()
            .is_some_and(|output| relevant.contains(&(output.space.clone(), output.offset)))
    };
    let parity = parity_inputs(instructions);
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
    // (loaded-into register, base register, field offset) for each LOAD —
    // the loaded value's class is the field's, known only after the pass.
    let mut loads: Vec<(u64, u64, i64)> = Vec::new();
    // A load's byte width keyed by its output varnode — `unique` temps
    // included, so `movzx eax, byte[s]` reports the byte it loaded, not the
    // register it widened into.
    let mut load_width: BTreeMap<(String, u64), u32> = BTreeMap::new();
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
    let mut sum_of: BTreeMap<VarKey, (VarKey, VarKey)> = BTreeMap::new();
    let mut address_of: BTreeMap<(String, u64), (u64, i64)> = BTreeMap::new();
    let mut spilled: BTreeMap<(u64, i64), u64> = BTreeMap::new();
    // Registers that went into computing a temporary. When the temporary
    // turns out to be an address, whatever pointer-width value it was built
    // from is the pointer -- `values[index]` is `LOAD(values + index * 4)`,
    // and without this the pointer parameter is only ever an addend.
    let mut built_from: BTreeMap<(String, u64), Vec<u64>> = BTreeMap::new();
    // Registers currently holding a stack address: the stack pointer and
    // anything copied or offset from it (`mov rbp, rsp`, `move s8, sp`,
    // `add r7, sp, #0`). An access through one is a frame slot.
    let mut frame: BTreeSet<u64> = machine.stack_pointer.into_iter().collect();
    // Registers whose current value is a zero an idiom wrote (`xor eax, eax`,
    // `sub eax, eax`, and the zero-extension of one): a constant, which
    // proves a width at most and takes nothing from the register's entry
    // value or from the sign of whatever the register held before.
    let mut zeroed: BTreeSet<u64> = BTreeSet::new();
    for instruction in instructions {
        for op in &instruction.ops {
            let opcode = op.opcode.as_str();
            // `op a, a`: `xor`/`sub` of a register with itself is the zeroing
            // idiom, and `and`/`or` of one with itself is `test r, r`, which
            // reads the value to compare it with zero and says nothing about
            // its signedness.
            let same_operands = op.inputs.len() == 2
                && op.inputs[0] == op.inputs[1]
                && op.inputs[0].space == "register";
            let zero_write = op.output.as_ref().is_some_and(|output| output.space == "register")
                && ((matches!(opcode, "INT_XOR" | "INT_SUB") && same_operands)
                    || (opcode == "INT_ZEXT"
                        && op.inputs.first().is_some_and(|input| {
                            input.space == "register" && zeroed.contains(&input.offset)
                        })));
            let mut spill_alias: Option<(u64, u32)> = None;
            let live = |facts: &mut Facts, input: &PcodeVarnode, class: Class| {
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
                    facts.constrain_register(origin, class);
                }
            };
            // What each temporary was computed from, one level at a time. A
            // product is not: `index * 4` is never the pointer it indexes.
            if let Some(output) = &op.output
                && matches!(
                    opcode,
                    "INT_ADD" | "INT_SUB" | "COPY" | "INT_ZEXT" | "INT_SEXT"
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
                    } else if input.space == "register" && input.size >= machine.pointer_size {
                        sources.push(input.offset);
                    } else if let Some(more) = built_from.get(&(input.space.clone(), input.offset))
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
            // Whether this op leaves its output holding a resolved address.
            // A register written by anything else no longer holds the one it
            // did: `lea rax,[rsi-1]` then `mov rax,rdi` is not `rsi-1`.
            let mut addressed = false;
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
                    addressed = true;
                }
            }
            // A copy of a resolved address is the same address: MIPS SLEIGH
            // computes `*(fp+disp)` as `t = fp+disp` then `u = t`, and the
            // STORE reads `u` — without this the slot never resolves.
            if opcode == "COPY"
                && let Some(output) = &op.output
                && let Some(input) = op.inputs.first()
                && let Some(pair) = address_of
                    .get(&(input.space.clone(), input.offset))
                    .copied()
            {
                address_of.insert((output.space.clone(), output.offset), pair);
                addressed = true;
            }
            if !addressed
                && let Some(output) = &op.output
                && output.space == "register"
            {
                address_of.remove(&(output.space.clone(), output.offset));
            }
            // `t = index * stride` or `t = index << shift`: the scaled index
            // of an array access.
            if let Some(output) = &op.output {
                let key = (output.space.clone(), output.offset);
                if opcode == "INT_MULT"
                    && let (Some(a), Some(b)) = (op.inputs.first(), op.inputs.get(1))
                {
                    let stride = if b.space == "const" {
                        Some(b.offset)
                    } else if a.space == "const" {
                        Some(a.offset)
                    } else {
                        None
                    };
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
                    && a.space != "const"
                    && b.space != "const"
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
                        | "INT_SDIV" | "INT_SREM" | "INT_SEXT" | "FLOAT_INT2FLOAT" => {
                            Class::Int(size * 8)
                        }
                        "INT_LESS" | "INT_LESSEQUAL" | "INT_CARRY" | "INT_RIGHT" | "INT_DIV"
                        | "INT_REM" | "INT_ZEXT" => Class::Uint(size * 8),
                        _ if opcode.starts_with("FLOAT_") => Class::Float(size * 8),
                        "COPY" | "INT_ADD" | "INT_SUB" | "INT_MULT" | "INT_AND" | "INT_OR"
                        | "INT_XOR" | "INT_LEFT" | "INT_EQUAL" | "INT_NOTEQUAL" => {
                            Class::Num(size * 8)
                        }
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
                    if let Some(output) = &op.output {
                        load_width.insert((output.space.clone(), output.offset), output.size);
                    }
                    if let Some(address) = op.inputs.get(1) {
                        let slot = address_of.get(&(address.space.clone(), address.offset));
                        // The loaded value's class is the field's class —
                        // but the field is only classified by a later use,
                        // so record the load and backfill after `fields`.
                        if let (Some(output), Some((base, disp))) = (&op.output, slot.copied())
                            && output.space == "register"
                        {
                            loads.push((output.offset, base, disp));
                        }
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
                                if let Some(origin) = sole_origin(&built_from, &defined, address)
                                {
                                    facts.constrain_register(origin, Class::Ptr);
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
                                    && !frame.contains(&base)
                                    && let Some(output) = &op.output
                                {
                                    struct_bases.insert(base);
                                    pending.insert(
                                        (output.space.clone(), output.offset),
                                        (base, disp, output.size),
                                    );
                                    if !defined.contains(&base) {
                                        facts.constrain_register(base, Class::Ptr);
                                    }
                                }
                            }
                        }
                    }
                }
                "STORE" => {
                    if let Some(address) = op.inputs.get(1) {
                        let key = address_of
                            .get(&(address.space.clone(), address.offset))
                            .copied();
                        match key {
                            Some(key) => {
                                // A store into `*(base+disp)` where `base`
                                // is an established struct base is a field
                                // write, never a spill — even when the value
                                // is a parameter register. A frame slot is
                                // never a field.
                                let in_frame = frame.contains(&key.0);
                                let is_struct_base = !in_frame && struct_bases.contains(&key.0);
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
                                    if !in_frame && (is_struct_base || !spilled.contains_key(&key)) {
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
                                        let entry = fields.entry((base, disp)).or_insert(Field {
                                            offset: disp,
                                            size: value.size,
                                            class: Class::Unknown,
                                        });
                                        entry.class = entry.class.join(class);
                                        entry.size = entry.size.max(value.size);
                                        if !defined.contains(&base) {
                                            facts.constrain_register(base, Class::Ptr);
                                        }
                                    }
                                }
                            }
                            None => {
                                live(&mut facts, address, Class::Ptr);
                                if let Some(origin) = sole_origin(&built_from, &defined, address)
                                {
                                    facts.constrain_register(origin, Class::Ptr);
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
                "INT_SLESS" | "INT_SLESSEQUAL" | "INT_SBORROW" if !signed_evidence(op) => {
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
                // `int2float` consumes a *signed* integer — Ghidra's
                // `opInt2Float` sign-extends its input (float.cc:614) — so
                // the generic FLOAT_ rule would misclassify it as a float.
                "FLOAT_INT2FLOAT" => {
                    for input in &op.inputs {
                        if input.size == 4 || input.size == 8 {
                            let class = Class::Int(input.size * 8);
                            live(&mut facts, input, class);
                        }
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
                // The parity flag's `value & 0xff` feeds only `popcount`: the
                // machine computing a flag, not the program masking a value.
                "INT_AND"
                    if op.output.as_ref().is_some_and(|output| {
                        parity.contains(&(output.space.clone(), output.offset))
                    }) => {}
                // `xor r, r` / `sub r, r` zero the register without reading it,
                // and `test r, r` (`and`/`or` of a register with itself) only
                // compares it with zero: none of them is evidence of a sign,
                // and a zeroing is not a read of the entry value.
                "INT_XOR" | "INT_SUB" if same_operands => {}
                "INT_AND" | "INT_OR" if same_operands => {
                    for input in &op.inputs {
                        let class = Class::Num(input.size * 8);
                        live(&mut facts, input, class);
                    }
                }
                // Plain arithmetic says the operand is a number of that
                // width and nothing more. A bitwise op is stronger: a value
                // you mask or XOR is conventionally unsigned, and a 64-bit
                // mask joins with a pointer without losing it.
                "INT_AND" | "INT_OR" | "INT_XOR" => {
                    for input in &op.inputs {
                        let class = Class::Uint(input.size * 8);
                        live(&mut facts, input, class);
                    }
                }
                "INT_ADD" | "INT_SUB" | "INT_MULT" | "INT_LEFT" | "INT_EQUAL" | "INT_NOTEQUAL" => {
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
                    // A zeroing idiom writes a constant: it leaves a class the
                    // body already proved for the register alone, and where
                    // there is none it is a number as wide as the zero it
                    // wrote (the width of the source for a zero-extension).
                    _ if zero_write => facts
                        .writes
                        .get(&output.offset)
                        .copied()
                        .filter(|class| *class != Class::Unknown)
                        .unwrap_or_else(|| {
                            let width = op.inputs.first().map_or(output.size, |input| {
                                if opcode == "INT_ZEXT" { input.size } else { output.size }
                            });
                            Class::Num(width * 8)
                        }),
                    // A loaded value's kind is unproven until a use commits
                    // to it, but its width is the load's — `opaque32`, not
                    // `unknown`, so a returned load reports its size.
                    "LOAD" => Class::Opaque(output.size * 8),
                    "INT_EQUAL" | "INT_NOTEQUAL" | "INT_LESS" | "INT_LESSEQUAL" | "INT_SLESS"
                    | "INT_SLESSEQUAL" | "BOOL_AND" | "BOOL_OR" | "BOOL_NEGATE" | "FLOAT_EQUAL"
                    | "FLOAT_NOTEQUAL" | "FLOAT_LESS" | "FLOAT_LESSEQUAL" => {
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
                        // A widened load is the loaded value, at the load's
                        // width: `movzx eax, byte[s]` is `opaque8`, not the
                        // 32-bit register it lands in.
                        if let Some(width) = source
                            .and_then(|input| load_width.get(&(input.space.clone(), input.offset)))
                        {
                            Class::Opaque(width * 8)
                        } else {
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
                    }
                    // `trunc` produces a signed integer — Ghidra's `opTrunc`
                    // casts to `intb` (float.cc:635) — and `nan` produces a
                    // boolean; neither is a float, so they precede the
                    // generic FLOAT_ output rule.
                    "FLOAT_TRUNC" => Class::Int(output.size * 8),
                    "FLOAT_NAN" => Class::Num(8),
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
                            // An opaque value carried through keeps its own
                            // width — `movzx eax, byte[s]` widens an 8-bit
                            // load into a 32-bit register, but the value is
                            // a byte, so the type is `opaque8` not 32.
                            Class::Opaque(_) => carried,
                            // The result is as wide as the operation says,
                            // with the kind its operands had.
                            Class::Int(_) => Class::Int(output.size * 8),
                            Class::Uint(_) => Class::Uint(output.size * 8),
                            Class::IntOrUint(_) => Class::IntOrUint(output.size * 8),
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
                // Written at all — even a `LOAD` whose class is unproven —
                // is what separates a value return from `void`.
                facts.touched.insert(output.offset);
            }
            // A copy carries the source's identity forward, then the output
            // counts as defined: its later uses are not the entry value.
            if let Some(output) = &op.output {
                // Consult the input's alias *before* the output's write
                // clears it: `add rax,rdx` reads rax's alias to record rdx
                // as a source, and `INT_ZEXT RCX←ECX` reads ECX's alias to
                // carry the parameter's identity.
                let carried = if (opcode == "COPY"
                    || (matches!(opcode, "INT_AND" | "INT_OR") && same_operands))
                    && let Some(input) = op.inputs.first()
                {
                    if input.space == "register" && !defined.contains(&input.offset) {
                        Some((input.offset, input.size))
                    } else {
                        alias.get(&(input.space.clone(), input.offset)).copied()
                    }
                } else if opcode == "INT_ZEXT"
                    && let Some(input) = op.inputs.first()
                {
                    // A zero-extension carries the value's identity: the x86
                    // `mov ecx,[m]` idiom emits `RCX = zext(ECX)`, and on
                    // aarch64 a 32-bit reload is `w8 = zext(LOAD(...))` where
                    // the loaded temp already aliases the spilled parameter.
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
                    // A copy or constant offset of a stack address is one;
                    // any other write ends the register's frame role. The
                    // stack pointer itself stays the frame throughout.
                    let from_frame = matches!(opcode, "COPY" | "INT_ADD" | "INT_SUB")
                        && (opcode == "COPY"
                            || op.inputs.get(1).is_some_and(|disp| disp.space == "const"))
                        && op.inputs.first().is_some_and(|input| {
                            if input.space == "register" {
                                frame.contains(&input.offset)
                            } else {
                                address_of
                                    .get(&(input.space.clone(), input.offset))
                                    .is_some_and(|(base, _)| frame.contains(base))
                            }
                        });
                    if from_frame {
                        frame.insert(output.offset);
                    } else if machine.stack_pointer != Some(output.offset) {
                        frame.remove(&output.offset);
                    }
                    defined.insert(output.offset);
                    if zero_write {
                        zeroed.insert(output.offset);
                    } else {
                        zeroed.remove(&output.offset);
                    }
                    facts.aliases.remove(&output.offset);
                    if let Some(a) = held {
                        facts.aliases.insert(output.offset, a);
                    }
                }
            }
        }
    }
    // A value loaded from a field carries the field's class: `n->next` is a
    // pointer, `p->x` a float. Backfill each load's destination register so
    // a `return n->next` reports `ptr`, not `num64`.
    for (dest, base, disp) in &loads {
        if let Some(field) = fields.get(&(*base, *disp))
            && field.class != Class::Unknown
            && facts.writes.get(dest).is_none_or(|c| *c == Class::Unknown)
        {
            facts.writes.insert(*dest, field.class);
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
        facts.structural.entry(base).or_insert(Ty::Array {
            elem: Box::new(Ty::Scalar(elem)),
            stride,
        });
    }
    facts
}

/// The one entry-value register an address was computed from, if exactly
/// one. `p[i]` with a byte index is `p + i`, and when both addends are
/// pointer-width parameters either could be the base, so a sum of two
/// names no pointer on its own. A register the body already redefined is
/// a computed value, not a candidate.
fn sole_origin(
    built_from: &BTreeMap<(String, u64), Vec<u64>>,
    defined: &BTreeSet<u64>,
    address: &PcodeVarnode,
) -> Option<u64> {
    let mut candidates = built_from
        .get(&(address.space.clone(), address.offset))?
        .iter()
        .filter(|origin| !defined.contains(origin));
    match (candidates.next(), candidates.next()) {
        (Some(origin), None) => Some(*origin),
        _ => None,
    }
}

/// The class already written to a register, without borrowing `facts`
/// mutably at the call site.
fn self_written(facts: &Facts, offset: u64) -> Class {
    facts.written(offset).join(facts.get(offset))
}

/// Merging these results into recovered prototypes (on unless `ROMWRIGHT_INFERRED_TYPES=0`).
pub mod prototypes;

/// What the direct callers of a function do with it: arguments set, result read.
pub mod call_support;

/// Float parameter registers the body also reads at another width.
pub mod register_overlap;

/// Variadic register-save areas: which argument registers are not parameters.
pub mod variadic;

/// Eight-byte parameters passed in an aligned pair of 4-byte registers.
pub mod pair_params;

#[cfg(test)]
mod tests {
    use super::*;

    /// x86-64: eight-byte pointers, RSP at register offset 0x20.
    const X86_64: Machine = Machine {
        pointer_size: 8,
        stack_pointer: Some(0x20),
    };
    /// The ARM-LE-32-v4t register file: r0 0x20, r1 0x24, r2 0x28, sp 0x54.
    const ARM: Machine = Machine {
        pointer_size: 4,
        stack_pointer: Some(0x54),
    };
    /// MIPS-LE-32: v0 0x8, v1 0xc, a0 0x10, sp 0x74, s8 0x78.
    const MIPS: Machine = Machine {
        pointer_size: 4,
        stack_pointer: Some(0x74),
    };
    /// PowerPC-BE-32: r1 (sp) 0x4, r3 0xc, r4 0x10, r5 0x14.
    const PPC: Machine = Machine {
        pointer_size: 4,
        stack_pointer: Some(0x4),
    };

    /// The x86-64 inference every pre-existing test was written against.
    fn infer(instructions: &[PcodeInstruction]) -> Facts {
        super::infer(instructions, &X86_64)
    }

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
    fn converting_a_loaded_integer_does_not_make_the_field_float() {
        let facts = infer(&[instruction(vec![
            op(
                "INT_ADD",
                Some(varnode("unique", 0x100, 8)),
                vec![varnode("register", 0x38, 8), varnode("const", 0x34, 8)],
            ),
            op(
                "LOAD",
                Some(varnode("unique", 0x200, 4)),
                vec![varnode("const", 0x1b1, 4), varnode("unique", 0x100, 8)],
            ),
            op(
                "FLOAT_INT2FLOAT",
                Some(varnode("unique", 0x300, 4)),
                vec![varnode("unique", 0x200, 4)],
            ),
        ])]);
        let Ty::Ptr(inner) = facts.structural(0x38).unwrap() else {
            panic!("expected pointer")
        };
        let Ty::Struct(fields) = inner.as_ref() else {
            panic!("expected structure")
        };
        assert_eq!(fields[&0x34].class, Class::Int(32));
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
    fn xor_of_a_register_with_itself_is_a_zero_not_a_read() {
        // `xor eax, eax; ret`: the function returns a constant, and the
        // zeroing neither reads rax's entry value (so rax is no parameter)
        // nor makes the zero unsigned.
        let facts = infer(&[instruction(vec![
            op(
                "INT_XOR",
                Some(varnode("register", 0, 4)),
                vec![varnode("register", 0, 4), varnode("register", 0, 4)],
            ),
            op(
                "INT_ZEXT",
                Some(varnode("register", 0, 8)),
                vec![varnode("register", 0, 4)],
            ),
        ])]);
        assert!(!facts.read_before_write(0));
        assert_eq!(facts.get(0), Class::Unknown);
        assert_eq!(facts.written(0), Class::Num(32));
    }

    #[test]
    fn a_zeroing_write_keeps_the_class_the_return_register_already_proved() {
        // `sar rax, 3` ... `xor eax, eax` on a path laid out last: the
        // zero is every numeric class at once, so the signed result the
        // body proved is still what the register carries.
        let facts = infer(&[
            instruction(vec![op(
                "INT_SRIGHT",
                Some(varnode("register", 0, 8)),
                vec![varnode("register", 0x38, 8), varnode("const", 3, 8)],
            )]),
            instruction(vec![
                op(
                    "INT_XOR",
                    Some(varnode("register", 0, 4)),
                    vec![varnode("register", 0, 4), varnode("register", 0, 4)],
                ),
                op(
                    "INT_ZEXT",
                    Some(varnode("register", 0, 8)),
                    vec![varnode("register", 0, 4)],
                ),
            ]),
        ]);
        assert_eq!(facts.written(0), Class::Int(64));
    }

    #[test]
    fn test_of_a_register_with_itself_keeps_the_sign_a_branch_reads() {
        // `test edi, edi; js`: the sign flag of `edi & edi` is edi's sign,
        // and the `and` is no evidence that edi is unsigned. The parity
        // flag's `& 0xff` is the machine's, not the program's.
        let facts = infer(&[instruction(vec![
            op(
                "INT_AND",
                Some(varnode("unique", 0x100, 4)),
                vec![varnode("register", 0x38, 4), varnode("register", 0x38, 4)],
            ),
            op(
                "INT_SLESS",
                Some(varnode("unique", 0x200, 1)),
                vec![varnode("unique", 0x100, 4), varnode("const", 0, 4)],
            ),
            op(
                "INT_AND",
                Some(varnode("unique", 0x300, 4)),
                vec![varnode("unique", 0x100, 4), varnode("const", 0xff, 4)],
            ),
            op(
                "POPCOUNT",
                Some(varnode("unique", 0x400, 1)),
                vec![varnode("unique", 0x300, 4)],
            ),
            op(
                "CBRANCH",
                None,
                vec![varnode("ram", 0x1100, 8), varnode("unique", 0x200, 1)],
            ),
        ])]);
        assert_eq!(facts.get(0x38), Class::Int(32));
    }

    #[test]
    fn a_register_rewritten_after_an_address_computation_holds_no_address() {
        // `lea rax, [rsi-1]` then `mov rax, rdi` then `movdqu xmm0, [rax]`:
        // the load goes through rdi; rsi was only ever an addend.
        let facts = infer(&[
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x100, 8)),
                    vec![varnode("register", 0x30, 8), varnode("const", u64::MAX, 8)],
                ),
                op(
                    "COPY",
                    Some(varnode("register", 0, 8)),
                    vec![varnode("unique", 0x100, 8)],
                ),
            ]),
            instruction(vec![op(
                "COPY",
                Some(varnode("register", 0, 8)),
                vec![varnode("register", 0x38, 8)],
            )]),
            instruction(vec![op(
                "LOAD",
                Some(varnode("unique", 0x500, 16)),
                vec![varnode("const", 3, 8), varnode("register", 0, 8)],
            )]),
        ]);
        assert_eq!(facts.get(0x38), Class::Ptr);
        assert_ne!(facts.get(0x30), Class::Ptr);
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
        // one register, so the answer is the width they agree on with the
        // sign unresolved — `IntOrUint`, the join of `Int` and `Uint`.
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
        assert_eq!(facts.get(0x38), Class::IntOrUint(32));
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
                vec![
                    varnode("register", 0x28, 8),
                    varnode("const", 0xfffffff8, 8),
                ],
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

    /// The join must be a semilattice join: commutative, associative,
    /// idempotent, and an upper bound. The `Num`/`Int`/`Uint` collapse that
    /// `IntOrUint` replaced broke associativity — the same evidence gave
    /// different answers by accumulation order, and the subtype solver's
    /// fixpoint diverged on it.
    #[test]
    fn join_is_a_semilattice_join() {
        use Class::*;
        let elements = [
            Unknown,
            Opaque(8),
            Opaque(64),
            Num(32),
            Num(64),
            Int(32),
            Int(64),
            Uint(32),
            Uint(64),
            IntOrUint(32),
            IntOrUint(64),
            Float(32),
            Float(64),
            Ptr,
            Code,
            Top,
        ];
        // The order `join` induces: `a <= b` iff `a.join(b) == b`.
        let leq = |a: Class, b: Class| a.join(b) == b;
        for &a in &elements {
            // Idempotent.
            assert_eq!(a.join(a), a, "idempotent: {a:?}");
            for &b in &elements {
                // Commutative.
                assert_eq!(a.join(b), b.join(a), "commutative: {a:?} {b:?}");
                // Upper bound: the join is at or above each operand.
                assert!(leq(a, a.join(b)), "upper bound a: {a:?} {b:?}");
                assert!(leq(b, a.join(b)), "upper bound b: {a:?} {b:?}");
                for &c in &elements {
                    // Associative.
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(b.join(c)),
                        "associative: {a:?} {b:?} {c:?}"
                    );
                }
            }
        }
        // The counterexample that broke it: sign-conflict then float must
        // not depend on which side the float joined from.
        assert_eq!(
            Int(32).join(Uint(32)).join(Float(32)),
            Int(32).join(Uint(32).join(Float(32))),
        );
    }

    #[test]
    fn mips_fields_off_a_four_byte_base_make_a_struct_pointer() {
        // `lw v0, 4(a0)` / `sw v0, 8(a0)`: a0 is a pointer to a struct with
        // four-byte fields at +4 and +8, and the loaded field is signed.
        let facts = super::infer(
            &[
                instruction(vec![
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x100, 4)),
                        vec![varnode("register", 0x10, 4), varnode("const", 4, 4)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("register", 0x8, 4)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x100, 4)],
                    ),
                ]),
                instruction(vec![
                    op(
                        "INT_SLESS",
                        Some(varnode("unique", 0x200, 1)),
                        vec![varnode("register", 0x8, 4), varnode("const", 10, 4)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1100, 4), varnode("unique", 0x200, 1)],
                    ),
                ]),
                instruction(vec![
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x108, 4)),
                        vec![varnode("register", 0x10, 4), varnode("const", 8, 4)],
                    ),
                    op(
                        "STORE",
                        None,
                        vec![
                            varnode("const", 0x1b1, 4),
                            varnode("unique", 0x108, 4),
                            varnode("register", 0xc, 4),
                        ],
                    ),
                ]),
            ],
            &MIPS,
        );
        assert_eq!(facts.get(0x10), Class::Ptr);
        let Some(Ty::Ptr(inner)) = facts.structural(0x10) else {
            panic!("a0 should be a pointer: {:?}", facts.structural(0x10))
        };
        let Ty::Struct(fields) = inner.as_ref() else {
            panic!("a0 should point at a struct: {inner:?}")
        };
        assert_eq!(fields[&4].size, 4);
        assert_eq!(fields[&4].class, Class::Int(32));
        assert_eq!(fields[&8].size, 4);
    }

    #[test]
    fn a_mips_parameter_spilled_after_a_frame_local_read_is_still_a_spill() {
        // gcc -O0 MIPS: the frame pointer is a copy of sp, and the body
        // reads a local before it spills a0. The local read must not make
        // the frame a struct base, or the spill reads as a field write and
        // the reload loses the parameter.
        let facts = super::infer(
            &[
                // addiu sp, sp, -24
                instruction(vec![op(
                    "INT_ADD",
                    Some(varnode("register", 0x74, 4)),
                    vec![varnode("register", 0x74, 4), varnode("const", 0xffff_ffe8, 4)],
                )]),
                // move s8, sp
                instruction(vec![op(
                    "COPY",
                    Some(varnode("register", 0x78, 4)),
                    vec![varnode("register", 0x74, 4)],
                )]),
                // lw v0, 8(s8): a local
                instruction(vec![
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x100, 4)),
                        vec![varnode("register", 0x78, 4), varnode("const", 8, 4)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("register", 0x8, 4)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x100, 4)],
                    ),
                ]),
                // sw a0, 24(s8): the spill
                instruction(vec![
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x108, 4)),
                        vec![varnode("register", 0x78, 4), varnode("const", 24, 4)],
                    ),
                    op(
                        "STORE",
                        None,
                        vec![
                            varnode("const", 0x1b1, 4),
                            varnode("unique", 0x108, 4),
                            varnode("register", 0x10, 4),
                        ],
                    ),
                ]),
                // lw v1, 24(s8): the reload
                instruction(vec![
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x110, 4)),
                        vec![varnode("register", 0x78, 4), varnode("const", 24, 4)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("register", 0xc, 4)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x110, 4)],
                    ),
                ]),
                // slt + bnez on the reloaded value
                instruction(vec![
                    op(
                        "INT_SLESS",
                        Some(varnode("unique", 0x200, 1)),
                        vec![varnode("register", 0xc, 4), varnode("const", 10, 4)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1100, 4), varnode("unique", 0x200, 1)],
                    ),
                ]),
            ],
            &MIPS,
        );
        assert_eq!(facts.get(0x10), Class::Int(32));
        assert!(facts.structural(0x78).is_none(), "the frame is not a struct");
    }

    #[test]
    fn arm_ldr_with_offset_types_the_field_and_the_base() {
        // `ldr r0, [r0, #4]` then `cmp r0, #10; bge`: r0 on entry points
        // at a struct whose word at +4 is a signed int.
        let facts = super::infer(
            &[
                instruction(vec![
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x100, 4)),
                        vec![varnode("register", 0x20, 4), varnode("const", 4, 4)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("register", 0x20, 4)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x100, 4)],
                    ),
                ]),
                instruction(vec![
                    op(
                        "INT_SLESS",
                        Some(varnode("unique", 0x200, 1)),
                        vec![varnode("register", 0x20, 4), varnode("const", 10, 4)],
                    ),
                    op(
                        "CBRANCH",
                        None,
                        vec![varnode("ram", 0x1100, 4), varnode("unique", 0x200, 1)],
                    ),
                ]),
            ],
            &ARM,
        );
        assert_eq!(facts.get(0x20), Class::Ptr);
        let Some(Ty::Ptr(inner)) = facts.structural(0x20) else {
            panic!("r0 should be a pointer: {:?}", facts.structural(0x20))
        };
        let Ty::Struct(fields) = inner.as_ref() else {
            panic!("r0 should point at a struct: {inner:?}")
        };
        assert_eq!(
            fields[&4],
            Field {
                offset: 4,
                size: 4,
                class: Class::Int(32)
            }
        );
    }

    #[test]
    fn arm_scaled_index_makes_the_four_byte_base_an_array_pointer() {
        // `ldr r2, [r0, r1, lsl #2]`: r0 is a word array, r1 its index.
        // The base is a four-byte register, which an eight-byte pointer
        // assumption never counted as an address source.
        let facts = super::infer(
            &[instruction(vec![
                op(
                    "INT_LEFT",
                    Some(varnode("unique", 0x100, 4)),
                    vec![varnode("register", 0x24, 4), varnode("const", 2, 4)],
                ),
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x108, 4)),
                    vec![varnode("register", 0x20, 4), varnode("unique", 0x100, 4)],
                ),
                op(
                    "LOAD",
                    Some(varnode("register", 0x28, 4)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x108, 4)],
                ),
            ])],
            &ARM,
        );
        assert_eq!(facts.get(0x20), Class::Ptr);
        assert_ne!(facts.get(0x24), Class::Ptr, "the index is not a pointer");
        assert_eq!(
            facts.structural(0x20),
            Some(&Ty::Array {
                elem: Box::new(Ty::Scalar(Class::Num(32))),
                stride: 4
            })
        );
    }

    #[test]
    fn arm_byte_index_sum_names_no_pointer() {
        // `ldrb r2, [r0, r1]`: either addend could be the base, and with
        // four-byte pointers both are pointer-width, so neither is claimed.
        let facts = super::infer(
            &[instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x108, 4)),
                    vec![varnode("register", 0x20, 4), varnode("register", 0x24, 4)],
                ),
                op(
                    "LOAD",
                    Some(varnode("unique", 0x200, 1)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x108, 4)],
                ),
            ])],
            &ARM,
        );
        assert_ne!(facts.get(0x20), Class::Ptr);
        assert_ne!(facts.get(0x24), Class::Ptr);
    }

    #[test]
    fn ppc_lwz_off_a_base_register_recovers_struct_fields() {
        // `lwz r3, 8(r4); addi r3, r3, 1; stw r3, 0xc(r4)`: r4 points at a
        // struct with word fields at +8 and +0xc.
        let facts = super::infer(
            &[
                instruction(vec![
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x100, 4)),
                        vec![varnode("register", 0x10, 4), varnode("const", 8, 4)],
                    ),
                    op(
                        "LOAD",
                        Some(varnode("register", 0xc, 4)),
                        vec![varnode("const", 0x1b1, 4), varnode("unique", 0x100, 4)],
                    ),
                ]),
                instruction(vec![op(
                    "INT_ADD",
                    Some(varnode("register", 0xc, 4)),
                    vec![varnode("register", 0xc, 4), varnode("const", 1, 4)],
                )]),
                instruction(vec![
                    op(
                        "INT_ADD",
                        Some(varnode("unique", 0x108, 4)),
                        vec![varnode("register", 0x10, 4), varnode("const", 0xc, 4)],
                    ),
                    op(
                        "STORE",
                        None,
                        vec![
                            varnode("const", 0x1b1, 4),
                            varnode("unique", 0x108, 4),
                            varnode("register", 0xc, 4),
                        ],
                    ),
                ]),
            ],
            &PPC,
        );
        assert_eq!(facts.get(0x10), Class::Ptr);
        let Some(Ty::Ptr(inner)) = facts.structural(0x10) else {
            panic!("r4 should be a pointer: {:?}", facts.structural(0x10))
        };
        let Ty::Struct(fields) = inner.as_ref() else {
            panic!("r4 should point at a struct: {inner:?}")
        };
        assert_eq!(fields.keys().copied().collect::<Vec<_>>(), vec![8, 0xc]);
        assert!(fields.values().all(|field| field.size == 4));
    }

    #[test]
    fn ppc_multiplied_index_is_not_the_pointer_it_indexes() {
        // `mulli r5, r5, 12; lwzx r3, r4, r5`: r4 is an array of 12-byte
        // records, r5 the index — a product is never a pointer.
        let facts = super::infer(
            &[instruction(vec![
                op(
                    "INT_MULT",
                    Some(varnode("register", 0x14, 4)),
                    vec![varnode("register", 0x14, 4), varnode("const", 12, 4)],
                ),
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x108, 4)),
                    vec![varnode("register", 0x10, 4), varnode("register", 0x14, 4)],
                ),
                op(
                    "LOAD",
                    Some(varnode("register", 0xc, 4)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x108, 4)],
                ),
            ])],
            &PPC,
        );
        assert_eq!(facts.get(0x10), Class::Ptr);
        assert_ne!(facts.get(0x14), Class::Ptr);
    }

    #[test]
    fn the_frame_is_never_a_struct_base_on_x86_64_either() {
        // `mov rbp, rsp; mov eax, [rbp-0x14]; mov [rbp-0x18], rdi;
        // mov rax, [rbp-0x18]; cmp rax, 10; jl`: the local read must not
        // turn the parameter's spill into a field write.
        let facts = infer(&[
            instruction(vec![op(
                "COPY",
                Some(varnode("register", 0x28, 8)),
                vec![varnode("register", 0x20, 8)],
            )]),
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x100, 8)),
                    vec![varnode("register", 0x28, 8), varnode("const", (-0x14i64) as u64, 8)],
                ),
                op(
                    "LOAD",
                    Some(varnode("register", 0x0, 4)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x100, 8)],
                ),
            ]),
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x108, 8)),
                    vec![varnode("register", 0x28, 8), varnode("const", (-0x18i64) as u64, 8)],
                ),
                op(
                    "STORE",
                    None,
                    vec![
                        varnode("const", 0x1b1, 4),
                        varnode("unique", 0x108, 8),
                        varnode("register", 0x38, 8),
                    ],
                ),
            ]),
            instruction(vec![
                op(
                    "INT_ADD",
                    Some(varnode("unique", 0x110, 8)),
                    vec![varnode("register", 0x28, 8), varnode("const", (-0x18i64) as u64, 8)],
                ),
                op(
                    "LOAD",
                    Some(varnode("register", 0x0, 8)),
                    vec![varnode("const", 0x1b1, 4), varnode("unique", 0x110, 8)],
                ),
                op(
                    "INT_SLESS",
                    Some(varnode("unique", 0x200, 1)),
                    vec![varnode("register", 0x0, 8), varnode("const", 10, 8)],
                ),
                op(
                    "CBRANCH",
                    None,
                    vec![varnode("ram", 0x1100, 8), varnode("unique", 0x200, 1)],
                ),
            ]),
        ]);
        assert_eq!(facts.get(0x38), Class::Int(64));
        assert!(facts.structural(0x28).is_none(), "rbp is the frame, not a struct");
    }
}
