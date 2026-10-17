//! Linkage evidence over SLEIGH p-code, not instruction encodings: whether a
//! short run of instructions does nothing but reach a pointer slot through an
//! indirect branch (an import stub, a PLT entry, a MIPS `lui/lw/jr t9` call
//! stub).
//!
//! The register-use rules follow Ghidra's `CreateThunkFunctionCmd`
//! (`getThunkedAddr`, `allow8bitNonUse`; Apache-2.0, Ghidra 12.1.3
//! `Features/Base/src/main/java/ghidra/app/cmd/function/CreateThunkFunctionCmd.java`).
//! The evaluator replaces the console's `linkage` command
//! (`RomwrightLinkageEmit`, once in `native/romwright_linkage.hh`): it reads
//! the p-code of each instruction as the translator emits it, keeps a bounded
//! table of register values (constants, pointer slots, slots still waiting on
//! caller context, and ISA-mode bits), and evaluates constant operations with
//! the decompiler's own `OpBehavior` table.
use super::{LinkageContext, LinkageResult, SleighLifter};
use kuna_base::address::Address;
use kuna_base::space::{spacetype, AddrSpace};
use kuna_num::float::FloatFormat;
use kuna_num::opbehavior::{register_instructions, FloatFormatProvider, OpBehavior};
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::sleigh::Sleigh;
use kuna_sleigh::translate::{PcodeEmit, Translate};
use std::rc::Rc;

/// Capacity of the value table: a stub that needs more is not a stub.
const CELLS: usize = 64;
/// Instructions of a stub (`for (i < 8; ...)` of the console command).
const STUB_INSTRUCTIONS: usize = 8;
/// Instructions between a caller's origin and the branch into the stub.
const CONTEXT_INSTRUCTIONS: usize = 64;
/// P-code operations of one instruction before it stops being a stub's.
const MAX_OPERATIONS: usize = 128;

/// The float formats `OpBehavior`'s float operations read, by encoding size.
struct Formats(Vec<FloatFormat>);

impl FloatFormatProvider for Formats {
    fn get_float_format(&self, size: i32) -> Option<&FloatFormat> {
        self.0.iter().find(|format| format.get_size() == size)
    }
}

/// What linkage evidence reads off the loaded language.
pub(super) struct LinkageEnv {
    code_space: Rc<AddrSpace>,
    data_space: Rc<AddrSpace>,
    /// Every address space by its manager index: a `LOAD`'s first input names
    /// the space it reads as that index (`VarnodeData::getSpaceFromConst`).
    spaces: Vec<Option<Rc<AddrSpace>>>,
    /// The language selects the instruction set with the low address bit.
    /// Ghidra decides this by the presence of a register of that name
    /// (`PseudoDisassembler.hasLowBitCodeModeInAddrValues`); in the pinned
    /// specs it is a context field -- MIPS declares `LowBitCodeMode=(1,1)`,
    /// ARM `(0,0)`.
    low_bit_mode: bool,
    /// `Translate::getAlignment`.
    alignment: u64,
    /// `OpBehavior::registerInstructions`, by opcode.
    behaviors: Vec<Option<Rc<dyn OpBehavior>>>,
}

impl LinkageEnv {
    pub(super) fn new(sleigh: &mut Sleigh, code_space: Rc<AddrSpace>, data_space: Rc<AddrSpace>) -> Self {
        let manager = sleigh.base().manager();
        let spaces = (0..manager.num_spaces()).map(|index| manager.get_space(index).cloned()).collect();
        let formats: Rc<dyn FloatFormatProvider> = Rc::new(Formats(sleigh.translate_base().float_formats().to_vec()));
        let mut behaviors = Vec::new();
        register_instructions(&mut behaviors, &formats);
        let low_bit_mode = sleigh.with_context_db_mut(|db| db.get_variable(b"LowBitCodeMode").is_ok());
        Self {
            code_space,
            data_space,
            spaces,
            low_bit_mode,
            alignment: sleigh.translate_base().get_alignment().max(0) as u64,
            behaviors,
        }
    }

    /// `memory(space)`: the default code or data space.
    fn memory(&self, space: &Rc<AddrSpace>) -> bool {
        Rc::ptr_eq(space, &self.code_space) || Rc::ptr_eq(space, &self.data_space)
    }
}

/// What a varnode is known to hold. `Mode` is a value derived from a code
/// pointer's ISA-mode bit rather than from the pointer itself: on a language
/// that selects the instruction set with the low address bit, `JXWritePC`
/// computes `(addr & 1) != 0`, hands it to `setISAMode`, and branches to
/// `addr & ~1` (Ghidra's `mips.sinc`, `JXWritePC`; ARM does the same). Such a
/// value cannot be the pointer, so it neither resolves a slot nor makes the
/// stub unknowable -- Ghidra tolerates exactly this, allowing flag-sized
/// registers to be set and never read (`CreateThunkFunctionCmd.getThunkedAddr`,
/// `allow8bitNonUse`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Unknown,
    Constant,
    Slot,
    UnresolvedSlot,
    Mode,
}

#[derive(Clone, Copy)]
struct Value {
    kind: Kind,
    value: u64,
}

struct Cell {
    var: VarnodeData,
    value: Value,
    used: bool,
}

fn mask(size: u32) -> u64 {
    if size >= 8 { !0 } else { (1u64 << (size * 8)) - 1 }
}

fn space_type(var: &VarnodeData) -> Option<spacetype> {
    var.space.as_ref().map(|space| space.get_type())
}

/// One run of instructions' p-code, evaluated as it is emitted.
struct Evidence {
    env: Rc<LinkageEnv>,
    cells: Vec<Cell>,
    instruction_mark: usize,
    probing: bool,
    unknown_read: bool,
    bad: bool,
    terminal: bool,
    flow: bool,
    call: bool,
    operations: usize,
    slot: u64,
    flow_target: u64,
}

impl Evidence {
    fn new(env: Rc<LinkageEnv>) -> Self {
        Self {
            env,
            cells: Vec::with_capacity(CELLS),
            instruction_mark: 0,
            probing: false,
            unknown_read: false,
            bad: false,
            terminal: false,
            flow: false,
            call: false,
            operations: 0,
            slot: 0,
            flow_target: 0,
        }
    }

    fn get(&mut self, var: &VarnodeData, consume: bool) -> Value {
        if var.size == 0 || var.size > 8 {
            self.bad = true;
            return Value { kind: Kind::Unknown, value: 0 };
        }
        match space_type(var) {
            Some(spacetype::IPTR_CONSTANT) => return Value { kind: Kind::Constant, value: var.offset },
            Some(_) if var.space.as_ref().is_some_and(|space| self.env.memory(space)) => {
                return Value { kind: Kind::Slot, value: var.offset };
            }
            _ => {}
        }
        if let Some(cell) = self.cells.iter_mut().find(|cell| cell.var == *var) {
            if consume {
                cell.used = true;
            }
            if matches!(cell.value.kind, Kind::Unknown | Kind::UnresolvedSlot) {
                self.unknown_read = true;
            }
            return cell.value;
        }
        self.unknown_read = true;
        Value { kind: Kind::Unknown, value: 0 }
    }

    fn put(&mut self, var: &VarnodeData, mut value: Value) {
        let memory = var.space.as_ref().is_some_and(|space| self.env.memory(space));
        if var.size == 0 || var.size > 8 || memory || space_type(var) == Some(spacetype::IPTR_CONSTANT) {
            self.bad = true;
            return;
        }
        if value.kind == Kind::Constant {
            value.value &= mask(var.size);
        }
        for cell in &mut self.cells {
            if cell.var == *var {
                cell.value = value;
                cell.used = false;
                return;
            }
            let same_space = match (&cell.var.space, &var.space) {
                (Some(a), Some(b)) => Rc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            };
            if same_space
                && if cell.var.offset <= var.offset {
                    var.offset - cell.var.offset < u64::from(cell.var.size)
                } else {
                    cell.var.offset - var.offset < u64::from(var.size)
                }
            {
                // Partial register aliases need an explicit value merge;
                // never retain stale bits.
                self.bad = true;
                return;
            }
        }
        if self.cells.len() == CELLS {
            self.bad = true;
            return;
        }
        self.cells.push(Cell { var: var.clone(), value, used: false });
    }

    fn begin_context(&mut self) {
        self.probing = true;
    }

    fn begin_linkage(&mut self) {
        self.probing = false;
        self.unknown_read = false;
        for cell in &mut self.cells {
            cell.used = true;
        }
    }

    fn begin_instruction(&mut self) {
        self.operations = 0;
        self.flow = false;
        self.call = false;
        // Where this instruction's own writes start (before the temporaries
        // go, as the console took it). A delay-slot instruction is emitted as
        // part of the branch that owns it, so its side effects belong to the
        // transfer rather than to the stub's data flow.
        self.instruction_mark = self.cells.len();
        let mut index = 0;
        while index < self.cells.len() {
            if space_type(&self.cells[index].var) == Some(spacetype::IPTR_INTERNAL) {
                self.cells.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }

    fn shape(&self, table: bool) -> bool {
        if self.bad || !self.terminal {
            return false;
        }
        if !table {
            for cell in self.cells.iter().take(self.instruction_mark) {
                // A register the stub computes and never reads means it does
                // more than reach a pointer slot -- except in the branch's own
                // instruction, whose delay slot writes the lazy-binding index
                // every MIPS stub writes (`addiu t8, t7, %lo(slot)`).
                if space_type(&cell.var) != Some(spacetype::IPTR_INTERNAL) && cell.var.size > 1 && !cell.used {
                    return false;
                }
            }
        }
        true
    }

    fn complete(&self, table: bool) -> bool {
        self.shape(table) && !self.unknown_read
    }

    fn needs_context(&self, table: bool) -> bool {
        self.shape(table) && self.unknown_read
    }

    fn operation(&mut self, opcode: OpCode, out: Option<&VarnodeData>, vars: &[VarnodeData]) {
        let size = vars.len();
        if self.probing && out.is_none() {
            // Caller stores cannot produce constants: memory contents are
            // never read by this evaluator. Retain only register facts
            // independent of memory.
            if opcode == OpCode::CPUI_STORE {
                return;
            }
            if matches!(opcode, OpCode::CPUI_CALL | OpCode::CPUI_BRANCH)
                && size == 1
                && vars[0].space.as_ref().is_some_and(|space| Rc::ptr_eq(space, &self.env.code_space))
            {
                self.flow = true;
                self.call = opcode == OpCode::CPUI_CALL;
                self.flow_target = vars[0].offset;
            } else {
                self.bad = true;
            }
            return;
        }
        if opcode == OpCode::CPUI_BRANCHIND && size == 1 {
            let target = self.get(&vars[0], true);
            if !matches!(target.kind, Kind::Slot | Kind::UnresolvedSlot) {
                self.bad = true;
            } else {
                self.terminal = true;
                self.slot = target.value;
            }
            return;
        }
        if opcode == OpCode::CPUI_CALLOTHER && out.is_none() {
            // A user-defined operation with no output is a processor side
            // effect, not data flow: MIPS switches ISA mode on an indirect
            // jump, which used to poison every stub the jump belongs to.
            return;
        }
        let Some(out) = out.filter(|out| out.size != 0 && out.size <= 8) else {
            self.bad = true;
            return; // Includes stores, calls, returns and other control flow.
        };
        if opcode == OpCode::CPUI_LOAD && size == 2 {
            let space = self.env.spaces.get(vars[0].offset as usize).and_then(Option::as_ref).cloned();
            let address = self.get(&vars[1], out.size >= vars[1].size);
            let Some(space) = space.filter(|space| self.env.memory(space) && space.get_word_size() != 0) else {
                self.bad = true;
                return;
            };
            if address.kind != Kind::Constant {
                self.unknown_read = true;
                self.put(out, Value { kind: Kind::UnresolvedSlot, value: 0 });
                return;
            }
            let word = u64::from(space.get_word_size());
            if address.value > !0u64 / word {
                self.bad = true;
                return;
            }
            let byte = AddrSpace::address_to_byte(address.value, space.get_word_size());
            self.put(out, Value { kind: Kind::Slot, value: byte });
            return;
        }
        let behavior = match self.env.behaviors.get(opcode as usize).and_then(Option::as_ref) {
            Some(behavior) if (1..=2).contains(&size) => Rc::clone(behavior),
            _ => {
                self.bad = true;
                return;
            }
        };
        let left = self.get(&vars[0], out.size >= vars[0].size);
        if opcode == OpCode::CPUI_COPY && size == 1 {
            if out.size != vars[0].size {
                self.bad = true;
                return;
            }
            self.put(out, left);
            return;
        }
        let right = if size == 2 {
            self.get(&vars[1], out.size >= vars[1].size)
        } else {
            Value { kind: Kind::Constant, value: 0 }
        };
        if self.bad {
            return;
        }
        // Processor alignment masking does not change the identity of the
        // loaded pointer slot, and neither does clearing the ISA-mode bit on
        // a language that carries the mode in the low address bit. `AND` is
        // commutative and SLEIGH writes it both ways round -- MIPS spells the
        // mask first (`tmp = -2; tmp = tmp & addr`, `JXWritePC`) and the mode
        // test second (`addr & 0x1`) -- so the pointer side is found rather
        // than assumed.
        if opcode == OpCode::CPUI_INT_AND && size == 2 {
            let (pointer, constant, pointer_size) = if right.kind == Kind::Constant && left.kind != Kind::Constant {
                (Some(left), right, vars[0].size)
            } else if left.kind == Kind::Constant && right.kind != Kind::Constant {
                (Some(right), left, vars[1].size)
            } else {
                (None, left, 0)
            };
            if let Some(pointer) = pointer.filter(|pointer| matches!(pointer.kind, Kind::Slot | Kind::UnresolvedSlot | Kind::Mode)) {
                let full = mask(pointer_size);
                let value = constant.value & full;
                let alignment = self.env.alignment;
                let aligning = alignment != 0 && alignment & (alignment - 1) == 0 && value == full & !(alignment - 1);
                let demoding = self.env.low_bit_mode && value == full & !1u64;
                if pointer.kind != Kind::Mode && out.size == pointer_size && (aligning || demoding) {
                    self.put(out, pointer);
                    return;
                }
                // The complement: the mode bit itself, which the branch hands
                // to `setISAMode` and never to the program counter.
                if self.env.low_bit_mode && value == 1 {
                    self.put(out, Value { kind: Kind::Mode, value: 0 });
                    return;
                }
            }
        }
        if behavior.is_special() || behavior.is_unary() != (size == 1) {
            self.bad = true;
            return;
        }
        if left.kind == Kind::Mode || right.kind == Kind::Mode {
            // A test or a copy of the mode bit stays a mode bit; nothing
            // derived from it can name the slot, and its being unread is not
            // a side effect.
            if matches!(left.kind, Kind::Mode | Kind::Constant) && matches!(right.kind, Kind::Mode | Kind::Constant) {
                self.put(out, Value { kind: Kind::Mode, value: 0 });
                return;
            }
            self.unknown_read = true;
            self.put(out, Value { kind: Kind::Unknown, value: 0 });
            return;
        }
        if left.kind != Kind::Constant || right.kind != Kind::Constant {
            self.unknown_read = true;
            self.put(out, Value { kind: Kind::Unknown, value: 0 });
            return;
        }
        let evaluated = if size == 1 {
            behavior.evaluate_unary(out.size as i32, vars[0].size as i32, left.value)
        } else {
            behavior.evaluate_binary(out.size as i32, vars[0].size as i32, left.value, right.value)
        };
        match evaluated {
            Ok(value) => self.put(out, Value { kind: Kind::Constant, value }),
            // An evaluation error (a division by zero, a float format the
            // language lacks) aborts the instruction as an exception did.
            Err(_) => self.bad = true,
        }
    }
}

impl PcodeEmit for Evidence {
    fn dump(&mut self, _addr: &Address, opcode: OpCode, out: Option<&VarnodeData>, vars: &[VarnodeData]) {
        self.operations += 1;
        if self.bad {
            return;
        }
        if self.terminal {
            // The ops that follow an indirect branch inside the same
            // instruction are its delay slot's: SLEIGH emits a delay-slot
            // instruction as part of the branch that owns it, and the walk
            // already stops at the branch. Marking those ops bad refused every
            // MIPS linkage stub -- `lui/lw/jr t9` -- and left its callee named
            // `FUN_<addr>` instead of `printf`.
            return;
        }
        if self.flow || self.operations > MAX_OPERATIONS {
            self.bad = true;
            return;
        }
        if opcode == OpCode::CPUI_COPY && vars.len() == 1 && out.is_some_and(|out| *out == vars[0]) {
            return;
        }
        self.operation(opcode, out, vars);
    }
}

impl SleighLifter {
    /// Decodes one instruction into `evidence`; its length, or `None` when it
    /// does not decode (every decode failure and every exception of the
    /// console's `oneInstruction`).
    fn linkage_instruction(&mut self, evidence: &mut Evidence, at: &Address) -> Option<i32> {
        if self.exhausts_parser_states(at) {
            return None;
        }
        self.sleigh.one_instruction(evidence, at).ok()
    }

    /// `callerContext`: the registers an instruction run from `origin` to
    /// `branch` leaves, when it ends in a plain jump to `target`. Constants and
    /// stores only: nothing here reads memory.
    fn caller_context(&mut self, evidence: &mut Evidence, origin: u64, branch: u64, target: u64) -> bool {
        let mut current = self.address(origin);
        let branch = self.address(branch);
        let target = self.address(target);
        if current.get_offset() > branch.get_offset() {
            return false;
        }
        evidence.begin_context();
        for _ in 0..CONTEXT_INSTRUCTIONS {
            if evidence.bad {
                break;
            }
            evidence.begin_instruction();
            let Some(size) = self.linkage_instruction(evidence, &current).filter(|size| *size > 0) else {
                return false;
            };
            if evidence.bad {
                return false;
            }
            let next = self.step(&current, size);
            if next.get_offset() <= current.get_offset() {
                return false;
            }
            if current.get_offset() == branch.get_offset() {
                if !evidence.flow || evidence.call || evidence.flow_target != target.get_offset() {
                    return false;
                }
                evidence.begin_linkage();
                return true;
            }
            if next.get_offset() > branch.get_offset() || (evidence.flow && evidence.flow_target != next.get_offset()) {
                return false;
            }
            current = next;
        }
        false
    }

    fn step(&self, at: &Address, size: i32) -> Address {
        let code = &self.code_space;
        Address::new(Rc::clone(code), code.wrap_offset(at.get_offset().wrapping_add(size as i64 as u64)))
    }

    /// One stub's answer: `from` (the caller's origin and branch) supplies
    /// registers the stub itself does not set.
    fn linkage_at(&mut self, start: u64, table: bool, from: Option<(u64, u64)>) -> LinkageResult {
        let mut evidence = Evidence::new(Rc::clone(&self.linkage));
        let mut current = self.address(start);
        let mut length = 0u32;
        if let Some((origin, branch)) = from
            && !self.caller_context(&mut evidence, origin, branch, start) {
                evidence.bad = true;
            }
        for index in 0..STUB_INSTRUCTIONS {
            if evidence.bad || evidence.terminal {
                break;
            }
            evidence.begin_instruction();
            let Some(size) = self.linkage_instruction(&mut evidence, &current).filter(|size| *size > 0) else {
                evidence.bad = true;
                break;
            };
            if evidence.operations == 0 && index != 0 {
                evidence.bad = true;
                break;
            }
            let next = self.step(&current, size);
            if next.get_offset() <= current.get_offset() {
                evidence.bad = true;
                break;
            }
            length += size as u32;
            current = next;
        }
        let valid = evidence.complete(table);
        let context = from.is_none() && evidence.needs_context(table);
        LinkageResult {
            address: start,
            length: if valid || context { length } else { 0 },
            slot: valid.then_some(evidence.slot),
            needs_context: context,
        }
    }

    /// The linkage shape of each address, in order (the console's `linkage`;
    /// with `table`, `linkage --table`: a PLT's metadata already establishes
    /// the entry boundary, so register setup need not be pure).
    pub fn linkages(&mut self, addresses: &[u64], table: bool) -> Vec<LinkageResult> {
        addresses.iter().map(|&address| self.linkage_at(address, table, None)).collect()
    }

    /// The linkage shape of each `target` when reached from its caller's
    /// registers (`linkage --from`).
    pub(crate) fn context_linkages(&mut self, contexts: &[LinkageContext]) -> Vec<LinkageResult> {
        contexts
            .iter()
            .map(|context| self.linkage_at(context.target, false, Some((context.origin, context.branch))))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::SleighLifter;
    use crate::native::{Mapping, NativeImport};
    use crate::session::RuntimeConfig;

    fn lifter(language: &str, bytes: Vec<u8>) -> Option<SleighLifter> {
        let mut cfg = RuntimeConfig::from_env();
        if !cfg.ghidra_install.join("Ghidra").is_dir() {
            eprintln!("SKIP: no Ghidra install");
            return None;
        }
        cfg.adopt_language(language);
        let import = NativeImport {
            language: language.into(),
            mappings: vec![Mapping { vaddr: 0x1000, size: bytes.len() as u64, file_off: 0, flags: 6, bytes }],
            ..Default::default()
        };
        Some(SleighLifter::mapped(&cfg, &import).unwrap())
    }

    /// A stub that loads a slot and jumps through it resolves the slot; one
    /// through an unknown register or after an unused write does not.
    /// (LLVM llvm-mc encodings; every positive computes the slot at 0x3008.)
    #[test]
    fn linkage_requires_bounded_side_effect_free_slot_flow() {
        /// Language, the stub's code, the same stub through an unknown register, and the same with an unused write.
        type Case = (&'static str, &'static [u8], &'static [u8], &'static [u8]);
        let cases: &[Case] = &[
            ("x86:LE:64:default", &[0xff, 0x25, 0x02, 0x20, 0, 0], &[0xff, 0xe0], &[0xb8, 1, 0, 0, 0]),
            ("x86:LE:32:default", &[0xff, 0x25, 0x08, 0x30, 0, 0], &[0xff, 0xe0], &[0xb8, 1, 0, 0, 0]),
            (
                "AARCH64:LE:64:v8A",
                &[0x10, 0, 0, 0xd0, 0x11, 6, 0x40, 0xf9, 0x20, 2, 0x1f, 0xd6],
                &[0x20, 2, 0x1f, 0xd6],
                &[0x20, 0, 0x80, 0xd2],
            ),
            (
                "PowerPC:BE:32:default",
                &[0x3d, 0x60, 0, 0, 0x81, 0x6b, 0x30, 8, 0x7d, 0x69, 3, 0xa6, 0x4e, 0x80, 4, 0x20],
                &[0x4e, 0x80, 4, 0x20],
                &[0x38, 0x60, 0, 1],
            ),
        ];
        for &(language, code, unknown, extra_write) in cases {
            let mut bytes = vec![0; 0x300];
            bytes[..code.len()].copy_from_slice(code);
            bytes[0x100..0x100 + unknown.len()].copy_from_slice(unknown);
            bytes[0x200..0x200 + extra_write.len()].copy_from_slice(extra_write);
            bytes[0x200 + extra_write.len()..0x200 + extra_write.len() + code.len()].copy_from_slice(code);
            let Some(mut lifter) = lifter(language, bytes) else { return };
            let rows = lifter.linkages(&[0x1000, 0x1100, 0x1200], false);
            assert_eq!(rows[0].slot, Some(0x3008), "{language}");
            assert_eq!(rows[0].length as usize, code.len(), "{language}");
            assert!(rows[1].slot.is_none(), "{language}: unknown incoming register");
            assert!(rows[2].slot.is_none(), "{language}: unused register write");
        }
        let mut bytes = vec![0; 0x300];
        // A store to a constant address, followed by a valid indirect transfer.
        bytes[..13].copy_from_slice(&[0xc6, 5, 0, 0, 0, 0, 1, 0xff, 0x25, 0xfb, 0x1f, 0, 0]);
        // One load, seven self-copies, one jump: exceeds the eight-instruction bound.
        bytes[0x100..0x107].copy_from_slice(&[0x48, 0x8b, 5, 1, 0x1f, 0, 0]);
        for i in 0..7 {
            bytes[0x107 + i * 3..0x10a + i * 3].copy_from_slice(&[0x48, 0x89, 0xc0]);
        }
        bytes[0x11c..0x11e].copy_from_slice(&[0xff, 0xe0]);
        let Some(mut lifter) = lifter("x86:LE:64:default", bytes) else { return };
        let rows = lifter.linkages(&[0x1000, 0x1100], false);
        assert!(rows.iter().all(|row| row.slot.is_none()), "stores and unbounded chains are not thunks");
    }
}
