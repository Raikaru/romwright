// Ventris linkage evidence over SLEIGH p-code, not instruction encodings.
// Register-use rules follow Ghidra CreateThunkFunctionCmd (Apache-2.0).
#ifndef VENTRIS_LINKAGE_HH
#define VENTRIS_LINKAGE_HH
#include "ifacedecomp.hh"
#include <array>

namespace ghidra {

class VentrisLinkageEmit : public PcodeEmit {
  // `Mode` is a value derived from a code pointer's ISA-mode bit rather than
  // from the pointer itself: on a language that selects the instruction set
  // with the low address bit, `JXWritePC` computes `(addr & 1) != 0`, hands it
  // to `setISAMode`, and branches to `addr & ~1` (Ghidra's `mips.sinc`,
  // `JXWritePC`; ARM does the same). Such a value cannot be the pointer, so it
  // neither resolves a slot nor makes the stub unknowable -- Ghidra tolerates
  // exactly this, allowing flag-sized registers to be set and never read
  // (`CreateThunkFunctionCmd.getThunkedAddr`, `allow8bitNonUse`).
  enum Kind { Unknown, Constant, Slot, UnresolvedSlot, Mode };
  struct Value {
    Kind kind;
    uintb value;
  };
  struct Cell {
    VarnodeData var;
    Value value;
    bool used;
  };
  Architecture &arch;
  std::array<Cell, 64> cells;
  size_t count;
  size_t instructionMark;
  bool probing, unknownRead, lowBitMode;

  bool memory(AddrSpace *space) const {
    return space == arch.getDefaultCodeSpace() ||
           space == arch.getDefaultDataSpace();
  }
  static uintb mask(uint4 size) {
    return size == sizeof(uintb) ? ~uintb(0) : (uintb(1) << (size * 8)) - 1;
  }
  Value get(const VarnodeData &var, bool consume) {
    if (var.size == 0 || var.size > sizeof(uintb)) {
      bad = true;
      return {Unknown, 0};
    }
    if (var.space->getType() == IPTR_CONSTANT)
      return {Constant, var.offset};
    if (memory(var.space))
      return {Slot, var.offset};
    for (size_t i = 0; i < count; ++i) {
      if (cells[i].var == var) {
        if (consume)
          cells[i].used = true;
        if (cells[i].value.kind == Unknown ||
            cells[i].value.kind == UnresolvedSlot)
          unknownRead = true;
        return cells[i].value;
      }
    }
    unknownRead = true;
    return {Unknown, 0};
  }
  void put(const VarnodeData &var, Value value) {
    if (var.size == 0 || var.size > sizeof(uintb) || memory(var.space) ||
        var.space->getType() == IPTR_CONSTANT) {
      bad = true;
      return;
    }
    if (value.kind == Constant)
      value.value &= mask(var.size);
    for (size_t i = 0; i < count; ++i) {
      Cell &cell = cells[i];
      if (cell.var == var) {
        cell.value = value;
        cell.used = false;
        return;
      }
      if (cell.var.space == var.space &&
          (cell.var.offset <= var.offset
               ? var.offset - cell.var.offset < cell.var.size
               : cell.var.offset - var.offset < var.size)) {
        // Partial register aliases need an explicit value merge; never retain
        // stale bits.
        bad = true;
        return;
      }
    }
    if (count == cells.size()) {
      bad = true;
      return;
    }
    cells[count++] = {var, value, false};
  }

public:
  bool bad, terminal, flow, call;
  size_t operations;
  uintb slot, flowTarget;
  explicit VentrisLinkageEmit(Architecture &conf)
      : arch(conf), count(0), probing(false), unknownRead(false),
        lowBitMode(false), bad(false), instructionMark(0), terminal(false),
        flow(false), call(false), operations(0), slot(0), flowTarget(0) {
    // Ghidra decides this by the presence of a register with this name
    // (`PseudoDisassembler.hasLowBitCodeModeInAddrValues`, which reads
    // `LOW_BIT_CODE_MODE_REGISTER_NAME`); in the pinned specs it is a context
    // field -- MIPS declares `LowBitCodeMode=(1,1)`, ARM `(0,0)`.
    if (conf.context != (ContextDatabase *)0) {
      try {
        conf.context->getDefaultValue("LowBitCodeMode");
        lowBitMode = true;
      } catch (LowlevelError &) {
      }
    }
  }

  void beginContext(void) { probing = true; }
  void beginLinkage(void) {
    probing = false;
    unknownRead = false;
    for (size_t i = 0; i < count; ++i)
      cells[i].used = true;
  }

  void beginInstruction(void) {
    operations = 0;
    flow = call = false;
    // Where this instruction's own writes start. A delay-slot instruction is
    // emitted as part of the branch that owns it, so its side effects belong
    // to the transfer rather than to the stub's data flow.
    instructionMark = count;
    for (size_t i = 0; i < count;) {
      if (cells[i].var.space->getType() == IPTR_INTERNAL)
        cells[i] = cells[--count];
      else
        ++i;
    }
  }
  bool shape(bool table) const {
    if (bad || !terminal)
      return false;
    for (size_t i = 0; !table && i < instructionMark && i < count; ++i) {
      // A register the stub computes and never reads means it does more than
      // reach a pointer slot -- except in the branch's own instruction, whose
      // delay slot writes the lazy-binding index every MIPS stub writes
      // (`addiu t8, t7, %lo(slot)`).
      if (cells[i].var.space->getType() != IPTR_INTERNAL &&
          cells[i].var.size > 1 && !cells[i].used)
        return false;
    }
    return true;
  }
  bool complete(bool table) const { return shape(table) && !unknownRead; }
  bool needsContext(bool table) const { return shape(table) && unknownRead; }
  virtual void dump(const Address &, OpCode opcode, VarnodeData *out,
                    VarnodeData *vars, int4 size) {
    ++operations;
    if (bad)
      return;
    if (terminal) {
      // The ops that follow an indirect branch inside the same instruction are
      // its delay slot's: SLEIGH emits a delay-slot instruction as part of the
      // branch that owns it, and the walk already stops at the branch. Marking
      // those ops bad refused every MIPS linkage stub -- `lui/lw/jr t9` -- and
      // left its callee named `FUN_<addr>` instead of `printf`.
      return;
    }
    if (flow || operations > 128) {
      bad = true;
      return;
    }
    if (opcode == CPUI_COPY && out != (VarnodeData *)0 && size == 1 &&
        *out == vars[0])
      return;
    if (probing && out == (VarnodeData *)0) {
      // Caller stores cannot produce constants: memory contents are never read
      // by this evaluator. Retain only register facts independent of memory.
      if (opcode == CPUI_STORE)
        return;
      if ((opcode == CPUI_CALL || opcode == CPUI_BRANCH) && size == 1 &&
          vars[0].space == arch.getDefaultCodeSpace()) {
        flow = true;
        call = opcode == CPUI_CALL;
        flowTarget = vars[0].offset;
      } else {
        bad = true;
      }
      return;
    }
    if (opcode == CPUI_BRANCHIND && size == 1) {
      Value target = get(vars[0], true);
      if (target.kind != Slot && target.kind != UnresolvedSlot)
        bad = true;
      else {
        terminal = true;
        slot = target.value;
      }
      return;
    }
    if (opcode == CPUI_CALLOTHER && out == (VarnodeData *)0) {
      // A user-defined operation with no output is a processor side effect,
      // not data flow: MIPS switches ISA mode on an indirect jump, which used
      // to poison every stub the jump belongs to.
      return;
    }
    if (out == (VarnodeData *)0 || out->size == 0 ||
        out->size > sizeof(uintb)) {
      bad = true;
      return; // Includes stores, calls, returns and other control flow.
    }
    if (opcode == CPUI_LOAD && size == 2) {
      AddrSpace *space = vars[0].getSpaceFromConst();
      Value address = get(vars[1], out->size >= vars[1].size);
      if (!memory(space) || space->getWordSize() == 0) {
        bad = true;
        return;
      }
      if (address.kind != Constant) {
        unknownRead = true;
        put(*out, {UnresolvedSlot, 0});
        return;
      }
      if (address.value > ~uintb(0) / space->getWordSize()) {
        bad = true;
        return;
      }
      put(*out, {Slot, AddrSpace::addressToByte(address.value,
                                                space->getWordSize())});
      return;
    }
    if (size < 1 || size > 2 || opcode >= arch.inst.size() ||
        arch.inst[opcode] == (TypeOp *)0) {
      bad = true;
      return;
    }
    Value left = get(vars[0], out->size >= vars[0].size);
    if (opcode == CPUI_COPY && size == 1) {
      if (out->size != vars[0].size) {
        bad = true;
        return;
      }
      put(*out, left);
      return;
    }
    Value right = size == 2 ? get(vars[1], out->size >= vars[1].size)
                            : Value{Constant, 0};
    if (bad)
      return;
    // Processor alignment masking does not change the identity of the loaded
    // pointer slot, and neither does clearing the ISA-mode bit on a language
    // that carries the mode in the low address bit. `AND` is commutative and
    // SLEIGH writes it both ways round -- MIPS spells the mask first
    // (`tmp = -2; tmp = tmp & addr`, `JXWritePC`) and the mode test second
    // (`addr & 0x1`) -- so the pointer side is found rather than assumed.
    if (opcode == CPUI_INT_AND && size == 2) {
      const Value *pointer = (Value *)0;
      const Value *constant = (Value *)0;
      uint4 pointerSize = 0;
      if (right.kind == Constant && left.kind != Constant) {
        pointer = &left;
        constant = &right;
        pointerSize = vars[0].size;
      } else if (left.kind == Constant && right.kind != Constant) {
        pointer = &right;
        constant = &left;
        pointerSize = vars[1].size;
      }
      if (pointer != (const Value *)0 &&
          (pointer->kind == Slot || pointer->kind == UnresolvedSlot ||
           pointer->kind == Mode)) {
        uintb full = mask(pointerSize);
        uintb value = constant->value & full;
        uintb alignment = arch.translate->getAlignment();
        bool aligning = alignment != 0 && (alignment & (alignment - 1)) == 0 &&
                        value == (full & ~(alignment - 1));
        bool demoding = lowBitMode && value == (full & ~uintb(1));
        if (pointer->kind != Mode && out->size == pointerSize &&
            (aligning || demoding)) {
          put(*out, *pointer);
          return;
        }
        // The complement: the mode bit itself, which the branch hands to
        // `setISAMode` and never to the program counter.
        if (lowBitMode && value == 1) {
          put(*out, {Mode, 0});
          return;
        }
      }
    }
    OpBehavior *behavior = arch.inst[opcode]->getBehavior();
    if (behavior->isSpecial() || behavior->isUnary() != (size == 1)) {
      bad = true;
      return;
    }
    if (left.kind == Mode || right.kind == Mode) {
      // A test or a copy of the mode bit stays a mode bit; nothing derived
      // from it can name the slot, and its being unread is not a side effect.
      if ((left.kind == Mode || left.kind == Constant) &&
          (right.kind == Mode || right.kind == Constant)) {
        put(*out, {Mode, 0});
        return;
      }
      unknownRead = true;
      put(*out, {Unknown, 0});
      return;
    }
    if (left.kind != Constant || right.kind != Constant) {
      unknownRead = true;
      put(*out, {Unknown, 0});
      return;
    }
    uintb value =
        size == 1 ? behavior->evaluateUnary(out->size, vars[0].size, left.value)
                  : behavior->evaluateBinary(out->size, vars[0].size,
                                             left.value, right.value);
    put(*out, {Constant, value});
  }
};

class IfcLinkage : public IfaceDecompCommand {
  bool callerContext(VentrisLinkageEmit &emit, Address current,
                     const Address &branch, const Address &target) {
    if (current.getSpace() != dcp->conf->getDefaultCodeSpace() ||
        branch.getSpace() != current.getSpace() ||
        target.getSpace() != current.getSpace() ||
        current.getOffset() > branch.getOffset())
      return false;
    emit.beginContext();
    for (int4 i = 0; i < 64 && !emit.bad; ++i) {
      emit.beginInstruction();
      int4 size = dcp->conf->translate->oneInstruction(emit, current);
      if (size <= 0 || emit.bad)
        return false;
      Address next = current + size;
      if (next.getOffset() <= current.getOffset())
        return false;
      if (current == branch) {
        if (!emit.flow || emit.call || emit.flowTarget != target.getOffset())
          return false;
        emit.beginLinkage();
        return true;
      }
      if (next.getOffset() > branch.getOffset() ||
          (emit.flow && emit.flowTarget != next.getOffset()))
        return false;
      current = next;
    }
    return false;
  }

public:
  virtual void execute(istream &input) {
    if (dcp->conf == (Architecture *)0)
      throw IfaceExecutionError("No architecture loaded");
    input >> ws;
    bool table = false, from = false;
    if (input.peek() == '-') {
      string option;
      input >> option;
      if (option == "--table")
        table = true;
      else if (option == "--from")
        from = true;
      else
        throw IfaceExecutionError("Unknown linkage option");
    }
    while (true) {
      input >> ws;
      if (input.eof())
        break;
      int4 ignored;
      Address origin, branch;
      if (from) {
        origin = parse_machaddr(input, ignored, *dcp->conf->types);
        branch = parse_machaddr(input, ignored, *dcp->conf->types);
        if (origin.isInvalid() || branch.isInvalid())
          break;
      }
      Address start = parse_machaddr(input, ignored, *dcp->conf->types);
      if (start.isInvalid())
        break;
      Address current = start;
      VentrisLinkageEmit emit(*dcp->conf);
      uint4 length = 0;
      try {
        if (from && !callerContext(emit, origin, branch, start))
          emit.bad = true;
        for (int4 i = 0; i < 8 && !emit.bad && !emit.terminal; ++i) {
          emit.beginInstruction();
          int4 size = dcp->conf->translate->oneInstruction(emit, current);
          if (size <= 0 || (emit.operations == 0 && i != 0)) {
            emit.bad = true;
            break;
          }
          Address next = current + size;
          if (next.getOffset() <= current.getOffset()) {
            emit.bad = true;
            break;
          }
          length += size;
          current = next;
        }
      } catch (LowlevelError &) {
        emit.bad = true;
      }
      bool valid = emit.complete(table);
      bool context = !from && emit.needsContext(table);
      *status->fileoptr << "LINKAGE {\"address\":" << dec << start.getOffset()
                        << ",\"length\":" << (valid || context ? length : 0)
                        << ",\"slot\":";
      if (valid)
        *status->fileoptr << emit.slot;
      else
        *status->fileoptr << "null";
      *status->fileoptr << ",\"needs_context\":"
                        << (context ? "true" : "false")
                        << "}" << endl;
    }
  }
};

} // namespace ghidra
#endif
