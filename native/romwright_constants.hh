// Native counterpart of ConstantPropagationContextEvaluator policy, using
// Funcdata raw flow and OpBehavior from the pinned Ghidra 12.1.3 sources.
#ifndef ROMWRIGHT_CONSTANTS_HH
#define ROMWRIGHT_CONSTANTS_HH

#include "ifacedecomp.hh"
#include "romwright_constant_state.hh"
#include "romwright_flow.hh"
#include "romwright_operand_refs.hh"
#include "romwright_x86_references.hh"
#include <algorithm>
#include <cstring>
#include <deque>
#include <tuple>
#include "flow.hh"

namespace ghidra {
namespace romwright_constants {

class MetadataOnlyEmit : public PcodeEmit {
public:
  void dump(const Address &, OpCode, VarnodeData *, VarnodeData *, int4) override {}
};

struct Region {
  Word start, end;
  unsigned flags;
  bool contains(Word address, int size = 1) const {
    return size > 0 && address >= start && address < end && Word(size) <= end - address;
  }
};

struct Fact {
  Word pc, value;
  const Varnode *varnode;
  std::tuple<Word, int, Word, int, Word> key() const {
    return std::make_tuple(pc, varnode->getSpace()->getIndex(),
                          varnode->getOffset(), varnode->getSize(), value);
  }
};

struct ReferenceFact {
  Word pc, target;
  unsigned access;
  // Bytes the access touches, from the p-code that performs it: a LOAD's
  // output, a STORE's value, a memory varnode's own size. Zero when the
  // address is only taken, which proves no width at all.
  unsigned width;
  std::pair<Word, Word> key() const { return std::make_pair(pc, target); }
  const char *kind() const {
    // Ghidra's RefType names for a flow whose target the propagation
    // resolved: `COMPUTED_CALL` and `COMPUTED_JUMP` (RefType.java).
    if (access & 16) return "COMPUTED_CALL";
    if (access & 32) return "COMPUTED_JUMP";
    // A load or store through the stack pointer: `target` is the offset from
    // the entry stack pointer, two's complement, and `width` the access.
    if (access & 64) return "STACK";
    if ((access & 3) == 3) return "READ_WRITE";
    if (access & 8) return "DATA"; // INDIRECTION in Ghidra's reference model.
    if (access & 2) return "WRITE";
    if (access & 1) return "READ";
    return "DATA";
  }
};

struct CallRegisterFact {
  Word pc, target, value;
};

struct Snapshot {
  State registers, memory;
  std::map<Location, unsigned char> modified;
  bool unknownWrites = false, callWrites = false;
  Snapshot(bool big, int unique) : registers(big, unique), memory(big) {}

  bool merge(const Snapshot &other) {
    bool changed = registers.merge(other.registers);
    changed |= memory.merge(other.memory);
    changed |= (!unknownWrites && other.unknownWrites) || (!callWrites && other.callWrites);
    unknownWrites |= other.unknownWrites;
    callWrites |= other.callWrites;
    if (unknownWrites) {
      modified.clear(); // Initial-image fallback is already disabled everywhere.
      return changed;
    }
    for (const auto &entry : other.modified) {
      auto position = modified.lower_bound(entry.first);
      if (position == modified.end() || position->first.space != entry.first.space ||
          position->first.offset != entry.first.offset) {
        modified.emplace_hint(position, entry);
        changed = true;
      } else if ((position->second | entry.second) != position->second) {
        position->second |= entry.second;
        changed = true;
      }
    }
    return changed;
  }

  void markWritten(int space, Word offset, int size) {
    while (size > 0) {
      unsigned first = unsigned(offset & 7);
      int count = std::min(size, 8 - int(first));
      modified[Location{space, offset & ~Word(7)}] |= ((1u << count) - 1) << first;
      offset += Word(count);
      size -= count;
    }
  }
};

struct RegisterSeed {
  VarnodeData storage;
  Word value;
};

class Propagation {
  Architecture &arch;
  Funcdata &function;
  const std::vector<Region> &regions;
  AddrSpace *dataSpace, *codeSpace;
  const VarnodeData *stackRegister = nullptr;
  VarnodeData modeRegister;
  bool hasModeRegister = false;
  Word first, end;
  int pointerSize, uniqueSpace, spaceCount, stackBase = -1;
  bool bigEndian, trustWritable;
  // Import slots, sorted. `VarnodeContext.getValue` (:540-544) answers a
  // read of a word carrying an external reference with the external itself,
  // so a call through it targets the EXTERNAL block, which no store fact
  // names; here the word reads as unknown, so no computed target -- the
  // lazy-binding stub the file holds there -- is ever laid down. The read
  // of the slot is a fact in its own right and is emitted regardless.
  std::vector<Word> externalSlots;
  // The instruction being evaluated, for the literal-pool rule in load().
  mutable Word currentPc = ~Word(0);
  std::size_t operations = 0;
  std::vector<ReferenceFact> references;
  std::vector<Word> instructionStarts;
  bool collectReferences = false;
  X86ReferencePolicy addressPolicy;
  std::size_t scalarReferenceCount = 0;
  std::vector<ParameterPieces> pointerStorage;
  std::vector<const BlockBasic *> originPending, originVisited;
  std::vector<RegisterSeed> registerSeeds;
  const VarnodeData *trackedRegister = nullptr;
  std::vector<CallRegisterFact> callRegisters;

  void callRegister(const PcodeOp &op, Snapshot &state) {
    if (trackedRegister == nullptr || (op.code() != CPUI_CALL && op.code() != CPUI_CALLIND))
      return;
    Value value = state.registers.get(trackedRegister->space->getIndex(),
                                     trackedRegister->offset, trackedRegister->size);
    if (!value.complete(trackedRegister->size) || value.bits == 0)
      return;
    Word target;
    if (op.code() == CPUI_CALL) {
      const FuncCallSpecs *call = function.getCallSpecs(&op);
      if (call == nullptr || call->getEntryAddress().isInvalid())
        return;
      target = call->getEntryAddress().getOffset();
    } else {
      Value destination = get(state, op.getIn(0));
      if (!destination.complete(pointerSize))
        return;
      target = destination.bits;
    }
    const Region *mapped = region(target);
    if (mapped != nullptr && (mapped->flags & 4) != 0)
      callRegisters.push_back({op.getAddr().getOffset(), target, value.bits});
  }

  void initializePointerStorage() {
    PrototypePieces prototype;
    prototype.model = arch.defaultfp;
    prototype.outtype = arch.types->getBase(pointerSize, TYPE_UINT);
    prototype.intypes.assign(8, prototype.outtype);
    prototype.firstVarArgSlot = -1;
    arch.defaultfp->assignParameterStorage(prototype, pointerStorage, true);
  }

  void storageReference(const PcodeOp &consumer, const ParameterPieces &storage,
                        Value value) {
    // VarnodeContext records the written register and its parents, not
    // unwritten child aliases. Preserve that distinction for wide registers.
    originPending.clear();
    originVisited.clear();
    originPending.push_back(consumer.getParent());
    bool initial = true;
    while (!originPending.empty()) {
      const BlockBasic *block = originPending.back();
      originPending.pop_back();
      auto cursor = block->endOp();
      if (initial) {
        cursor = consumer.getBasicIter();
        initial = false;
      } else {
        if (std::find(originVisited.begin(), originVisited.end(), block) != originVisited.end())
          continue;
        originVisited.push_back(block);
      }
      const PcodeOp *setter = nullptr;
      while (cursor != block->beginOp()) {
        if (++operations > 1000000)
          throw LowlevelError("Constant propagation exceeds one million p-code operations");
        const PcodeOp &op = **--cursor;
        const Varnode *output = op.getOut();
        if (output != nullptr && output->getSpace() == storage.addr.getSpace() &&
            output->getOffset() >= storage.addr.getOffset() &&
            output->getSize() <= pointerSize &&
            output->getOffset() - storage.addr.getOffset() <= Word(pointerSize - output->getSize())) {
          setter = &op;
          break;
        }
        if ((op.code() == CPUI_CALL || op.code() == CPUI_CALLIND) &&
            !pointerStorage.empty() && storage.addr == pointerStorage.front().addr) {
          setter = &op;
          break;
        }
      }
      if (setter != nullptr)
        reference(*setter, dataSpace, value, 4);
      else if (block->sizeIn() == 0)
        reference(consumer, dataSpace, value, 4);
      else {
        for (int index = 0; index < block->sizeIn(); ++index)
          originPending.push_back(static_cast<const BlockBasic *>(block->getIn(index)));
      }
    }
  }

  void useReferences(const PcodeOp &op, Snapshot &state) {
    bool returning = op.code() == CPUI_RETURN;
    if (!returning && op.code() != CPUI_CALL && op.code() != CPUI_CALLIND)
      return;
    Word target = ~Word(0);
    if (op.code() == CPUI_CALL) {
      const FuncCallSpecs *call = function.getCallSpecs(&op);
      if (call != nullptr && !call->getEntryAddress().isInvalid())
        target = call->getEntryAddress().getOffset();
    }
    std::size_t begin = returning ? 0 : 1;
    std::size_t finish = returning ? std::min(std::size_t(1), pointerStorage.size()) :
        pointerStorage.size();
    for (std::size_t index = begin; index < finish; ++index) {
      const ParameterPieces &storage = pointerStorage[index];
      if (storage.addr.isInvalid() || storage.type->getSize() != pointerSize)
        continue;
      AddrSpace *space = storage.addr.getSpace();
      // Unknown signatures do not justify reading guessed stack arguments.
      if (space->getType() != IPTR_PROCESSOR || memorySpace(space))
        continue;
      Value value = state.registers.get(space->getIndex(), storage.addr.getOffset(), pointerSize);
      if (value.complete(pointerSize) && value.bits != target && region(value.bits) != nullptr)
        storageReference(op, storage, value);
    }
  }

  void reference(const PcodeOp &op, AddrSpace *space, Value value, unsigned access,
                 bool addressOperand = false, unsigned width = 0) {
    Location address;
    if (!collectReferences || value.base >= 0 || !location(space, value, address) ||
        address.offset < 4 || address.offset > space->getHighest() || region(address.offset) == nullptr)
      return;
    if (access == 4 && !addressOperand) {
      if (address.offset < 1024 || space->getHighest() - address.offset < 256 ||
          address.offset == 0xffff || address.offset == 0xffffffff)
        return;
      // SymbolicPropogator.evaluatePureDataRef rejects speculative pointers
      // to an instruction's fallthrough, including a CALL's saved return PC.
      const auto *sleigh = dynamic_cast<const Sleigh *>(arch.translate);
      if (sleigh == nullptr)
        throw LowlevelError("Reference validation requires a SLEIGH translator");
      if (space == op.getAddr().getSpace() &&
          address.offset == op.getAddr().getOffset() + sleigh->instructionLength(op.getAddr())) {
        MetadataOnlyEmit emitted;
        InstructionFlow flow;
        sleigh->oneInstructionFlow(emitted, op.getAddr(), flow);
        if (flow.type().fallthrough)
          return;
      }
      // Pure data must not point into this function's decoded instructions.
      // Do not use the caller's bounding range as a containment approximation.
      if (address.offset != first) {
        if (instructionStarts.empty()) {
          const BlockGraph &graph = function.getBasicBlocks();
          for (int index = 0; index < graph.getSize(); ++index) {
            const auto *block = static_cast<const BlockBasic *>(graph.getBlock(index));
            for (auto it = block->beginOp(); it != block->endOp(); ++it) {
              Word pc = (*it)->getAddr().getOffset();
              if (pc >= first && pc < end)
                instructionStarts.push_back(pc);
            }
          }
          std::sort(instructionStarts.begin(), instructionStarts.end());
          instructionStarts.erase(std::unique(instructionStarts.begin(), instructionStarts.end()),
                                  instructionStarts.end());
        }
        if (std::binary_search(instructionStarts.begin(), instructionStarts.end(), address.offset))
          return;
      }
    }
    references.push_back(
        ReferenceFact{op.getAddr().getOffset(), address.offset, access, width});
  }

  void literalReferences() {
    // ScalarOperandAnalyzer.getDefaultEnablement2 excludes aligned ISAs.
    // Computed pointer uses remain independent of the scalar analyzer.
    if (arch.translate->getAlignment() != 1)
      return;
    const auto *sleigh = dynamic_cast<const Sleigh *>(arch.translate);
    if (sleigh == nullptr)
      throw LowlevelError("Operand references require a SLEIGH translator");
    std::vector<VarnodeData> scalars;
    MetadataOnlyEmit emitted;
    InstructionFlow flow;
    for (auto it = function.beginOpAll(); it != function.endOpAll(); ++it) {
      const PcodeOp &source = *it->second;
      Word pc = source.getAddr().getOffset();
      if (!source.isInstructionStart() || pc < first || pc >= end)
        continue;
      ParserWalker walker(sleigh->getInstructionContext(source.getAddr()));
      walker.baseState();
      scalars.clear();
      walker.getConstructor()->collectOperandScalars(walker, scalars, true);
      bool haveFlow = false;
      for (const VarnodeData &scalar : scalars) {
        Value value = Value::constant(scalar.offset, scalar.size);
        if (value.bits < 4096 || region(value.bits) == nullptr)
          continue;
        // ScalarOperandAnalyzer's non-relocation-guided exclusions.
        switch (value.bits) {
        case 0xffff: case 0xff00: case 0xffffff: case 0xff0000: case 0xff00ff:
        case 0xffffffff: case 0xffffff00: case 0xffff0000: case 0xff000000:
          continue;
        default:
          break;
        }
        // Compiler call-fixups can remove CALL ops from Funcdata. Operand
        // classification must retain the original instruction's flow targets.
        if (!haveFlow) {
          flow.clear();
          sleigh->oneInstructionFlow(emitted, source.getAddr(), flow);
          haveFlow = true;
        }
        bool control = std::any_of(flow.targets.begin(), flow.targets.end(),
            [&](const Address &target) { return target.getOffset() == value.bits; });
        if (!control)
          reference(source, dataSpace, value, 4);
      }
    }
  }

  unsigned indirectAccess(const PcodeOp &source) const {
    class JumpEmit : public PcodeEmit {
    public:
      bool jump = false;
      virtual void dump(const Address &, OpCode code, VarnodeData *, VarnodeData *, int4) {
        jump |= code == CPUI_BRANCHIND;
      }
    } emitted;
    // FlowInfo can replace an unresolved BRANCHIND with CALLIND plus a halt.
    // Classify the original instruction, not that recovery transformation.
    arch.translate->oneInstruction(emitted, source.getAddr());
    return emitted.jump ? 8 : 1;
  }

  unsigned loadAccess(const PcodeOp &load) const {
    // Jump operands retain INDIRECTION; propagation records call loads as READ.
    const Varnode *value = load.getOut();
    if (value == nullptr)
      return load.code() == CPUI_CALLIND || load.code() == CPUI_BRANCHIND ?
          indirectAccess(load) : 1;
    auto next = load.getBasicIter();
    for (++next; next != load.getParent()->endOp(); ++next) {
      const PcodeOp &use = **next;
      if (use.getAddr() != load.getAddr())
        break;
      OpCode code = use.code();
      if (code != CPUI_CALLIND && code != CPUI_BRANCH && code != CPUI_BRANCHIND &&
          code != CPUI_CBRANCH)
        continue;
      const Varnode *target = use.getIn(0);
      if (target->getAddr() == value->getAddr() && target->getSize() == value->getSize())
        return indirectAccess(load);
    }
    return 1;
  }

  // A call or branch through a register the propagation knows: Ghidra's
  // SymbolicPropogator hands such a flow to `evaluateDestination` and
  // `evaluateReference` with the flow's own RefType, and the ARM analyzer
  // turns a target's low bit into the instruction-set mode
  // (`PseudoDisassembler.setTargetContextForDisassembly`). The target is
  // reported as the register holds it, low bit included, so the consumer can
  // apply that rule; only a value inside the image is a target at all.
  void computedFlow(const PcodeOp &op, Snapshot &state) {
    OpCode code = op.code();
    if ((code != CPUI_CALLIND && code != CPUI_BRANCHIND) || op.numInput() < 1)
      return;
    const Varnode *operand = op.getIn(0);
    if (memorySpace(operand->getSpace()) || operand->isConstant())
      return; // A slot read is a data reference; a literal target is direct flow.
    Value target = get(state, operand);
    if (target.base >= 0 || !target.complete(operand->getSize()))
      return;
    // The mode bit lives in the target's low bit only on languages with
    // a mode register (ARM Thumb): there the branch cleared it from the
    // address and the switch register hands it back. Elsewhere (x86)
    // bit 0 is address payload -- clearing it turned the valid odd
    // target 0x400123 into 0x400122, mid-instruction. Mask only when a
    // mode register exists.
    Word raw = hasModeRegister ? target.bits & ~Word(1) : target.bits;
    if (hasModeRegister) {
      Value mode = state.registers.get(modeRegister.space->getIndex(), modeRegister.offset,
                                       (int)modeRegister.size);
      if (mode.base < 0 && mode.complete((int)modeRegister.size) && (mode.bits & 1) != 0)
        raw |= 1;
    }
    if (raw < 4 || region(raw & ~Word(1)) == nullptr)
      return;
    // Classify the original instruction, not a recovery transform:
    // FlowInfo can replace an unresolved BRANCHIND with CALLIND plus
    // a halt, and op.code() would then misreport a jump as a call.
    // indirectAccess re-translates the address for the original form.
    references.push_back(ReferenceFact{op.getAddr().getOffset(), raw,
                                       indirectAccess(op) == 8 ? 32u : 16u, 0});
  }

  int pointerSizeOf(const PcodeOp &op) const {
    return op.getIn(1) == nullptr ? pointerSize : op.getIn(1)->getSize();
  }

  /// Does one of the instruction's display operands add up to this stack
  /// offset? Registers count with the offset the propagation holds for them
  /// when that value is stack-relative, scalars with their signed value
  /// (`NewFunctionStackAnalysisCmd.getStackOpIndex`, also accepting a match
  /// in the low 16 bits).
  bool operandNamesSlot(const Address &pc, Snapshot &state, Word offset, int size) const {
    const auto *sleigh = dynamic_cast<const Sleigh *>(arch.translate);
    if (sleigh == nullptr)
      return false;
    std::vector<std::vector<OperandObject> > operands;
    try {
      // A returning instruction names no slot: `pop {..., pc}` reloads the
      // frame it tears down, and Ghidra's analyzer skips it
      // (`evaluateSymbolicReference`: "if (instr.getFlowType().isTerminal())
      // return false").
      MetadataOnlyEmit emitted;
      InstructionFlow flow;
      sleigh->oneInstructionFlow(emitted, pc, flow);
      if (flow.type().terminal)
        return false;
      ParserWalker walker(sleigh->getInstructionContext(pc));
      walker.baseState();
      walker.getConstructor()->collectOperandObjects(walker, operands);
    } catch (LowlevelError &) {
      return false;
    }
    Word mask = widthMask(size);
    for (const auto &operand : operands) {
      Word local = 0;
      for (const OperandObject &object : operand) {
        if (object.isRegister) {
          Value value = state.registers.get(object.storage.space->getIndex(),
                                            object.storage.offset, (int)object.storage.size);
          if (value.base != stackBase)
            continue;
          local += value.bits;
        } else {
          local += (Word)object.scalar;
        }
        if (((local ^ offset) & mask) == 0 || ((local ^ offset) & 0xffff) == 0)
          return true;
      }
    }
    return false;
  }

  void memoryReferences(const PcodeOp &op, Snapshot &state) {
    OpCode code = op.code();
    if ((code == CPUI_LOAD || code == CPUI_STORE) && op.numInput() >= 2) {
      AddrSpace *space = op.getIn(0)->getSpaceFromConst();
      Value pointer = get(state, op.getIn(1));
      unsigned access = code == CPUI_LOAD ? 1 : 2;
      // A stack access is a fact about the frame, not about memory: Ghidra's
      // stack analyzer turns every operand SymbolicPropogator resolves to the
      // stack space into a stack reference and then a variable
      // (`NewFunctionStackAnalysisCmd.defineFuncVariable`, sized from the
      // LOAD output or STORE value like `getRefSize`). It is reported with
      // the offset relative to the entry stack pointer, which is what Ghidra's
      // frame offsets are.
      if (stackBase >= 0 && pointer.base == stackBase && collectReferences) {
        const Varnode *accessed = code == CPUI_LOAD ? op.getOut() : op.getIn(2);
        unsigned width = accessed == nullptr ? 0 : (unsigned)accessed->getSize();
        // Only an access an instruction *operand* spells as a stack slot: a
        // register the propagation knows to be stack-relative plus the
        // operand's scalars summing to the offset (`getStackOpIndex`). A
        // push or pop stores through the stack pointer too, but names no
        // slot, and Ghidra creates no variable for it.
        if (width != 0 && operandNamesSlot(op.getAddr(), state, pointer.bits, pointerSizeOf(op)))
          references.push_back(ReferenceFact{op.getAddr().getOffset(), pointer.bits,
                                             64u | access, width});
      }
      Location candidate;
      if (pointer.base >= 0 && pointer.base != stackBase &&
          location(space, Value(pointer.bits, pointer.known, -1, pointer.size), candidate) &&
          region(candidate.offset) != nullptr) {
        const auto *sleigh = dynamic_cast<const Sleigh *>(arch.translate);
        if (sleigh == nullptr)
          throw LowlevelError("Symbolic reference validation requires a SLEIGH translator");
        MetadataOnlyEmit emitted;
        InstructionFlow flow;
        sleigh->oneInstructionFlow(emitted, op.getAddr(), flow);
        const char *kind = flow.type().kind;
        if (std::strcmp(kind, "CALL") != 0 && std::strcmp(kind, "CALLIND") != 0) {
          // A non-stack symbolic offset is speculative DATA, not a proved load/store.
          pointer.base = -1;
          access = 4;
        }
      }
      // A LOAD's output and a STORE's value are the access: their size is
      // how many bytes the instruction touches at the target.
      const Varnode *accessed = code == CPUI_LOAD ? op.getOut() : op.getIn(2);
      unsigned width = accessed == nullptr ? 0 : (unsigned)accessed->getSize();
      reference(op, space, pointer, access, false, access == 4 ? 0 : width);
      if (code == CPUI_STORE)
        reference(op, dataSpace, get(state, op.getIn(2)), 4);
    }
    // Raw flow can represent fixed-address loads/stores as memory varnodes.
    for (int index = 0; index < op.numInput(); ++index) {
      const Varnode *input = op.getIn(index);
      if (!memorySpace(input->getSpace()) ||
          ((code == CPUI_BRANCH || code == CPUI_CBRANCH || code == CPUI_CALL) && index == 0))
        continue;
      AddrSpace *space = input->getSpace();
      reference(op, space, Value::constant(input->getOffset() / space->getWordSize(),
                                          space->getAddrSize()), loadAccess(op),
                false, (unsigned)input->getSize());
    }
    const Varnode *output = op.getOut();
    if (output != nullptr && memorySpace(output->getSpace())) {
      AddrSpace *space = output->getSpace();
      reference(op, space, Value::constant(output->getOffset() / space->getWordSize(),
                                          space->getAddrSize()), 2, false,
                (unsigned)output->getSize());
    }
  }

  bool memorySpace(const AddrSpace *space) const {
    return space == dataSpace || space == codeSpace;
  }

  const Region *region(Word address, int size = 1) const {
    for (const Region &candidate : regions)
      if (candidate.contains(address, size))
        return &candidate;
    return nullptr;
  }

  bool location(AddrSpace *space, Value pointer, Location &result) const {
    int size = pointer.size;
    if (size < 1 || size > 8 || !memorySpace(space) || space->getWordSize() == 0)
      return false;
    Word offset;
    if (pointer.base >= 0) {
      if (pointer.base > (std::numeric_limits<int>::max() - spaceCount) / spaceCount)
        return false;
      result.space = -1 - (pointer.base * spaceCount + space->getIndex());
      // Bias the virtual origin so ordinary negative stack offsets do not
      // straddle the storage map's unsigned boundary. Never emit this value.
      offset = (pointer.bits + (Word(1) << (size * 8 - 1))) & widthMask(size);
    } else {
      if (!pointer.complete(size))
        return false;
      result.space = space->getIndex();
      offset = pointer.bits;
      // SymbolicPropogator.makeReference (:2624-2633): a negative offset was
      // sign-extended past the space -- MIPS64 with 32-bit addresses does
      // that to every lui -- and is chopped to the space's width; a positive
      // one is taken as it is.
      if ((offset >> (size * 8 - 1)) & 1)
        offset = space->wrapOffset(offset);
    }
    if (offset > ~Word(0) / space->getWordSize())
      return false;
    result.offset = AddrSpace::addressToByte(offset, space->getWordSize());
    return true;
  }

  void forgetMemory(Snapshot &state, bool call) const {
    state.memory = State(bigEndian);
    if (call)
      state.callWrites = true;
    else {
      state.unknownWrites = true;
      state.modified.clear();
    }
  }

  Value load(Snapshot &state, AddrSpace *space, Value pointer, int size) const {
    Location address;
    if (size < 1 || size > 8 || !location(space, pointer, address) ||
        Word(size - 1) > ~Word(0) - address.offset)
      return Value();
    Value value = state.memory.get(address.space, address.offset, size);
    if (value.base >= 0 || value.complete(size) || address.space < 0)
      return value;
    if (std::binary_search(externalSlots.begin(), externalSlots.end(), address.offset))
      return value;
    // Ghidra reads writable memory without asking the evaluator when it lies
    // within 4096 bytes ahead of the instruction (`VarnodeContext.getValue`:
    // "if the value loaded is too far away, ask the evaluator"), which is
    // what makes a pc-relative literal pool a constant on ARM even though
    // the code was copied into RAM -- and nothing the function did before
    // (a call, a coprocessor operation) is taken to have rewritten its own
    // literal pool. Farther away, writable memory is trusted only on
    // request, and never once something may have written it.
    bool nearby = currentPc != ~Word(0) && address.offset >= currentPc &&
                  address.offset - currentPc <= 4096;
    if (!nearby && state.unknownWrites)
      return value;
    const Region *mapping = region(address.offset, size);
    if (mapping == nullptr || (mapping->flags & 2) == 0 ||
        ((mapping->flags & 1) != 0 && !nearby && (!trustWritable || state.callWrites)) ||
        (size != 1 && size != 2 && size != 4 && size != 8))
      return value;
    uint1 bytes[8];
    try {
      arch.loader->loadFill(bytes, size, Address(space, address.offset));
    } catch (DataUnavailError &) {
      return value;
    }
    Word initial = 0, available = 0;
    Word previousCell = 0;
    auto dirty = state.modified.end();
    for (int byte = 0; byte < size; ++byte) {
      unsigned shift = unsigned(space->isBigEndian() ? size - 1 - byte : byte) * 8;
      initial |= Word(bytes[byte]) << shift;
      Word at = address.offset + Word(byte);
      Word cell = at & ~Word(7);
      if (byte == 0 || cell != previousCell) {
        dirty = state.modified.find(Location{address.space, cell});
        previousCell = cell;
      }
      if (dirty == state.modified.end() || (dirty->second & (1u << (at & 7))) == 0)
        available |= Word(0xff) << shift;
    }
    // VarnodeContext does not trust zero read from the initial image.
    if (initial == 0)
      return value;
    available &= ~value.known;
    return Value(value.bits | (initial & available), value.known | available, -1, size);
  }

  Value get(Snapshot &state, const Varnode *varnode) const {
    AddrSpace *space = varnode->getSpace();
    if (space->getType() == IPTR_CONSTANT)
      return Value::constant(varnode->getOffset(), varnode->getSize());
    if (memorySpace(space)) {
      Word words = varnode->getOffset() / space->getWordSize();
      if (words * space->getWordSize() != varnode->getOffset())
        return Value();
      return load(state, space, Value::constant(words, space->getAddrSize()), varnode->getSize());
    }
    return state.registers.get(space->getIndex(), varnode->getOffset(), varnode->getSize());
  }

  void store(Snapshot &state, AddrSpace *space, Value pointer, int size, Value value) const {
    Location address;
    if (size < 1 || size > 8 || !location(space, pointer, address) ||
        Word(size - 1) > ~Word(0) - address.offset) {
      forgetMemory(state, false);
      return;
    }
    bool stack = address.space < 0 && (-1 - address.space) / spaceCount == stackBase;
    if (address.space < 0 && !stack)
      forgetMemory(state, false); // An opaque incoming pointer may alias any memory.
    else {
      // A concrete store or a frame-relative store can invalidate aliases
      // held through other opaque incoming pointers.
      bool mapped = address.space >= 0 && region(address.offset, size) != nullptr;
      state.memory.retain([&](int id, Word, int) {
        return id >= 0 || ((stack || mapped) && (-1 - id) / spaceCount == stackBase);
      });
    }
    state.memory.put(address.space, address.offset, size, value);
    if (!state.unknownWrites && address.space >= 0)
      state.markWritten(address.space, address.offset, size);
  }

  Value evaluate(Snapshot &state, const PcodeOp &op) const {
    const Varnode *output = op.getOut();
    if (output == nullptr || output->getSize() < 1 || output->getSize() > 8)
      return Value();
    int size = output->getSize(), inputs = op.numInput();
    OpCode code = op.code();
    if (code == CPUI_LOAD && inputs == 2)
      return load(state, op.getIn(0)->getSpaceFromConst(), get(state, op.getIn(1)), size);
    if (inputs < 1 || inputs > 2 || op.getIn(0)->getSize() > 8)
      return Value();
    Value left = get(state, op.getIn(0));
    if (code == CPUI_COPY)
      return size == op.getIn(0)->getSize() ? left : Value();
    Value right = inputs == 2 ? get(state, op.getIn(1)) : Value();
    if (inputs == 2 && op.getIn(1)->getSize() > 8)
      return Value();
    bool sameStorage = inputs == 2 && !memorySpace(op.getIn(0)->getSpace()) &&
        op.getIn(0)->getSpace() == op.getIn(1)->getSpace() &&
        op.getIn(0)->getOffset() == op.getIn(1)->getOffset() &&
        op.getIn(0)->getSize() == op.getIn(1)->getSize();
    if (sameStorage && (code == CPUI_INT_XOR || code == CPUI_INT_SUB))
      return Value::constant(0, size);
    if (size == op.getIn(0)->getSize() && inputs == 2) {
      if (code == CPUI_INT_AND && right.base >= 0 &&
          left.complete(size) && op.getIn(1)->getSize() == size)
        std::swap(left, right);
      if (code == CPUI_INT_AND && left.base >= 0 &&
          right.complete(op.getIn(1)->getSize()) && right.bits != 0 && (right.bits & 1) == 0) {
        // VarnodeContext.and preserves a symbolic origin for alignment masks.
        // Rebase it conservatively: old pointers/slots must not alias the new
        // frame merely because both use the same reusable abstract base id.
        state.registers.forgetRelativeBase(left.base);
        state.memory.forgetRelativeBase(left.base);
        state.memory.retain([&](int id, Word, int) {
          return id >= 0 || (-1 - id) / spaceCount != left.base;
        });
        return Value::relative(left.base, left.bits & right.bits, size);
      }
      if (left.base >= 0 && right.complete(op.getIn(1)->getSize()) &&
          (code == CPUI_INT_ADD || code == CPUI_INT_SUB))
        return Value::relative(left.base, code == CPUI_INT_ADD ? left.bits + right.bits :
                               left.bits - right.bits, size);
      if (right.base >= 0 && left.complete(op.getIn(0)->getSize()) && code == CPUI_INT_ADD)
        return Value::relative(right.base, left.bits + right.bits, size);
      if (left.base >= 0 && left.base == right.base && code == CPUI_INT_SUB)
        return Value::constant(left.bits - right.bits, size);
      // `or rd, rs, zero` is how MIPS spells a register move; a zero operand
      // leaves the other side, symbolic origin included, exactly as
      // VarnodeContext's or/xor keep a symbolic value when the other operand
      // is the constant zero.
      if (code == CPUI_INT_OR || code == CPUI_INT_XOR) {
        if (left.base >= 0 && right.complete(op.getIn(1)->getSize()) && right.bits == 0)
          return Value::relative(left.base, left.bits, size);
        if (right.base >= 0 && left.complete(op.getIn(0)->getSize()) && left.bits == 0 &&
            op.getIn(1)->getSize() == size)
          return Value::relative(right.base, right.bits, size);
      }
    }
    if (left.base < 0 && right.base < 0 && inputs == 2) {
      if (code == CPUI_INT_AND)
        return Value(left.bits & right.bits, ((left.known & right.known) |
                     (left.known & ~left.bits) | (right.known & ~right.bits)) & widthMask(size));
      if (code == CPUI_INT_OR)
        return Value(left.bits | right.bits, ((left.known & right.known) |
                     (left.known & left.bits) | (right.known & right.bits)) & widthMask(size));
      if (code == CPUI_INT_XOR)
        return Value(left.bits ^ right.bits, left.known & right.known & widthMask(size));
    }
    if (!left.complete(op.getIn(0)->getSize()) ||
        (inputs == 2 && !right.complete(op.getIn(1)->getSize())))
      return Value();
    OpBehavior *behavior = op.getOpcode()->getBehavior();
    if (behavior->isSpecial() || behavior->isUnary() != (inputs == 1))
      return Value();
    return Value::constant(inputs == 1 ?
        behavior->evaluateUnary(size, op.getIn(0)->getSize(), left.bits) :
        behavior->evaluateBinary(size, op.getIn(0)->getSize(), left.bits, right.bits), size);
  }

  void observe(std::vector<Fact> *facts, const PcodeOp &op, Value value) const {
    const Varnode *output = op.getOut();
    if (facts == nullptr || output == nullptr || output->getSize() != pointerSize ||
        !value.complete(pointerSize) || memorySpace(output->getSpace()))
      return;
    Word scale = dataSpace->getWordSize();
    if (scale == 0 || value.bits > dataSpace->getHighest() / scale)
      return;
    Word target = AddrSpace::addressToByte(value.bits, scale);
    if (target < 1024 || dataSpace->getHighest() - target < 256 ||
        target == 0xffff || target == 0xffffffff || region(target) == nullptr)
      return;
    facts->push_back(Fact{op.getAddr().getOffset(), value.bits, output});
  }

  int transfer(const BlockBasic &block, Snapshot &state, std::vector<Fact> *facts) {
    int branch = -1;
    for (auto it = block.beginOp(); it != block.endOp(); ++it) {
      const PcodeOp &op = **it;
      currentPc = op.getAddr().getOffset();
      if (++operations > 1000000)
        throw LowlevelError("Constant propagation exceeds one million p-code operations");
      if (op.getAddr().getOffset() < first || op.getAddr().getOffset() >= end)
        return -2;
      state.registers.beginInstruction(op.getAddr().getSpace()->getIndex(), op.getAddr().getOffset());
      OpCode code = op.code();
      if (collectReferences) {
        memoryReferences(op, state);
        useReferences(op, state);
        callRegister(op, state);
        computedFlow(op, state);
      }
      if (code == CPUI_CBRANCH && op.numInput() == 2) {
        Value condition = get(state, op.getIn(1));
        if (condition.complete(op.getIn(1)->getSize()))
          branch = condition.bits != 0 ? 1 : 0;
      } else if (code == CPUI_STORE && op.numInput() == 3) {
        store(state, op.getIn(0)->getSpaceFromConst(), get(state, op.getIn(1)),
              op.getIn(2)->getSize(), get(state, op.getIn(2)));
      } else if (code == CPUI_CALL || code == CPUI_CALLIND) {
        const FuncCallSpecs *call = function.getCallSpecs(&op);
        bool hasModel = call != nullptr && call->hasModel();
        Value stackValue = stackRegister == nullptr ? Value() :
            state.registers.get(stackRegister->space->getIndex(), stackRegister->offset,
                                stackRegister->size);
        state.registers.retain([&](int space, Word offset, int size) {
          if (space == uniqueSpace)
            return true;
          Address storage(arch.getSpace(space), offset);
          uint4 effect = hasModel ? call->hasEffect(storage, size) :
              arch.defaultfp->hasEffect(storage, size);
          return effect == EffectRecord::unaffected;
        });
        forgetMemory(state, true);
        if (stackRegister != nullptr) {
          int extraPop = hasModel ? call->getExtraPop() : arch.defaultfp->getExtraPop();
          int size = stackRegister->size;
          Value restored;
          if (extraPop != ProtoModel::extrapop_unknown) {
            Word amount = static_cast<Word>(static_cast<std::int64_t>(extraPop));
            if (stackValue.base >= 0)
              restored = Value::relative(stackValue.base, stackValue.bits + amount, size);
            else if (stackValue.complete(size))
              restored = Value::constant(stackValue.bits + amount, size);
            else if (extraPop == 0)
              restored = stackValue;
          }
          // CALL's raw p-code includes its push; the callee's RET does not
          // occur in this function's flow. Apply the prototype's stack pop.
          state.registers.put(stackRegister->space->getIndex(), stackRegister->offset,
                              size, restored);
        }
      } else if (code == CPUI_CALLOTHER) {
        // A user-defined operation touches only what it names: Ghidra clears
        // the op's output and nothing else (`SymbolicPropogator.applyPcode`,
        // `case PcodeOp.CALLOTHER`). Wiping every register here lost the
        // instruction-set switch ARM writes just before an interworking
        // branch (`SetThumbMode`: `TB = ...; setISAMode(TB)`), so no computed
        // target ever carried its mode.
      }
      if (op.getOut() != nullptr) {
        Value value = code == CPUI_CALLOTHER ? Value() : evaluate(state, op);
        const Varnode *output = op.getOut();
        if (memorySpace(output->getSpace())) {
          AddrSpace *space = output->getSpace();
          store(state, space, Value::constant(output->getOffset() / space->getWordSize(),
                space->getAddrSize()), output->getSize(), value);
        } else {
          state.registers.put(output->getSpace()->getIndex(), output->getOffset(),
                              output->getSize(), value);
        }
        observe(facts, op, value);
        if (collectReferences && output->getSpace()->getType() == IPTR_PROCESSOR &&
            !memorySpace(output->getSpace()) && value.complete(value.size) &&
            value.bits > 4096 && region(value.bits) != nullptr &&
            addressPolicy.matches(op.getAddr())) {
          // X86Analyzer preserves an existing reference on the LEA operand.
          auto limit = references.begin() + scalarReferenceCount;
          auto existing = std::lower_bound(references.begin(), limit, op.getAddr().getOffset(),
              [](const ReferenceFact &fact, Word pc) { return fact.pc < pc; });
          if (existing == limit || existing->pc != op.getAddr().getOffset())
            reference(op, dataSpace, value, 4, true);
        }
      }
    }
    return branch;
  }

  Snapshot initialState() {
    Snapshot initial(bigEndian, uniqueSpace);
    std::map<Location, int> registers;
    const BlockGraph &graph = function.getBasicBlocks();
    for (int index = 0; index < graph.getSize(); ++index) {
      const auto *block = static_cast<const BlockBasic *>(graph.getBlock(index));
      for (auto it = block->beginOp(); it != block->endOp(); ++it) {
        const PcodeOp &op = **it;
        for (int input = 0; input < op.numInput(); ++input) {
          const Varnode *value = op.getIn(input);
          if (value->getSpace()->getType() != IPTR_PROCESSOR || memorySpace(value->getSpace()) ||
              value->getSize() < 1 || value->getSize() > 8)
            continue;
          int &size = registers[Location{value->getSpace()->getIndex(), value->getOffset()}];
          size = std::max(size, int(value->getSize()));
        }
      }
    }
    int base = 0, previousSpace = -1;
    Word previousEnd = 0;
    for (const auto &entry : registers) {
      if (entry.first.space == previousSpace && entry.first.offset < previousEnd)
        continue;
      initial.registers.put(entry.first.space, entry.first.offset, entry.second,
                            Value::relative(base, 0, entry.second));
      if (stackRegister != nullptr && entry.first.space == stackRegister->space->getIndex() &&
          entry.first.offset == stackRegister->offset && entry.second == stackRegister->size)
        stackBase = base;
      ++base;
      previousSpace = entry.first.space;
      previousEnd = entry.first.offset + Word(entry.second);
    }
    for (const RegisterSeed &seed : registerSeeds)
      initial.registers.put(seed.storage.space->getIndex(), seed.storage.offset,
                            seed.storage.size, Value::constant(seed.value, seed.storage.size));
    return initial;
  }

public:
  Propagation(Architecture &architecture, Funcdata &data, const std::vector<Region> &mapped,
              Word start, Word finish, bool trust, std::vector<RegisterSeed> seeds = {},
              const VarnodeData *tracked = nullptr)
      : arch(architecture), function(data), regions(mapped),
        dataSpace(arch.getDefaultDataSpace()), codeSpace(arch.getDefaultCodeSpace()),
        first(start), end(finish), pointerSize(arch.types->getSizeOfPointer()),
        uniqueSpace(arch.getUniqueSpace()->getIndex()), spaceCount(arch.numSpaces()),
        bigEndian(dataSpace->isBigEndian()), trustWritable(trust), registerSeeds(std::move(seeds)),
        trackedRegister(tracked) {
    AddrSpace *stack = arch.getStackSpace();
    if (stack != nullptr && stack->numSpacebase() != 0)
      stackRegister = &stack->getSpacebase(0);
    // The register an interworking branch writes the target's instruction
    // set into: ARM's `SetThumbMode` sets `TB`, which its specs name
    // `ISAModeSwitch` for analysis (ARM.sinc:208-225); MIPS names its own
    // switch the same (mips.sinc:388). Ghidra's ARM analyzer reads exactly
    // this register at a computed flow -- "if the TB register is set, that
    // trumps any mode we are tracking" (`ArmAnalyzer.flowArmThumb`).
    try {
      modeRegister = arch.translate->getRegister("ISAModeSwitch");
      hasModeRegister = modeRegister.size >= 1 && modeRegister.size <= 8;
    } catch (LowlevelError &) {
      hasModeRegister = false;
    }
  }

  /// The switch register under the name the language's own spec gives it,
  /// when the pspec only aliases it (ARM's `TB`).
  void useExternalSlots(std::vector<Word> slots) {
    std::sort(slots.begin(), slots.end());
    externalSlots = std::move(slots);
  }

  void useModeRegister(const std::string &name) {
    try {
      modeRegister = arch.translate->getRegister(name);
      hasModeRegister = modeRegister.size >= 1 && modeRegister.size <= 8;
    } catch (LowlevelError &) {
    }
  }

  std::vector<Fact> run(bool referenceMode = false) {
    const BlockGraph &graph = function.getBasicBlocks();
    if (graph.getSize() == 0 || function.hasBadData() || function.hasUnimplemented())
      throw LowlevelError("Constant propagation requires decodable function flow");
    struct Node {
      Snapshot input;
      bool queued = true;
      explicit Node(const Snapshot &state) : input(state) {}
    };
    // Raw-flow block indices can have gaps and entry insertion can reorder
    // the graph. Use block identity, not an assumed contiguous index.
    std::map<const BlockBasic *, Node> nodes;
    std::deque<const BlockBasic *> pending;
    const auto *entry = static_cast<const BlockBasic *>(graph.getBlock(0));
    nodes.emplace(entry, Node(initialState()));
    pending.push_back(entry);
    while (!pending.empty()) {
      const BlockBasic *block = pending.front();
      pending.pop_front();
      Node &node = nodes.find(block)->second;
      node.queued = false;
      Snapshot output = node.input;
      int choice = transfer(*block, output, nullptr);
      if (choice == -2)
        continue;
      for (int edge = 0; edge < block->sizeOut(); ++edge) {
        // Ghidra reference analysis follows false conditional branches too.
        if (!referenceMode && choice >= 0 && block->sizeOut() == 2 && edge != choice)
          continue;
        const auto *next = static_cast<const BlockBasic *>(block->getOut(edge));
        auto position = nodes.lower_bound(next);
        bool fresh = position == nodes.end() || position->first != next;
        if (fresh)
          position = nodes.emplace_hint(position, next, Node(output));
        else if (!position->second.input.merge(output))
          continue;
        if (fresh || !position->second.queued) {
          position->second.queued = true;
          pending.push_back(next);
        }
      }
    }
    std::vector<Fact> facts;
    collectReferences = referenceMode;
    if (referenceMode) {
      initializePointerStorage();
      addressPolicy.configure(arch);
      literalReferences();
      scalarReferenceCount = references.size();
    }
    for (const auto &entry : nodes) {
      Snapshot final = entry.second.input;
      transfer(*entry.first, final, referenceMode ? nullptr : &facts);
    }
    std::sort(facts.begin(), facts.end(), [](const Fact &a, const Fact &b) { return a.key() < b.key(); });
    facts.erase(std::unique(facts.begin(), facts.end(),
        [](const Fact &a, const Fact &b) { return a.key() == b.key(); }), facts.end());
    return facts;
  }

  const std::vector<CallRegisterFact> &callRegisterFacts() {
    std::sort(callRegisters.begin(), callRegisters.end(),
        [](const CallRegisterFact &a, const CallRegisterFact &b) { return a.pc < b.pc; });
    return callRegisters;
  }

  const std::vector<ReferenceFact> &referenceFacts() {
    std::sort(references.begin(), references.end(),
        [](const ReferenceFact &a, const ReferenceFact &b) { return a.key() < b.key(); });
    std::size_t count = 0;
    for (std::size_t index = 0; index < references.size(); ++index) {
      if (count != 0 && references[count - 1].key() == references[index].key()) {
        references[count - 1].access |= references[index].access;
        references[count - 1].width =
            std::max(references[count - 1].width, references[index].width);
      }
      else {
        if (count != index)
          references[count] = references[index];
        ++count;
      }
    }
    references.resize(count);
    return references;
  }
};

} // namespace romwright_constants

class IfcConstants : public IfaceDecompCommand {
  bool referenceMode;
  static void writeString(ostream &out, const string &value) {
    const char *digits = "0123456789abcdef";
    out << '"';
    for (unsigned char byte : value) {
      if (byte == '"' || byte == '\\')
        out << '\\' << char(byte);
      else if (byte < 0x20)
        out << "\\u00" << digits[byte >> 4] << digits[byte & 15];
      else
        out << char(byte);
    }
    out << '"';
  }

public:
  std::string modeRegisterName;
  explicit IfcConstants(bool references = false) : referenceMode(references) {}
  virtual void execute(istream &input) {
    if (dcp->conf == nullptr)
      throw IfaceExecutionError("No architecture loaded");
    uintb start, end;
    unsigned trust;
    input.unsetf(ios::basefield);
    if (!(input >> start >> end >> trust) || start >= end || trust > 1)
      throw IfaceParseError("Expected propagation <start> <end-exclusive> <trust-writable:0|1> <start> <end> <flags> ...");
    vector<romwright_constants::Region> regions;
    vector<romwright_constants::RegisterSeed> seeds;
    vector<romwright_constants::Word> externals;
    const VarnodeData *tracked = nullptr;
    modeRegisterName.clear();
    while (true) {
      input >> ws;
      if (input.eof())
        break;
      if (input.peek() == '-') {
        string option, name;
        uintb value;
        if (!(input >> option >> name) ||
            (option != "--register" && option != "--track-register" &&
             option != "--mode-register" && option != "--external"))
          throw IfaceParseError("Expected --register <name> <value>, --track-register <name>, --mode-register <name> or --external <address>");
        if (option == "--external") {
          uintb slot;
          istringstream text(name);
          text.unsetf(ios::basefield);
          if (!(text >> slot))
            throw IfaceParseError("Invalid external slot address");
          externals.push_back(slot);
          continue;
        }
        const VarnodeData &storage = dcp->conf->translate->getRegister(name);
        if (option == "--mode-register") {
          // The register the pspec aliases as ISAModeSwitch; see
          // Propagation's constructor for why the alias travels by option.
          modeRegisterName = name;
          continue;
        }
        if (storage.space->getType() != IPTR_PROCESSOR ||
            storage.space == dcp->conf->getDefaultCodeSpace() ||
            storage.space == dcp->conf->getDefaultDataSpace() ||
            storage.size < 1 || storage.size > 8)
          throw IfaceParseError("Invalid propagation register context");
        if (option == "--track-register") {
          if (!referenceMode || tracked != nullptr)
            throw IfaceParseError("Reference propagation accepts one tracked register");
          tracked = &storage;
          continue;
        }
        if (!(input >> value) || value > romwright_constants::widthMask(storage.size))
          throw IfaceParseError("Invalid propagation register value");
        seeds.push_back({storage, value});
        continue;
      }
      romwright_constants::Region range;
      if (!(input >> range.start >> range.end >> range.flags) ||
          range.start >= range.end || range.flags > 7)
        throw IfaceParseError("Malformed constant-propagation mapping");
      regions.push_back(range);
    }
    if (regions.empty())
      throw IfaceParseError("Constant propagation requires mapped ranges");
    Architecture &arch = *dcp->conf;
    AddrSpace *space = arch.getDefaultCodeSpace();
    if (end - 1 > space->getHighest())
      throw IfaceParseError("Function range exceeds the code address space");
    const Address entry(space, start);
    // A symbol-owned Funcdata has an independent scope id. Anonymous roots
    // collide with the address-derived scope used by jump-table recovery.
    // Register only our temporary symbol; existing function bodies stay intact.
    struct EntrySymbol {
      Scope *owner;
      FunctionSymbol *added;
      ~EntrySymbol() {
        if (added != nullptr)
          owner->removeSymbol(added);
      }
    } symbol{arch.symboltab->getGlobalScope(), nullptr};
    symbol.added = symbol.owner->addFunction(entry, "romwright_constants");
    Funcdata &function = *symbol.added->getFunction();
    // Bad bytes inside the range end that path's flow; they do not abort the
    // pass. FlowInfo already truncates control flow at an unresolvable
    // instruction and warns, unless the architecture asks it to throw
    // (flow.cc:420-456), and a propagation query over a real image reaches
    // data all the time -- one such byte failed the whole import of a
    // 53 MB executable.
    struct FlowOptions {
      Architecture &arch;
      uint4 saved;
      explicit FlowOptions(Architecture &a) : arch(a), saved(a.flowoptions) {
        arch.flowoptions &= ~(uint4)(FlowInfo::error_unimplemented |
                                     FlowInfo::error_reinterpreted |
                                     FlowInfo::error_toomanyinstructions);
      }
      ~FlowOptions() { arch.flowoptions = saved; }
    } options(arch);
    function.followFlow(entry, Address(space, end - 1));
    romwright_constants::Propagation propagation(arch, function, regions, start, end, trust != 0,
                                                std::move(seeds), tracked);
    if (!modeRegisterName.empty())
      propagation.useModeRegister(modeRegisterName);
    propagation.useExternalSlots(std::move(externals));
    vector<romwright_constants::Fact> facts = propagation.run(referenceMode);
    ostream &out = *status->fileoptr;
    out << (referenceMode ? "REFERENCES [" : "CONSTANTS [") << dec;
    bool first = true;
    if (referenceMode) {
      for (const auto &fact : propagation.referenceFacts()) {
        if (!first)
          out << ',';
        first = false;
        out << "{\"from\":" << fact.pc << ",\"to\":" << fact.target
            << ",\"kind\":\"" << fact.kind() << "\",\"size\":" << fact.width << "}";
      }
    }
    for (const auto &fact : facts) {
      if (!first)
        out << ',';
      first = false;
      out << "{\"pc\":" << fact.pc << ",\"value\":" << fact.value << ",\"varnode\":{\"space\":";
      writeString(out, fact.varnode->getSpace()->getName());
      out << ",\"offset\":" << fact.varnode->getOffset()
          << ",\"size\":" << fact.varnode->getSize() << "}}";
    }
    out << "]\n";
    if (tracked != nullptr) {
      out << "CALL_REGISTERS [";
      first = true;
      for (const auto &fact : propagation.callRegisterFacts()) {
        if (!first) out << ',';
        first = false;
        out << "{\"pc\":" << fact.pc << ",\"target\":" << fact.target
            << ",\"value\":" << fact.value << "}";
      }
      out << "]\n";
    }
    out.flush();
  }
};

} // namespace ghidra
#endif
