// OperandSymbol.printList and SleighInstructionPrototype.getOpObjects,
// Ghidra 12.1.3 (Apache-2.0). Walk display operands, not p-code constants.
#ifndef VENTRIS_OPERAND_REFS_HH
#define VENTRIS_OPERAND_REFS_HH

#include "sleigh.hh"

namespace ghidra {

struct OperandObject {
  bool isRegister;
  VarnodeData storage;
  intb scalar;
};

inline void Constructor::collectOperandScalars(ParserWalker &walker,
                                               vector<VarnodeData> &scalars,
                                               bool bodyOnly) const {
  if (bodyOnly && flowthruindex >= 0) {
    const TripleSymbol *symbol = operands[flowthruindex]->getDefiningSymbol();
    if (symbol != nullptr && symbol->getType() == SleighSymbol::subtable_symbol) {
      walker.pushOperand(flowthruindex);
      walker.getConstructor()->collectOperandScalars(walker, scalars, true);
      walker.popOperand();
      return;
    }
  }
  int4 start = bodyOnly ? firstwhitespace : 0;
  if (start < 0)
    return;
  for (int4 index = start; index < int4(printpiece.size()); ++index) {
    const string &piece = printpiece[index];
    if (piece.size() < 2 || piece[0] != '\n')
      continue;
    int4 operand = piece[1] - 'A';
    const TripleSymbol *symbol = operands[operand]->getDefiningSymbol();
    uint4 operandEnd = walker.getOffset(operand);
    walker.pushOperand(operand);
    if (symbol != nullptr && symbol->getType() == SleighSymbol::subtable_symbol) {
      walker.getConstructor()->collectOperandScalars(walker, scalars, false);
    } else if (symbol == nullptr || symbol->getType() == SleighSymbol::value_symbol ||
               symbol->getType() == SleighSymbol::valuemap_symbol) {
      const FixedHandle &handle = walker.getParentHandle();
      if (handle.space != nullptr && handle.space->getType() == IPTR_CONSTANT) {
        int4 size = handle.size;
        if (size == 0)
          size = int4(operandEnd - walker.getOffset(-1));
        if (size == 0)
          size = walker.getCurSpace()->getAddrSize();
        if (size > 0 && size <= int4(sizeof(uintb)))
          scalars.push_back(VarnodeData{handle.space, handle.offset_offset, size});
      }
    }
    walker.popOperand();
  }
}

/// One object a display operand is made of, as Ghidra's
/// `SleighInstructionPrototype.getOpObjects` reports them: a register (its
/// storage) or a scalar (its value, sign-extended to `size`).


/// The objects of every top-level display operand, in operand order. A
/// subtable operand contributes the objects of the constructor it resolves
/// to, so `[sp,#4]` yields the register `sp` and the scalar 4 under one
/// operand -- which is what `NewFunctionStackAnalysisCmd.getStackOpIndex`
/// sums to decide whether an operand names a stack slot.
inline void Constructor::collectOperandObjectsInto(ParserWalker &walker,
                                                   vector<OperandObject> &objects, bool bodyOnly) const {
  const Constructor *ct = this;
  if (bodyOnly && ct->flowthruindex >= 0) {
    const TripleSymbol *symbol = ct->getOperand(ct->flowthruindex)->getDefiningSymbol();
    if (symbol != nullptr && symbol->getType() == SleighSymbol::subtable_symbol) {
      walker.pushOperand(ct->flowthruindex);
      walker.getConstructor()->collectOperandObjectsInto(walker, objects, true);
      walker.popOperand();
      return;
    }
  }
  int4 start = bodyOnly ? ct->firstwhitespace : 0;
  if (start < 0)
    return;
  const vector<string> &pieces = ct->printpiece;
  for (int4 index = start; index < int4(pieces.size()); ++index) {
    const string &piece = pieces[index];
    if (piece.size() < 2 || piece[0] != '\n')
      continue;
    int4 operand = piece[1] - 'A';
    const TripleSymbol *symbol = ct->getOperand(operand)->getDefiningSymbol();
    uint4 operandEnd = walker.getOffset(operand);
    walker.pushOperand(operand);
    if (symbol != nullptr && symbol->getType() == SleighSymbol::subtable_symbol) {
      walker.getConstructor()->collectOperandObjectsInto(walker, objects, false);
    } else {
      const FixedHandle &handle = walker.getParentHandle();
      if (handle.space != nullptr && handle.space->getType() == IPTR_CONSTANT) {
        int4 size = handle.size;
        if (size == 0)
          size = int4(operandEnd - walker.getOffset(-1));
        if (size == 0)
          size = walker.getCurSpace()->getAddrSize();
        if (size > 0 && size <= int4(sizeof(uintb))) {
          intb value = (intb)handle.offset_offset;
          if (size < int4(sizeof(uintb)))
            value = (value << (8 * (sizeof(uintb) - size))) >> (8 * (sizeof(uintb) - size));
          objects.push_back(OperandObject{false, VarnodeData{handle.space, handle.offset_offset, (uint4)size}, value});
        }
      } else if (handle.space != nullptr && handle.space->getType() == IPTR_PROCESSOR &&
                 handle.offset_space == nullptr) {
        objects.push_back(OperandObject{true, VarnodeData{handle.space, handle.offset_offset, handle.size}, 0});
      }
    }
    walker.popOperand();
  }
}

/// Objects grouped by top-level display operand.
inline void Constructor::collectOperandObjects(ParserWalker &walker, vector<vector<OperandObject> > &operands) const {
  const Constructor *ct = this;
  // A root constructor that only prints one subtable operand (`^instruction`)
  // has that subtable's constructor as the instruction proper; the display
  // operands are its. `printBody` descends the same way.
  int4 depth = 0;
  while (ct->flowthruindex >= 0) {
    const TripleSymbol *symbol = ct->operands[ct->flowthruindex]->getDefiningSymbol();
    if (symbol == nullptr || symbol->getType() != SleighSymbol::subtable_symbol)
      break;
    walker.pushOperand(ct->flowthruindex);
    ct = walker.getConstructor();
    ++depth;
  }
  const vector<string> &pieces = ct->printpiece;
  int4 start = ct->firstwhitespace;
  if (start < 0) {
    for (; depth > 0; --depth)
      walker.popOperand();
    return;
  }
  for (int4 index = start; index < int4(pieces.size()); ++index) {
    const string &piece = pieces[index];
    if (piece.size() < 2 || piece[0] != '\n')
      continue;
    int4 operand = piece[1] - 'A';
    vector<OperandObject> objects;
    const TripleSymbol *symbol = ct->getOperand(operand)->getDefiningSymbol();
    uint4 operandEnd = walker.getOffset(operand);
    walker.pushOperand(operand);
    if (symbol != nullptr && symbol->getType() == SleighSymbol::subtable_symbol) {
      walker.getConstructor()->collectOperandObjectsInto(walker, objects, false);
    } else {
      const FixedHandle &handle = walker.getParentHandle();
      if (handle.space != nullptr && handle.space->getType() == IPTR_CONSTANT) {
        int4 size = handle.size;
        if (size == 0)
          size = int4(operandEnd - walker.getOffset(-1));
        if (size == 0)
          size = walker.getCurSpace()->getAddrSize();
        if (size > 0 && size <= int4(sizeof(uintb))) {
          intb value = (intb)handle.offset_offset;
          if (size < int4(sizeof(uintb)))
            value = (value << (8 * (sizeof(uintb) - size))) >> (8 * (sizeof(uintb) - size));
          objects.push_back(OperandObject{false, VarnodeData{handle.space, handle.offset_offset, (uint4)size}, value});
        }
      } else if (handle.space != nullptr && handle.space->getType() == IPTR_PROCESSOR &&
                 handle.offset_space == nullptr) {
        objects.push_back(OperandObject{true, VarnodeData{handle.space, handle.offset_offset, handle.size}, 0});
      }
    }
    walker.popOperand();
    operands.push_back(std::move(objects));
  }
  for (; depth > 0; --depth)
    walker.popOperand();
}

} // namespace ghidra
#endif
