// OperandSymbol.printList and SleighInstructionPrototype.getOpObjects,
// Ghidra 12.1.3 (Apache-2.0). Walk display operands, not p-code constants.
#ifndef VENTRIS_OPERAND_REFS_HH
#define VENTRIS_OPERAND_REFS_HH

#include "sleigh.hh"

namespace ghidra {

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

} // namespace ghidra
#endif
