// Positive return hints from completed native CFGs, never rendered C text.
// API/flag contracts: pinned funcdata.hh, block.hh, op.hh, jumptable.hh
// and Funcdata::opMarkHalt (Apache-2.0). Unknown flow is not a proof.
#ifndef ROMWRIGHT_NONRETURN_HH
#define ROMWRIGHT_NONRETURN_HH
#include "funcdata.hh"

namespace ghidra {

inline bool romwrightNoReturnHint(const Funcdata &fd) {
  if (!fd.isProcComplete() || fd.hasRestartPending() ||
      fd.hasUnimplemented() || fd.hasBadData()) return false;
  const BlockGraph &blocks = fd.getBasicBlocks();
  if (blocks.getSize() == 0) return false;
  // Checking every retained block is conservative even if an unreachable
  // component survives optimization; it needs no auxiliary traversal storage.
  for (int4 i = 0; i < blocks.getSize(); ++i) {
    const BlockBasic *block = static_cast<const BlockBasic *>(blocks.getBlock(i));
    for (auto it = block->beginOp(); it != block->endOp(); ++it) {
      const PcodeOp *op = *it;
      const uint4 halt = op->getHaltType();
      if (halt != 0 && halt != PcodeOp::noreturn) return false;
      if (op->code() == CPUI_RETURN && halt != PcodeOp::noreturn) return false;
      if (op->code() == CPUI_BRANCHIND) {
        const JumpTable *table = fd.findJumpTable(op);
        if (table == nullptr || !table->isRecovered() || table->isPartial()) return false;
      }
    }
    if (block->sizeOut() == 0) {
      const PcodeOp *last = block->lastOp();
      if (last == nullptr || last->code() != CPUI_RETURN ||
          last->getHaltType() != PcodeOp::noreturn) return false;
    }
    for (int4 edge = 0; edge < block->sizeOut(); ++edge) {
      if (block->getOut(edge)->getParent() != &blocks) return false;
    }
  }
  return true;
}

// Export a hint through the existing prototype flag without changing cached
// facts, C output, or later calls. Restoration also covers encoding exceptions.
class RomwrightNoReturnHint {
  FuncProto &prototype;
  bool original;
public:
  explicit RomwrightNoReturnHint(Funcdata &fd)
    : prototype(fd.getFuncProto()), original(prototype.isNoReturn()) {
    if (!original && romwrightNoReturnHint(fd)) prototype.setNoReturn(true);
  }
  ~RomwrightNoReturnHint() { prototype.setNoReturn(original); }
};

} // namespace ghidra
#endif
