// PowerPC conditional return recovery for the SLEIGH translator.
//
// The stock PowerPC SLEIGH uses BRANCHIND for CTR-conditional LR exits.
// `Sleigh::oneInstruction` enables this adapter only for decoded bclr words
// with BO[2]=0, BH=0 and LK=0. The CTR update and conditional p-code stay
// unchanged; only the final LR transfer is reported as a RETURN. The p-code
// emit interface is the pinned translate.hh `PcodeEmit` (Ghidra 12.1.3,
// Apache-2.0).
#ifndef ROMWRIGHT_PPC_RETURN_HH
#define ROMWRIGHT_PPC_RETURN_HH

#include "translate.hh"

namespace ghidra {

class PowerPcReturnEmit : public PcodeEmit {
  PcodeEmit &destination;
  const VarnodeData &lr;
public:
  PowerPcReturnEmit(PcodeEmit &emit, const VarnodeData &link) : destination(emit), lr(link) {}
  void dump(const Address &addr, OpCode opcode, VarnodeData *out,
            VarnodeData *inputs, int4 count) override {
    if (opcode == CPUI_BRANCHIND && count == 1 && inputs[0].space == lr.space
        && inputs[0].offset == lr.offset && inputs[0].size == lr.size)
      opcode = CPUI_RETURN;
    destination.dump(addr, opcode, out, inputs, count);
  }
};

} // namespace ghidra
#endif
