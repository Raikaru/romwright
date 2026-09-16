#ifndef ROMWRIGHT_IR_STATE_HH
#define ROMWRIGHT_IR_STATE_HH
#include "opcodes.hh"
#include <map>
namespace ghidra {
class PcodeOp;
// A projection lasts only for one encode/PrintC response. Native CALL objects
// and their FuncCallSpecs/INDIRECT bookkeeping remain intact.
inline std::map<const PcodeOp *, OpCode> &romwrightIrProjections() {
  static std::map<const PcodeOp *, OpCode> projections;
  return projections;
}
class RomwrightIrProjectionScope {
public:
  RomwrightIrProjectionScope() { romwrightIrProjections().clear(); }
  ~RomwrightIrProjectionScope() { romwrightIrProjections().clear(); }
};
}
#endif
