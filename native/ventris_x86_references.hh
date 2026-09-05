// X86Analyzer.evaluateContext, Ghidra 12.1.3 (Apache-2.0).
// Processor policy stays outside the generic propagation and discovery logic.
#ifndef VENTRIS_X86_REFERENCES_HH
#define VENTRIS_X86_REFERENCES_HH

#include "sleigh_arch.hh"
#include "sleigh.hh"
#include <sstream>

namespace ghidra {
namespace ventris_constants {

class X86ReferencePolicy {
  const Sleigh *translator = nullptr;
  Address last;
  bool addressFormation = false;

public:
  void configure(Architecture &arch) {
    const auto *native = dynamic_cast<const SleighArchitecture *>(&arch);
    if (native == nullptr)
      return;
    // Same target selection and normalization as resolveArchitecture.
    const string &target = native->getTarget();
    string id = target.empty() || target == "default" ? arch.loader->getArchType() : target;
    if (id.compare(0, 7, "binary-") == 0)
      id.erase(0, 7);
    else if (id.compare(0, 8, "default-") == 0)
      id.erase(0, 8);
    if (SleighArchitecture::normalizeArchitecture(id).compare(0, 4, "x86:") == 0)
      translator = dynamic_cast<const Sleigh *>(arch.translate);
  }

  bool matches(const Address &pc) {
    if (translator == nullptr)
      return false;
    if (pc != last) {
      ParserWalker walker(translator->getInstructionContext(pc));
      walker.baseState();
      std::ostringstream mnemonic;
      walker.getConstructor()->printMnemonic(mnemonic, walker);
      addressFormation = mnemonic.str() == "LEA";
      last = pc;
    }
    return addressFormation;
  }
};

} // namespace ventris_constants
} // namespace ghidra
#endif
