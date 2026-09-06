#ifndef VENTRIS_CALLFIXUPS_HH
#define VENTRIS_CALLFIXUPS_HH

#include "ifacedecomp.hh"
#include "inject_sleigh.hh"
#include <algorithm>

namespace ghidra {

// Compiler <callfixup><target> metadata supplies the semantics. The caller
// must establish the function and its label before binding this context.
class IfcReferenceFixup : public IfaceDecompCommand {
public:
  void execute(istream &s) override {
    if (dcp->conf == nullptr || dcp->conf->loader == nullptr)
      throw IfaceExecutionError("No binary loaded");
    int4 size;
    Address address = parse_machaddr(s, size, *dcp->conf->types);
    string label, extra;
    if (!(s >> label) || (s >> extra))
      throw IfaceExecutionError("Expected function address and pattern label");
    PcodeInjectLibrary &library = *dcp->conf->pcodeinjectlib;
    for (const auto &entry : library.getCallFixups()) {
      const auto *payload = dynamic_cast<const InjectPayloadCallfixup *>(
          library.getPayload(entry.second));
      if (payload == nullptr)
        continue;
      const auto &targets = payload->getTargetSymbolNames();
      if (std::find(targets.begin(), targets.end(), label) == targets.end())
        continue;
      Scope *scope = dcp->conf->symboltab->getGlobalScope();
      Funcdata *function = scope->queryFunction(address);
      if (function == nullptr)
        function = scope->addFunction(address, label)->getFunction();
      int4 current = function->getFuncProto().getInjectId();
      if (current >= 0 && current != entry.second)
        throw IfaceExecutionError("Conflicting compiler call-fixup labels");
      function->getFuncProto().setInjectId(entry.second);
      *status->optr << "FIXUP 1" << endl;
      return;
    }
    *status->optr << "FIXUP 0" << endl;
  }
};

} // namespace ghidra
#endif
