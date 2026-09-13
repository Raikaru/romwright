#ifndef ROMWRIGHT_PCODE_HH
#define ROMWRIGHT_PCODE_HH

#include "sleigh.hh"

namespace ghidra {

// Export only: the p-code SLEIGH already generated for one instruction, in
// the order the translator emitted it. No analysis happens here -- the
// consumer (crates/romwright-core/src/native/vsa.rs) does the reasoning, so the
// pinned tree grows a printer and nothing else.
//
// One line per instruction, then one per operation:
//
//   PCODE r0x401000 len=5 ops=3
//   OP 0 COPY out=register:0x0:8 in=const:0x1:8
//
// A varnode is `<space>:<offset>:<size>`, with the space named as the
// translator names it, so `const`, `register`, `unique` and `ram` all read
// back unambiguously.
class PcodePrinter : public PcodeEmit {
  ostream &out;
  int4 index = 0;
public:
  PcodePrinter(ostream &s) : out(s) {}
  int4 count(void) const { return index; }
  void reset(void) { index = 0; }

  void printVarnode(const char *label,const VarnodeData &var) {
    out << ' ' << label << '=' << var.space->getName() << ':' << "0x" << hex
        << var.offset << ':' << dec << var.size;
  }

  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize) {
    out << "OP " << dec << index++ << ' ' << get_opname(opc);
    if (outvar != (VarnodeData *)0)
      printVarnode("out",*outvar);
    for(int4 i=0;i<isize;++i) {
      ostringstream label;
      label << 'i' << i;
      printVarnode(label.str().c_str(),vars[i]);
    }
    out << '\n';
  }
};

} // namespace ghidra
#endif
