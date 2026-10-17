#ifndef ROMWRIGHT_BYTES_HH
#define ROMWRIGHT_BYTES_HH
// The NUL-free six-bit varint writer (and its reader) the printer IR and the
// structuring query share (crates/romwright-worker/src/printc/ir.rs).
#include "op.hh"
#include "varnode.hh"
#include "space.hh"
#include "variable.hh"
#include "merge.hh"

namespace ghidra {

/// Private calls the stage 3 handoff makes (romwright_merge.hh), through the
/// friend declarations native/ghidra-opt-sleigh.patch adds to PcodeOp,
/// Varnode and HighVariable.
class RomwrightMergeApply {
public:
  static void remove(HighVariable *high,Varnode *vn) { high->remove(vn); }
  static void merge(HighVariable *high1,HighVariable *high2,bool speculative) { high1->merge(high2,(HighIntersectTest *)0,speculative); }
  static void setIndirectOnly(Varnode *vn) { vn->setFlags(Varnode::indirectonly); }
  static uint4 opFlags(const PcodeOp *op) { return op->flags; }
  static void groupWith(HighVariable *high,int4 off,HighVariable *other) { high->groupWith(off,other); }
  static void clearProtoPartial(Varnode *vn) { vn->clearFlags(Varnode::proto_partial); }
  static const vector<PcodeOp *> &protoPartialOf(const Merge &merge) { return merge.protoPartial; }
};

/// Integer/string writer for the IR blob (decoded by printc/ir.rs). The blob
/// travels inside the burst protocol, which reserves NUL, so no byte is 0:
/// integers use six-bit groups, least significant first, each byte marked
/// with 0x40 and continuation 0x80.
class RomwrightIrBytes {
public:
  string data;
  void byte(uint4 v) { data.push_back((char)(v & 0xff)); }
  void u(uint8 v) {
    do {
      uint4 b = 0x40 | (uint4)(v & 0x3f);
      v >>= 6;
      if (v != 0) b |= 0x80;
      byte(b);
    } while(v != 0);
  }
  void s(int8 v) { u(((uint8)v << 1) ^ (uint8)(v >> 63)); }
  void flag(bool v) { u(v ? 1 : 0); }
  void str(const string &v) {
    if (v.find('\0') != string::npos)
      throw LowlevelError("Printer IR string contains NUL");
    u(v.size());
    data.append(v);
  }
  void op(const PcodeOp *o) { flag(o != (const PcodeOp *)0); if (o != (const PcodeOp *)0) u(o->getTime()); }
  void vn(const Varnode *v) { flag(v != (const Varnode *)0); if (v != (const Varnode *)0) u(v->getCreateIndex()); }
  /// The value PackedEncode::writeSpace would write: special code or index.
  void space(const AddrSpace *spc) {
    switch(spc->getType()) {
    case IPTR_FSPEC: flag(true); u(2); break;
    case IPTR_IOP: flag(true); u(3); break;
    case IPTR_JOIN: flag(true); u(1); break;
    case IPTR_SPACEBASE: flag(true); u(spc->isFormalStackSpace() ? 0 : 4); break;
    default: flag(false); u(spc->getIndex()); break;
    }
  }
};

/// Reads what RomwrightIrBytes wrote.
class RomwrightIrReader {
  const string &data;
  size_t pos;
public:
  RomwrightIrReader(const string &d) : data(d), pos(0) {}
  uint8 u(void) {
    uint8 v = 0;
    int4 shift = 0;
    for(;;) {
      if (pos >= data.size()) throw LowlevelError("Structuring answer truncated");
      uint4 b = (uint1)data[pos++];
      v |= (uint8)(b & 0x3f) << shift;
      shift += 6;
      if ((b & 0x80) == 0) break;
    }
    return v;
  }
  int8 s(void) { uint8 v = u(); return (int8)(v >> 1) ^ -(int8)(v & 1); }
  bool atEnd(void) const { return pos == data.size(); }
};

}
#endif
