// Stack symbol layout decisions (docs/types-port.md, section 13). API contracts: the pinned varmap.cc,
// coreaction.cc and funcdata_varnode.cc (Apache-2.0).
/// \file romwright_layout.hh
/// \brief Stack symbol layout decisions (docs/types-port.md, section 13).
///
/// The decompiler lays out the stack frame in \b ScopeLocal::restructure from range hints (one per
/// varnode in the stack space, one per pointer into it) and names what it finds. The rules here
/// change two inputs of that layout, each for a class of functions the quality pass of stage 3
/// traced to it (`stack0x...` names and partial members of stack locals):
///
///  - \b STACK_ALIGN: an open range (a pointer into the frame) that starts where its element type cannot
///    be is typed as bytes (\b romwrightOpenType, used by \b MapState::gatherOpen and \b addGuard).
///  - \b STACK_FOLD: the low bits of a stack address are known, since the frame is aligned
///    (\b RuleRomwrightStackAlign): the run-time alignment arithmetic of an unaligned MIPS load or store (an
///    \b INT_AND of the address) becomes a constant, so the access is a plain one at an aligned address.
///  - \b STACK_REFS: the address of a stack location no symbol covers (a \b PTRSUB of the stack pointer) gets
///    one, sized by the widest value stored there (\b romwrightStackReference, used by
///    \b ActionNameVars::linkSymbols after every varnode has its symbol).
///
/// `ROMWRIGHT_NATIVE_LAYOUT=1` turns every rule off (the previous output byte for byte);
/// `ROMWRIGHT_LAYOUT_<RULE>=off` turns one off. The worker's rules for global objects are in
/// `crates/romwright-worker/src/layout.rs` and answer to the same switches.
#ifndef __ROMWRIGHT_LAYOUT_HH__
#define __ROMWRIGHT_LAYOUT_HH__

#include <cstdlib>
#include <string>
#include "funcdata.hh"
#include "ruleaction.hh"

namespace ghidra {

/// \brief Whether a layout rule is on: every rule unless \b ROMWRIGHT_NATIVE_LAYOUT is 1 or its own switch is "off"
inline bool romwrightLayoutRule(const char *rule)

{
  const char *all = getenv("ROMWRIGHT_NATIVE_LAYOUT");
  if (all != (const char *)0 && all[0] == '1' && all[1] == '\0') return false;
  const char *one = getenv(rule);
  return !(one != (const char *)0 && std::string(one) == "off");
}

/// \brief The type of an \e open range that starts at an address its element could not be at
///
/// A pointer into the stack is the evidence for an open range, typed as the pointer's target.
/// When the range starts at an offset the target type cannot naturally be at (a 4 or 8 byte
/// integer at an odd offset), the pointer is a byte-granular address into some object: the
/// aligned-down address of an unaligned load or store (MIPS \b lwl/lwr, \b sdl/sdr), or a
/// pointer into a byte array cast to a wider type. It says nothing of an object of that type
/// there, and typing the range so makes it swallow the aligned accesses beside it. The range
/// keeps its extent and its place, and loses the type.
/// \param offset is the offset the range starts at
/// \param ct is the type of the pointer's target, or null
/// \param types is the factory for the replacement
/// \return the type to give the range
inline Datatype *romwrightOpenType(uintb offset,Datatype *ct,TypeFactory *types)

{
  static const bool on = romwrightLayoutRule("ROMWRIGHT_LAYOUT_STACK_ALIGN");
  if (!on || ct == (Datatype *)0) return ct;
  switch(ct->getMetatype()) {
    case TYPE_UNKNOWN:
    case TYPE_INT:
    case TYPE_UINT:
    case TYPE_BOOL:
    case TYPE_FLOAT:
    case TYPE_PTR:
      break;
    default:
      return ct;
  }
  int4 align = ct->getSize();
  if (align > 4) align = 4;		// A frame is not aligned to its widest member on every ABI
  if (align < 2 || (offset % align) == 0) return ct;
  return types->getBase(1,TYPE_UNKNOWN);
}

/// \brief Give the stack address a \b PTRSUB takes a symbol to refer to
///
/// \b linkSymbolReference finds the symbol that contains the address, and finds none for an address
/// in the parameter region of the frame (the symbol of an input there is not mapped throughout the
/// function) and for one a layout left uncovered. The reference then prints as the location itself
/// (\b stack0x00000020), which no declaration names. Here the symbol is looked for ignoring where it is in use, and made,
/// as wide as the widest value stored at the address, when there is none.
/// \param data is the function
/// \param vn is the constant offset operand of the \b PTRSUB
/// \return the symbol the reference is to, or null
inline Symbol *romwrightStackReference(Funcdata &data,Varnode *vn)

{
  static const bool on = romwrightLayoutRule("ROMWRIGHT_LAYOUT_STACK_REFS");
  if (!on) return (Symbol *)0;
  PcodeOp *op = vn->loneDescend();
  if (op == (PcodeOp *)0 || op->code() != CPUI_PTRSUB) return (Symbol *)0;
  Varnode *in0 = op->getIn(0);
  Datatype *ptype = in0->getHigh()->getType();
  if (ptype->getMetatype() != TYPE_PTR) return (Symbol *)0;
  Datatype *sb = ((TypePointer *)ptype)->getPtrTo();
  if (sb->getMetatype() != TYPE_SPACEBASE) return (Symbol *)0;
  ScopeLocal *local = data.getScopeLocal();
  if (((TypeSpacebase *)sb)->getMap() != local) return (Symbol *)0;
  Address addr = ((TypeSpacebase *)sb)->getAddress(vn->getOffset(),in0->getSize(),op->getAddr());
  if (addr.isInvalid()) return (Symbol *)0;
  SymbolEntry *entry = local->findOverlap(addr,1);
  if (entry == (SymbolEntry *)0) {
    int4 size = 1;
    const int4 widths[3] = { 8, 4, 2 };
    for(int4 i=0;i<3;++i) {
      if (data.beginLoc(widths[i],addr) != data.endLoc(widths[i],addr)) {
	size = widths[i];
	break;
      }
    }
    if (local->findOverlap(addr,size) != (SymbolEntry *)0) size = 1;
    try {
      entry = local->addSymbol("",data.getArch()->types->getBase(size,TYPE_UNKNOWN),addr,Address());
    }
    catch(LowlevelError &err) {
      return (Symbol *)0;
    }
  }
  if (entry->getAddr().getOffset() > addr.getOffset()) return (Symbol *)0;
  int4 off = (int4)(addr.getOffset() - entry->getAddr().getOffset()) + entry->getOffset();
  data.romwrightSymbolReference(vn,entry,off);
  return entry->getSymbol();
}

/// \brief Fold a mask of a stack address: the entry stack pointer is aligned, so the low bits of \b sp + c are those of c
///
/// An unaligned MIPS access (\b sdl, \b sdr, \b lwl, \b lwr...) computes the aligned-down address of its operand at run time:
/// \code
///   t = (sp + c + 7) & 7;   p = (sp + c + 7) - t;   *p = ...
/// \endcode
/// The compiler wrote it for an address it knew, and the frame it knew it in is aligned to the ABI (8 bytes on
/// the MIPS ABIs, 16 on the Emotion Engine's). With the low bits of \b sp known, the mask is a constant and the access
/// is a store or load of the whole doubleword it always was. Only an \b INT_AND of a sum of the stack
/// pointer, constants and low-part extractions by a mask of up to 3 bits is folded, and only in
/// the MIPS languages (the ones with \b hi and \b lo); the offsets are relative to the stack pointer on entry.
class RuleRomwrightStackAlign : public Rule {
  static bool offset(Varnode *vn,Funcdata &data,uintb &sum,int4 &bases,int4 depth);
  static bool mipsLike(Funcdata &data);
public:
  RuleRomwrightStackAlign(const string &g) : Rule(g, 0, "romwrightstackalign") {}	///< Constructor
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    return new RuleRomwrightStackAlign(getGroup());
  }
  virtual void getOpList(vector<uint4> &oplist) const { oplist.push_back(CPUI_INT_AND); }
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
};

/// \brief Add up the constants of a stack address expression
/// \param vn is the expression
/// \param data is the function
/// \param sum accumulates the constants
/// \param bases counts the stack pointer inputs
/// \param depth limits the walk
/// \return \b false if \b vn is anything but the stack pointer, constants and the operations that keep the low bits
inline bool RuleRomwrightStackAlign::offset(Varnode *vn,Funcdata &data,uintb &sum,int4 &bases,int4 depth)

{
  if (depth > 6) return false;
  if (vn->isConstant()) {
    sum += vn->getOffset();
    return true;
  }
  if (vn->isSpacebase() && vn->isInput()) {
    if (data.getArch()->getSpaceBySpacebase(vn->getAddr(),vn->getSize()) != data.getScopeLocal()->getSpaceId())
      return false;
    bases += 1;
    return true;
  }
  PcodeOp *def = vn->getDef();
  if (def == (PcodeOp *)0) return false;
  switch(def->code()) {
    case CPUI_COPY:
      return offset(def->getIn(0),data,sum,bases,depth+1);
    case CPUI_SUBPIECE:
      if (def->getIn(1)->getOffset() != 0) return false;
      return offset(def->getIn(0),data,sum,bases,depth+1);
    case CPUI_INT_ADD:
    case CPUI_PTRSUB:
      return offset(def->getIn(0),data,sum,bases,depth+1) && offset(def->getIn(1),data,sum,bases,depth+1);
    case CPUI_INT_SUB: {
      uintb part = 0;
      int4 none = 0;
      if (!offset(def->getIn(1),data,part,none,depth+1) || none != 0) return false;
      sum -= part;
      return offset(def->getIn(0),data,sum,bases,depth+1);
    }
    default:
      break;
  }
  return false;
}

/// \brief Is this a MIPS language: the one with the multiply-divide registers \b hi and \b lo
inline bool RuleRomwrightStackAlign::mipsLike(Funcdata &data)

{
  static int4 known = -1;
  if (known < 0) {
    try {
      data.getArch()->translate->getRegister("hi");
      data.getArch()->translate->getRegister("lo");
      known = 1;
    }
    catch(LowlevelError &err) {
      known = 0;
    }
  }
  return known == 1;
}

inline int4 RuleRomwrightStackAlign::applyOp(PcodeOp *op,Funcdata &data)

{
  static const bool on = romwrightLayoutRule("ROMWRIGHT_LAYOUT_STACK_FOLD");
  if (!on) return 0;
  Varnode *mask = op->getIn(1);
  if (!mask->isConstant()) return 0;
  uintb m = mask->getOffset();
  if (m == 0 || m > 7 || ((m + 1) & m) != 0) return 0;		// A mask of the low one to three bits
  if (!mipsLike(data)) return 0;
  uintb sum = 0;
  int4 bases = 0;
  if (!offset(op->getIn(0),data,sum,bases,0) || bases != 1) return 0;
  Varnode *out = op->getOut();
  data.opRemoveInput(op,1);
  data.opSetOpcode(op,CPUI_COPY);
  data.opSetInput(op,data.newConstant(out->getSize(),sum & m),0);
  return 1;
}

} // End namespace ghidra

#endif
