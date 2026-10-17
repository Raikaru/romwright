#ifndef ROMWRIGHT_MERGE_HH
#define ROMWRIGHT_MERGE_HH
// Stage 3 of the decompiler port (docs/merge-port.md): the worker decides
// which p-code values share a C variable (merge.cc), which print as
// sub-expressions (ActionMarkExplicit, ActionMarkImplied) and the for-loop op
// moves; this header is the C++ side of that handoff.
//
// RomwrightMerge replaces the actions from ActionMergeRequired to
// ActionCopyMarker. It sends the worker the function's p-code as
// ActionAssignHigh leaves it (RomwrightPrintIrExport::mergeQuery) and, when
// the worker decides the function, replays the log it answers with on the
// real Funcdata and HighVariable objects, in the order the stock actions
// would have made the same calls. When the worker declines (or
// ROMWRIGHT_NATIVE_MERGE=1) the stock actions run, in their stock order.
//
// ROMWRIGHT_RUST_MERGE=verify (a worker setting) has the stock actions run
// after the worker has decided, and sends the resulting state back for the
// worker to compare with its own (printc/merge/mod.rs `answer_dump`).
#include "romwright_printir.hh"
#include "merge.hh"
#include "variable.hh"

namespace ghidra {

inline Address romwrightMergeAddress(Funcdata &data,const vector<PcodeOp *> &ops,const vector<BlockBasic *> &blocks,int4 kind,uint8 id) {
  if (kind == 0) {
    if (id >= ops.size()) throw LowlevelError("Merge answer names a missing op");
    return ops[id]->getAddr();
  }
  if (id >= blocks.size()) throw LowlevelError("Merge answer names a missing block");
  return kind == 1 ? blocks[id]->getStart() : blocks[id]->getStop();
}

/// Replays the worker's decisions (printc/merge/mod.rs `encode_log`).
inline void romwrightMergeReplay(Funcdata &data,const vector<const PcodeOp *> &opsIn,const vector<const Varnode *> &vnsIn,
				 const string &answer) {
  vector<PcodeOp *> ops;
  vector<Varnode *> vns;
  vector<BlockBasic *> blocks;
  for(size_t i=0;i<opsIn.size();++i) ops.push_back(const_cast<PcodeOp *>(opsIn[i]));
  for(size_t i=0;i<vnsIn.size();++i) vns.push_back(const_cast<Varnode *>(vnsIn[i]));
  const BlockGraph &graph(data.getBasicBlocks());
  for(int4 i=0;i<graph.getSize();++i) blocks.push_back((BlockBasic *)graph.getBlock(i));
  RomwrightIrReader reader(answer);
  for(;;) {
    uint8 tag = reader.u();
    if (tag == 0) break;
    switch(tag) {
    case 1: {
      int4 kind = (int4)reader.u();
      uint8 id = reader.u();
      Address addr = romwrightMergeAddress(data,ops,blocks,kind,id);
      PcodeOp *op = data.newOp(1,addr);
      data.opSetOpcode(op,CPUI_COPY);
      ops.push_back(op);
      break;
    }
    case 2: {
      int4 size = (int4)reader.u();
      uint8 from = reader.u();
      if (from >= vns.size()) throw LowlevelError("Merge answer names a missing varnode");
      vns.push_back(data.newUnique(size,vns[from]->getType()));
      break;
    }
    case 3: {
      uint8 op = reader.u(); uint8 vn = reader.u();
      if (op >= ops.size() || vn >= vns.size()) throw LowlevelError("Merge answer names a missing op or varnode");
      data.opSetOutput(ops[op],vns[vn]);
      break;
    }
    case 4: {
      uint8 op = reader.u(); uint8 vn = reader.u(); int4 slot = (int4)reader.u();
      if (op >= ops.size() || vn >= vns.size()) throw LowlevelError("Merge answer names a missing op or varnode");
      data.opSetInput(ops[op],vns[vn],slot);
      break;
    }
    case 5: {
      uint8 op = reader.u(); int4 kind = (int4)reader.u(); uint8 id = reader.u();
      if (op >= ops.size()) throw LowlevelError("Merge answer names a missing op");
      if (kind < 2) {
	if (id >= ops.size()) throw LowlevelError("Merge answer names a missing op");
	if (kind == 0) data.opInsertBefore(ops[op],ops[id]);
	else data.opInsertAfter(ops[op],ops[id]);
      }
      else {
	if (id >= blocks.size()) throw LowlevelError("Merge answer names a missing block");
	if (kind == 2) data.opInsertBegin(ops[op],blocks[id]);
	else data.opInsertEnd(ops[op],blocks[id]);
      }
      break;
    }
    case 6: {
      uint8 op = reader.u();
      if (op >= ops.size()) throw LowlevelError("Merge answer names a missing op");
      data.opUninsert(ops[op]);
      break;
    }
    case 7: {
      uint8 op = reader.u();
      if (op >= ops.size()) throw LowlevelError("Merge answer names a missing op");
      data.opDestroy(ops[op]);
      break;
    }
    case 8: {
      uint8 from = reader.u(); uint8 to = reader.u();
      if (from >= vns.size() || to >= vns.size()) throw LowlevelError("Merge answer names a missing varnode");
      data.totalReplace(vns[from],vns[to]);
      break;
    }
    case 9: {
      uint8 vn = reader.u();
      if (vn >= vns.size()) throw LowlevelError("Merge answer names a missing varnode");
      RomwrightMergeApply::remove(vns[vn]->getHigh(),vns[vn]);
      break;
    }
    case 10: {
      uint8 a = reader.u(); uint8 b = reader.u(); bool spec = reader.u() != 0;
      if (a >= vns.size() || b >= vns.size()) throw LowlevelError("Merge answer names a missing varnode");
      RomwrightMergeApply::merge(vns[a]->getHigh(),vns[b]->getHigh(),spec);
      break;
    }
    case 11: case 12: case 13: case 17: {
      uint8 vn = reader.u();
      if (vn >= vns.size()) throw LowlevelError("Merge answer names a missing varnode");
      if (tag == 11) vns[vn]->setExplicit();
      else if (tag == 12) vns[vn]->clearImplied();
      else if (tag == 13) Merge::markImplied(vns[vn]);
      else RomwrightMergeApply::setIndirectOnly(vns[vn]);
      break;
    }
    case 18: {
      uint8 a = reader.u(); uint8 b = reader.u(); int8 off = reader.s();
      if (a >= vns.size() || b >= vns.size()) throw LowlevelError("Merge answer names a missing varnode");
      RomwrightMergeApply::groupWith(vns[a]->getHigh(),(int4)off,vns[b]->getHigh());
      break;
    }
    case 19: {
      uint8 vn = reader.u();
      if (vn >= vns.size()) throw LowlevelError("Merge answer names a missing varnode");
      RomwrightMergeApply::clearProtoPartial(vns[vn]);
      break;
    }
    case 14: case 15: case 16: {
      uint8 op = reader.u();
      if (op >= ops.size()) throw LowlevelError("Merge answer names a missing op");
      if (tag == 14) data.opMarkNonPrinting(ops[op]);
      else if (tag == 15) data.opMarkPrinting(ops[op]);
      else data.opMarkSpecialPrint(ops[op]);
      break;
    }
    default:
      throw LowlevelError("Merge answer has an unknown entry");
    }
  }
  RomwrightFunctionState &state(romwrightStates()[&data]);
  state.clearLoops();
  uint8 n = reader.u();
  for(uint8 i=0;i<n;++i) {
    RomwrightLoop loop;
    loop.head = (int4)reader.u();
    loop.tail = (int4)reader.u();
    uint8 init = reader.u();
    uint8 iter = reader.u();
    if (init > ops.size() || iter > ops.size() || iter == 0) throw LowlevelError("Merge answer names a missing op");
    loop.initializeOp = init == 0 ? (PcodeOp *)0 : ops[init-1];
    loop.iterateOp = ops[iter-1];
    state.loops.push_back(loop);
  }
}

/// The decompiler's own final state, for ROMWRIGHT_RUST_MERGE=verify (printc/ir.rs `decode_merge_dump`).
inline string romwrightMergeDump(Funcdata &data) {
  RomwrightIrBytes out;
  out.u(0);
  out.u(4);
  out.u(data.getAddress().getOffset());
  const BlockGraph &graph(data.getBasicBlocks());
  out.u(graph.getSize());
  for(int4 b=0;b<graph.getSize();++b) {
    const BlockBasic *bb = (const BlockBasic *)graph.getBlock(b);
    uint4 count = 0;
    list<PcodeOp *>::const_iterator iter;
    for(iter=bb->beginOp();iter!=bb->endOp();++iter) count += 1;
    out.u(count);
    for(iter=bb->beginOp();iter!=bb->endOp();++iter) {
      const PcodeOp *op = *iter;
      out.u(op->getTime());
      out.u(op->code());
      out.flag((RomwrightMergeApply::opFlags(op) & PcodeOp::nonprinting) != 0);
      out.flag(op->doesSpecialPrinting());
      out.u(op->getOut() == (const Varnode *)0 ? 0 : op->getOut()->getCreateIndex() + 1);
      out.u(op->numInput());
      for(int4 j=0;j<op->numInput();++j) out.u(op->getIn(j)->getCreateIndex());
    }
  }
  vector<const Varnode *> vns;
  VarnodeLocSet::const_iterator viter;
  for(viter=data.beginLoc();viter!=data.endLoc();++viter) {
    const Varnode *vn = *viter;
    if (vn->isAnnotation()) continue;
    vns.push_back(vn);
  }
  out.u(vns.size());
  for(size_t i=0;i<vns.size();++i) {
    const Varnode *vn = vns[i];
    const HighVariable *high = vn->getHigh();
    uint4 rep = vn->getCreateIndex();
    for(int4 j=0;j<high->numInstances();++j)
      if (high->getInstance(j)->getCreateIndex() < rep) rep = high->getInstance(j)->getCreateIndex();
    out.u(vn->getCreateIndex());
    out.u(rep);
    out.flag(vn->isExplicit());
    out.flag(vn->isImplied());
    out.flag(vn->isIndirectOnly());
  }
  RomwrightFunctionState &state(romwrightStates()[&data]);
  out.u(state.loops.size());
  for(size_t i=0;i<state.loops.size();++i) {
    out.u(state.loops[i].head);
    out.u(state.loops[i].tail);
    out.u(state.loops[i].initializeOp == (PcodeOp *)0 ? 0 : state.loops[i].initializeOp->getTime() + 1);
    out.u(state.loops[i].iterateOp == (PcodeOp *)0 ? 0 : state.loops[i].iterateOp->getTime() + 1);
  }
  return out.data;
}

/// ActionNameVars' default-name loop, with the worker deciding the names
/// (printc/merge/names.rs). Returns \b false when the decompiler must name the
/// variables itself.
inline bool romwrightNameVars(Funcdata &data,const vector<Varnode *> &namerec,int4 &base) {
  if (!romwrightMergeActive()) return false;
  ArchitectureGhidra *arch = dynamic_cast<ArchitectureGhidra *>(data.getArch());
  if (arch == (ArchitectureGhidra *)0) return false;
  vector<Varnode *> todo;
  set<const Symbol *> seen;
  for(uint4 i=0;i<namerec.size();++i) {
    Varnode *vn = namerec[i];
    Symbol *sym = vn->getHigh()->getSymbol();
    if (sym == (Symbol *)0) return false;
    if (!sym->isNameUndefined()) continue;
    if (!seen.insert(sym).second) continue;
    todo.push_back(vn);
  }
  if (todo.empty()) return true;
  vector<string> localNames;
  data.getScopeLocal()->romwrightNames(localNames);
  RomwrightIrBytes query;
  query.u(0);
  query.u(3);
  query.u(data.getAddress().getOffset());
  query.s(base);
  query.u(localNames.size());
  for(size_t i=0;i<localNames.size();++i) query.str(localNames[i]);
  query.u(todo.size());
  for(size_t i=0;i<todo.size();++i) {
    Varnode *vn = todo[i];
    Symbol *sym = vn->getHigh()->getSymbol();
    Scope *scope = sym->getScope();
    Address addr;
    uint4 flags = 0;
    int4 index = -1;
    Datatype *ct = sym->getType();
    if (!vn->isConstant()) {
      HighVariable *high = vn->getHigh();
      addr = vn->getAddr();
      flags = vn->getFlags();
      if (sym->getCategory() == Symbol::function_parameter || high->isInput()) {
	if (sym->getCategory() == Symbol::function_parameter) index = sym->getCategoryIndex() + 1;
	flags |= Varnode::input;
      }
    }
    else if (sym->numEntries() != 0) {
      SymbolEntry *entry = sym->getMapEntry(0);
      addr = entry->getAddr();
      Address usepoint = entry->getFirstUseAddress();
      flags = usepoint.isInvalid() ? Varnode::addrtied : 0;
      if (sym->getCategory() == Symbol::function_parameter) {
	flags |= Varnode::input;
	index = sym->getCategoryIndex() + 1;
      }
    }
    query.u(flags);
    query.s(index);
    query.flag(ct != (Datatype *)0);
    ostringstream base_s;
    if (ct != (Datatype *)0) ct->printNameBase(base_s);
    query.str(base_s.str());
    int4 sz = (ct == (Datatype *)0) ? 1 : ct->getSize();
    query.u(sz);
    string spaceName;
    string regName;
    uint8 offset = 0;
    uint8 wordOffset = 0;
    int4 addrSize = 0;
    if (!addr.isInvalid()) {
      spaceName = addr.getSpace()->getName();
      offset = addr.getOffset();
      wordOffset = AddrSpace::byteToAddress(addr.getOffset(),addr.getSpace()->getWordSize());
      addrSize = addr.getAddrSize();
      regName = data.getArch()->translate->getRegisterName(addr.getSpace(),addr.getOffset(),sz);
    }
    query.str(spaceName);
    query.u(offset);
    query.u(addrSize);
    query.u(wordOffset);
    query.str(regName);
    int8 start = 0;
    bool unusual = false;
    bool stackLocal = false;
    ScopeLocal *local = dynamic_cast<ScopeLocal *>(scope);
    if (local != (ScopeLocal *)0 && !addr.isInvalid()) stackLocal = local->romwrightStackNaming(addr,flags,start,unusual);
    query.flag(stackLocal);
    query.s(start);
    query.flag(unusual);
  }
  string answer = arch->romwrightStructureQuery(query.data);
  if (answer.size() == 0 || answer[0] != 'o') return false;
  string rest = answer.substr(1);
  RomwrightIrReader reader(rest);
  int4 newBase = (int4)reader.u();
  uint8 n = reader.u();
  if (n != todo.size()) throw LowlevelError("Names answer has the wrong length");
  for(uint8 i=0;i<n;++i) {
    bool unique = reader.u() != 0;
    uint8 len = reader.u();
    string name;
    for(uint8 k=0;k<len;++k) name.push_back((char)reader.u());
    Symbol *sym = todo[i]->getHigh()->getSymbol();
    Scope *scope = sym->getScope();
    scope->renameSymbol(sym,unique ? scope->makeNameUnique(name) : name);
  }
  base = newBase;
  return true;
}

/// The stock actions the worker's decisions replace, in the pipeline's order (coreaction.cc).
class RomwrightMergeStock {
  ActionMergeRequired required;
  ActionMarkExplicit markExplicit;
  ActionMarkImplied markImplied;
  ActionMergeMultiEntry multiEntry;
  ActionMergeCopy mergeCopy;
  ActionDominantCopy dominantCopy;
  ActionDynamicSymbols dynamic;
  ActionMarkIndirectOnly indirectOnly;
  ActionMergeAdjacent adjacent;
  ActionMergeType mergeType;
  ActionHideShadow hideShadow;
  ActionCopyMarker copyMarker;
public:
  RomwrightMergeStock(const string &g) : required(g),markExplicit(g),markImplied(g),multiEntry(g),mergeCopy(g),dominantCopy(g),
					 dynamic(g),indirectOnly(g),adjacent(g),mergeType(g),hideShadow(g),copyMarker(g) {}
  void apply(Funcdata &data) {
    required.apply(data);
    markExplicit.apply(data);
    markImplied.apply(data);
    multiEntry.apply(data);
    mergeCopy.apply(data);
    dominantCopy.apply(data);
    dynamic.apply(data);
    indirectOnly.apply(data);
    adjacent.apply(data);
    mergeType.apply(data);
    hideShadow.apply(data);
    copyMarker.apply(data);
  }
};

/// ActionMergeRequired .. ActionCopyMarker, decided by the worker per function.
class RomwrightMerge : public Action {
  RomwrightMergeStock stock;
public:
  RomwrightMerge(const string &g) : Action(rule_onceperfunc,"romwrightmerge",g), stock(g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new RomwrightMerge(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    RomwrightFunctionState &state(romwrightStates()[&data]);
    state.mergeOwned = false;
    ArchitectureGhidra *arch = dynamic_cast<ArchitectureGhidra *>(data.getArch());
    PrintC *print = dynamic_cast<PrintC *>(data.getArch()->print);
    string answer("n");
    vector<const PcodeOp *> ops;
    vector<const Varnode *> vns;
    if (arch != (ArchitectureGhidra *)0 && print != (PrintC *)0) {
      try {
	list<PcodeOp *>::const_iterator oiter;
	for(oiter=data.beginOpAlive();oiter!=data.endOpAlive();++oiter) ops.push_back(*oiter);
	VarnodeLocSet::const_iterator viter;
	for(viter=data.beginLoc();viter!=data.endLoc();++viter) vns.push_back(*viter);
	ScopeLocal *local = data.getScopeLocal();
	bool multi = local->beginMultiEntry() != local->endMultiEntry();
	bool dyn = local->beginDynamic() != local->endDynamic();
	RomwrightIrBytes query;
	RomwrightPrintIrExport exporter(print,data,query);
	exporter.mergeQuery(ops,vns,state.loopCandidates,multi,dyn);
	answer = arch->romwrightStructureQuery(query.data);
      }
      catch(LowlevelError &err) {
	answer = "n";
      }
    }
    if (answer.size() > 0 && answer[0] == 'o') {
      romwrightMergeReplay(data,ops,vns,answer.substr(1));
      state.mergeOwned = true;
      return 0;
    }
    bool verify = answer.size() > 0 && answer[0] == 'v';
    // The decompiler's own actions: the for-loop moves (deferred from ActionStructureTransform), then the merge.
    romwrightLoopTransform(data);
    stock.apply(data);
    if (verify) {
      romwrightLoopFinalize(data);
      state.mergeOwned = true;
      try { arch->romwrightStructureQuery(romwrightMergeDump(data)); }
      catch(LowlevelError &err) { }
    }
    return 0;
  }
};

}
#endif
