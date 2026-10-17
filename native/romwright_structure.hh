#ifndef ROMWRIGHT_STRUCTURE_HH
#define ROMWRIGHT_STRUCTURE_HH
// Block structuring moves to Rust (crates/romwright-worker/src/printc/collapse,
// docs/printer-ir.md "Unstructured handoff").
//
// By default ghidra_opt no longer builds the structured block tree: the
// actions that did (ActionBlockStructure, ActionPreferComplement,
// ActionFinalStructure) leave the basic-block graph as it is, and
// romwrightEncodePrintIr exports that graph for the worker to structure.
// Two places in the pipeline used the tree to change the p-code and still do:
//
//   * ActionReturnSplit splits a return block's in-edges that structuring
//     would have turned into gotos. It asks the worker, which structures the
//     current graph (romwrightReturnSplitSlots, the "romwright_structure"
//     query), and splits the edges it names.
//   * ActionStructureTransform moves for-loop initializer and iterator ops
//     into place before variables merge (BlockWhileDo::finalTransform). The
//     loops are found on the basic-block graph itself (romwrightLoopTransform).
//
// Stage 3 (romwright_merge.hh, docs/merge-port.md): by default the worker
// also decides these two for-loop moves, with the merge it decides: the
// transform happens inside the worker's decision log and the finalize at its end
// (RomwrightStructureTransform and RomwrightFinalStructure then do nothing for a
// function the worker decided). They run here when ROMWRIGHT_NATIVE_MERGE=1 or
// the worker declines the function.
//
// ROMWRIGHT_NATIVE_STRUCTURE=1 restores the stock path (Ghidra structures
// and the worker uses its tree; the graph is exported too, as it was when
// structuring started, so the worker can structure it and compare);
// =2 is the stock path without ActionPreferComplement, the reference the
// worker's structurer is compared with.
#include "funcdata.hh"
#include "block.hh"
#include "blockaction.hh"
#include "coreaction.hh"
#include "ghidra_arch.hh"
#include "romwright_bytes.hh"
#include <cstdlib>
#include <ctime>
#include <map>

namespace ghidra {

/// 0: the worker structures (default); 1: stock structuring; 2: stock
/// structuring without ActionPreferComplement.
inline int4 romwrightStructureMode(void) {
  static int4 mode = -1;
  if (mode < 0) {
    const char *env = getenv("ROMWRIGHT_NATIVE_STRUCTURE");
    mode = 0;
    if (env != (const char *)0 && env[0] != 0 && !(env[0] == '0' && env[1] == 0))
      mode = (env[0] == '2') ? 2 : 1;
  }
  return mode;
}
inline bool romwrightNativeStructure(void) { return romwrightStructureMode() != 0; }

struct RomwrightEdgeFact {
  int4 block;
  int4 rev;
  uint4 label;
};

/// What the structurer reads of one basic block (printc/collapse.rs `CfgBlock`).
struct RomwrightBlockFact {
  uint4 flags;			///< 0x10 switch, 0x400 goto out of the interior, 0x800 goto into it
  uint4 last;			///< 0 no op, 1 RETURN, 2 CBRANCH, 3 other
  bool fall;			///< the CBRANCH's fall-through is its true branch
  bool complex;			///< BlockBasic::isComplex
  vector<RomwrightEdgeFact> ins;
  vector<RomwrightEdgeFact> outs;
};

/// A for-loop candidate on the basic-block graph: BlockWhileDo's analysis
/// (block.cc `finalTransform`, `finalizePrinting`) without the structure
/// around it, ported from there.
struct RomwrightLoop {
  int4 head;			///< the block holding the loop test
  int4 tail;			///< the block that flows back to it
  PcodeOp *loopDef;		///< MULTIEQUAL merging the loop variable
  PcodeOp *initializeOp;	///< statement used as initializer
  PcodeOp *iterateOp;		///< statement used as iterator
  RomwrightLoop(void) { head = tail = -1; loopDef = initializeOp = iterateOp = (PcodeOp *)0; }
};

/// A condition's split point (FlowBlock::getSplitPoint): nothing, one basic
/// block's CBRANCH, or two conditions joined by && or ||.
struct RomwrightSplit {
  int4 kind;			///< 0 none, 1 basic block, 2 condition
  int4 block;
  int4 left;			///< index in the pool, for a condition
  int4 right;
};

/// What the cast phase reads of one varnode, read before anything probes the
/// function (the exporter's probes -- PrintC's own handlers -- update lazily
/// evaluated state: a HighVariable's type may change under them).
struct RomwrightNodeFact {
  const Datatype *high;		///< getHighTypeReadFacing / getHighTypeDefFacing
  const Datatype *own;		///< getTypeReadFacing / getTypeDefFacing
  uint4 flags;			///< RomwrightPrintIrExport::nodeFlags (+16 sole reader is a RETURN, +32 implied: outputs only)
  RomwrightNodeFact(void) : high((const Datatype *)0), own((const Datatype *)0), flags(0) {}
};

/// What the cast phase reads of one op.
struct RomwrightOpFact {
  bool hasOut;
  RomwrightNodeFact out;
  const Datatype *outLocal;		///< PcodeOp::outputTypeLocal
  const Datatype *token;		///< getOutputToken (PTRSUB, SUBPIECE)
  bool matching;			///< PTRSUB: its input's type still fits
  vector<const Datatype *> locals;	///< inputTypeLocal per slot
  RomwrightOpFact(void) : hasOut(false), outLocal((const Datatype *)0), token((const Datatype *)0), matching(true) {}
};

struct RomwrightCastFacts {
  bool valid;
  map<pair<const Varnode *,const PcodeOp *>,RomwrightNodeFact> reads;
  map<const Varnode *,RomwrightNodeFact> defs;
  map<const PcodeOp *,RomwrightOpFact> ops;
  RomwrightCastFacts(void) : valid(false) {}
  void clear(void) { valid = false; reads.clear(); defs.clear(); ops.clear(); }
};

struct RomwrightFunctionState {
  vector<RomwrightBlockFact> facts;	///< the graph when structuring last started
  map<int4,vector<int4> > returnSlots;	///< the worker's answer for ActionReturnSplit, by return block
  vector<RomwrightSplit> splitPool;	///< the split points of the worker's `if`/`else` blocks
  vector<int4> splits;			///< each `if`/`else`'s split point in the pool, for ActionPreferComplement
  vector<int4> preferred;		///< the `if`/`else` blocks (by position in splits) complemented in place
  vector<int4> loopCandidates;		///< the worker's `while` loops, inner first: head, test block and tail (three each)
  vector<RomwrightLoop> loops;
  RomwrightCastFacts castFacts;		///< the cast phase's inputs, read before the first probe
  bool castsPending;			///< the cast action left this function's casts to the worker (decided in romwrightFinishCasts)
  bool mergeOwned;			///< the worker decided this function's merge, explicit/implied marking and for-loop moves (romwright_merge.hh)
  RomwrightFunctionState(void) : castsPending(false), mergeOwned(false) {}
  void clearLoops(void) { loops.clear(); }
};

inline map<const Funcdata *,RomwrightFunctionState> &romwrightStates(void) {
  static map<const Funcdata *,RomwrightFunctionState> states;
  return states;
}

/// The edge flags the structurer reads: goto (or irreducible), loop, default and back edge.
inline uint4 romwrightEdgeLabel(const FlowBlock *bl,int4 out) {
  return (bl->isGotoOut(out) ? 1 : 0) | (bl->isLoopOut(out) ? 2 : 0) | (bl->isDefaultBranch(out) ? 4 : 0) |
    (bl->isBackEdgeOut(out) ? 0x80 : 0);
}

inline void romwrightCaptureBlock(const BlockBasic *bb,RomwrightBlockFact &fact) {
  fact.flags = (bb->isSwitchOut() ? 0x10 : 0) | (bb->hasInteriorGoto() ? 0x400 : 0) | (bb->isInteriorGotoTarget() ? 0x800 : 0);
  const PcodeOp *last = bb->lastOp();
  fact.last = last == (const PcodeOp *)0 ? 0 : (last->code() == CPUI_RETURN ? 1 : (last->code() == CPUI_CBRANCH ? 2 : 3));
  fact.fall = last != (const PcodeOp *)0 && last->code() == CPUI_CBRANCH && last->isFallthruTrue();
  fact.complex = bb->isComplex();
  fact.ins.clear();
  fact.outs.clear();
  for(int4 i=0;i<bb->sizeIn();++i) {
    const FlowBlock *src = bb->getIn(i);
    RomwrightEdgeFact edge;
    edge.block = src->getIndex();
    edge.rev = bb->getInRevIndex(i);
    edge.label = romwrightEdgeLabel(src,edge.rev);
    fact.ins.push_back(edge);
  }
  for(int4 i=0;i<bb->sizeOut();++i) {
    RomwrightEdgeFact edge;
    edge.block = bb->getOut(i)->getIndex();
    edge.rev = bb->getOutRevIndex(i);
    edge.label = romwrightEdgeLabel(bb,i);
    fact.outs.push_back(edge);
  }
}

/// The shape record of printc/ir.rs `Reader::cfg` up to the block's label.
inline void romwrightEncodeShape(RomwrightIrBytes &out,const RomwrightBlockFact &fact,const PcodeOp *last,bool flipped) {
  out.u(fact.flags);
  out.u(fact.last);
  out.op(last);
  out.flag(fact.fall);
  out.flag(fact.complex);
  out.flag(flipped);
  out.u(fact.ins.size());
  for(size_t i=0;i<fact.ins.size();++i) {
    out.s(fact.ins[i].block);
    out.u(fact.ins[i].rev);
    out.u(fact.ins[i].label);
  }
  out.u(fact.outs.size());
  for(size_t i=0;i<fact.outs.size();++i) {
    out.s(fact.outs[i].block);
    out.u(fact.outs[i].rev);
    out.u(fact.outs[i].label);
  }
}

/// Remember the graph as structuring starts: what `isComplex` and the
/// condition polarities were when Ghidra's own structurer would have run.
inline void romwrightSnapshotStructure(Funcdata &data) {
  RomwrightFunctionState &state(romwrightStates()[&data]);
  const BlockGraph &graph(data.getBasicBlocks());
  state.facts.assign(graph.getSize(),RomwrightBlockFact());
  for(int4 i=0;i<graph.getSize();++i)
    romwrightCaptureBlock((const BlockBasic *)graph.getBlock(i),state.facts[i]);
}

/// Reads one split point of the worker's answer (pre-order) into the pool.
inline int4 romwrightReadSplit(RomwrightIrReader &reader,vector<RomwrightSplit> &pool,int4 blocks) {
  RomwrightSplit split;
  split.kind = (int4)reader.u();
  split.block = -1;
  split.left = split.right = -1;
  if (split.kind == 1) {
    split.block = (int4)reader.u();
    if (split.block >= blocks) throw LowlevelError("Structuring answer names a missing block");
  }
  else if (split.kind == 2) {
    split.left = romwrightReadSplit(reader,pool,blocks);
    split.right = romwrightReadSplit(reader,pool,blocks);
  }
  else if (split.kind != 0)
    throw LowlevelError("Structuring answer has a bad split point");
  pool.push_back(split);
  return (int4)pool.size() - 1;
}

/// BlockCondition::flipInPlaceTest and BlockBasic::flipInPlaceTest over a split point.
inline int4 romwrightFlipTest(const BlockGraph &graph,const vector<RomwrightSplit> &pool,int4 at,vector<PcodeOp *> &fliplist) {
  const RomwrightSplit &split(pool[at]);
  if (split.kind == 1)
    return ((const BlockBasic *)graph.getBlock(split.block))->flipInPlaceTest(fliplist);
  if (split.kind != 2) return 2;
  if (pool[split.left].kind == 0 || pool[split.right].kind == 0) return 2;
  int4 subtest1 = romwrightFlipTest(graph,pool,split.left,fliplist);
  if (subtest1 == 2) return 2;
  int4 subtest2 = romwrightFlipTest(graph,pool,split.right,fliplist);
  if (subtest2 == 2) return 2;
  return subtest1;
}

inline void romwrightFlipExecute(const BlockGraph &graph,const vector<RomwrightSplit> &pool,int4 at) {
  const RomwrightSplit &split(pool[at]);
  if (split.kind == 1)
    ((BlockBasic *)graph.getBlock(split.block))->flipInPlaceExecute();
  else if (split.kind == 2) {
    romwrightFlipExecute(graph,pool,split.left);
    romwrightFlipExecute(graph,pool,split.right);
  }
}

/// ActionPreferComplement without the structure: BlockIf::preferComplement for
/// each `if`/`else` the worker's structure has. The worker swaps the arms of the
/// ones this changed (the export lists them).
inline int4 romwrightPreferComplement(Funcdata &data) {
  RomwrightFunctionState &state(romwrightStates()[&data]);
  const BlockGraph &graph(data.getBasicBlocks());
  int4 changed = 0;
  state.preferred.clear();
  for(size_t i=0;i<state.splits.size();++i) {
    vector<PcodeOp *> fliplist;
    if (0 != romwrightFlipTest(graph,state.splitPool,state.splits[i],fliplist)) continue;
    romwrightFlipExecute(graph,state.splitPool,state.splits[i]);
    data.opFlipInPlaceExecute(fliplist);
    state.preferred.push_back((int4)i);
    changed += 1;
  }
  data.clearDeadOps();
  return changed;
}

/// ActionBlockStructure without the structure. The worker structures the
/// graph and answers what Ghidra's structurer would have done to the p-code:
/// negate the conditions it laid out the other way round (`negateCondition`,
/// which RuleCondNegate and the boolean rules turn into the complemented
/// comparison on the next pass), and which return-block edges are gotos.
/// One plain block goes into the structure so the rest of the pipeline sees
/// "structured" until the control flow changes again. Returns the number of
/// conditions negated: ActionBlockStructure's change count.
inline int4 romwrightStructurePlaceholder(Funcdata &data) {
  romwrightSnapshotStructure(data);
  ArchitectureGhidra *arch = dynamic_cast<ArchitectureGhidra *>(data.getArch());
  if (arch == (ArchitectureGhidra *)0)
    throw LowlevelError("Structuring needs the worker's structurer");
  const BlockGraph &graph(data.getBasicBlocks());
  RomwrightFunctionState &state(romwrightStates()[&data]);
  RomwrightIrBytes query;
  query.u(graph.getSize());
  for(int4 i=0;i<graph.getSize();++i)
    romwrightEncodeShape(query,state.facts[i],((const BlockBasic *)graph.getBlock(i))->lastOp(),false);
  string answer = arch->romwrightStructureQuery(query.data);
  RomwrightIrReader reader(answer);
  vector<int4> flips;
  uint8 n = reader.u();
  for(uint8 i=0;i<n;++i) {
    uint8 block = reader.u();
    if (block >= (uint8)graph.getSize())
      throw LowlevelError("Structuring answer names a missing block");
    flips.push_back((int4)block);
  }
  state.returnSlots.clear();
  n = reader.u();
  for(uint8 i=0;i<n;++i) {
    uint8 block = reader.u();
    if (block >= (uint8)graph.getSize())
      throw LowlevelError("Structuring answer names a missing block");
    vector<int4> &slots(state.returnSlots[(int4)block]);
    uint8 k = reader.u();
    for(uint8 j=0;j<k;++j) {
      uint8 slot = reader.u();
      if (slot >= (uint8)graph.getBlock((int4)block)->sizeIn())
	throw LowlevelError("Structuring answer names a missing edge");
      slots.push_back((int4)slot);
    }
  }
  state.splitPool.clear();
  state.splits.clear();
  state.preferred.clear();
  n = reader.u();
  for(uint8 i=0;i<n;++i)
    state.splits.push_back(romwrightReadSplit(reader,state.splitPool,graph.getSize()));
  state.loopCandidates.clear();
  n = reader.u();
  for(uint8 i=0;i<3*n;++i) {
    uint8 block = reader.u();
    if (block >= (uint8)graph.getSize())
      throw LowlevelError("Structuring answer names a missing block");
    state.loopCandidates.push_back((int4)block);
  }
  if (!reader.atEnd())
    throw LowlevelError("Structuring answer has trailing bytes");
  for(size_t i=0;i<flips.size();++i)
    graph.getBlock(flips[i])->negateCondition(true);
  data.getStructure().newBlock();
  return (int4)flips.size();
}

/// BlockWhileDo::findLoopVariable
inline void romwrightFindLoopVariable(RomwrightLoop &loop,PcodeOp *cbranch,BlockBasic *head,BlockBasic *tail,PcodeOp *lastOp) {
  Varnode *vn = cbranch->getIn(1);
  if (!vn->isWritten()) return;
  PcodeOp *op = vn->getDef();
  int4 slot = tail->getOutRevIndex(0);
  PcodeOpNode path[4];
  int4 count = 0;
  if (op->isCall() || op->isMarker()) return;
  path[0].op = op;
  path[0].slot = 0;
  while(count>=0) {
    PcodeOp *curOp = path[count].op;
    int4 ind = path[count].slot++;
    if (ind >= curOp->numInput()) {
      count -= 1;
      continue;
    }
    Varnode *nextVn = curOp->getIn(ind);
    if (!nextVn->isWritten()) continue;
    PcodeOp *defOp = nextVn->getDef();
    if (defOp->code() == CPUI_MULTIEQUAL) {
      if (defOp->getParent() != head) continue;
      Varnode *itvn = defOp->getIn(slot);
      if (!itvn->isWritten()) continue;
      PcodeOp *possibleIterate = itvn->getDef();
      if (possibleIterate->getParent() == tail) {
	if (possibleIterate->isMarker()) continue;
	if (!possibleIterate->isMoveable(lastOp)) continue;
	loop.loopDef = defOp;
	loop.iterateOp = possibleIterate;
	return;
      }
    }
    else {
      if (count == 3) continue;
      if (defOp->isCall() || defOp->isMarker()) continue;
      count += 1;
      path[count].op = defOp;
      path[count].slot = 0;
    }
  }
}

/// BlockWhileDo::findInitializer
inline PcodeOp *romwrightFindInitializer(RomwrightLoop &loop,BlockBasic *head,int4 slot) {
  if (head->sizeIn() != 2) return (PcodeOp *)0;
  slot = 1 - slot;
  Varnode *initVn = loop.loopDef->getIn(slot);
  if (!initVn->isWritten()) return (PcodeOp *)0;
  PcodeOp *res = initVn->getDef();
  if (res->isMarker()) return (PcodeOp *)0;
  FlowBlock *initialBlock = res->getParent();
  if (initialBlock != head->getIn(slot)) return (PcodeOp *)0;
  PcodeOp *lastOp = initialBlock->lastOp();
  if (lastOp == (PcodeOp *)0) return (PcodeOp *)0;
  if (initialBlock->sizeOut() != 1) return (PcodeOp *)0;
  if (lastOp->isBranch()) {
    lastOp = lastOp->previousOp();
    if (lastOp == (PcodeOp *)0) return (PcodeOp *)0;
  }
  loop.initializeOp = res;
  return lastOp;
}

/// BlockWhileDo::testTerminal
inline PcodeOp *romwrightTestTerminal(Funcdata &data,const RomwrightLoop &loop,int4 slot) {
  Varnode *vn = loop.loopDef->getIn(slot);
  if (!vn->isWritten()) return (PcodeOp *)0;
  PcodeOp *finalOp = vn->getDef();
  BlockBasic *parentBlock = (BlockBasic *)loop.loopDef->getParent()->getIn(slot);
  PcodeOp *resOp = finalOp;
  if (finalOp->code() == CPUI_COPY && finalOp->notPrinted()) {
    vn = finalOp->getIn(0);
    if (!vn->isWritten()) return (PcodeOp *)0;
    resOp = vn->getDef();
    if (resOp->getParent() != parentBlock) return (PcodeOp *)0;
  }
  if (!vn->isExplicit()) return (PcodeOp *)0;
  if (resOp->notPrinted()) return (PcodeOp *)0;
  PcodeOp *lastOp = finalOp->getParent()->lastOp();
  if (lastOp->isBranch()) lastOp = lastOp->previousOp();
  if (!data.moveRespectingCover(finalOp,lastOp)) return (PcodeOp *)0;
  return resOp;
}

/// BlockWhileDo::testIterateForm
inline bool romwrightTestIterateForm(const RomwrightLoop &loop) {
  Varnode *targetVn = loop.loopDef->getOut();
  HighVariable *high = targetVn->getHigh();
  vector<PcodeOpNode> path;
  path.push_back(PcodeOpNode(loop.iterateOp,0));
  while(!path.empty()) {
    PcodeOpNode &node(path.back());
    if (node.op->numInput() <= node.slot) {
      path.pop_back();
      continue;
    }
    Varnode *vn = node.op->getIn(node.slot);
    node.slot += 1;
    if (vn->isAnnotation()) continue;
    if (vn->getHigh() == high) return true;
    if (vn->isExplicit()) continue;
    if (!vn->isWritten()) continue;
    path.push_back(PcodeOpNode(vn->getDef(),0));
  }
  return false;
}

/// ActionStructureTransform without the structure: BlockWhileDo::finalTransform
/// for the `while` loops the worker's structure has (inner ones first).
inline void romwrightLoopTransform(Funcdata &data) {
  RomwrightFunctionState &state(romwrightStates()[&data]);
  state.clearLoops();
  if (!data.getArch()->analyze_for_loops) return;
  const BlockGraph &graph(data.getBasicBlocks());
  for(size_t c=0;c+2<state.loopCandidates.size();c+=3) {
    BlockBasic *head = (BlockBasic *)graph.getBlock(state.loopCandidates[c]);
    PcodeOp *cbranch = ((BlockBasic *)graph.getBlock(state.loopCandidates[c+1]))->lastOp();
    BlockBasic *tail = (BlockBasic *)graph.getBlock(state.loopCandidates[c+2]);
    if (cbranch == (PcodeOp *)0 || cbranch->code() != CPUI_CBRANCH) continue;
    PcodeOp *lastOp = tail->lastOp();	// there must be a last op in the body, for an iterator statement
    if (lastOp == (PcodeOp *)0) continue;
    if (tail->sizeOut() != 1) continue;
    if (tail->getOut(0) != head) continue;
    if (lastOp->isBranch()) {
      lastOp = lastOp->previousOp();
      if (lastOp == (PcodeOp *)0) continue;
    }
    RomwrightLoop loop;
    loop.head = head->getIndex();
    loop.tail = tail->getIndex();
    romwrightFindLoopVariable(loop,cbranch,head,tail,lastOp);
    if (loop.iterateOp == (PcodeOp *)0) continue;
    if (loop.iterateOp != lastOp) {
      data.opUninsert(loop.iterateOp);
      data.opInsertAfter(loop.iterateOp,lastOp);
    }
    lastOp = romwrightFindInitializer(loop,head,tail->getOutRevIndex(0));
    if (lastOp != (PcodeOp *)0) {
      if (!loop.initializeOp->isMoveable(lastOp)) {
	loop.initializeOp = (PcodeOp *)0;
      }
      else if (loop.initializeOp != lastOp) {
	data.opUninsert(loop.initializeOp);
	data.opInsertAfter(loop.initializeOp,lastOp);
      }
    }
    state.loops.push_back(loop);
  }
}

/// ActionFinalStructure without the structure: the for-loop tests that need
/// the merged variables (BlockWhileDo::finalizePrinting).
inline void romwrightLoopFinalize(Funcdata &data) {
  RomwrightFunctionState &state(romwrightStates()[&data]);
  vector<RomwrightLoop> kept;
  for(size_t i=0;i<state.loops.size();++i) {
    RomwrightLoop &loop(state.loops[i]);
    int4 slot = loop.iterateOp->getParent()->getOutRevIndex(0);
    loop.iterateOp = romwrightTestTerminal(data,loop,slot);
    if (loop.iterateOp == (PcodeOp *)0) continue;
    if (!romwrightTestIterateForm(loop)) continue;
    if (loop.initializeOp == (PcodeOp *)0)
      romwrightFindInitializer(loop,loop.loopDef->getParent(),slot);
    if (loop.initializeOp != (PcodeOp *)0)
      loop.initializeOp = romwrightTestTerminal(data,loop,1-slot);
    // As Ghidra does, so the loops after this one see these statements as
    // not printed; they are printed again below.
    data.opMarkNonPrinting(loop.iterateOp);
    if (loop.initializeOp != (PcodeOp *)0) data.opMarkNonPrinting(loop.initializeOp);
    kept.push_back(loop);
  }
  // The statements stay exported: the worker takes them out of their blocks
  // when its structure prints the loop as a `for`, and leaves them where they
  // are when it does not.
  for(size_t i=0;i<kept.size();++i) {
    data.opMarkPrinting(kept[i].iterateOp);
    if (kept[i].initializeOp != (PcodeOp *)0) data.opMarkPrinting(kept[i].initializeOp);
  }
  state.loops.swap(kept);
}

/// ActionReturnSplit's edges: what the worker answered when the current
/// structure was (not) built, for each candidate return block.
inline void romwrightReturnSplitSlots(Funcdata &data,const vector<BlockBasic *> &candidates,vector<vector<int4> > &slots) {
  slots.assign(candidates.size(),vector<int4>());
  const RomwrightFunctionState &state(romwrightStates()[&data]);
  for(size_t i=0;i<candidates.size();++i) {
    map<int4,vector<int4> >::const_iterator it = state.returnSlots.find(candidates[i]->getIndex());
    if (it != state.returnSlots.end()) slots[i] = it->second;
  }
}

/// ActionBlockStructure when the worker structures: see romwrightStructurePlaceholder.
class RomwrightBlockStructure : public Action {
public:
  RomwrightBlockStructure(const string &g) : Action(0,"blockstructure",g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new RomwrightBlockStructure(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    if (data.getStructure().getSize() != 0) return 0;	// Already structured
    data.installSwitchDefaults();
    count += romwrightStructurePlaceholder(data);
    return 0;
  }
};

/// Stock ActionBlockStructure, noting the graph it structures (the worker's
/// structurer is given the same graph to compare with).
class RomwrightNativeBlockStructure : public ActionBlockStructure {
public:
  RomwrightNativeBlockStructure(const string &g) : ActionBlockStructure(g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new RomwrightNativeBlockStructure(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    if (data.getStructure().getSize() == 0) {
      data.installSwitchDefaults();
      romwrightSnapshotStructure(data);
    }
    return ActionBlockStructure::apply(data);
  }
};

/// ActionPreferComplement: the worker's if/else blocks (mode 0), or nothing (mode 2).
class RomwrightPreferComplement : public Action {
public:
  RomwrightPreferComplement(const string &g) : Action(0,"prefercomplement",g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new RomwrightPreferComplement(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    if (data.getStructure().getSize() == 0) return 0;
    if (romwrightStructureMode() == 0) count += romwrightPreferComplement(data);
    return 0;
  }
};

/// 0: the worker decides the casts, function by function (default); 1: ActionSetCasts (ROMWRIGHT_NATIVE_CASTS).
inline int4 romwrightCastsMode(void) {
  static int4 mode = -1;
  if (mode < 0) {
    const char *env = getenv("ROMWRIGHT_NATIVE_CASTS");
    mode = (env != (const char *)0 && env[0] != 0 && !(env[0] == '0' && env[1] == 0)) ? 1 : 0;
  }
  return mode;
}

/// 0: the worker decides the merge (default); 1: the decompiler's merge actions (ROMWRIGHT_NATIVE_MERGE).
inline int4 romwrightMergeMode(void) {
  static int4 mode = -1;
  if (mode < 0) {
    const char *env = getenv("ROMWRIGHT_NATIVE_MERGE");
    mode = (env != (const char *)0 && env[0] != 0 && !(env[0] == '0' && env[1] == 0)) ? 1 : 0;
  }
  return mode;
}

/// Stage 3 (docs/merge-port.md) runs when the worker structures and casts too: its for-loop tests read the
/// pre-cast p-code, which is the input of the worker's casts only.
inline bool romwrightMergeActive(void) {
  return romwrightMergeMode() == 0 && !romwrightNativeStructure() && romwrightCastsMode() == 0;
}

/// ActionStructureTransform without the structure.
class RomwrightStructureTransform : public Action {
public:
  RomwrightStructureTransform(const string &g) : Action(0,"structuretransform",g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new RomwrightStructureTransform(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    if (romwrightMergeActive()) return 0;	// the merge action moves them (romwright_merge.hh), with the worker's decisions
    romwrightLoopTransform(data);
    return 0;
  }
};

/// ActionFinalStructure without the structure.
class RomwrightFinalStructure : public Action {
public:
  RomwrightFinalStructure(const string &g) : Action(0,"finalstructure",g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new RomwrightFinalStructure(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    if (romwrightStates()[&data].mergeOwned) return 0;	// decided with the merge
    romwrightLoopFinalize(data);
    return 0;
  }
};

/// ActionReturnSplit, splitting the edges the worker's structure makes gotos
/// (ActionReturnSplit::apply with its structure question answered by the worker).
class RomwrightReturnSplit : public Action {
  /// ActionReturnSplit::isSplittable
  static bool isSplittable(BlockBasic *b) {
    list<PcodeOp *>::const_iterator iter;
    for(iter=b->beginOp();iter!=b->endOp();++iter) {
      PcodeOp *op = *iter;
      OpCode opc = op->code();
      if (opc == CPUI_MULTIEQUAL) continue;
      if ((opc == CPUI_COPY)||(opc == CPUI_RETURN)) {
	for(int4 i=0;i<op->numInput();++i) {
	  if (op->getIn(i)->isConstant()) continue;
	  if (op->getIn(i)->isAnnotation()) continue;
	  if (op->getIn(i)->isFree()) return false;
	}
	continue;
      }
      return false;
    }
    return true;
  }
public:
  RomwrightReturnSplit(const string &g) : Action(0,"returnsplit",g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new RomwrightReturnSplit(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    if (data.getStructure().getSize() == 0)
      return 0;			// Some other restructuring happened first
    vector<BlockBasic *> candidates;
    list<PcodeOp *>::const_iterator iter,iterend;
    iterend = data.endOp(CPUI_RETURN);
    for(iter=data.beginOp(CPUI_RETURN);iter!=iterend;++iter) {
      PcodeOp *op = *iter;
      if (op->isDead()) continue;
      BlockBasic *parent = op->getParent();
      if (parent->sizeIn() <= 1) continue;
      if (!isSplittable(parent)) continue;
      candidates.push_back(parent);
    }
    vector<vector<int4> > slots;
    romwrightReturnSplitSlots(data,candidates,slots);
    vector<int4> splitedge;
    vector<BlockBasic *> retnode;
    for(size_t i=0;i<candidates.size();++i) {
      for(size_t j=0;j<slots[i].size();++j) {
	splitedge.push_back(slots[i][j]);
	retnode.push_back(candidates[i]);
      }
    }
    for(size_t i=0;i<splitedge.size();++i) {
      data.nodeSplit(retnode[i],splitedge[i]);
      count += 1;
    }
    return 0;
  }
};

/// The structuring actions the pipeline is built with (coreaction.cc): the
/// worker's when it structures, otherwise Ghidra's.
inline Action *romwrightBlockStructure(const string &g) {
  if (romwrightNativeStructure()) return new RomwrightNativeBlockStructure(g);
  return new RomwrightBlockStructure(g);
}
inline Action *romwrightMakePreferComplement(const string &g) {
  if (romwrightStructureMode() == 1) return new ActionPreferComplement(g);
  return new RomwrightPreferComplement(g);
}
inline Action *romwrightStructureTransform(const string &g) {
  if (romwrightNativeStructure()) return new ActionStructureTransform(g);
  return new RomwrightStructureTransform(g);
}
inline Action *romwrightFinalStructure(const string &g) {
  if (romwrightNativeStructure()) return new ActionFinalStructure(g);
  return new RomwrightFinalStructure(g);
}
inline Action *romwrightReturnSplit(const string &g) {
  if (romwrightNativeStructure()) return new ActionReturnSplit(g);
  return new RomwrightReturnSplit(g);
}

/// What ActionInferTypes costs one function (docs/types-port.md, stage 2b): how
/// often the mainloop ran it, and how big the data-flow graph was each time
/// (what a per-iteration type query to the worker would have to carry).
struct RomwrightInferStats {
  int4 calls;			///< applications that did work (type recovery started)
  int8 micros;			///< time spent in them
  int8 sumOps;			///< alive ops, summed over the calls
  int8 sumVarnodes;		///< varnodes, summed over the calls
  int4 lastOps;
  int4 lastVarnodes;
  RomwrightInferStats(void) : calls(0), micros(0), sumOps(0), sumVarnodes(0), lastOps(0), lastVarnodes(0) {}
};

inline map<const Funcdata *,RomwrightInferStats> &romwrightInferStats(void) {
  static map<const Funcdata *,RomwrightInferStats> stats;
  return stats;
}

/// ActionInferTypes, counted. The decompiler's own propagation runs unchanged.
class RomwrightInferTypes : public ActionInferTypes {
public:
  RomwrightInferTypes(const string &g) : ActionInferTypes(g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new RomwrightInferTypes(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    if (getenv("ROMWRIGHT_INFER_LOG") == (const char *)0 || !data.hasTypeRecoveryStarted())
      return ActionInferTypes::apply(data);
    RomwrightInferStats &stats(romwrightInferStats()[&data]);
    int4 ops = 0;
    list<PcodeOp *>::const_iterator oiter;
    for(oiter=data.beginOpAlive();oiter!=data.endOpAlive();++oiter) ops += 1;
    int4 varnodes = 0;
    VarnodeLocSet::const_iterator viter;
    for(viter=data.beginLoc();viter!=data.endLoc();++viter) varnodes += 1;
    struct timespec before,after;
    clock_gettime(CLOCK_MONOTONIC,&before);
    int4 res = ActionInferTypes::apply(data);
    clock_gettime(CLOCK_MONOTONIC,&after);
    stats.calls += 1;
    stats.micros += (int8)(after.tv_sec - before.tv_sec) * 1000000 + (after.tv_nsec - before.tv_nsec) / 1000;
    stats.sumOps += ops;
    stats.sumVarnodes += varnodes;
    stats.lastOps = ops;
    stats.lastVarnodes = varnodes;
    return res;
  }
};
inline Action *romwrightInferTypes(const string &g) { return new RomwrightInferTypes(g); }

/// ActionSetCasts without the casts: marks the function as awaiting the
/// worker's decision (romwrightFinishCasts, romwright_printir.hh), which
/// runs before the p-code is read to print it.
class RomwrightSetCasts : public Action {
public:
  RomwrightSetCasts(const string &g) : Action(rule_onceperfunc,"setcasts",g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new RomwrightSetCasts(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    data.startCastPhase();
    RomwrightFunctionState &state(romwrightStates()[&data]);
    state.castsPending = true;
    state.castFacts.clear();
    return 0;
  }
};
inline Action *romwrightSetCasts(const string &g) {
  if (romwrightNativeStructure() || romwrightCastsMode() != 0) return new ActionSetCasts(g);
  return new RomwrightSetCasts(g);
}

}
#endif
