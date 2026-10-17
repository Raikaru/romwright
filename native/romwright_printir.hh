#ifndef ROMWRIGHT_PRINTIR_HH
#define ROMWRIGHT_PRINTIR_HH
// Printer IR export for the worker's Rust C printer
// (crates/romwright-worker/src/printc, docs/printer-ir.md).
//
// PrintC's block layer -- statement order, labels, gotos, if/else, loops,
// switch, comments, braces -- moves to Rust. What it reads from the live
// Funcdata is exported here: the structured block tree after ActionFinalStructure
// with every flag PrintC consults, and, for each place PrintC emits an
// expression, declaration, label or comment, the Emit calls PrintC's own
// handlers make for it ("fragments"). Fragments keep casts, field access,
// constants, symbol scoping and token links exactly as PrintC produces them;
// the Rust side replays them through its port of EmitPrettyPrint.
//
// Always exported: the worker prints C from this IR. The element is appended
// after PrintC's own markup, which stays only as the reference the printer
// differential (benchmarks/printer_diff.py) compares against byte for byte.
#include "printc.hh"
#include "funcdata.hh"
#include "comment.hh"
#include "coreaction.hh"
#include "typeop.hh"
#include "romwright_ir_state.hh"
#include "romwright_bytes.hh"
#include "romwright_structure.hh"

namespace ghidra {

// Private document metadata; keep synchronized with printc/ir.rs.
static ElementId ELEM_ROMWRIGHT_PRINTIR("romwright_printir",4091);

/// Expression tree tags (printc/ir.rs `Expr`).
enum {
  RW_EXPR_OPAQUE = 0, RW_EXPR_CONST = 1, RW_EXPR_VAR = 2, RW_EXPR_OP = 3
};

/// Records every Emit call PrintC makes while one fragment is captured.
/// Open calls return fragment-local ids; the Rust replay maps them.
class RomwrightCaptureEmit : public Emit {
  RomwrightIrBytes *out;
  int4 nextId;
  int4 maxline;
  int4 events;			// Emit calls since capture(): a probe that made one is a single token
  int4 open(uint4 code) { events += 1; out->byte(code); int4 id = nextId++; out->u(id); return id; }
  void close(uint4 code,int4 id) { events += 1; out->byte(code); out->u(id); }
  void named(uint4 code,const string &name,syntax_highlight hl) { events += 1; out->byte(code); out->str(name); out->u(hl); }
public:
  enum {
    begin_document = 1, end_document, begin_function, end_function, begin_block, end_block,
    tag_line, tag_line_indent, begin_return_type, end_return_type, begin_var_decl, end_var_decl,
    begin_statement, end_statement, begin_func_proto, end_func_proto, tag_variable, tag_op,
    tag_func_name, tag_type, tag_field, tag_bit_field, tag_comment, tag_label, tag_case_label,
    print_syntax, open_paren, close_paren, open_group, close_group, emit_spaces, start_indent,
    stop_indent, start_comment, stop_comment
  };
  RomwrightCaptureEmit(int4 maxlinesize) : Emit() { out = (RomwrightIrBytes *)0; nextId = 1; maxline = maxlinesize; events = 0; }
  void capture(RomwrightIrBytes *o) { out = o; nextId = 1; events = 0; }
  int4 eventCount(void) const { return events; }
  virtual int4 beginDocument(void) { return open(begin_document); }
  virtual void endDocument(int4 id) { close(end_document,id); }
  virtual int4 beginFunction(const Funcdata *fd) { return open(begin_function); }
  virtual void endFunction(int4 id) { close(end_function,id); }
  virtual int4 beginBlock(const FlowBlock *bl) { int4 id = open(begin_block); out->s(bl->getIndex()); return id; }
  virtual void endBlock(int4 id) { close(end_block,id); }
  virtual void tagLine(void) { events += 1; out->byte(tag_line); }
  virtual void tagLine(int4 indent) { events += 1; out->byte(tag_line_indent); out->s(indent); }
  virtual int4 beginReturnType(const Varnode *vn) { int4 id = open(begin_return_type); out->vn(vn); return id; }
  virtual void endReturnType(int4 id) { close(end_return_type,id); }
  virtual int4 beginVarDecl(const Symbol *sym) { int4 id = open(begin_var_decl); out->u(sym->getId()); return id; }
  virtual void endVarDecl(int4 id) { close(end_var_decl,id); }
  virtual int4 beginStatement(const PcodeOp *op) { int4 id = open(begin_statement); out->op(op); return id; }
  virtual void endStatement(int4 id) { close(end_statement,id); }
  virtual int4 beginFuncProto(void) { return open(begin_func_proto); }
  virtual void endFuncProto(int4 id) { close(end_func_proto,id); }
  virtual void tagVariable(const string &name,syntax_highlight hl,const Varnode *vn,const PcodeOp *op) {
    named(tag_variable,name,hl); out->vn(vn); out->op(op); }
  virtual void tagOp(const string &name,syntax_highlight hl,const PcodeOp *op) {
    named(tag_op,name,hl); out->op(op); }
  virtual void tagFuncName(const string &name,syntax_highlight hl,const Funcdata *fd,const PcodeOp *op) {
    named(tag_func_name,name,hl); out->op(op); }
  virtual void tagType(const string &name,syntax_highlight hl,const Datatype *ct) {
    named(tag_type,name,hl); out->u(ct->getUnsizedId()); }
  virtual void tagField(const string &name,syntax_highlight hl,const Datatype *ct,int4 off,const PcodeOp *op) {
    named(tag_field,name,hl);
    out->flag(ct != (const Datatype *)0);
    if (ct != (const Datatype *)0) {
      out->str(ct->getName()); out->u(ct->getUnsizedId()); out->s(off); out->op(op);
    }
  }
  virtual void tagBitField(const string &name,syntax_highlight hl,const Datatype *ct,int4 id,const PcodeOp *op) {
    named(tag_bit_field,name,hl); out->str(ct->getName()); out->u(ct->getUnsizedId()); out->s(id); out->op(op); }
  virtual void tagComment(const string &name,syntax_highlight hl,const AddrSpace *spc,uintb off) {
    named(tag_comment,name,hl); out->space(spc); out->u(off); }
  virtual void tagLabel(const string &name,syntax_highlight hl,const AddrSpace *spc,uintb off) {
    named(tag_label,name,hl); out->space(spc); out->u(off); }
  virtual void tagCaseLabel(const string &name,syntax_highlight hl,const PcodeOp *op,uintb value) {
    named(tag_case_label,name,hl); out->op(op); out->u(value); }
  virtual void print(const string &data,syntax_highlight hl=no_color) { named(print_syntax,data,hl); }
  virtual int4 openParen(const string &paren,int4 id=0) { int4 nid = open(open_paren); out->str(paren); return nid; }
  virtual void closeParen(const string &paren,int4 id) { close(close_paren,id); out->str(paren); }
  virtual int4 openGroup(void) { return open(open_group); }
  virtual void closeGroup(int4 id) { close(close_group,id); }
  virtual void setOutputStream(ostream *t) {}
  virtual ostream *getOutputStream(void) const { return (ostream *)0; }
  virtual void spaces(int4 num,int4 bump=0) { events += 1; out->byte(emit_spaces); out->s(num); out->s(bump); }
  virtual int4 startIndent(void) { return open(start_indent); }
  virtual void stopIndent(int4 id) { close(stop_indent,id); }
  virtual int4 startComment(void) { return open(start_comment); }
  virtual void stopComment(int4 id) { close(stop_comment,id); }
  virtual int4 getMaxLineSize(void) const { return maxline; }
  virtual bool emitsMarkup(void) const { return true; }
};

/// Names PrintC's protected members through pointers-to-member of a derived
/// class, which C++ permits; never instantiated.
class RomwrightPrintCAccess : public PrintC {
public:
  static Emit *&emitOf(PrintC *p) { return p->*(&RomwrightPrintCAccess::emit); }
  static uint4 &modsOf(PrintC *p) { return p->*(&RomwrightPrintCAccess::mods); }
  static CommentSorter &sorterOf(PrintC *p) { return p->*(&RomwrightPrintCAccess::commsorter); }
  static uint4 instrComments(PrintC *p) { return p->*(&RomwrightPrintCAccess::instr_comment_type); }
  static uint4 headComments(PrintC *p) { return p->*(&RomwrightPrintCAccess::head_comment_type); }
  static bool unplaced(PrintC *p) { return p->*(&RomwrightPrintCAccess::option_unplaced); }
  static int4 braceFunc(PrintC *p) { return p->*(&RomwrightPrintCAccess::option_brace_func); }
  static int4 braceIfElse(PrintC *p) { return p->*(&RomwrightPrintCAccess::option_brace_ifelse); }
  static int4 braceLoop(PrintC *p) { return p->*(&RomwrightPrintCAccess::option_brace_loop); }
  static int4 braceSwitch(PrintC *p) { return p->*(&RomwrightPrintCAccess::option_brace_switch); }
  static void expression(PrintC *p,const PcodeOp *op) { (p->*(&RomwrightPrintCAccess::emitExpression))(op); }
  static void switchCase(PrintC *p,int4 i,const BlockSwitch *bl) { (p->*(&RomwrightPrintCAccess::emitSwitchCase))(i,bl); }
  /// PrintC::emitSwitchCase for the case block \b target of the switch whose
  /// jump table is \b jump: what it prints depends only on the table, the
  /// target's labels and whether the edge is the default.
  static void switchCaseFor(PrintC *p,const JumpTable *jump,const FlowBlock *target,bool isdefault) {
    Emit *emit = emitOf(p);
    PcodeOp *indop = jump->getIndirectOp();
    const Datatype *ct = indop->getIn(0)->getHighTypeReadFacing(indop);
    const PcodeOp *op = target->firstOp();
    int4 num = jump->numIndicesByBlock(target);
    if (num <= 0) return;
    if (isdefault) {
      uintb val = jump->getLabelByIndex(jump->getIndexByBlock(target,0));
      emit->tagLine();
      emit->tagCaseLabel(KEYWORD_DEFAULT,EmitMarkup::keyword_color,op,val);
      emit->print(COLON);
      return;
    }
    uint4 displayFormat = jump->getDisplayFormat();
    if (displayFormat == 0)
      displayFormat = ct->getDisplayFormat();
    for(int4 i=0;i<num;++i) {
      uintb val = jump->getLabelByIndex(jump->getIndexByBlock(target,i));
      emit->tagLine();
      emit->print(KEYWORD_CASE,EmitMarkup::keyword_color);
      emit->spaces(1);
      (p->*(&RomwrightPrintCAccess::pushConstant))(val,ct,casetoken,(Varnode *)0,op,displayFormat);
      (p->*(&RomwrightPrintCAccess::recurse))();
      emit->print(COLON);
    }
  }
  /// PrintC::emitLabel, except for a block with no operations whose cover is
  /// not a single range: BlockBasic::getEntryAddr then returns an invalid
  /// Address, and emitLabel dereferences its null space (queryCodeLabel,
  /// getShortcut). Ghidra only reaches that for a goto to such a block; the
  /// exporter prints every leaf's label, so it reaches it routinely. Name the
  /// block by the start of its cover (else the function's entry), as
  /// emitLabel names an unlabelled block by its address.
  static void label(PrintC *p,const FlowBlock *bl) {
    const FlowBlock *leaf = bl->getFrontLeaf();
    if (leaf != (const FlowBlock *)0) {
      const BlockBasic *bb = (const BlockBasic *)leaf->subBlock(0);
      if (bb->getEntryAddr().isInvalid()) {
	Address addr = bb->getStart();
	if (addr.isInvalid()) addr = bb->getFuncdata()->getAddress();
	ostringstream lb;
	if (bb->isJoined()) lb << "joined_";
	else if (bb->isDuplicated()) lb << "dup_";
	else lb << "code_";
	lb << addr.getShortcut();
	addr.printRaw(lb);
	emitOf(p)->tagLabel(lb.str(),EmitMarkup::no_color,addr.getSpace(),addr.getOffset());
	return;
      }
    }
    (p->*(&RomwrightPrintCAccess::emitLabel))(bl);
  }
  static void declaration(PrintC *p,const Funcdata *fd) { (p->*(&RomwrightPrintCAccess::emitFunctionDeclaration))(fd); }
  static void locals(PrintC *p,const Funcdata *fd) { (p->*(&RomwrightPrintCAccess::emitLocalVarDecls))(fd); }
  static void header(PrintC *p,const Funcdata *fd) { (p->*(&RomwrightPrintCAccess::emitCommentFuncHeader))(fd); }
  static void lineComment(PrintC *p,int4 indent,const Comment *c) { (p->*(&RomwrightPrintCAccess::emitLineComment))(indent,c); }
  static void leaveScope(PrintC *p) { (p->*(&RomwrightPrintCAccess::popScope))(); }
  // Version 4 (print trees): the options and symbol scope PrintC's expression emission consults.
  static const Scope *curScope(PrintC *p) { return p->*(&RomwrightPrintCAccess::curscope); }
  static int4 namespaces(PrintC *p) { return (int4)(p->*(&RomwrightPrintCAccess::namespc_strategy)); }
  static bool noCasts(PrintC *p) { return p->*(&RomwrightPrintCAccess::option_nocasts); }
  static bool hideExts(PrintC *p) { return p->*(&RomwrightPrintCAccess::option_hide_exts); }
  static bool nullOption(PrintC *p) { return p->*(&RomwrightPrintCAccess::option_NULL); }
  static bool inplaceOps(PrintC *p) { return p->*(&RomwrightPrintCAccess::option_inplace_ops); }
  static const string &suffixOf(PrintC *p) { return p->*(&RomwrightPrintCAccess::sizeSuffix); }
  static void explicitVn(PrintC *p,const Varnode *vn,const PcodeOp *op) { (p->*(&RomwrightPrintCAccess::pushVnExplicit))(vn,op); }
  static void symbolDetail(PrintC *p,const Varnode *vn,const PcodeOp *op,bool isRead) {
    (p->*(&RomwrightPrintCAccess::pushSymbolDetail))(vn,op,isRead); }
  static bool addressOfCast(PrintC *p,const PcodeOp *op) { return (p->*(&RomwrightPrintCAccess::checkAddressOfCast))(op); }
  static int4 hiddenThis(PrintC *p,const PcodeOp *op,FuncProto *fc) { return (p->*(&RomwrightPrintCAccess::getHiddenThisSlot))(op,fc); }
  static void unnamedLocation(PrintC *p,const Address &addr,const Varnode *vn,const PcodeOp *op) {
    (p->*(&RomwrightPrintCAccess::pushUnnamedLocation))(addr,vn,op); }
  static string functionName(PrintC *p,const Address &addr) { return (p->*(&RomwrightPrintCAccess::genericFunctionName))(addr); }
  static string typeName(PrintC *p,const Datatype *ct) { return (p->*(&RomwrightPrintCAccess::genericTypeName))(ct); }
};

class RomwrightPrintIrExport {
  typedef RomwrightPrintCAccess Access;
  PrintC *print;
  const Funcdata &fd;
  RomwrightCaptureEmit capture;
  RomwrightIrBytes &out;
  CommentSorter sorter;		// Placed exactly as docFunction places PrintC's own
  uint4 instr;
  const RomwrightCastFacts *facts;	// the cast phase's inputs as they were before the first probe, when casts are pending
  bool pending;			// casts pending (version 6): print trees are pre-cast, with the data the worker's cast pass reads
  set<int4> sizes;		// varnode sizes seen in pending trees: the core types the cast pass may ask for

  /// Captures what \b emitter emits as one length-prefixed fragment.
  template<typename F> void fragment(F emitter) {
    RomwrightIrBytes bytes;
    capture.capture(&bytes);
    emitter();
    out.str(bytes.data);
  }

  void expression(const PcodeOp *op,bool comma) {
    if (pending) { out.str(string()); return; }	// the worker prints this statement from its print tree
    uint4 &mods(Access::modsOf(print));
    uint4 saved = mods;
    if (comma) mods |= PrintLanguage::comma_separate;
    else mods &= ~(uint4)PrintLanguage::comma_separate;
    fragment([&]() { Access::expression(print,op); });
    mods = saved;
  }

  void label(const FlowBlock *target) {
    out.flag(target != (const FlowBlock *)0);
    if (target != (const FlowBlock *)0)
      fragment([&]() { Access::label(print,target); });
  }

  /// The basic block a structured block starts with (its front leaf's
  /// BlockBasic), as the index the basic-block graph uses; -1 when none.
  static int4 frontBasic(const FlowBlock *bl) {
    const FlowBlock *leaf = bl->getFrontLeaf();
    if (leaf == (const FlowBlock *)0 || leaf->subBlock(0) == (const FlowBlock *)0) return -1;
    return leaf->subBlock(0)->getIndex();
  }

  /// A goto's target: its front basic block and the label PrintC prints.
  void target(const FlowBlock *bl) {
    out.flag(bl != (const FlowBlock *)0);
    if (bl != (const FlowBlock *)0) {
      out.s(frontBasic(bl));
      fragment([&]() { Access::label(print,bl); });
    }
  }

  /// for-loop initializer and iterator ops: not printed in their basic
  /// block, so a copy of that block placed elsewhere would lose them.
  set<const PcodeOp *> loopOps;
  /// A for-loop the decompiler found: where it sits on the basic-block graph
  /// and the ops it takes out of their blocks.
  struct LoopRec {
    int4 head;
    int4 tail;
    const PcodeOp *init;
    const PcodeOp *iterate;
  };
  vector<LoopRec> loopRecs;
  void addLoop(int4 head,int4 tail,const PcodeOp *init,const PcodeOp *iterate) {
    if (init == (const PcodeOp *)0 && iterate == (const PcodeOp *)0) return;
    LoopRec rec;
    rec.head = head;
    rec.tail = tail;
    rec.init = init;
    rec.iterate = iterate;
    loopRecs.push_back(rec);
    if (!romwrightNativeStructure()) return;	// the worker decides which loops print as for loops
    if (init != (const PcodeOp *)0) loopOps.insert(init);
    if (iterate != (const PcodeOp *)0) loopOps.insert(iterate);
  }
  /// Stock structuring: the loops of its tree.
  void collectLoopOps(const FlowBlock *bl) {
    FlowBlock::block_type type = bl->getType();
    if (type == FlowBlock::t_basic || type == FlowBlock::t_plain || type == FlowBlock::t_copy) return;
    const BlockGraph *graph = (const BlockGraph *)bl;
    if (type == FlowBlock::t_whiledo) {
      const BlockWhileDo *loop = (const BlockWhileDo *)bl;
      const PcodeOp *bodyLast = graph->getSize() > 1 ? graph->getBlock(1)->lastOp() : (const PcodeOp *)0;
      addLoop(frontBasic(bl),bodyLast != (const PcodeOp *)0 ? bodyLast->getParent()->getIndex() : -1,loop->getInitializeOp(),loop->getIterateOp());
    }
    for(int4 i=0;i<graph->getSize();++i)
      collectLoopOps(graph->getBlock(i));
  }
  /// The worker structures: the loops its for-loop transform set up.
  void collectLoopOpsFromState(void) {
    map<const Funcdata *,RomwrightFunctionState>::const_iterator it = romwrightStates().find(&fd);
    if (it == romwrightStates().end()) return;
    for(size_t i=0;i<it->second.loops.size();++i)
      addLoop(it->second.loops[i].head,it->second.loops[i].tail,it->second.loops[i].initializeOp,it->second.loops[i].iterateOp);
  }

  /// The CBRANCH's condition as PrintC prints its negation (booleanflip:
  /// a negated comparison token or `!`), flipping the op only meanwhile.
  void negated(const PcodeOp *op) {
    Funcdata &data(const_cast<Funcdata &>(fd));
    PcodeOp *mutableOp = const_cast<PcodeOp *>(op);
    data.opFlipCondition(mutableOp);
    try {
      expression(op,false);
      out.flag(true);
      expression(op,true);
    }
    catch(...) {
      data.opFlipCondition(mutableOp);
      throw;
    }
    data.opFlipCondition(mutableOp);
  }

  // Version 3: expression trees. A printed expression is an RPN tree of
  // opcodes over varnodes; here the same tree is exported structurally so
  // Rust passes can compare, negate and propagate conditions. An implied
  // varnode expands to its defining op (PrintC prints it inline); an explicit
  // one is a leaf naming its SSA value (createIndex) and its HighVariable (the
  // C variable the printer names). `treeCalls` / `treeStores` record whether
  // the walked expression may change memory.
  map<const HighVariable *,uint4> highIds;
  RomwrightIrBytes *tw;		// where the tree being walked is written
  int4 treeBudget;
  bool treeCalls;
  bool treeStores;

  uint4 highId(const Varnode *vn) {
    const HighVariable *high = (const HighVariable *)0;
    try { high = vn->getHigh(); } catch(LowlevelError &) { return 0; }
    map<const HighVariable *,uint4>::const_iterator it = highIds.find(high);
    if (it != highIds.end()) return it->second;
    uint4 id = highIds.size() + 1;
    highIds[high] = id;
    return id;
  }

  void varLeaf(const Varnode *vn) {
    tw->u(RW_EXPR_VAR);
    tw->u(vn->getSize());
    tw->u(vn->getCreateIndex());
    tw->u(highId(vn));
    // Class: 0 register or unique, 1 stack, 2 other memory; flags: persist,
    // address tied, address forced -- what a call or store may change.
    uint4 cls = 2;
    const AddrSpace *spc = vn->getSpace();
    if (spc->getType() == IPTR_INTERNAL) cls = 0;
    else if (spc->getType() == IPTR_SPACEBASE) cls = 1;
    else if (spc->getType() == IPTR_PROCESSOR && spc->getName() == "register") cls = 0;
    uint4 flags = (vn->isPersist() ? 1 : 0) | (vn->isAddrTied() ? 2 : 0) | (vn->isAddrForce() ? 4 : 0);
    tw->u(cls | (flags << 2));
  }

  void tree(const Varnode *vn,int4 depth) {
    if (vn == (const Varnode *)0) { tw->u(RW_EXPR_OPAQUE); return; }
    if (vn->isConstant()) {
      tw->u(RW_EXPR_CONST); tw->u(vn->getSize()); tw->u(vn->getOffset());
      return;
    }
    if (vn->isImplied() && vn->isWritten() && depth < 40 && treeBudget > 0) {
      opTree(vn->getDef(),depth + 1);
      return;
    }
    varLeaf(vn);
  }

  void opTree(const PcodeOp *op,int4 depth) {
    treeBudget -= 1;
    if (op->isCall() || op->code() == CPUI_CALLOTHER) treeCalls = true;
    if (op->code() == CPUI_STORE) treeStores = true;
    tw->u(RW_EXPR_OP);
    tw->u(op->code());
    int4 n = op->numInput();
    tw->u(n);
    for(int4 i=0;i<n;++i)
      tree(op->getIn(i),depth);
  }

  /// A statement candidate's effect: its opcode, whether it (or an implied
  /// expression inside it) calls or stores, the written variable, the
  /// polarity of a CBRANCH and the inputs as trees (a CBRANCH only its
  /// condition).
  void effect(const PcodeOp *op) {
    RomwrightIrBytes body;
    tw = &body;
    treeBudget = 400;
    treeCalls = op->isCall() || op->code() == CPUI_CALLOTHER;
    treeStores = op->code() == CPUI_STORE;
    const Varnode *res = op->getOut();
    bool written = res != (const Varnode *)0 && !res->isImplied();
    body.flag(written);
    if (written) varLeaf(res);
    bool cbranch = op->code() == CPUI_CBRANCH;
    body.flag(cbranch && op->isBooleanFlip());
    int4 n = cbranch ? 1 : op->numInput();
    body.u(n);
    for(int4 i=0;i<n;++i)
      tree(op->getIn(cbranch ? 1 : i),0);
    out.u(op->code());
    out.flag(treeCalls);
    out.flag(treeStores);
    out.data.append(body.data);
  }

  // Version 4: print trees. What PrintC's expression emission reads for one
  // statement, so the worker prints it itself (printc/render.rs): per op its
  // code, time and the choices the cast strategy and the symbol table make
  // (cast kinds, type ids, symbol names and scope paths); per leaf either the
  // data Rust formats (an integer, a symbol) or the single token PrintC's own
  // handler produced (a string literal, a float, a function name). Anything
  // the worker does not print yet is an unsupported node naming why, and the
  // statement keeps its PrintC fragment. Types and symbols are interned in
  // tables at the end of the blob.
  enum { PT_NO = 0, PT_CONST = 1, PT_ATOM = 2, PT_SYMBOL = 3, PT_PARTIAL = 4, PT_OP = 5 };
  RomwrightIrBytes *pw;		// where the print tree being written goes
  int4 ptBudget;
  bool probing;
  map<const Datatype *,uint4> typeIds;
  vector<const Datatype *> typeList;
  map<string,uint4> symIds;
  vector<string> symList;

  uint4 typeRef(const Datatype *ct) {
    map<const Datatype *,uint4>::const_iterator it = typeIds.find(ct);
    if (it != typeIds.end()) return it->second;
    uint4 id = typeList.size();
    typeIds[ct] = id;
    typeList.push_back(ct);
    return id;
  }

  void no(const string &why) { pw->u(PT_NO); pw->str(why); }

  /// The namespace path PrintC::pushSymbolScope prints before \b sym, outermost first.
  void scopeNames(const Symbol *sym,vector<string> &names) {
    const Scope *cur = Access::curScope(print);
    int4 strategy = Access::namespaces(print);
    int4 depth;
    if (strategy == PrintLanguage::MINIMAL_NAMESPACES)
      depth = sym->getResolutionDepth(cur);
    else if (strategy == PrintLanguage::ALL_NAMESPACES)
      depth = (sym->getScope() == cur) ? 0 : sym->getResolutionDepth((const Scope *)0);
    else
      depth = 0;
    vector<const Scope *> list;
    const Scope *point = sym->getScope();
    for(int4 i=0;i<depth;++i) {
      list.push_back(point);
      point = point->getParent();
    }
    for(int4 i=depth-1;i>=0;--i)
      names.push_back(list[i]->getDisplayName());
  }

  /// PrintC::pushSymbol's token: colour, name (with the unmerged suffix) and scope path.
  uint4 symbolRef(const Symbol *sym,const Varnode *vn) {
    uint4 hl;
    if (sym->isVolatile()) hl = EmitMarkup::special_color;
    else if (sym->getScope()->isGlobal()) hl = EmitMarkup::global_color;
    else if (sym->getCategory() == Symbol::function_parameter) hl = EmitMarkup::param_color;
    else if (sym->getCategory() == Symbol::equate) hl = EmitMarkup::const_color;
    else hl = EmitMarkup::var_color;
    string name = sym->getDisplayName();
    if (sym->hasMergeProblems() && vn != (const Varnode *)0) {
      const HighVariable *high = vn->getHigh();
      if (high->isUnmerged()) {
	ostringstream s;
	s << sym->getDisplayName();
	SymbolEntry *entry = high->getSymbolEntry();
	if (entry != (SymbolEntry *)0)
	  s << '$' << dec << entry->getSymbol()->getMapEntryPosition(entry);
	else
	  s << "$$";
	name = s.str();
      }
    }
    vector<string> scopes;
    scopeNames(sym,scopes);
    RomwrightIrBytes rec;
    rec.u(hl);
    rec.str(name);
    rec.u(scopes.size());
    for(size_t i=0;i<scopes.size();++i) rec.str(scopes[i]);
    map<string,uint4>::const_iterator it = symIds.find(rec.data);
    if (it != symIds.end()) return it->second;
    uint4 id = symList.size();
    symIds[rec.data] = id;
    symList.push_back(rec.data);
    return id;
  }

  /// The single token PrintC's handler emits for an explicit varnode, when it emits one.
  void atomProbe(const Varnode *vn,const PcodeOp *op,bool isRead,bool symbolOnly,const char *why) {
    RomwrightIrBytes bytes;
    capture.capture(&bytes);
    probing = true;
    if (symbolOnly) Access::symbolDetail(print,vn,op,isRead);
    else Access::explicitVn(print,vn,op);
    probing = false;
    if (capture.eventCount() == 1) {
      pw->u(PT_ATOM);
      pw->u(vn->getSize());
      pw->str(bytes.data);
    }
    else
      no(why);
  }

  void optionalVn(const Varnode *vn) {
    pw->flag(vn != (const Varnode *)0);
    if (vn != (const Varnode *)0) pw->u(vn->getCreateIndex());
  }

  /// PrintC::pushPartialSymbol's input.
  void partialLeaf(const Varnode *vn,const Symbol *sym,int4 off,int4 size,const HighVariable *high,bool isRead) {
    bool bigend = false;
    if (vn != (const Varnode *)0) {
      const SymbolEntry *whole = sym->getFirstWholeMap();
      const AddrSpace *spc = (const AddrSpace *)0;
      if (whole != (const SymbolEntry *)0) spc = whole->getAddr().getSpace();
      if (spc == (const AddrSpace *)0) spc = vn->getSpace();
      bigend = spc->isBigEndian();
    }
    pw->u(PT_PARTIAL);
    optionalVn(vn);
    pw->u(symbolRef(sym,vn));
    pw->s(off);
    pw->s(size);
    pw->u(typeRef(sym->getType()));
    pw->u(typeRef(high->getType()));
    pw->u((isRead ? 1 : 0) | (bigend ? 2 : 0));
  }

  /// PrintC::pushSymbolDetail's decision for an explicit, non-constant varnode (vn may be null: the symbol of a spacebase PTRSUB).
  void symbolLeaf(const Varnode *vn,const Symbol *sym,int4 symboloff,int4 size,const HighVariable *high,
		  bool isRead,const PcodeOp *op) {
    if (symboloff == -1) {
      if (!sym->getType()->needsResolution()) {
	pw->u(PT_SYMBOL);
	optionalVn(vn);
	pw->u(size);
	pw->u(symbolRef(sym,vn));
	return;
      }
      symboloff = 0;
    }
    if (symboloff + size <= sym->getType()->getSize()) {
      partialLeaf(vn,sym,symboloff,size,high,isRead);
      return;
    }
    // PrintC::pushMismatchSymbol
    atomProbe(vn,op,isRead,true,"symbol:mismatch");
  }

  void constLeaf(const Varnode *vn,const PcodeOp *op) {
    const Datatype *ct = vn->getHighTypeReadFacing(op);
    const HighVariable *high = vn->getHigh();
    const Symbol *sym = high->getSymbol();
    type_metatype meta = ct->getMetatype();
    bool equate = sym != (const Symbol *)0 && sym->isNameLocked() && sym->getCategory() == Symbol::equate;
    uint4 symfmt = sym != (const Symbol *)0 ? 1 + sym->getDisplayFormat() : 0;
    uint4 kind;
    bool intLike = meta == TYPE_UNKNOWN || meta == TYPE_BOOL || meta == TYPE_UINT || meta == TYPE_INT;
    if (equate || ct->isEnumType() || !intLike) kind = 3;
    else if ((meta == TYPE_UINT || meta == TYPE_INT) && ct->isCharPrint()) {
      kind = (vn->getOffset() < 0x80 && symfmt <= 1 && high->getType()->getDisplayFormat() == 0) ? 1 : 3;
    }
    else kind = 0;
    if (kind == 3) {
      // PrintC::pushPtrCharConstant, pushPtrCodeConstant, floats, enumerations, equates: one token or not ours.
      RomwrightIrBytes bytes;
      capture.capture(&bytes);
      probing = true;
      Access::explicitVn(print,vn,op);
      probing = false;
      if (capture.eventCount() == 1) {
	pw->u(PT_ATOM);
	pw->u(vn->getSize());
	pw->str(bytes.data);
	return;
      }
      if (equate || ct->isEnumType()) { no("const:enum-or-equate"); return; }
      if (meta == TYPE_FLOAT || meta == TYPE_VOID) { no("const:float"); return; }
      kind = 2;			// Default printing: a cast and a hex integer
    }
    pw->u(PT_CONST);
    pw->u(vn->getCreateIndex());
    pw->u(vn->getSize());
    pw->u(vn->getOffset());
    pw->u(typeRef(ct));
    pw->u((vn->isUnsignedPrint() ? 1 : 0) | (vn->isLongPrint() ? 2 : 0));
    pw->u(symfmt);
    pw->u(kind);
  }

  /// PrintLanguage::pushVnExplicit / pushSymbolDetail for an explicit varnode.
  void explicitLeaf(const Varnode *vn,const PcodeOp *op,bool isRead) {
    if (vn->isAnnotation()) { no("annotation"); return; }
    try {
      if (vn->isConstant()) { constLeaf(vn,op); return; }
      const HighVariable *high = vn->getHigh();
      const Symbol *sym = high->getSymbol();
      if (sym == (const Symbol *)0) {
	atomProbe(vn,op,isRead,true,"symbol:none");
	return;
      }
      symbolLeaf(vn,sym,high->getSymbolOffset(),vn->getSize(),high,isRead,op);
    }
    catch(LowlevelError &err) {
      if (probing) throw;
      no("leaf:error");
    }
  }

  /// The flags the cast phase reads of a varnode.
  static uint4 nodeFlags(const Varnode *vn) {
    bool nzhigh = true;
    if (vn->getSize() <= (int4)sizeof(uintb)) nzhigh = ((vn->getNZMask() >> (8 * vn->getSize() - 1)) & 1) != 0;
    return (vn->isTypeLock() ? 1 : 0) | (nzhigh ? 2 : 0) | (vn->isConstant() ? 4 : 0) | (vn->isWritten() ? 8 : 0);
  }

  /// Casts pending: after a leaf (tags PT_CONST..PT_PARTIAL) its types and flags.
  void leafInfo(size_t start,const Varnode *vn,const PcodeOp *reader,bool defFacing) {
    uint4 tag = ((uint1)pw->data[start]) & 0x3f;
    if (tag < PT_CONST || tag > PT_PARTIAL) return;
    sizes.insert(vn->getSize());
    const Datatype *high = (const Datatype *)0;
    const Datatype *own = (const Datatype *)0;
    uint4 flags = 0;
    bool known = false;
    if (facts != (const RomwrightCastFacts *)0) {
      if (defFacing) {
	map<const Varnode *,RomwrightNodeFact>::const_iterator it = facts->defs.find(vn);
	if (it != facts->defs.end()) { high = it->second.high; own = it->second.own; flags = it->second.flags & 15; known = true; }
      }
      else {
	map<pair<const Varnode *,const PcodeOp *>,RomwrightNodeFact>::const_iterator it = facts->reads.find(make_pair(vn,reader));
	if (it != facts->reads.end()) { high = it->second.high; own = it->second.own; flags = it->second.flags & 15; known = true; }
      }
    }
    if (!known) {
      high = defFacing ? vn->getHighTypeDefFacing() : vn->getHighTypeReadFacing(reader);
      own = defFacing ? vn->getTypeDefFacing() : vn->getTypeReadFacing(reader);
      flags = nodeFlags(vn);
    }
    pw->u(typeRef(high));
    pw->u(typeRef(own));
    pw->u(flags);
  }

  void child(const Varnode *vn,const PcodeOp *reader) {
    if (vn->isImplied()) {
      if (vn->hasImpliedField() || !vn->isWritten()) { no("implied-field"); return; }
      opNode(vn->getDef(),reader);
      return;
    }
    size_t start = pw->data.size();
    explicitLeaf(vn,reader,true);
    if (pending) leafInfo(start,vn,reader,false);
  }

  /// PrintC::pushSymbolScope + the callee name of PrintC::opCall.
  void callee(const PcodeOp *op) {
    const Varnode *callpoint = op->getIn(0);
    if (callpoint->getSpace()->getType() != IPTR_FSPEC) throw LowlevelError("Missing function callspec");
    FuncCallSpecs *fc = FuncCallSpecs::getFspecFromConst(callpoint->getAddr());
    vector<string> scopes;
    string name;
    if (fc->getName().size() == 0)
      name = Access::functionName(print,fc->getEntryAddress());
    else {
      Funcdata *callee = fc->getFuncdata();
      if (callee != (Funcdata *)0) scopeNames(callee->getSymbol(),scopes);
      name = fc->getName();
    }
    pw->str(name);
    pw->u(scopes.size());
    for(size_t i=0;i<scopes.size();++i) pw->str(scopes[i]);
  }

  /// The type-kind choices PrintC::opPtrsub makes before it pushes anything.
  void ptrsubExtra(const PcodeOp *op) {
    const Varnode *in0 = op->getIn(0);
    uintb in1const = op->getIn(1)->getOffset();
    const Datatype *ptype = in0->getHighTypeReadFacing(op);
    if (ptype->getMetatype() != TYPE_PTR) throw LowlevelError("PTRSUB off of non-pointer type");
    if (ptype->isFormalPointerRel()) { pw->u(0); pw->str("ptrsub:relative"); return; }
    const TypePointer *tp = (const TypePointer *)ptype;
    const Datatype *ct = tp->getPtrTo();
    type_metatype meta = ct->getMetatype();
    if (meta == TYPE_STRUCT) {
      int8 suboff = (int4)in1const;
      if (tp->getWordSize() != 1) { pw->u(0); pw->str("ptrsub:word-size"); return; }
      int8 newoff;
      const TypeField *fld = ct->findTruncation(suboff,0,op,0,newoff);
      string fieldname;
      const Datatype *fieldtype;
      int4 fieldid;
      if (fld == (const TypeField *)0) {
	if (ct->getSize() <= suboff || suboff < 0) throw LowlevelError("PTRSUB out of bounds into struct");
	ostringstream s;
	s << "field_0x" << hex << suboff;
	fieldname = s.str();
	fieldtype = (const Datatype *)0;
	fieldid = suboff;
      }
      else {
	fieldname = fld->name;
	fieldtype = fld->type;
	fieldid = fld->ident;
      }
      pw->u(1);
      pw->u(typeRef(ct));
      pw->str(fieldname);
      pw->s(fieldid);
      pw->flag(fieldtype != (const Datatype *)0 && fieldtype->getMetatype() == TYPE_ARRAY);
    }
    else if (meta == TYPE_SPACEBASE) {
      const HighVariable *high = op->getIn(1)->getHigh();
      const Symbol *symbol = high->getSymbol();
      if (symbol == (const Symbol *)0) {
	// PrintC::pushUnnamedLocation: one token naming the address.
	const TypeSpacebase *sb = (const TypeSpacebase *)ct;
	Address addr = sb->getAddress(in1const,in0->getSize(),op->getAddr());
	RomwrightIrBytes bytes;
	capture.capture(&bytes);
	probing = true;
	Access::unnamedLocation(print,addr,(const Varnode *)0,op);
	probing = false;
	if (capture.eventCount() != 1) { pw->u(0); pw->str("ptrsub:no-symbol"); return; }
	pw->u(2);
	pw->u(0);
	pw->u(PT_ATOM);
	pw->u(0);
	pw->str(bytes.data);
	return;
      }
      type_metatype symmeta = symbol->getType()->getMetatype();
      pw->u(2);
      pw->u(symmeta == TYPE_ARRAY ? 1 : (symmeta == TYPE_CODE ? 2 : 0));
      int4 off = high->getSymbolOffset();
      if (off == 0) {
	pw->u(PT_SYMBOL);
	optionalVn((const Varnode *)0);
	pw->u(0);
	pw->u(symbolRef(symbol,(const Varnode *)0));
      }
      else {
	pw->u(PT_PARTIAL);
	optionalVn((const Varnode *)0);
	pw->u(symbolRef(symbol,(const Varnode *)0));
	pw->s(off);
	pw->s(0);
	pw->u(typeRef(symbol->getType()));
	pw->u(typeRef(symbol->getType()));
	pw->u(0);
      }
    }
    else if (meta == TYPE_ARRAY) {
      if (in1const != 0) throw LowlevelError("PTRSUB with non-zero offset into array type");
      pw->u(3);
    }
    else {
      pw->u(0);
      pw->str(meta == TYPE_UNION ? "ptrsub:union" : "ptrsub:other");
    }
  }

  static uint4 haltKind(const PcodeOp *op) {
    switch(op->getHaltType()) {
    case PcodeOp::noreturn:
    case PcodeOp::halt: return 1;
    case PcodeOp::badinstruction: return 2;
    case PcodeOp::unimplemented: return 3;
    case PcodeOp::missing: return 4;
    default: break;
    }
    return 0;
  }

  /// PrintC::opSubpiece's special printing (into pw): 1 and the partial
  /// symbol leaf, 2 and the field, or 0 when it falls through to a cast.
  uint4 subpieceSpecial(const PcodeOp *op) {
    const Varnode *vn = op->getIn(0);
    const Datatype *ct = vn->getHighTypeReadFacing(op);
    if (!ct->isPieceStructured()) return 0;
    if (ct->needsResolution()) throw LowlevelError("resolved piece");
    int4 byteOff = TypeOpSubpiece::computeByteOffsetForComposite(op);
    const HighVariable *high = vn->getHigh();
    const Symbol *sym = high->getSymbol();
    const Varnode *outvn = op->getOut();
    if (sym != (const Symbol *)0 && vn->isExplicit()) {
      int4 suboff = high->getSymbolOffset();
      if (suboff > 0) byteOff += suboff;
      partialLeaf(outvn,sym,byteOff,outvn->getSize(),outvn->getHigh(),true);
      return 1;
    }
    int8 offset;
    const TypeField *field = ct->findTruncation(byteOff,outvn->getSize(),op,1,offset);
    if (field != (const TypeField *)0 && offset == 0) {
      pw->u(typeRef(ct));
      pw->str(field->name);
      pw->s(field->ident);
      return 2;
    }
    return 0;
  }

  /// One p-code op as PrintC prints it: the inputs that print, in order.
  /// PT_OP code time out-size input-count extras inputs.
  void opNode(const PcodeOp *op,const PcodeOp *readOp) {
    if (--ptBudget < 0) { no("size"); return; }
    OpCode code = op->code();
    // PrintC::opSubpiece's special printing: a piece of a structured variable
    // prints as the field or element it is. 0 none (a cast or SUB), 1 a
    // partial symbol, 2 a field of the input.
    uint4 pieceKind = 0;
    RomwrightIrBytes pieceBytes;
    if (code == CPUI_SUBPIECE && op->doesSpecialPrinting()) {
      RomwrightIrBytes *saved = pw;
      try {
	pw = &pieceBytes;
	pieceKind = subpieceSpecial(op);
	pw = saved;
      }
      catch(LowlevelError &err) {
	pw = saved;
	no("special-printing:SUBPIECE");
	return;
      }
    }
    // The patched PrintC::opCall prints a canonicalised helper call (a
    // projection the IR passes proposed) as the division or remainder it is.
    const auto projection = romwrightIrProjections().find(op);
    bool projected = code == CPUI_CALL && projection != romwrightIrProjections().end();
    if (projected) code = projection->second;
    if (op->doesSpecialPrinting() && code != CPUI_SUBPIECE) { no(string("special-printing:") + get_opname(code)); return; }
    switch(code) {
    case CPUI_CPOOLREF: case CPUI_NEW: case CPUI_INSERT: case CPUI_ZPULL: case CPUI_SPULL:
      no(string("op-kind:") + get_opname(code));
      return;
    default:
      break;
    }
    vector<const Varnode *> kids;
    vector<int4> slots;
    int4 n = op->numInput();
    const PcodeOp *absorbedZext = (const PcodeOp *)0;
    switch(code) {
    case CPUI_LOAD: kids.push_back(op->getIn(1)); slots.push_back(1); break;
    case CPUI_STORE: kids.push_back(op->getIn(1)); slots.push_back(1); kids.push_back(op->getIn(2)); slots.push_back(2); break;
    case CPUI_BRANCH: case CPUI_MULTIEQUAL: case CPUI_INDIRECT: break;
    case CPUI_CBRANCH: kids.push_back(op->getIn(1)); slots.push_back(1); break;
    case CPUI_BRANCHIND: kids.push_back(op->getIn(0)); slots.push_back(0); break;
    case CPUI_CALL: case CPUI_CALLOTHER:
      for(int4 i=1;i<n;++i) { kids.push_back(op->getIn(i)); slots.push_back(i); }
      break;
    case CPUI_INT_DIV: case CPUI_INT_SDIV: case CPUI_INT_REM: case CPUI_INT_SREM:
      if (projected) { kids.push_back(op->getIn(1)); slots.push_back(1); kids.push_back(op->getIn(2)); slots.push_back(2); break; }
      for(int4 i=0;i<n;++i) { kids.push_back(op->getIn(i)); slots.push_back(i); }
      break;
    case CPUI_RETURN: if (n > 1) { kids.push_back(op->getIn(1)); slots.push_back(1); } break;
    case CPUI_PTRADD: kids.push_back(op->getIn(0)); slots.push_back(0); kids.push_back(op->getIn(1)); slots.push_back(1); break;
    case CPUI_PTRSUB: kids.push_back(op->getIn(0)); slots.push_back(0); break;
    case CPUI_SEGMENTOP: kids.push_back(op->getIn(2)); slots.push_back(2); break;
    case CPUI_FLOAT_INT2FLOAT: {
      absorbedZext = TypeOpFloatInt2Float::absorbZext(op);
      // Casts pending: the extension is a node of its own (its input casts are decided with the rest); the worker prints its input.
      kids.push_back(absorbedZext != (const PcodeOp *)0 ? (pending ? absorbedZext->getOut() : absorbedZext->getIn(0)) : op->getIn(0));
      slots.push_back(0);
      break;
    }
    case CPUI_SUBPIECE:
      if (pieceKind == 1) break;
      if (pieceKind == 2) { kids.push_back(op->getIn(0)); slots.push_back(0); break; }
      for(int4 i=0;i<n;++i) { kids.push_back(op->getIn(i)); slots.push_back(i); }
      break;
    default:
      for(int4 i=0;i<n;++i) { kids.push_back(op->getIn(i)); slots.push_back(i); }
      break;
    }
    RomwrightIrBytes *saved = pw;
    try {
      RomwrightIrBytes head;
      pw = &head;
      head.u(PT_OP);
      head.u(code);
      head.u(op->getTime());
      head.u(op->getOut() != (const Varnode *)0 ? op->getOut()->getSize() : 0);
      head.u(kids.size());
      switch(code) {
      case CPUI_INT_ZEXT: case CPUI_INT_SEXT: {
	const Datatype *outtype = op->getOut()->getHighTypeDefFacing();
	head.u(typeRef(outtype));
	head.u(typeRef(op->getIn(0)->getHighTypeReadFacing(op)));
	head.flag(Access::hideExts(print) && print->getCastStrategy()->isExtensionCastImplied(op,readOp));
	head.flag(outtype->isPointerToArray() && Access::addressOfCast(print,op));
	break;
      }
      case CPUI_SUBPIECE: {
	const Datatype *outtype = op->getOut()->getHighTypeDefFacing();
	head.u(typeRef(outtype));
	head.u(typeRef(op->getIn(0)->getHighTypeReadFacing(op)));
	head.u(op->getIn(1)->getOffset());
	head.flag(outtype->isPointerToArray() && Access::addressOfCast(print,op));
	head.u(pieceKind);
	head.data.append(pieceBytes.data);
	break;
      }
      case CPUI_CAST: case CPUI_FLOAT_FLOAT2FLOAT: case CPUI_FLOAT_TRUNC: {
	const Datatype *outtype = op->getOut()->getHighTypeDefFacing();
	head.u(typeRef(outtype));
	head.flag(outtype->isPointerToArray() && Access::addressOfCast(print,op));
	break;
      }
      case CPUI_FLOAT_INT2FLOAT:
	head.u(typeRef(op->getOut()->getHighTypeDefFacing()));
	break;
      case CPUI_CBRANCH:
	head.flag(op->isBooleanFlip());
	break;
      case CPUI_CALL:
	callee(op);
	break;
      case CPUI_CALLIND: {
	FuncCallSpecs *fc = op->getParent()->getFuncdata()->getCallSpecs(op);
	if (fc == (FuncCallSpecs *)0) throw LowlevelError("Missing indirect function callspec");
	head.s(Access::hiddenThis(print,op,fc));
	break;
      }
      case CPUI_CALLOTHER: {
	UserPcodeOp *userop = fd.getArch()->userops.getOp(op->getIn(0)->getOffset());
	head.u(userop->getDisplay());
	head.str(op->getOpcode()->getOperatorName(op));
	break;
      }
      case CPUI_RETURN:
	head.u(haltKind(op));
	break;
      case CPUI_PTRSUB:
	ptrsubExtra(op);
	break;
      default:
	break;
      }
      if (pending) opInfo(op,code,slots,absorbedZext != (const PcodeOp *)0);
      pw = saved;
      pw->data.append(head.data);
    }
    catch(LowlevelError &err) {
      pw = saved;
      no("op:error");
      return;
    }
    for(size_t i=0;i<kids.size();++i)
      child(kids[i],op);
  }

  /// Casts pending: what the cast phase reads of an op node, after the
  /// per-opcode extras and before the kids: the output (types, flags, local
  /// type), what the op decides before any cast (PTRSUB, SUBPIECE), and per
  /// kid its slot and the local type the slot requires.
  void opInfo(const PcodeOp *op,uint4 code,const vector<int4> &slots,bool absorbed) {
    const RomwrightOpFact *fact = (const RomwrightOpFact *)0;
    if (facts != (const RomwrightCastFacts *)0) {
      map<const PcodeOp *,RomwrightOpFact>::const_iterator it = facts->ops.find(op);
      if (it != facts->ops.end()) fact = &it->second;
    }
    const Varnode *outvn = op->getOut();
    pw->flag(outvn != (const Varnode *)0);
    if (outvn != (const Varnode *)0) {
      sizes.insert(outvn->getSize());
      if (fact != (const RomwrightOpFact *)0 && fact->hasOut) {
	pw->u(typeRef(fact->out.high));
	pw->u(typeRef(fact->out.own));
	pw->u(fact->out.flags);
	pw->u(typeRef(fact->outLocal));
      }
      else {
	pw->u(typeRef(outvn->getHighTypeDefFacing()));
	pw->u(typeRef(outvn->getTypeDefFacing()));
	const PcodeOp *lone = outvn->loneDescend();
	pw->u(nodeFlags(outvn) | ((lone != (const PcodeOp *)0 && lone->code() == CPUI_RETURN) ? 16 : 0) | (lone == (const PcodeOp *)0 ? 64 : 0) | (outvn->isImplied() ? 32 : 0));
	pw->u(typeRef(op->outputTypeLocal()));
      }
    }
    pw->flag(absorbed);
    pw->flag(op->isBoolOutput());
    pw->flag(op->isCall());
    switch(code) {
    case CPUI_LOAD: case CPUI_STORE:
      pw->u(op->getIn(0)->getSpaceFromConst()->getWordSize());
      break;
    case CPUI_CALL: {
      // Which parts of the callee's prototype are declared: the rest is read off the call, after the casts.
      const Varnode *callpoint = op->getIn(0);
      bool inputLocked = true,outputLocked = true;
      if (callpoint->getSpace()->getType() == IPTR_FSPEC) {
	FuncCallSpecs *fc = FuncCallSpecs::getFspecFromConst(callpoint->getAddr());
	inputLocked = fc->isInputLocked();
	outputLocked = fc->isOutputLocked();
      }
      pw->flag(inputLocked);
      pw->flag(outputLocked);
      break;
    }
    case CPUI_PTRADD:
      pw->u(op->getIn(2)->getOffset());
      break;
    case CPUI_PTRSUB: {
      uintb off = op->getIn(1)->getOffset();
      pw->u(off);
      if (fact != (const RomwrightOpFact *)0 && fact->token != (const Datatype *)0) {
	pw->flag(fact->matching);
	pw->u(typeRef(fact->token));
      }
      else {
	pw->flag(op->getIn(0)->getTypeReadFacing(op)->isPtrsubMatching((int8)off,0,0));
	pw->u(typeRef(op->getOpcode()->getOutputToken(op,print->getCastStrategy())));
      }
      break;
    }
    case CPUI_SUBPIECE:
      if (fact != (const RomwrightOpFact *)0 && fact->token != (const Datatype *)0)
	pw->u(typeRef(fact->token));
      else
	pw->u(typeRef(op->getOpcode()->getOutputToken(op,print->getCastStrategy())));
      break;
    default:
      break;
    }
    for(size_t i=0;i<slots.size();++i) {
      pw->u(slots[i]);
      if (fact != (const RomwrightOpFact *)0 && (size_t)slots[i] < fact->locals.size() && fact->locals[slots[i]] != (const Datatype *)0)
	pw->u(typeRef(fact->locals[slots[i]]));
      else
	pw->u(typeRef(op->inputTypeLocal(slots[i])));
    }
  }

  /// A statement's print tree: the written variable (if any), then the op.
  void printTree(const PcodeOp *op) {
    pw = &out;
    ptBudget = 1500;
    probing = false;
    const Varnode *res = op->getOut();
    out.flag(res != (const Varnode *)0);
    if (res != (const Varnode *)0) {
      size_t start = out.data.size();
      explicitLeaf(res,op,false);
      if (pending) leafInfo(start,res,op,true);
    }
    opNode(op,(const PcodeOp *)0);
  }

  void printTables(void) {
    // Writing a type can intern the types it refers to: close the table first.
    vector<pair<int4,uint4> > seeds;	// the core types the cast pass may ask for: (size, kind) with kind 0..3 getBase(INT, UINT, UNKNOWN, BOOL), 4 getBaseNoChar(1,INT)
    vector<uint4> seedRefs;
    if (pending) {
      TypeFactory *tlst = fd.getArch()->types;
      sizes.insert(1);	// `char`, for the compiler-dependent casts
      static const type_metatype metas[4] = { TYPE_INT, TYPE_UINT, TYPE_UNKNOWN, TYPE_BOOL };
      for(set<int4>::const_iterator sit=sizes.begin();sit!=sizes.end();++sit) {
	if (*sit < 1 || *sit > 16) continue;
	for(uint4 k=0;k<4;++k) {
	  seeds.push_back(make_pair(*sit,k));
	  seedRefs.push_back(typeRef(tlst->getBase(*sit,metas[k])));
	}
      }
      seeds.push_back(make_pair(1,(uint4)4));
      seedRefs.push_back(typeRef(tlst->getBaseNoChar(1,TYPE_INT)));
    }
    for(size_t i=0;i<typeList.size();++i) {
      const Datatype *ct = typeList[i];
      type_metatype meta = ct->getMetatype();
      if (ct->getTypedef() != (const Datatype *)0) typeRef(ct->getTypedef());
      if (meta == TYPE_PTR || meta == TYPE_PTRREL) typeRef(((const TypePointer *)ct)->getPtrTo());
      else if (meta == TYPE_ARRAY) typeRef(((const TypeArray *)ct)->getBase());
      else if (meta == TYPE_CODE && ((const TypeCode *)ct)->getPrototype() == (const FuncProto *)0)
	typeRef(fd.getArch()->types->getTypeVoid());
      else if (meta == TYPE_STRUCT) {
	vector<TypeField>::const_iterator fiter;
	for(fiter=((const TypeStruct *)ct)->beginField();fiter!=((const TypeStruct *)ct)->endField();++fiter)
	  typeRef((*fiter).type);
      }
    }
    out.u(symList.size());
    for(size_t i=0;i<symList.size();++i) out.data.append(symList[i]);
    out.u(typeList.size());
    for(size_t i=0;i<typeList.size();++i) {
      const Datatype *ct = typeList[i];
      type_metatype meta = ct->getMetatype();
      out.u(ct->getUnsizedId());
      out.str(ct->getName());
      out.str(ct->getDisplayName());
      out.str(ct->getName().size() == 0 ? Access::typeName(print,ct) : string());
      out.u(meta);
      out.u(ct->getSize());
      out.u(ct->getDisplayFormat());
      out.u((ct->isCharPrint() ? 1 : 0) | (ct->isEnumType() ? 2 : 0) | (ct->needsResolution() ? 4 : 0) |
	    (ct->isPointerToArray() ? 8 : 0));
      if (meta == TYPE_PTR || meta == TYPE_PTRREL) out.u(typeRef(((const TypePointer *)ct)->getPtrTo()) + 1);
      else if (meta == TYPE_ARRAY) out.u(typeRef(((const TypeArray *)ct)->getBase()) + 1);
      else if (meta == TYPE_CODE && ((const TypeCode *)ct)->getPrototype() == (const FuncProto *)0)
	out.u(typeRef(fd.getArch()->types->getTypeVoid()) + 1);
      else out.u(0);
      out.u(meta == TYPE_ARRAY ? ((const TypeArray *)ct)->numElements() : 0);
      out.flag(meta == TYPE_CODE && ((const TypeCode *)ct)->getPrototype() != (const FuncProto *)0);
      if (meta == TYPE_STRUCT) {
	const TypeStruct *st = (const TypeStruct *)ct;
	out.u(st->endField() - st->beginField());
	vector<TypeField>::const_iterator fiter;
	for(fiter=st->beginField();fiter!=st->endField();++fiter) {
	  out.s((*fiter).offset);
	  out.s((*fiter).ident);
	  out.str((*fiter).name);
	  out.u(typeRef((*fiter).type));
	}
      }
      // Version 6: what the cast strategy compares.
      out.u(ct->getSubMeta());
      out.u(ct->getTypedef() != (const Datatype *)0 ? typeRef(ct->getTypedef()) + 1 : 0);
      out.u((meta == TYPE_PTR || meta == TYPE_PTRREL) ? ((const TypePointer *)ct)->getWordSize() : 0);
      out.u((meta == TYPE_PTR || meta == TYPE_PTRREL) && ((const TypePointer *)ct)->getSpace() != (const AddrSpace *)0 ?
	    ((const TypePointer *)ct)->getSpace()->getIndex() + 1 : 0);
      out.u(ct->getAlignSize());
      out.flag(ct->isVariableLength());
    }
    // Version 6: the core types and the order of the types that are not plain integers or pointers.
    out.u(fd.getArch()->types->getSizeOfInt());
    out.u(seeds.size());
    for(size_t i=0;i<seeds.size();++i) {
      out.u(seeds[i].first);
      out.u(seeds[i].second);
      out.u(seedRefs[i]);
    }
    vector<size_t> complexTypes;
    for(size_t i=0;i<typeList.size();++i) {
      const Datatype *ct = typeList[i];
      type_metatype meta = ct->getMetatype();
      if (meta == TYPE_STRUCT || meta == TYPE_UNION || meta == TYPE_CODE || meta == TYPE_PTRREL || meta == TYPE_SPACEBASE ||
	  meta == TYPE_PARTIALSTRUCT || meta == TYPE_PARTIALUNION || ct->isEnumType())
	complexTypes.push_back(i);
    }
    vector<size_t> pairA,pairB;
    vector<int4> pairOrder;
    for(size_t a=0;a<complexTypes.size();++a)
      for(size_t b=a+1;b<complexTypes.size();++b) {
	const Datatype *x = typeList[complexTypes[a]];
	const Datatype *y = typeList[complexTypes[b]];
	if (x->getSubMeta() != y->getSubMeta() || x->getSize() != y->getSize()) continue;
	pairA.push_back(complexTypes[a]);
	pairB.push_back(complexTypes[b]);
	int4 order = x->typeOrder(*y);
	pairOrder.push_back(order < 0 ? -1 : (order > 0 ? 1 : 0));
      }
    out.u(pairA.size());
    for(size_t i=0;i<pairA.size();++i) {
      out.u(pairA[i]);
      out.u(pairB[i]);
      out.s(pairOrder[i]);
    }
  }

  /// emitBlockBasic's statement candidates: notPrinted ops, implied outputs
  /// and plain BRANCHes never print in structured mode.
  void statement(const PcodeOp *op,const BlockBasic *bb) {
    out.u(op->getTime());
    out.flag(op->isBranch());
    sorter.setupBlockList(bb);
    sorter.setupOpList(op);
    uint8 bound = 0;
    while(sorter.hasNext()) { sorter.getNext(); bound += 1; }
    out.u(bound);
    expression(op,false);
    bool cbranch = op->code() == CPUI_CBRANCH;
    out.flag(cbranch);
    if (cbranch) expression(op,true);
    effect(op);			// Version 3: the statement's expression tree
    printTree(op);		// Version 4: what the worker needs to print it
  }

  void basic(const BlockBasic *bb) {
    vector<Comment *> comments;
    sorter.setupBlockList(bb);
    sorter.setupOpList((const PcodeOp *)0);
    while(sorter.hasNext()) comments.push_back(sorter.getNext());
    out.u(comments.size());
    for(size_t i=0;i<comments.size();++i) {
      const Comment *comm = comments[i];
      out.flag((instr & comm->getType()) != 0);
      fragment([&]() { Access::lineComment(print,-1,comm); });
    }
    vector<const PcodeOp *> ops;
    list<PcodeOp *>::const_iterator iter;
    for(iter=bb->beginOp();iter!=bb->endOp();++iter) {
      const PcodeOp *op = *iter;
      if (op->notPrinted() || op->code() == CPUI_BRANCH) continue;
      const Varnode *vn = op->getOut();
      if (vn != (const Varnode *)0 && vn->isImplied()) continue;
      ops.push_back(op);
    }
    out.u(ops.size());
    for(size_t i=0;i<ops.size();++i)
      statement(ops[i],bb);
    const PcodeOp *last = bb->lastOp();
    bool branch = last != (const PcodeOp *)0 && last->isBranch();
    out.flag(branch);
    if (branch) {
      expression(last,false);
      bool cbranch = last->code() == CPUI_CBRANCH;
      out.flag(cbranch);
      if (cbranch) expression(last,true);
      // Version 4: the branch op is a statement candidate too, unless notPrinted.
      int4 shared = -1;
      for(size_t i=0;i<ops.size();++i)
	if (ops[i] == last) shared = i;
      out.flag(shared >= 0);
      if (shared >= 0) out.u(shared);
      else printTree(last);
    }
    // Version 2: what a structuring pass needs to print this block anywhere.
    out.u(bb->sizeOut());
    for(int4 i=0;i<bb->sizeOut();++i)
      out.s(bb->getOut(i)->getIndex());
    bool cbranch = branch && last->code() == CPUI_CBRANCH;
    out.flag(cbranch);
    if (cbranch) negated(last);
    bool holdsLoopOp = false;
    for(iter=bb->beginOp();iter!=bb->endOp();++iter)
      if (loopOps.find(*iter) != loopOps.end()) holdsLoopOp = true;
    out.flag(holdsLoopOp);
  }

  void node(const FlowBlock *bl) {
    FlowBlock::block_type type = bl->getType();
    out.u(type);
    out.s(bl->getIndex());
    out.op(bl->lastOp());
    // emitAnyLabelStatement, less the runtime only_branch test.
    const FlowBlock *leaf = bl->isLabelBumpUp() ? (const FlowBlock *)0 : bl->getFrontLeaf();
    bool labelled = leaf != (const FlowBlock *)0 && leaf->isUnstructuredTarget() &&
      leaf->getType() == FlowBlock::t_copy;
    label(labelled ? leaf : (const FlowBlock *)0);
    if (type == FlowBlock::t_basic) {
      basic((const BlockBasic *)bl);
      return;
    }
    if (type == FlowBlock::t_plain) return;
    if (type == FlowBlock::t_copy) {
      out.u(1);
      node(bl->subBlock(0));
      fragment([&]() { Access::label(print,bl); });	// Version 2: every leaf's label
      return;
    }
    const BlockGraph *graph = (const BlockGraph *)bl;
    int4 size = graph->getSize();
    out.u(size);
    for(int4 i=0;i<size;++i)
      node(graph->getBlock(i));
    switch(type) {
    case FlowBlock::t_goto: {
      const BlockGoto *gotoBlock = (const BlockGoto *)bl;
      out.flag(gotoBlock->gotoPrints());
      out.u(gotoBlock->getGotoType());
      target(gotoBlock->getGotoTarget());
      break;
    }
    case FlowBlock::t_ls:
      for(int4 i=0;i+1<size;++i)
	out.flag(graph->getBlock(i+1) != graph->getBlock(i)->nextInFlow());
      break;
    case FlowBlock::t_condition:
      out.flag(((const BlockCondition *)bl)->getOpcode() == CPUI_BOOL_AND);
      break;
    case FlowBlock::t_if: {
      const BlockIf *ifBlock = (const BlockIf *)bl;
      out.u(ifBlock->getGotoType());
      target(ifBlock->getGotoTarget());
      break;
    }
    case FlowBlock::t_whiledo: {
      const BlockWhileDo *loop = (const BlockWhileDo *)bl;
      out.flag(loop->hasOverflowSyntax());
      const PcodeOp *init = loop->getInitializeOp();
      out.op(init);
      if (init != (const PcodeOp *)0) { expression(init,true); printTree(init); }
      const PcodeOp *iterate = loop->getIterateOp();
      out.op(iterate);
      if (iterate != (const PcodeOp *)0) { expression(iterate,true); printTree(iterate); }
      break;
    }
    case FlowBlock::t_switch: {
      const BlockSwitch *switchBlock = (const BlockSwitch *)bl;
      int4 cases = switchBlock->getNumCaseBlocks();
      out.u(cases);
      for(int4 i=0;i<cases;++i) {
	const FlowBlock *caseBlock = switchBlock->getCaseBlock(i);
	uint4 gotoType = switchBlock->getGotoType(i);
	fragment([&]() { Access::switchCase(print,i,switchBlock); });
	out.u(gotoType);
	out.flag(switchBlock->isExit(i));
	if (gotoType != 0) {
	  // An unstructured case (a BlockMultiGoto edge) prints as a goto to
	  // a block elsewhere in the tree; only its label is needed.
	  target(caseBlock);
	  continue;
	}
	// The case block is a child of the switch; emitBlockSwitch prints it
	// directly, so any other placement is exported in place.
	int4 child = 0;
	while(child < size && graph->getBlock(child) != caseBlock) ++child;
	out.flag(child < size);
	if (child < size)
	  out.u(child);
	else
	  node(caseBlock);
      }
      break;
    }
    default:
      break;
    }
  }
  /// A switch block's case labels per out-edge: the jump-table entries that
  /// reach the target and PrintC's `emitSwitchCase` lines for it.
  void switchEdges(const BlockBasic *bb) {
    const JumpTable *jump = bb->getJumptable();
    if (jump == (const JumpTable *)0) { out.u(0); return; }
    out.u(bb->sizeOut());
    for(int4 i=0;i<bb->sizeOut();++i) {
      const FlowBlock *target = bb->getOut(i);
      int4 num = jump->numIndicesByBlock(target);
      out.flag(num > 0);
      if (num <= 0) continue;
      out.u(num);
      for(int4 k=0;k<num;++k)
	out.u(jump->getLabelByIndex(jump->getIndexByBlock(target,k)));
      bool isdefault = bb->isDefaultBranch(i);
      fragment([&]() { Access::switchCaseFor(print,jump,target,isdefault); });
    }
  }

  /// Version 5: the unstructured control-flow graph (printc/collapse.rs) and
  /// the for-loops found on it. With stock structuring the graph is the one
  /// that was structured: as it was when structuring started.
  void cfgSection(void) {
    const BlockGraph &graph(fd.getBasicBlocks());
    map<const Funcdata *,RomwrightFunctionState>::const_iterator it = romwrightStates().find(&fd);
    const vector<RomwrightBlockFact> *facts = (it != romwrightStates().end() &&
					       (int4)it->second.facts.size() == graph.getSize()) ? &it->second.facts : (const vector<RomwrightBlockFact> *)0;
    out.u(graph.getSize());
    for(int4 i=0;i<graph.getSize();++i) {
      const BlockBasic *bb = (const BlockBasic *)graph.getBlock(i);
      RomwrightBlockFact fact;
      romwrightCaptureBlock(bb,fact);
      bool flipped = false;
      if (facts != (const vector<RomwrightBlockFact> *)0) {
	const RomwrightBlockFact &seen((*facts)[i]);
	// The graph that was structured. Its conditions were negated since (in
	// the p-code, where the statements print them): `flipped` says which.
	flipped = fact.fall != seen.fall;
	fact.flags = seen.flags;
	fact.fall = seen.fall;
	fact.ins = seen.ins;
	fact.outs = seen.outs;
	fact.complex = seen.complex;
      }
      romwrightEncodeShape(out,fact,bb->lastOp(),flipped);
      BlockCopy leaf(const_cast<BlockBasic *>(bb));	// emitLabel names a leaf
      fragment([&]() { Access::label(print,&leaf); });
      if (bb->isSwitchOut()) switchEdges(bb);
      else out.u(0);
      basic(bb);
    }
    out.u(loopRecs.size());
    for(size_t i=0;i<loopRecs.size();++i) {
      out.s(loopRecs[i].head);
      out.s(loopRecs[i].tail);
      out.op(loopRecs[i].init);
      if (loopRecs[i].init != (const PcodeOp *)0) { expression(loopRecs[i].init,true); printTree(loopRecs[i].init); }
      out.op(loopRecs[i].iterate);
      if (loopRecs[i].iterate != (const PcodeOp *)0) { expression(loopRecs[i].iterate,true); printTree(loopRecs[i].iterate); }
    }
    // The `if`/`else` blocks whose tests ActionPreferComplement changed in place.
    if (it != romwrightStates().end() && romwrightStructureMode() == 0) {
      out.u(it->second.preferred.size());
      for(size_t i=0;i<it->second.preferred.size();++i)
	out.u(it->second.preferred[i]);
    }
    else
      out.u(0);
  }
public:
  static uint4 flagsOf(const Varnode *vn) { return nodeFlags(vn); }
  RomwrightPrintIrExport(PrintC *p,const Funcdata &f,RomwrightIrBytes &o,bool casts = false,const RomwrightCastFacts *known = (const RomwrightCastFacts *)0)
    : print(p), fd(f), capture(Access::emitOf(p)->getMaxLineSize()), out(o) {
    instr = Access::instrComments(p);
    pw = &o;
    ptBudget = 0;
    probing = false;
    pending = casts;
    facts = known;
  }

  Emit *captureEmit(void) { return &capture; }

  /// An address as the merge mirror writes it: the space's index and the offset
  /// (an invalid address, which a block without cover has, as (0,0)).
  void mergeAddr(RomwrightIrBytes &o,const Address &addr) {
    if (addr.isInvalid()) { o.u(0); o.u(0); return; }
    o.u(addr.getSpace()->getIndex());
    o.u(addr.getOffset());
  }

  /// The merge query (printc/ir.rs `decode_merge_query`, docs/merge-port.md):
  /// the function's p-code as `ActionAssignHigh` leaves it. \b ops are the
  /// alive ops in alive-list order and \b vns every varnode in location
  /// order: their positions are the ids the worker's answer refers to.
  void mergeQuery(const vector<const PcodeOp *> &ops,const vector<const Varnode *> &vns,
		  const vector<int4> &loopCandidates,bool multiEntry,bool dynamic) {
    pending = false;
    map<const PcodeOp *,uint4> opId;
    map<const Varnode *,uint4> vnId;
    for(size_t i=0;i<ops.size();++i) opId[ops[i]] = i;
    for(size_t i=0;i<vns.size();++i) vnId[vns[i]] = i;
    const AddrSpaceManager *manage = fd.getArch();
    RomwrightIrBytes body;
    // blocks
    const BlockGraph &graph(fd.getBasicBlocks());
    body.u(graph.getSize());
    for(int4 b=0;b<graph.getSize();++b) {
      const BlockBasic *bb = (const BlockBasic *)graph.getBlock(b);
      body.u(bb->sizeIn());
      for(int4 j=0;j<bb->sizeIn();++j) body.u(bb->getIn(j)->getIndex());
      body.u(bb->sizeOut());
      for(int4 j=0;j<bb->sizeOut();++j) { body.u(bb->getOut(j)->getIndex()); body.u(bb->getOutRevIndex(j)); }
      const FlowBlock *dom = bb->getImmedDom();
      body.u(dom == (const FlowBlock *)0 ? 0 : dom->getIndex() + 1);
      mergeAddr(body,bb->getStart());
      mergeAddr(body,bb->getStop());
      vector<uint4> listed;
      list<PcodeOp *>::const_iterator iter;
      for(iter=bb->beginOp();iter!=bb->endOp();++iter) {
	map<const PcodeOp *,uint4>::const_iterator found = opId.find(*iter);
	if (found == opId.end()) throw LowlevelError("Merge mirror: block op is not alive");
	listed.push_back(found->second);
      }
      body.u(listed.size());
      for(size_t i=0;i<listed.size();++i) body.u(listed[i]);
    }
    // ops
    body.u(ops.size());
    for(size_t i=0;i<ops.size();++i) {
      const PcodeOp *op = ops[i];
      body.u(op->getTime());
      mergeAddr(body,op->getAddr());
      body.u(op->code());
      body.u(op->getParent() == (const BlockBasic *)0 ? 0 : op->getParent()->getIndex() + 1);
      body.u(op->getSeqNum().getOrder());
      body.u(RomwrightMergeApply::opFlags(op));
      body.u((op->doesSpecialPrinting() ? 2 : 0) | (op->isPartialRoot() ? 0x100 : 0));
      body.u(op->numInput());
      for(int4 j=0;j<op->numInput();++j) {
	map<const Varnode *,uint4>::const_iterator found = vnId.find(op->getIn(j));
	if (found == vnId.end()) throw LowlevelError("Merge mirror: op input is not in the function");
	body.u(found->second);
      }
      const Varnode *outvn = op->getOut();
      if (outvn == (const Varnode *)0) body.u(0);
      else {
	map<const Varnode *,uint4>::const_iterator found = vnId.find(outvn);
	if (found == vnId.end()) throw LowlevelError("Merge mirror: op output is not in the function");
	body.u(found->second + 1);
      }
      uint4 target = 0;
      if (op->code() == CPUI_INDIRECT && op->numInput() > 1 && op->getIn(1)->getSpace()->getType() == IPTR_IOP) {
	map<const PcodeOp *,uint4>::const_iterator found = opId.find(PcodeOp::getOpFromConst(op->getIn(1)->getAddr()));
	if (found != opId.end()) target = found->second + 1;
      }
      body.u(target);
      vector<uint4> mask((op->numInput() + 31) / 32,0);
      if (outvn != (const Varnode *)0 && !op->isCall()) {
	try {
	  const Datatype *ct = op->outputTypeLocal();
	  for(int4 j=0;j<op->numInput();++j)
	    if (ct == op->inputTypeLocal(j)) mask[j/32] |= (1u << (j%32));
	}
	catch(LowlevelError &err) { mask.assign(mask.size(),0); }
      }
      body.u(mask.size());
      for(size_t j=0;j<mask.size();++j) body.u(mask[j]);
    }
    // varnodes
    map<const Symbol *,uint4> symIdx;
    map<const SymbolEntry *,uint4> entryIdx;
    vector<const Symbol *> symList;
    body.u(vns.size());
    for(size_t i=0;i<vns.size();++i) {
      const Varnode *vn = vns[i];
      body.u(vn->getCreateIndex());
      body.u(vn->getSize());
      mergeAddr(body,vn->getAddr());
      body.u(vn->getFlags());
      body.u(typeRef(vn->getType()));
      const PcodeOp *def = vn->getDef();
      body.u(def == (const PcodeOp *)0 ? 0 : opId.find(def)->second + 1);
      uint4 count = 0;
      list<PcodeOp *>::const_iterator iter;
      for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) count += 1;
      body.u(count);
      for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
	map<const PcodeOp *,uint4>::const_iterator found = opId.find(*iter);
	if (found == opId.end()) throw LowlevelError("Merge mirror: reader is not alive");
	body.u(found->second);
      }
      const Symbol *sym = (const Symbol *)0;
      int4 symoff = -1;
      if (!vn->isAnnotation()) {
	const HighVariable *high = vn->getHigh();
	sym = high->getSymbol();
	symoff = high->getSymbolOffset();
      }
      if (sym == (const Symbol *)0) { body.u(0); body.s(-1); }
      else {
	map<const Symbol *,uint4>::const_iterator found = symIdx.find(sym);
	uint4 id;
	if (found == symIdx.end()) { id = symList.size(); symIdx[sym] = id; symList.push_back(sym); }
	else id = found->second;
	body.u(id + 1);
	body.s(symoff);
      }
      const SymbolEntry *entry = vn->isAnnotation() ? (const SymbolEntry *)0 : vn->getSymbolEntry();
      if (entry == (const SymbolEntry *)0) { body.u(0); body.s(0); }
      else {
	map<const SymbolEntry *,uint4>::const_iterator found = entryIdx.find(entry);
	uint4 id;
	if (found == entryIdx.end()) { id = entryIdx.size(); entryIdx[entry] = id; }
	else id = found->second;
	body.u(id + 1);
	body.s(entry->getOffset());
      }
    }
    // calls, affecting ops, loop candidates
    body.u(fd.numCalls());
    for(int4 i=0;i<fd.numCalls();++i) {
      map<const PcodeOp *,uint4>::const_iterator found = opId.find(fd.getCallSpecs(i)->getOp());
      if (found == opId.end()) throw LowlevelError("Merge mirror: call op is not alive");
      body.u(found->second);
    }
    vector<const LoadGuard *> guards;
    const list<LoadGuard> &storeGuard(fd.getStoreGuards());
    for(list<LoadGuard>::const_iterator giter=storeGuard.begin();giter!=storeGuard.end();++giter)
      if ((*giter).isValid(CPUI_STORE) && opId.find((*giter).getOp()) != opId.end()) guards.push_back(&*giter);
    body.u(guards.size() + fd.numCalls());
    for(int4 i=0;i<fd.numCalls();++i) {
      body.u(opId.find(fd.getCallSpecs(i)->getOp())->second);
      body.flag(false);
    }
    for(size_t i=0;i<guards.size();++i) {
      body.u(opId.find(guards[i]->getOp())->second);
      body.flag(true);
      body.u(fd.getArch()->getStackSpace()->getIndex());
      body.u(guards[i]->getMinimum());
      body.u(guards[i]->getMaximum());
    }
    body.u(loopCandidates.size() / 3);
    for(size_t i=0;i+2<loopCandidates.size();i+=3) {
      body.u(loopCandidates[i]);
      body.u(loopCandidates[i+1]);
      body.u(loopCandidates[i+2]);
    }
    {
      const vector<PcodeOp *> &roots(RomwrightMergeApply::protoPartialOf(const_cast<Funcdata &>(fd).getMerge()));
      vector<uint4> listed;
      for(size_t i=0;i<roots.size();++i) {
	map<const PcodeOp *,uint4>::const_iterator found = opId.find(roots[i]);
	if (found != opId.end()) listed.push_back(found->second);
      }
      body.u(listed.size());
      for(size_t i=0;i<listed.size();++i) body.u(listed[i]);
    }
    // header
    out.u(0);
    out.u(2);
    out.u(fd.getAddress().getOffset());
    out.u(fd.getArch()->max_implied_ref);
    out.u(fd.getArch()->max_term_duplication);
    out.flag(fd.getArch()->analyze_for_loops);
    out.u(fd.romwrightOpUniqId());
    out.u(fd.romwrightCreateIndex());
    out.u(fd.romwrightUniqueOffset());
    out.u(manage->getUniqueSpace()->getIndex());
    out.flag(multiEntry);
    out.flag(dynamic);
    for(size_t i=0;i<typeList.size();++i)
      if (typeList[i]->hasStripped()) typeRef(typeList[i]->getStripped());
    printTables();
    out.u(typeList.size());
    for(size_t i=0;i<typeList.size();++i) {
      uint4 stripped = 0;
      if (typeList[i]->hasStripped()) {
	map<const Datatype *,uint4>::const_iterator found = typeIds.find(typeList[i]->getStripped());
	if (found != typeIds.end()) stripped = found->second + 1;
      }
      out.u(stripped);
    }
    uint4 numSpaces = 0;
    for(int4 i=0;i<manage->numSpaces();++i) if (manage->getSpace(i) != (AddrSpace *)0) numSpaces += 1;
    out.u(numSpaces);
    for(int4 i=0;i<manage->numSpaces();++i) {
      const AddrSpace *spc = manage->getSpace(i);
      if (spc == (const AddrSpace *)0) continue;
      uint4 kind = 4;
      if (spc->getType() == IPTR_PROCESSOR) kind = 0;
      else if (spc->getType() == IPTR_SPACEBASE) kind = 1;
      else if (spc->getType() == IPTR_INTERNAL) kind = 2;
      else if (spc->getType() == IPTR_CONSTANT) kind = 3;
      out.u(spc->getIndex());
      out.u(kind);
      out.flag(spc->isBigEndian());
    }
    out.u(symList.size());
    for(size_t i=0;i<symList.size();++i) {
      out.flag(symList[i]->isIsolated());
      out.u(symList[i]->getType()->getMetatype());
    }
    out.data.append(body.data);
  }

  /// The options of PrintC's expression emission, as the header carries them (printc/ir.rs `options`).
  void writeOptions(RomwrightIrBytes &o) {
    uint4 mods = Access::modsOf(print);
    o.u((Access::noCasts(print) ? 1 : 0) | (Access::hideExts(print) ? 2 : 0) |
	(Access::nullOption(print) ? 4 : 0) | (Access::inplaceOps(print) ? 8 : 0) |
	((mods & PrintLanguage::hide_thisparam) != 0 ? 16 : 0));
    o.u(mods & (PrintLanguage::force_hex | PrintLanguage::force_dec | PrintLanguage::bestfit |
		PrintLanguage::force_scinote | PrintLanguage::force_pointer));
    o.str(Access::suffixOf(print));
  }

  /// The cast query (printc/query.rs `answer_casts`): a zero where a structuring query has its block count, then 0 (decide) or 1 (the decompiler's own casts, verify mode), the options, the type tables, then every statement's pre-cast print tree block by block (the op filter of `basic`).
  void castQuery(uint4 marker) {
    pending = true;
    RomwrightIrBytes scratch;
    capture.capture(&scratch);
    Access::declaration(print,&fd);	// Enters the function's scope for the symbols below
    string prefix;
    prefix.swap(out.data);
    const BlockGraph &graph(fd.getBasicBlocks());
    out.u(graph.getSize());
    for(int4 b=0;b<graph.getSize();++b) {
      const BlockBasic *bb = (const BlockBasic *)graph.getBlock(b);
      vector<const PcodeOp *> ops;
      list<PcodeOp *>::const_iterator iter;
      for(iter=bb->beginOp();iter!=bb->endOp();++iter) {
	const PcodeOp *op = *iter;
	if (op->notPrinted() || op->code() == CPUI_BRANCH) continue;
	const Varnode *vn = op->getOut();
	if (vn != (const Varnode *)0 && vn->isImplied()) continue;
	ops.push_back(op);
      }
      out.u(ops.size());
      for(size_t i=0;i<ops.size();++i)
	printTree(ops[i]);
      const PcodeOp *last = bb->lastOp();
      bool branch = last != (const PcodeOp *)0 && last->isBranch();
      bool shared = false;
      for(size_t i=0;i<ops.size();++i)
	if (ops[i] == last) shared = true;
      out.flag(branch && !shared);
      if (branch && !shared) printTree(last);
    }
    // The initializer and iterator statements of the for-loop candidates (the worker declines when a cast would
    // change which op each is: the loop analysis ran on the p-code before the casts).
    collectLoopOpsFromState();
    out.u(loopRecs.size());
    for(size_t i=0;i<loopRecs.size();++i) {
      out.flag(loopRecs[i].init != (const PcodeOp *)0);
      if (loopRecs[i].init != (const PcodeOp *)0) printTree(loopRecs[i].init);
      out.flag(loopRecs[i].iterate != (const PcodeOp *)0);
      if (loopRecs[i].iterate != (const PcodeOp *)0) printTree(loopRecs[i].iterate);
    }
    string body;
    body.swap(out.data);
    out.data.swap(prefix);
    out.u(0);
    out.u(marker);
    writeOptions(out);
    printTables();
    out.data.append(body);
    Access::leaveScope(print);
  }

  void run(void) {
    uint4 heads = Access::headComments(print);
    bool unplacedComments = Access::unplaced(print);
    const CommentDatabase &db(*fd.getArch()->commentdb);
    sorter.setupFunctionList(instr|heads,&fd,db,unplacedComments);
    Access::sorterOf(print).setupFunctionList(instr|heads,&fd,db,unplacedComments);
    fragment([&]() { Access::header(print,&fd); });
    // Enters the function's scope, as docFunction does, for everything below.
    fragment([&]() { Access::declaration(print,&fd); });
    fragment([&]() { Access::locals(print,&fd); });
    // Version 4: the type and symbol tables the print trees index come before
    // the block tree that holds them; the tree is written aside first.
    string prefix;
    prefix.swap(out.data);
    const BlockGraph &root(fd.getStructure());
    bool hasTree = romwrightNativeStructure();
    if (hasTree) collectLoopOps(&root);
    else collectLoopOpsFromState();
    out.flag(hasTree);
    if (hasTree) {
      out.u(root.getSize());
      for(int4 i=0;i<root.getSize();++i)
	node(root.getBlock(i));
    }
    cfgSection();
    string body;
    body.swap(out.data);
    out.data.swap(prefix);
    printTables();
    out.data.append(body);
    Access::leaveScope(print);
  }
};

/// Appends the printer IR after PrintC's markup. \b countAfter is the
/// TokenSplit id counter once docFunction finished, which fixes the ids
/// EmitMarkup writes for parentheses.
inline void romwrightEncodePrintIr(PrintLanguage *language,const Funcdata &fd,Encoder &encoder) {
  TokenSplit probe;
  int4 countAfter = probe.beginDocument();
  RomwrightIrBytes out;
  out.data.append("RWPI",4);
  out.u(7);			// Format version (2: structuring fields, 3: expression trees, 4: print trees, 5: unstructured graph, 6: pre-cast trees and cast data, 7: merge owner; printc/ir.rs)
  PrintC *print = dynamic_cast<PrintC *>(language);
  if (print == (PrintC *)0)
    throw LowlevelError("Printer IR requires the C printer");
  if ((RomwrightPrintCAccess::modsOf(print) & PrintLanguage::flat) != 0)
    throw LowlevelError("Printer IR requires structured printing");
  Emit *&slot(RomwrightPrintCAccess::emitOf(print));
  Emit *saved = slot;
  out.s(saved->getMaxLineSize());
  out.s(saved->getIndentIncrement());
  out.u(RomwrightPrintCAccess::braceFunc(print));
  out.u(RomwrightPrintCAccess::braceIfElse(print));
  out.u(RomwrightPrintCAccess::braceLoop(print));
  out.u(RomwrightPrintCAccess::braceSwitch(print));
  out.s(countAfter);
  uint4 mods = RomwrightPrintCAccess::modsOf(print);
  // Version 4: the options PrintC's expression emission consults. The worker
  // prints expressions only for the defaults (no in-place operators, NULL
  // keyword or hidden `this`), whose options are honoured below.
  out.u((RomwrightPrintCAccess::noCasts(print) ? 1 : 0) | (RomwrightPrintCAccess::hideExts(print) ? 2 : 0) |
	(RomwrightPrintCAccess::nullOption(print) ? 4 : 0) | (RomwrightPrintCAccess::inplaceOps(print) ? 8 : 0) |
	((mods & PrintLanguage::hide_thisparam) != 0 ? 16 : 0));
  out.u(mods & (PrintLanguage::force_hex | PrintLanguage::force_dec | PrintLanguage::bestfit |
		PrintLanguage::force_scinote | PrintLanguage::force_pointer));
  out.str(RomwrightPrintCAccess::suffixOf(print));
  bool castsPending = false;
  const RomwrightCastFacts *castFacts = (const RomwrightCastFacts *)0;
  {
    map<const Funcdata *,RomwrightFunctionState>::const_iterator sit = romwrightStates().find(&fd);
    castsPending = sit != romwrightStates().end() && sit->second.castsPending;
    if (castsPending && sit->second.castFacts.valid) castFacts = &sit->second.castFacts;
  }
  out.flag(castsPending);
  {
    map<const Funcdata *,RomwrightFunctionState>::const_iterator mit = romwrightStates().find(&fd);
    out.flag(mit != romwrightStates().end() && mit->second.mergeOwned);	// version 7: the worker decided the merge
  }
  RomwrightPrintIrExport exporter(print,fd,out,castsPending,castFacts);
  try {
    slot = exporter.captureEmit();
    exporter.run();
  }
  catch(...) {
    slot = saved;
    RomwrightPrintCAccess::modsOf(print) = mods;
    print->clear();
    throw;
  }
  slot = saved;
  encoder.openElement(ELEM_ROMWRIGHT_PRINTIR);
  encoder.writeString(ATTRIB_CONTENT,out.data);
  encoder.closeElement(ELEM_ROMWRIGHT_PRINTIR);
}

/// Reads what the cast phase needs of every op and varnode before anything
/// probes the function: PrintC's handlers update lazily evaluated state (a
/// HighVariable's type) that ActionSetCasts would have read first.
inline void romwrightCaptureCastFacts(PrintC *print,Funcdata &fd,RomwrightCastFacts &facts) {
  facts.clear();
  list<PcodeOp *>::const_iterator iter;
  for(iter=fd.beginOpAlive();iter!=fd.endOpAlive();++iter) {
    const PcodeOp *op = *iter;
    RomwrightOpFact &of(facts.ops[op]);
    const Varnode *outvn = op->getOut();
    bool outHigh = false;
    if (outvn != (const Varnode *)0) {
      try { outvn->getHigh(); outHigh = true; }
      catch(LowlevelError &err) { outHigh = false; }
    }
    if (outHigh) {
      of.hasOut = true;
      of.out.high = outvn->getHighTypeDefFacing();
      of.out.own = outvn->getTypeDefFacing();
      const PcodeOp *lone = outvn->loneDescend();
      of.out.flags = RomwrightPrintIrExport::flagsOf(outvn) | ((lone != (const PcodeOp *)0 && lone->code() == CPUI_RETURN) ? 16 : 0) | (lone == (const PcodeOp *)0 ? 64 : 0) |
	(outvn->isImplied() ? 32 : 0);
      of.outLocal = op->outputTypeLocal();
      facts.defs[outvn] = of.out;
    }
    OpCode code = op->code();
    try {
      if (code == CPUI_PTRSUB && outHigh && !op->getIn(0)->isAnnotation()) {
	uintb off = op->getIn(1)->getOffset();
	of.matching = op->getIn(0)->getTypeReadFacing(op)->isPtrsubMatching((int8)off,0,0);
	of.token = op->getOpcode()->getOutputToken(op,print->getCastStrategy());
      }
      else if (code == CPUI_SUBPIECE && outHigh)
	of.token = op->getOpcode()->getOutputToken(op,print->getCastStrategy());
    }
    catch(LowlevelError &err) { of.token = (const Datatype *)0; }
    for(int4 slot=0;slot<op->numInput();++slot) {
      const Varnode *vn = op->getIn(slot);
      bool hasHigh = false;
      if (!vn->isAnnotation()) {
	try { vn->getHigh(); hasHigh = true; }
	catch(LowlevelError &err) { hasHigh = false; }
      }
      if (hasHigh) {
	RomwrightNodeFact nf;
	nf.high = vn->getHighTypeReadFacing(op);
	nf.own = vn->getTypeReadFacing(op);
	nf.flags = RomwrightPrintIrExport::flagsOf(vn);
	facts.reads[make_pair(vn,op)] = nf;
      }
      const Datatype *local = (const Datatype *)0;
      try { local = op->inputTypeLocal(slot); }
      catch(LowlevelError &err) { local = (const Datatype *)0; }
      of.locals.push_back(local);
    }
  }
  facts.valid = true;
}

/// Decides who casts \b fd: the worker (its cast pass over the pre-cast print
/// trees, answered per function: printc/casts.rs) or ActionSetCasts. The
/// pipeline's cast action only marks the function pending
/// (romwright_structure.hh); this runs before anything reads the p-code to
/// print it. ROMWRIGHT_NATIVE_CASTS=1, the stock structuring path and a
/// render with projected helper calls run ActionSetCasts.
inline void romwrightFinishCasts(PrintLanguage *language,Funcdata &fd) {
  map<const Funcdata *,RomwrightFunctionState>::iterator sit = romwrightStates().find(&fd);
  if (sit == romwrightStates().end() || !sit->second.castsPending) return;
  sit->second.castsPending = false;
  if (getenv("ROMWRIGHT_INFER_LOG") != (const char *)0) {
    map<const Funcdata *,RomwrightInferStats>::const_iterator iit = romwrightInferStats().find(&fd);
    if (iit != romwrightInferStats().end()) {
      FILE *log = fopen(getenv("ROMWRIGHT_INFER_LOG"),"a");
      if (log != (FILE *)0) {
	int4 ops = 0;
	list<PcodeOp *>::const_iterator oiter;
	for(oiter=fd.beginOpAlive();oiter!=fd.endOpAlive();++oiter) ops += 1;
	fprintf(log,"{\"infer\": {\"address\": %llu, \"calls\": %d, \"micros\": %lld, \"sum_ops\": %lld, \"sum_varnodes\": %lld, \"last_ops\": %d, \"last_varnodes\": %d, \"final_ops\": %d}}\n",
		(unsigned long long)fd.getAddress().getOffset(),(int)iit->second.calls,(long long)iit->second.micros,(long long)iit->second.sumOps,
		(long long)iit->second.sumVarnodes,(int)iit->second.lastOps,(int)iit->second.lastVarnodes,(int)ops);
	fclose(log);
      }
      romwrightInferStats().erase(&fd);
    }
  }
  if (getenv("ROMWRIGHT_CAST_TRACE") != (const char *)0) {
    list<PcodeOp *>::const_iterator oiter;
    for(oiter=fd.beginOpAlive();oiter!=fd.endOpAlive();++oiter) {
	const PcodeOp *op = *oiter;
	if (op->code() != CPUI_STORE) continue;
	fprintf(stderr,"trace store t=%d ptr=%s(%d,%d) value=%s(%d)\n",(int)op->getTime(),op->getIn(1)->getHighTypeReadFacing(op)->getName().c_str(),
		(int)op->getIn(1)->getHighTypeReadFacing(op)->getMetatype(),(int)op->getIn(1)->getSize(),
		op->getIn(2)->getHighTypeReadFacing(op)->getName().c_str(),(int)op->getIn(2)->getHighTypeReadFacing(op)->getMetatype());
    }
  }
  bool rust = romwrightCastsMode() == 0 && !romwrightNativeStructure() && romwrightIrProjections().empty();
  PrintC *print = dynamic_cast<PrintC *>(language);
  ArchitectureGhidra *arch = dynamic_cast<ArchitectureGhidra *>(fd.getArch());
  if (print == (PrintC *)0 || arch == (ArchitectureGhidra *)0) rust = false;
  bool verify = false;
  if (rust) {
    RomwrightIrBytes query;
    Emit *&slot(RomwrightPrintCAccess::emitOf(print));
    Emit *saved = slot;
    uint4 mods = RomwrightPrintCAccess::modsOf(print);
    try {
      if (!sit->second.castFacts.valid)	// a render after edits reuses the facts read before the first probe
	romwrightCaptureCastFacts(print,fd,sit->second.castFacts);
      RomwrightPrintIrExport exporter(print,fd,query,true,&sit->second.castFacts);
      slot = exporter.captureEmit();
      exporter.castQuery(0);
      slot = saved;
    }
    catch(LowlevelError &err) {
      slot = saved;
      RomwrightPrintCAccess::modsOf(print) = mods;
      print->clear();
      rust = false;
    }
    if (rust) {
      string answer = arch->romwrightStructureQuery(query.data);
      verify = answer.size() > 0 && answer[0] == 'v';
      rust = answer.size() > 0 && answer[0] == 'o';
      if (rust) {
	// The warnings ActionSetCasts::checkPointerIssues would have added: (op time, opcode) pairs.
	string rest = answer.substr(1);
	RomwrightIrReader reader(rest);
	uint8 n = reader.u();
	map<uintm,const PcodeOp *> byTime;
	if (n > 0) {
	  list<PcodeOp *>::const_iterator oiter;
	  for(oiter=fd.beginOpAlive();oiter!=fd.endOpAlive();++oiter)
	    byTime[(*oiter)->getTime()] = *oiter;
	}
	for(uint8 i=0;i<n;++i) {
	  uint8 time = reader.u();
	  uint8 code = reader.u();
	  map<uintm,const PcodeOp *>::const_iterator found = byTime.find((uintm)time);
	  if (found == byTime.end()) throw LowlevelError("Cast answer names a missing op");
	  string name = (code == CPUI_LOAD) ? "Load" : "Store";
	  fd.warning(name + " size is inaccurate",found->second->getAddr());
	}
      }
    }
  }
  if (rust)
    sit->second.castsPending = true;
  else {
    ActionSetCasts stock("");
    stock.apply(fd);
    if (verify) {
      // The decompiler's own casts, for the worker to compare its casts with (ROMWRIGHT_RUST_CASTS=verify).
      RomwrightIrBytes query;
      Emit *&slot(RomwrightPrintCAccess::emitOf(print));
      Emit *saved = slot;
      uint4 mods = RomwrightPrintCAccess::modsOf(print);
      try {
	RomwrightPrintIrExport exporter(print,fd,query,true);
	slot = exporter.captureEmit();
	exporter.castQuery(1);
	slot = saved;
	arch->romwrightStructureQuery(query.data);
      }
      catch(LowlevelError &err) {
	slot = saved;
	RomwrightPrintCAccess::modsOf(print) = mods;
	print->clear();
      }
    }
  }
}

}
#endif
