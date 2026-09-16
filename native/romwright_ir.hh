#ifndef ROMWRIGHT_IR_HH
#define ROMWRIGHT_IR_HH
#include "ghidra_process.hh"
#include "blockaction.hh"
#include "romwright_ir_state.hh"
#include "romwright_nonreturn.hh"
#include <set>
namespace ghidra {

// Private document metadata, not part of Funcdata's persistent serialization.
// Keep the packed id synchronized with worker/prototype.rs.
static ElementId ELEM_ROMWRIGHT_CALLPROTOTYPE("romwright_callprototype",4090);

inline void romwrightEncodeCallPrototypes(const Funcdata &data,Encoder &encoder) {
  for (int4 i=0; i<data.numCalls(); ++i) {
    const FuncCallSpecs *call = data.getCallSpecs(i);
    const PcodeOp *op = call->getOp();
    if (op->isDead())
      continue;
    encoder.openElement(ELEM_ROMWRIGHT_CALLPROTOTYPE);
    encoder.writeUnsignedInteger(ATTRIB_OPREF,op->getTime());
    if (!call->getEntryAddress().isInvalid())
      call->getEntryAddress().encode(encoder);
    // An unlocked FuncCallSpecs store can still be an empty placeholder after
    // recovery. Read the actual call operands, as PrintC::opCall does, while
    // preserving declared parameter lists (including variadic boundaries).
    encoder.openElement(ELEM_PROTOTYPE);
    encoder.writeString(ATTRIB_MODEL,call->getModelName());
    if (call->isDotdotdot())
      encoder.writeBool(ATTRIB_DOTDOTDOT,true);
    if (call->isNoReturn())
      encoder.writeBool(ATTRIB_NORETURN,true);
    encoder.openElement(ELEM_RETURNSYM);
    if (call->isOutputLocked())
      call->getOutputType()->encodeRef(encoder);
    else if (op->getOut() != (Varnode *)0)
      op->getOut()->getHighTypeDefFacing()->encodeRef(encoder);
    else {
      // A discarded result does not prove that the callee returns void.
      encoder.openElement(ELEM_TYPE);
      encoder.writeString(ATTRIB_METATYPE,"unknown");
      encoder.writeSignedInteger(ATTRIB_SIZE,0);
      encoder.closeElement(ELEM_TYPE);
    }
    encoder.closeElement(ELEM_RETURNSYM);
    encoder.openElement(ELEM_INTERNALLIST);
    const bool declared = call->isInputLocked();
    const int4 count = declared ? call->numParams() : op->numInput()-1;
    for (int4 parameter=0; parameter<count; ++parameter) {
      encoder.openElement(ELEM_PARAM);
      Datatype *type = declared ? call->getParam(parameter)->getType()
          : op->getIn(parameter+1)->getHighTypeReadFacing(op);
      type->encodeRef(encoder);
      encoder.closeElement(ELEM_PARAM);
    }
    encoder.closeElement(ELEM_INTERNALLIST);
    encoder.closeElement(ELEM_PROTOTYPE);
    encoder.closeElement(ELEM_ROMWRIGHT_CALLPROTOTYPE);
  }
}

class RenderFunctionIr : public GhidraCommand {
  struct Edit {
    uintb pc;
    uintm time;
    OpCode before;
    OpCode after;
    int4 width;
    uintb constant;
    string helper;
    PcodeOp *op;
  };
  struct Cut { int4 source; int4 slot; int4 target; int4 incoming; };
  Address address;
  vector<Edit> edits;
  vector<Cut> cuts;

  virtual void loadParameters(void) {
    edits.clear();
    cuts.clear();
    GhidraCommand::loadParameters();
    PackedDecode location(ghidra);
    ArchitectureGhidra::readStringStream(sin, location);
    address = Address::decode(location);
    PackedDecode decoder(ghidra);
    ArchitectureGhidra::readStringStream(sin, decoder);
    uint4 root = decoder.openElement(ELEM_DOC);
    while (decoder.peekElement() != 0) {
      uint4 tag = decoder.peekElement();
      if (tag == ELEM_OP) {
        decoder.openElement(ELEM_OP);
        Edit edit;
        edit.pc = decoder.readUnsignedInteger(ATTRIB_OFFSET);
        edit.time = decoder.readUnsignedInteger(ATTRIB_REF);
        edit.before = (OpCode)decoder.readSignedInteger(ATTRIB_OPCODE);
        edit.after = (OpCode)decoder.readSignedInteger(ATTRIB_CODE);
        edit.width = decoder.readSignedInteger(ATTRIB_SIZE);
        edit.constant = decoder.readUnsignedInteger(ATTRIB_VALUE);
        edit.helper = decoder.readString(ATTRIB_NAME);
        edit.op = (PcodeOp *)0;
        edits.push_back(edit);
        decoder.closeElement(tag);
      }
      else if (tag == ELEM_EDGE) {
        decoder.openElement(ELEM_EDGE);
        Cut cut;
        cut.source = decoder.readSignedInteger(ATTRIB_INDEX);
        cut.slot = decoder.readSignedInteger(ATTRIB_REV);
        cut.target = decoder.readSignedInteger(ATTRIB_END);
        cuts.push_back(cut);
        decoder.closeElement(tag);
      }
      else throw LowlevelError("Unknown FunctionIR edit element");
    }
    decoder.closeElement(root);
  }

  void validate(Funcdata *data) {
    std::set<PcodeOp *> seen;
    for (size_t i=0; i<edits.size(); ++i) {
      Edit &edit = edits[i];
      edit.op = data->findOp(SeqNum(Address(address.getSpace(), edit.pc), edit.time));
      if (edit.op == (PcodeOp *)0 || !seen.insert(edit.op).second || edit.op->code() != edit.before)
        throw LowlevelError("FunctionIR operation identity changed");
      PcodeOp *op = edit.op;
      if (edit.width <= 0 || edit.width > 8 || op->getOut() == (Varnode *)0 || op->getOut()->getSize() != edit.width)
        throw LowlevelError("FunctionIR output width mismatch");
      if (edit.before == CPUI_INT_ADD && edit.after == CPUI_INT_SUB && edit.helper.empty()) {
        if (op->numInput() != 2 || !op->getIn(1)->isConstant() ||
            op->getIn(0)->getSize() != edit.width || op->getIn(1)->getSize() != edit.width ||
            op->getIn(1)->getTypeReadFacing(op)->getMetatype() != TYPE_INT)
          throw LowlevelError("FunctionIR subtraction lacks signed constant evidence");
        uintb mask = calc_mask(edit.width);
        uintb bits = op->getIn(1)->getOffset() & mask;
        uintb sign = (uintb)1 << (edit.width*8-1);
        if ((bits & sign) == 0 || bits == sign || edit.constant != ((-bits) & mask))
          throw LowlevelError("FunctionIR subtraction changes the constant value");
      }
      else if (edit.before == CPUI_CALL && !edit.helper.empty()) {
        bool isSigned = edit.after == CPUI_INT_SDIV || edit.after == CPUI_INT_SREM;
        if (!isSigned && edit.after != CPUI_INT_DIV && edit.after != CPUI_INT_REM)
          throw LowlevelError("Unsupported FunctionIR helper projection");
        if (op->numInput() != 3 || op->getIn(0)->getSpace()->getType() != IPTR_FSPEC)
          throw LowlevelError("FunctionIR helper arity mismatch");
        FuncCallSpecs *call = FuncCallSpecs::getFspecFromConst(op->getIn(0)->getAddr());
        if (call->getName() != edit.helper || call->isNoReturn())
          throw LowlevelError("FunctionIR helper identity mismatch");
        type_metatype expected = isSigned ? TYPE_INT : TYPE_UINT;
        if (op->getOut()->getTypeDefFacing()->getMetatype() != expected)
          throw LowlevelError("FunctionIR helper result signedness mismatch");
        for (int4 slot=1; slot<3; ++slot) {
          if (op->getIn(slot)->getSize() != edit.width || op->getIn(slot)->getTypeReadFacing(op)->getMetatype() != expected)
            throw LowlevelError("FunctionIR helper argument type mismatch");
        }
      }
      else throw LowlevelError("Unsupported FunctionIR operation rewrite");
    }
    const BlockGraph &blocks = data->getBasicBlocks();
    std::set<std::pair<int4,int4> > seenCuts;
    for (size_t i=0; i<cuts.size(); ++i) {
      Cut &cut = cuts[i];
      if (cut.source < 0 || cut.source >= blocks.getSize() || cut.slot < 0 ||
          !seenCuts.insert(std::make_pair(cut.source, cut.slot)).second)
        throw LowlevelError("Invalid FunctionIR source edge");
      FlowBlock *source = blocks.getBlock(cut.source);
      if (cut.slot >= source->sizeOut() || source->getOut(cut.slot)->getIndex() != cut.target)
        throw LowlevelError("FunctionIR control-flow edge changed");
      cut.incoming = source->getOutRevIndex(cut.slot);
    }
  }
public:
  virtual void rawAction(void) {
    Funcdata *data = ghidra->symboltab->getGlobalScope()->queryFunction(address);
    if (data == (Funcdata *)0 || !data->isProcComplete())
      throw LowlevelError("FunctionIR requires a completed native function");
    validate(data);  // No mutation before every record has been checked.
    RomwrightIrProjectionScope projection;
    for (size_t i=0; i<edits.size(); ++i) {
      const Edit &edit = edits[i];
      if (!edit.helper.empty()) {
        romwrightIrProjections()[edit.op] = edit.after;
      }
      else {
        Datatype *type = edit.op->getIn(1)->getTypeReadFacing(edit.op);
        Varnode *constant = data->newConstant(edit.width, edit.constant);
        constant->updateType(type, false, true);
        data->opSetInput(edit.op, constant, 1);
        data->opSetOpcode(edit.op, edit.after);
      }
    }
    if (!cuts.empty()) {
      for (size_t i=0; i<cuts.size(); ++i)
        data->getBasicBlocks().getBlock(cuts[i].source)->setGotoBranch(cuts[i].slot);
      data->getStructure().clear();
      ActionBlockStructure structure("");
      structure.apply(*data);
      ActionFinalStructure finalize("");
      finalize.apply(*data);
    }
    sout.write("\000\000\001\016",4);
    PackedEncode encoder(sout);
    encoder.openElement(ELEM_DOC);
    {
      RomwrightNoReturnHint hint(*data);
      data->encode(encoder, 0, true);
    }
    romwrightEncodeCallPrototypes(*data,encoder);
    // Final printing may negate a condition and swap its outgoing slots.
    // The destination's incoming edge preserves identity, including parallel
    // edges; acknowledge both the requested and the projected slot.
    for (size_t i=0; i<cuts.size(); ++i) {
      const Cut &cut = cuts[i];
      FlowBlock *target = data->getBasicBlocks().getBlock(cut.target);
      if (cut.incoming >= target->sizeIn() ||
          target->getIn(cut.incoming)->getIndex() != cut.source)
        throw LowlevelError("FunctionIR projection lost a control-flow edge");
      encoder.openElement(ELEM_BLOCKEDGE);
      for (int4 phase=0; phase<2; ++phase) {
        encoder.openElement(ELEM_EDGE);
        encoder.writeSignedInteger(ATTRIB_INDEX, cut.source);
        encoder.writeSignedInteger(ATTRIB_REV,
            phase == 0 ? cut.slot : target->getInRevIndex(cut.incoming));
        encoder.writeSignedInteger(ATTRIB_END, cut.target);
        encoder.closeElement(ELEM_EDGE);
      }
      encoder.closeElement(ELEM_BLOCKEDGE);
    }
    ghidra->print->docFunction(data);
    encoder.closeElement(ELEM_DOC);
    sout.write("\000\000\001\017",4);
  }
};
}
#endif
