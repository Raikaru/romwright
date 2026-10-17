// sleigh_diff: the disassembly / p-code differential between two compiled languages.
//
// Disassembles (or lifts) every aligned word of a 32-bit little-endian ELF's executable
// segments, or of a word list, with one compiled .sla and prints one line per word:
//   ADDR WORD MNEMONIC OPERANDS len=N      (p-code: one indented line per op after it)
// Run it once per .sla and diff the outputs. `cop2hash` hashes the disassembly of all
// 3 x 2^26 words of the primary opcodes that carry R5900 COP2 (18, lqc2 54, sqc2 62).
//
// Build against the pinned decompiler sources (libsla.a), outside the pinned tree:
//   cp -r third_party/ghidra/decompiler /tmp/sla && make -C /tmp/sla libsla.a
//   g++ -std=c++11 -O2 -I/tmp/sla native/sleigh_diff.cc /tmp/sla/libsla.a -lz -o sleigh_diff
// usage: sleigh_diff SLA asm|pcode ELF | SLA asm|pcode -words (hex words on stdin) | SLA cop2hash x
#include "loadimage.hh"
#include "sleigh.hh"
#include "emulate.hh"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdio>
using namespace ghidra;
using std::cout; using std::cerr; using std::string;

struct Seg { uint64_t va; std::vector<uint8_t> b; };
class Img : public LoadImage {
public:
  std::vector<Seg> segs;
  Img() : LoadImage("img") {}
  void loadFill(uint1 *ptr, int4 size, const Address &addr) override {
    uint64_t a = addr.getOffset();
    for (int i = 0; i < size; i++) {
      uint64_t x = a + i; ptr[i] = 0;
      for (auto &s : segs) if (x >= s.va && x < s.va + s.b.size()) { ptr[i] = s.b[x - s.va]; break; }
    }
  }
  string getArchType() const override { return "img"; }
  void adjustVma(long) override {}
};
struct Asm : public AssemblyEmit {
  string m, b;
  void dump(const Address &, const string &mn, const string &body) override { m = mn; b = body; }
};
struct Pc : public PcodeEmit {
  Translate *t; std::vector<string> uo; std::ostringstream o;
  void vd(const VarnodeData &d) {
    o << '(' << d.space->getName() << ',';
    if (d.space->getType() == IPTR_CONSTANT) o << "0x" << std::hex << d.offset << std::dec;
    else d.space->printOffset(o, d.offset);
    o << ',' << d.size << ')';
  }
  void dump(const Address &, OpCode opc, VarnodeData *out, VarnodeData *v, int4 n) override {
    o << "    ";
    if (out) { vd(*out); o << " = "; }
    o << get_opname(opc);
    for (int i = 0; i < n; i++) {
      o << ' ';
      if (opc == CPUI_CALLOTHER && i == 0) o << uo[(int4)v[0].offset];
      else vd(v[i]);
    }
    o << '\n';
  }
};

static uint64_t fnv(uint64_t h, const std::string &s) { for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; } return h; }
// -cop2hash: every word of the three COP2-bearing primary opcodes (cop2 = 18, lqc2 = 54, sqc2 = 62),
// asm text only, hashed per primary opcode.
static int cop2hash(const char *sla) {
  const uint32_t CHUNK = 1u << 19;
  for (uint32_t prime : {18u, 54u, 62u}) {
    uint64_t h = 1469598103934665603ULL; uint64_t errs = 0, n = 0;
    for (uint32_t c = 0; c < (1u << 26) / CHUNK; c++) {
      Img img; ContextInternal ctx; Sleigh trans(&img, &ctx); DocumentStorage ds;
      std::istringstream fn(string("<sleigh>") + sla + "</sleigh>");
      Element *root = ds.parseDocument(fn)->getRoot(); ds.registerTag(root); trans.initialize(ds);
      Seg s; s.va = 0x100000; s.b.resize(CHUNK * 8, 0);
      for (uint32_t i = 0; i < CHUNK; i++) { uint32_t w = (prime << 26) | (c * CHUNK + i); memcpy(&s.b[i * 8], &w, 4); }
      img.segs.push_back(s);
      Asm ae;
      for (uint32_t i = 0; i < CHUNK; i++) {
        Address ad(trans.getDefaultCodeSpace(), 0x100000 + (uint64_t)i * 8);
        try { int len = trans.printAssembly(ae, ad); h = fnv(h, ae.m + " " + ae.b + " " + std::to_string(len) + "\n"); }
        catch (LowlevelError &) { errs++; h = fnv(h, "ERR\n"); }
        n++;
      }
    }
    cout << "prime " << prime << " words " << n << " undecodable " << errs << " hash " << std::hex << h << std::dec << "\n";
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 4) { cerr << "sleigh_diff SLA asm|pcode ELF|-words, or SLA cop2hash x\n"; return 2; }
  AttributeId::initialize(); ElementId::initialize();
  if (!strcmp(argv[2], "cop2hash")) return cop2hash(argv[1]);
  Img img; ContextInternal ctx;
  Sleigh trans(&img, &ctx);
  DocumentStorage ds;
  std::istringstream fn(string("<sleigh>") + argv[1] + "</sleigh>");
  Element *root = ds.parseDocument(fn)->getRoot();
  ds.registerTag(root);
  trans.initialize(ds);
  bool pcode = !strcmp(argv[2], "pcode");
  std::vector<std::pair<uint64_t, uint64_t>> ranges;
  if (!strcmp(argv[3], "-words")) {
    // stdin: lines "HEXWORD" -> placed consecutively at 0x100000 with a nop after each
    std::string line; Seg s; s.va = 0x100000;
    while (std::getline(std::cin, line)) {
      uint32_t w = strtoul(line.c_str(), 0, 16);
      for (int k = 0; k < 4; k++) s.b.push_back(w >> (8 * k));
      for (int k = 0; k < 4; k++) s.b.push_back(0);
    }
    ranges.push_back({s.va, s.va + s.b.size()});
    img.segs.push_back(s);
    // step 8
    Asm ae; Pc pe; pe.t = &trans; trans.getUserOpNames(pe.uo);
    for (uint64_t a = s.va; a < s.va + s.b.size(); a += 8) {
      Address ad(trans.getDefaultCodeSpace(), a);
      char buf[32]; uint32_t w; memcpy(&w, &img.segs[0].b[a - s.va], 4);
      try {
        int len = trans.printAssembly(ae, ad);
        pe.o.str(""); 
        snprintf(buf,32,"%08x",w); cout << std::hex << a << " " << buf << " " << ae.m << ' ' << ae.b << " len=" << std::dec << len << '\n';
        if (pcode) { trans.oneInstruction(pe, ad); cout << pe.o.str(); }
      } catch (LowlevelError &e) { cout << std::hex << a << ' ' << "ERR " << e.explain << '\n'; }
    }
    return 0;
  }
  // ELF
  FILE *f = fopen(argv[3], "rb"); std::vector<uint8_t> d(1 << 26); size_t n = fread(d.data(), 1, d.size(), f); d.resize(n);
  uint32_t phoff; memcpy(&phoff, &d[0x1c], 4); uint16_t phes, phn; memcpy(&phes, &d[0x2a], 2); memcpy(&phn, &d[0x2c], 2);
  for (int i = 0; i < phn; i++) {
    uint32_t h[8]; memcpy(h, &d[phoff + i * phes], 32);
    if (h[0] == 1 && (h[6] & 1)) { Seg s; s.va = h[2]; s.b.assign(d.begin() + h[1], d.begin() + h[1] + h[4]); img.segs.push_back(s); }
  }
  Asm ae; Pc pe; pe.t = &trans; trans.getUserOpNames(pe.uo);
  for (auto &s : img.segs) {
    for (uint64_t a = s.va; a + 4 <= s.va + s.b.size(); a += 4) {
      Address ad(trans.getDefaultCodeSpace(), a);
      uint32_t w; memcpy(&w, &s.b[a - s.va], 4);
      try {
        int len = trans.printAssembly(ae, ad);
        pe.o.str("");
        char buf[16]; snprintf(buf, 16, "%08x", w);
        cout << std::hex << a << ' ' << buf << ' ' << ae.m << ' ' << ae.b << " len=" << std::dec << len << '\n';
        if (pcode) { trans.oneInstruction(pe, ad); cout << pe.o.str(); }
      } catch (LowlevelError &e) { cout << std::hex << a << ' ' << "ERR " << e.explain << '\n'; }
    }
  }
}
