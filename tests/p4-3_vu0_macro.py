#!/usr/bin/env python3
"""P4.3: PS2 VU0 macro-mode (COP2) semantics on the r5900 language.

Three layers, each against the installed language (`ROMWRIGHT_GHIDRA`):

  decode      every op family disassembles under its own mnemonic and dest
              suffix, so the lane rewrite changed no decoding;
  semantics   the lifted p-code of every family (all 16 dest masks, the four
              broadcast fields, aliased and vf0 operands, the I/Q/ACC scalars,
              the VI file, the VU0 data memory ops, lqc2/sqc2/qmfc2/qmtc2,
              cfc2/ctc2) is run by a small p-code interpreter and compared
              bit for bit against an independent reference of the VU User's
              Manual (macro-mode instructions are the micro instructions);
  decompile   a ps2sdk-shaped vector routine prints as per-lane float C with
              no `_v*`/`_lqc2`-style unknown call left.

Not modelled, so not tested: MAC/status flags, FTOI saturation, VU
round-toward-zero, +-MAX clamping, the R register, vcallms.

usage: tests/p4-3_vu0_macro.py [--cases N] [--seed S]
env:   ROMWRIGHT_GHIDRA (install holding the compiled r5900 language),
       ROMWRIGHT_CLI (default target/release/romwright-cli)
"""
import argparse
import math
import os
import random
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = Path(os.environ.get("ROMWRIGHT_CLI", ROOT / "target" / "release" / "romwright-cli"))
BASE = 0x100000

# ---------------------------------------------------------------- encodings

def lqc2(ft, off, base): return (54 << 26) | (base << 21) | (ft << 16) | (off & 0xffff)
def sqc2(ft, off, base): return (62 << 26) | (base << 21) | (ft << 16) | (off & 0xffff)
def upper(func, dest, ft, fs, fd):
    return 0x4A000000 | (dest << 21) | (ft << 16) | (fs << 11) | (fd << 6) | func
def special(op7, dest, ft, fs):
    """The 11-bit group: low two bits of the op in bits 0-1, the rest in bits 6-10."""
    return 0x4A000000 | (dest << 21) | (ft << 16) | (fs << 11) | ((op7 >> 2) << 6) | 0x3C | (op7 & 3)
def cop2_move(sub, rt, reg): return (18 << 26) | (sub << 21) | (rt << 16) | (reg << 11)
JR_RA, NOP = 0x03E00008, 0
# control registers a cfc2 reads exactly: VI0-15, CLIP, I, Q. The others (Status, MAC, R and the
# VPU-controlled ones) are written by instructions this language does not model, so a read is opaque.
EXACT_CC = set(range(16)) | {18, 21, 22}

def dest_suffix(dest):
    letters = "".join("xyzw"[i] for i in range(4) if dest >> (3 - i) & 1)
    return "." + letters if letters else ""

# (op7 or func, form) tables. `a` rows go through `special`, others through `upper`.
ARITH = {  # kind: (reg, i, q, bc0)  functions of the D forms
    "add": (0x28, 0x22, 0x20, 0x00), "sub": (0x2C, 0x26, 0x24, 0x04),
    "mul": (0x2A, 0x1E, 0x1C, 0x18), "madd": (0x29, 0x23, 0x21, 0x08),
    "msub": (0x2D, 0x27, 0x25, 0x0C),
}
ARITH_A = {  # (reg, i, q, bc0) op7 of the ACC forms
    "add": (40, 34, 32, 0), "sub": (44, 38, 36, 4), "mul": (42, 30, 28, 24),
    "madd": (41, 35, 33, 8), "msub": (45, 39, 37, 12),
}
MAXMIN = {"max": (0x2B, 0x1D, 0x10), "mini": (0x2F, 0x1F, 0x14)}
SPECIAL = {
    "vabs": 29, "vclip": 31, "vmove": 48, "vmr32": 49, "vopmula": 46, "vnop": 47,
    "vftoi0": 20, "vftoi4": 21, "vftoi12": 22, "vftoi15": 23,
    "vitof0": 16, "vitof4": 17, "vitof12": 18, "vitof15": 19,
    "vdiv": 56, "vsqrt": 57, "vrsqrt": 58, "vwaitq": 59,
    "vmtir": 60, "vmfir": 61, "vilwr": 62, "viswr": 63,
    "vlqi": 52, "vsqi": 53, "vlqd": 54, "vsqd": 55,
}

# ------------------------------------------------------------------- f32

def f32(x):
    try:
        return struct.unpack("<f", struct.pack("<f", x))[0]
    except OverflowError:
        return math.copysign(math.inf, x)
def bits(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]
def fl(b):
    return struct.unpack("<f", struct.pack("<I", b & 0xFFFFFFFF))[0]

# ------------------------------------------------------------- reference

class Ref:
    """The architectural state the macro instructions touch. Lanes are stored as their
    32-bit patterns (an FTOI result is an integer in a float register) and lane 0 is x."""
    def __init__(self, rng):
        r = rng
        def val(): return bits(f32(r.choice([r.uniform(-50, 50), r.uniform(-2, 2), float(r.randint(-9, 9)), r.uniform(0.01, 8)])))
        self.vf = [[val() for _ in range(4)] for _ in range(32)]
        self.vf[0] = [0, 0, 0, bits(1.0)]
        self.acc = [val() for _ in range(4)]
        self.I, self.Q = val(), bits(f32(r.uniform(0.1, 6)))
        self.vi = [0] + [r.randint(0, 0xFFFF) for _ in range(15)]
        self.clip = r.randint(0, 0xFFFFFF)
        self.cc = {n: r.getrandbits(32) for n in range(16, 32) if n not in (18, 21, 22)}   # 18, 21, 22: CLIP, I, Q
        self.gpr = {n: r.getrandbits(128) for n in range(1, 32)}
        self.mem = {0x11004000 + q * 16 + lane * 4: val() for q in range(0x100) for lane in range(4)}
        self.ram = {0x2000 + q * 16 + lane * 4: val() for q in range(8) for lane in range(4)}

def lanes(dest): return [i for i in range(4) if dest >> (3 - i) & 1]
def sext16(v): return v - 0x10000 if v & 0x8000 else v
def sext32(v): return v - (1 << 32) if v & 0x80000000 else v
SCALE = {"0": 1, "4": 16, "12": 4096, "15": 32768}

def ref_exec(st, spec):
    """Apply one instruction (a spec from make_cases) to the Ref `st`."""
    k, vf = spec["k"], st.vf
    dest, fs, ft, fd = spec.get("dest", 0), spec.get("fs", 0), spec.get("ft", 0), spec.get("fd", 0)
    F = lambda b: fl(b)
    def put_vf(reg, i, b):
        if reg != 0: vf[reg][i] = b & 0xFFFFFFFF
    def vi(n): return 0 if n == 0 else st.vi[n]
    def put_vi(n, v):
        if n != 0: st.vi[n] = v & 0xFFFF
    if k == "arith":
        op, form, target, bc = spec["op"], spec["form"], spec["target"], spec.get("bc", 0)
        res = {}
        for i in lanes(dest):
            s = F(vf[fs][i])
            r = {"reg": lambda: F(vf[ft][i]), "i": lambda: F(st.I), "q": lambda: F(st.Q), "bc": lambda: F(vf[ft][bc])}[form]()
            a = F(st.acc[i])
            v = {"add": lambda: s + r, "sub": lambda: s - r, "mul": lambda: s * r,
                 "madd": lambda: a + f32(s * r), "msub": lambda: a - f32(s * r)}[op]()
            res[i] = bits(f32(v))
        for i, b in res.items():
            if target == "d": put_vf(fd, i, b)
            else: st.acc[i] = b
    elif k == "maxmin":
        op, form, bc = spec["op"], spec["form"], spec.get("bc", 0)
        res = {}
        for i in lanes(dest):
            s = F(vf[fs][i])
            t = {"reg": lambda: F(vf[ft][i]), "i": lambda: F(st.I), "bc": lambda: F(vf[ft][bc])}[form]()
            pick_t = (s < t) if op == "max" else (t < s)
            res[i] = bits(t if pick_t else s)
        for i, b in res.items(): put_vf(fd, i, b)
    elif k == "unary":
        n, res = spec["name"], {}
        for i in lanes(dest):
            x = F(vf[fs][i])
            if n == "vabs": res[i] = bits(abs(x))
            elif n == "vmove": res[i] = vf[fs][i]
            elif n == "vmr32": res[i] = vf[fs][(i + 1) % 4]
            elif n.startswith("vftoi"):
                sc = SCALE[n[5:]]
                res[i] = int(f32(x * sc)) & 0xFFFFFFFF if sc != 1 else int(x) & 0xFFFFFFFF
            else:   # vitof
                sc = SCALE[n[5:]]
                v = f32(float(sext32(vf[fs][i])))
                res[i] = bits(f32(v * (1.0 / sc)))
        for i, b in res.items(): put_vf(ft, i, b)
    elif k == "vmfir":
        for i in lanes(dest): put_vf(ft, i, sext16(vi(fs)) & 0xFFFFFFFF)
    elif k == "opmula":
        s, t = [F(b) for b in vf[fs]], [F(b) for b in vf[ft]]
        prod = [s[1] * t[2], s[2] * t[0], s[0] * t[1]]
        for i in lanes(dest):
            if i < 3: st.acc[i] = bits(f32(prod[i]))
    elif k == "opmsub":
        s, t = [F(b) for b in vf[fs]], [F(b) for b in vf[ft]]
        a = [F(b) for b in st.acc]
        prod = [a[0] - f32(s[1] * t[2]), a[1] - f32(s[2] * t[0]), a[2] - f32(s[0] * t[1])]
        for i in lanes(dest):
            if i < 3: put_vf(fd, i, bits(f32(prod[i])))
    elif k == "vclip":
        w = abs(F(vf[ft][3])); x, y, z = (F(vf[fs][i]) for i in range(3))
        b = (x > w) | ((x < -w) << 1) | ((y > w) << 2) | ((y < -w) << 3) | ((z > w) << 4) | ((z < -w) << 5)
        st.clip = ((st.clip << 6) | b) & 0xFFFFFF
    elif k == "vdiv":
        st.Q = bits(f32(F(vf[fs][spec["fsf"]]) / F(vf[ft][spec["ftf"]])))
    elif k == "vsqrt":
        st.Q = bits(f32(math.sqrt(abs(F(vf[ft][spec["ftf"]])))))
    elif k == "vrsqrt":
        st.Q = bits(f32(F(vf[fs][spec["fsf"]]) / f32(math.sqrt(abs(F(vf[ft][spec["ftf"]]))))))
    elif k == "vmtir":
        put_vi(ft, vf[fs][spec["fsf"]])
    elif k == "iop":
        a, b, n = vi(fs), vi(ft), spec["name"]
        if n == "viadd": put_vi(fd, a + b)
        elif n == "visub": put_vi(fd, a - b)
        elif n == "viand": put_vi(fd, a & b)
        elif n == "vior": put_vi(fd, a | b)
        else: put_vi(ft, a + spec["imm5"])
    elif k in ("vlqi", "vlqd", "vsqi", "vsqd"):
        reg = fs if k in ("vlqi", "vlqd") else ft
        if k in ("vlqd", "vsqd"): put_vi(reg, vi(reg) - 1)
        a = 0x11004000 + ((vi(reg) & 0xFF) << 4)
        for i in lanes(dest):
            if k in ("vlqi", "vlqd"): put_vf(ft, i, st.mem[a + 4 * i])
            else: st.mem[a + 4 * i] = vf[fs][i]
        if k in ("vlqi", "vsqi"): put_vi(reg, vi(reg) + 1)
    elif k == "vilwr":
        a = 0x11004000 + ((vi(fs) & 0xFF) << 4)
        put_vi(ft, st.mem[a + 4 * lanes(dest)[0]])
    elif k == "viswr":
        a = 0x11004000 + ((vi(fs) & 0xFF) << 4)
        for i in lanes(dest): st.mem[a + 4 * i] = vi(ft)
    elif k == "lqc2":
        for i in range(4): put_vf(ft, i, st.ram[spec["addr"] + 4 * i])
    elif k == "sqc2":
        for i in range(4): st.ram[spec["addr"] + 4 * i] = vf[ft][i]
    elif k == "qmfc2":
        if spec["rt"] != 0: st.gpr[spec["rt"]] = sum(vf[fs][i] << (32 * i) for i in range(4))
    elif k == "qmtc2":
        g = st.gpr.get(spec["rt"], 0)
        for i in range(4): put_vf(fs, i, g >> (32 * i))
    elif k == "cfc2":
        n = spec["cc"]
        v = vi(n) if n < 16 else {18: st.clip, 21: st.I, 22: st.Q}.get(n) if n in (18, 21, 22) else st.cc[n]
        if spec["rt"] != 0:
            old = st.gpr[spec["rt"]]
            st.gpr[spec["rt"]] = (old & (((1 << 64) - 1) << 64)) | (sext32(v) & ((1 << 64) - 1))
    elif k == "ctc2":
        n, v = spec["cc"], (st.gpr.get(spec["rt"], 0) & 0xFFFFFFFF if spec["rt"] else 0)
        if 0 < n < 16: st.vi[n] = v & 0xFFFF
        elif n == 18: st.clip = v & 0xFFFFFF
        elif n == 21: st.I = v
        elif n == 22: st.Q = v
        elif n >= 16: st.cc[n] = v
    else:
        raise AssertionError(k)

# -------------------------------------------------------------- interpreter

class Machine:
    OPS = None
    def __init__(self):
        self.reg = bytearray(0x6000)
        self.uniq = {}
        self.ram = {}

    def put_reg(self, off, size, val):
        self.reg[off:off + size] = (val & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
    def get_reg(self, off, size):
        return int.from_bytes(self.reg[off:off + size], "little")

    def rd(self, v):
        space, off, size = v
        if space == "const": return off & ((1 << (8 * size)) - 1)
        if space == "register": return self.get_reg(off, size)
        if space == "unique":
            return sum(self.uniq.get(off + i, 0) << (8 * i) for i in range(size))
        raise AssertionError(space)
    def wr(self, v, val):
        space, off, size = v
        val &= (1 << (8 * size)) - 1
        if space == "register": self.put_reg(off, size, val)
        elif space == "unique":
            for i in range(size): self.uniq[off + i] = (val >> (8 * i)) & 0xFF
        else: raise AssertionError(space)

    def run(self, ops):
        pc = 0
        while pc < len(ops):
            name, out, ins = ops[pc]
            pc += 1
            ev = self.eval(name, out, ins)
            if isinstance(ev, tuple) and ev[0] == "jump": pc += ev[1] - 1

    def eval(self, name, out, ins):
        rd = self.rd
        def sgn(v, size): return v - (1 << (8 * size)) if v >> (8 * size - 1) & 1 else v
        def mask(size): return (1 << (8 * size)) - 1
        if name == "COPY": self.wr(out, rd(ins[0]))
        elif name in ("INT_ADD", "INT_SUB", "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_MULT"):
            a, b = rd(ins[0]), rd(ins[1])
            r = {"INT_ADD": a + b, "INT_SUB": a - b, "INT_AND": a & b, "INT_OR": a | b, "INT_XOR": a ^ b,
                 "INT_LEFT": a << b if b < 128 else 0, "INT_RIGHT": a >> b if b < 128 else 0, "INT_MULT": a * b}[name]
            self.wr(out, r)
        elif name == "INT_NEGATE": self.wr(out, ~rd(ins[0]))
        elif name == "INT_SEXT": self.wr(out, sgn(rd(ins[0]), ins[0][2]))
        elif name == "INT_ZEXT": self.wr(out, rd(ins[0]))
        elif name == "INT_EQUAL": self.wr(out, int(rd(ins[0]) == rd(ins[1])))
        elif name == "INT_NOTEQUAL": self.wr(out, int(rd(ins[0]) != rd(ins[1])))
        elif name == "INT_LESS": self.wr(out, int(rd(ins[0]) < rd(ins[1])))
        elif name == "INT_SLESS": self.wr(out, int(sgn(rd(ins[0]), ins[0][2]) < sgn(rd(ins[1]), ins[1][2])))
        elif name == "BOOL_NEGATE": self.wr(out, int(not rd(ins[0])))
        elif name == "SUBPIECE": self.wr(out, rd(ins[0]) >> (8 * rd(ins[1])))
        elif name == "PIECE": self.wr(out, (rd(ins[0]) << (8 * ins[1][2])) | rd(ins[1]))
        elif name == "CBRANCH":
            if rd(ins[1]): return ("jump", sgn(rd(ins[0]), ins[0][2]))
        elif name == "BRANCH": return ("jump", sgn(rd(ins[0]), ins[0][2]))
        elif name == "LOAD":
            addr = rd(ins[1]); size = out[2]
            self.wr(out, sum(self.ram.get(addr + i, 0) << (8 * i) for i in range(size)))
        elif name == "STORE":
            addr = rd(ins[1]); size = ins[2][2]; val = rd(ins[2])
            for i in range(size): self.ram[addr + i] = (val >> (8 * i)) & 0xFF
        elif name.startswith("FLOAT_") or name in ("INT2FLOAT", "TRUNC"):
            self.eval_float(name, out, ins)
        else:
            raise AssertionError(f"p-code op {name} is not modelled by the test interpreter")

    def eval_float(self, name, out, ins):
        rd = self.rd
        def f(v): return fl(rd(v))
        def put(x): self.wr(out, bits(f32(x)))
        if name == "FLOAT_ADD": put(f(ins[0]) + f(ins[1]))
        elif name == "FLOAT_SUB": put(f(ins[0]) - f(ins[1]))
        elif name == "FLOAT_MULT": put(f(ins[0]) * f(ins[1]))
        elif name == "FLOAT_DIV": put(f(ins[0]) / f(ins[1]))
        elif name == "FLOAT_NEG": put(-f(ins[0]))
        elif name == "FLOAT_ABS": put(abs(f(ins[0])))
        elif name == "FLOAT_SQRT": put(math.sqrt(f(ins[0])))
        elif name == "FLOAT_LESS": self.wr(out, int(f(ins[0]) < f(ins[1])))
        elif name == "FLOAT_LESSEQUAL": self.wr(out, int(f(ins[0]) <= f(ins[1])))
        elif name == "FLOAT_EQUAL": self.wr(out, int(f(ins[0]) == f(ins[1])))
        elif name == "INT2FLOAT":
            size = ins[0][2]; v = rd(ins[0])
            if v >> (8 * size - 1) & 1: v -= 1 << (8 * size)
            put(float(v))
        elif name == "TRUNC": self.wr(out, int(f(ins[0])))
        else: raise AssertionError(name)

OFF_VF, OFF_ACC, OFF_VI, OFF_CC = 0x4100, 0x4400, 0x4000, 0x4300
OFF_I, OFF_Q, OFF_CLIP = 0x4354, 0x4358, 0x4348
def gpr_off(n): return n * 16

def load_state(m, st):
    for n in range(32):
        for i in range(4): m.put_reg(OFF_VF + 16 * n + 4 * i, 4, st.vf[n][i])
    for i in range(4): m.put_reg(OFF_ACC + 4 * i, 4, st.acc[i])
    m.put_reg(OFF_I, 4, st.I); m.put_reg(OFF_Q, 4, st.Q)
    for n in range(16): m.put_reg(OFF_VI + 4 * n, 4, st.vi[n])
    m.put_reg(OFF_CLIP, 4, st.clip)
    for n, v in st.cc.items():
        m.put_reg(OFF_CC + 4 * n, 4, v)
    for n, v in st.gpr.items(): m.put_reg(gpr_off(n), 16, v)
    for a, v in st.mem.items():
        for i in range(4): m.ram[a + i] = (v >> (8 * i)) & 0xFF
    for a, v in st.ram.items():
        for i in range(4): m.ram[a + i] = (v >> (8 * i)) & 0xFF

def diff_state(m, st, spec, word):
    bad = []
    for n in range(1, 32):
        for i in range(4):
            got = m.get_reg(OFF_VF + 16 * n + 4 * i, 4)
            if got != st.vf[n][i]: bad.append(f"vf{n}.{'xyzw'[i]} {got:08x} != {st.vf[n][i]:08x}")
    for i in range(4):
        got = m.get_reg(OFF_ACC + 4 * i, 4)
        if got != st.acc[i]: bad.append(f"acc.{'xyzw'[i]} {got:08x} != {st.acc[i]:08x}")
    for name, off, want in (("I", OFF_I, st.I), ("Q", OFF_Q, st.Q), ("clip", OFF_CLIP, st.clip)):
        if m.get_reg(off, 4) != want: bad.append(f"{name} {m.get_reg(off, 4):08x} != {want:08x}")
    for n in range(16):
        if m.get_reg(OFF_VI + 4 * n, 4) != (st.vi[n] if n else 0): bad.append(f"vi{n} {m.get_reg(OFF_VI + 4 * n, 4):x} != {st.vi[n]:x}")
    for n, v in st.cc.items():
        if m.get_reg(OFF_CC + 4 * n, 4) != v: bad.append(f"cc{n} {m.get_reg(OFF_CC + 4 * n, 4):08x} != {v:08x}")
    for n in range(1, 32):
        if m.get_reg(gpr_off(n), 16) != st.gpr[n]: bad.append(f"gpr{n} {m.get_reg(gpr_off(n), 16):032x} != {st.gpr[n]:032x}")
    for a, v in {**st.mem, **st.ram}.items():
        got = sum(m.ram.get(a + i, 0) << (8 * i) for i in range(4))
        if got != v: bad.append(f"mem[{a:x}] {got:08x} != {v:08x}")
    return bad

# ------------------------------------------------------------------- cases

def make_cases(rng, per_family):
    cases = []   # (word, spec, mnemonic, extra setup)
    regs = [0, 1, 2, 3, 4]
    def pick(): return rng.choice(regs)
    def dest(): return rng.randint(0, 15)
    for op, (reg, i, q, bc0) in ARITH.items():
        for form, func in (("reg", reg), ("i", i), ("q", q)):
            for _ in range(per_family):
                d, fs, ft, fd = dest(), pick(), pick(), pick()
                nm = f"v{op}" + {"reg": "", "i": "i", "q": "q"}[form]
                cases.append((upper(func, d, ft, fs, fd), dict(k="arith", op=op, form=form, target="d", dest=d, fs=fs, ft=ft, fd=fd), nm + dest_suffix(d)))
        for bc in range(4):
            for _ in range(per_family):
                d, fs, ft, fd = dest(), pick(), pick(), pick()
                cases.append((upper(bc0 + bc, d, ft, fs, fd), dict(k="arith", op=op, form="bc", bc=bc, target="d", dest=d, fs=fs, ft=ft, fd=fd), f"v{op}{'xyzw'[bc]}" + dest_suffix(d)))
    for op, (reg, i, q, bc0) in ARITH_A.items():
        for form, sp in (("reg", reg), ("i", i), ("q", q)):
            for _ in range(per_family):
                d, fs, ft = dest(), pick(), pick()
                nm = f"v{op}a" + {"reg": "", "i": "i", "q": "q"}[form]
                cases.append((special(sp, d, ft, fs), dict(k="arith", op=op, form=form, target="a", dest=d, fs=fs, ft=ft), nm + dest_suffix(d)))
        for bc in range(4):
            for _ in range(per_family):
                d, fs, ft = dest(), pick(), pick()
                cases.append((special(bc0 + bc, d, ft, fs), dict(k="arith", op=op, form="bc", bc=bc, target="a", dest=d, fs=fs, ft=ft), f"v{op}a{'xyzw'[bc]}" + dest_suffix(d)))
    for op, (reg, i, bc0) in MAXMIN.items():
        for form, func in (("reg", reg), ("i", i)):
            for _ in range(per_family):
                d, fs, ft, fd = dest(), pick(), pick(), pick()
                nm = {"max": ("vmax", "vmaxi"), "mini": ("vmini", "vminii")}[op][form == "i"]
                cases.append((upper(func, d, ft, fs, fd), dict(k="maxmin", op=op, form=form, dest=d, fs=fs, ft=ft, fd=fd), nm + dest_suffix(d)))
        for bc in range(4):
            for _ in range(per_family):
                d, fs, ft, fd = dest(), pick(), pick(), pick()
                nm = "vmax" if op == "max" else "vminibc"
                cases.append((upper(bc0 + bc, d, ft, fs, fd), dict(k="maxmin", op=op, form="bc", bc=bc, dest=d, fs=fs, ft=ft, fd=fd), f"{nm}{'xyzw'[bc]}" + dest_suffix(d)))
    for name in ("vabs", "vmove", "vmr32") + tuple(f"vftoi{n}" for n in (0, 4, 12, 15)) + tuple(f"vitof{n}" for n in (0, 4, 12, 15)):
        for _ in range(per_family):
            d, fs, ft = dest(), pick(), pick()
            cases.append((special(SPECIAL[name], d, ft, fs), dict(k="unary", name=name, dest=d, fs=fs, ft=ft), name + dest_suffix(d)))
    for _ in range(per_family):
        d, fs, ft, fd = dest(), pick(), pick(), pick()
        cases.append((special(SPECIAL["vopmula"], d, ft, fs), dict(k="opmula", dest=d, fs=fs, ft=ft), "vopmula" + dest_suffix(d)))
        d, fs, ft, fd = dest(), pick(), pick(), pick()
        cases.append((upper(0x2E, d, ft, fs, fd), dict(k="opmsub", dest=d, fs=fs, ft=ft, fd=fd), "vopmsub" + dest_suffix(d)))
        d, fs, ft = dest(), pick(), pick()
        cases.append((special(SPECIAL["vclip"], d, ft, fs), dict(k="vclip", dest=d, fs=fs, ft=ft), "vclipw" + dest_suffix(d)))
        for name in ("vdiv", "vsqrt", "vrsqrt"):
            fsf, ftf = rng.randint(0, 3), rng.randint(0, 3)
            fs, ft = rng.choice([1, 2, 3]), rng.choice([1, 2, 3])
            cases.append((special(SPECIAL[name], ftf << 2 | fsf, ft, fs), dict(k=name, fsf=fsf, ftf=ftf, fs=fs, ft=ft, positive=True), name))
        fsf = rng.randint(0, 3)
        fs, ft = pick(), rng.randint(0, 15)
        cases.append((special(SPECIAL["vmtir"], fsf, ft, fs), dict(k="vmtir", fsf=fsf, fs=fs, ft=ft), "vmtir"))
        d, ft, fs = dest(), pick(), rng.randint(0, 15)
        cases.append((special(SPECIAL["vmfir"], d, ft, fs), dict(k="vmfir", dest=d, fs=fs, ft=ft), "vmfir" + dest_suffix(d)))
        for name, func in (("viadd", 0x30), ("visub", 0x31), ("viand", 0x34), ("vior", 0x35)):
            fs, ft, fd = rng.randint(0, 15), rng.randint(0, 15), rng.randint(0, 15)
            cases.append((upper(func, 0, ft, fs, fd), dict(k="iop", name=name, fs=fs, ft=ft, fd=fd), name))
        fs, ft, imm = rng.randint(0, 15), rng.randint(0, 15), rng.randint(-16, 15)
        cases.append((upper(0x32, 0, ft, fs, imm & 31), dict(k="iop", name="viaddi", fs=fs, ft=ft, imm5=imm), "viaddi"))
        for name in ("vlqi", "vlqd"):
            d, ft, fs = dest(), pick(), rng.randint(0, 15)
            cases.append((special(SPECIAL[name], d, ft, fs), dict(k=name, dest=d, fs=fs, ft=ft), name + dest_suffix(d)))
        for name in ("vsqi", "vsqd"):
            d, fs, ft = dest(), pick(), rng.randint(0, 15)
            cases.append((special(SPECIAL[name], d, ft, fs), dict(k=name, dest=d, fs=fs, ft=ft), name + dest_suffix(d)))
        lane = rng.choice([1, 2, 4, 8])
        fs, ft = rng.randint(0, 15), rng.randint(0, 15)
        cases.append((special(SPECIAL["vilwr"], lane, ft, fs), dict(k="vilwr", dest=lane, fs=fs, ft=ft), "vilwr" + dest_suffix(lane)))
        d = dest()
        cases.append((special(SPECIAL["viswr"], d, ft, fs), dict(k="viswr", dest=d, fs=fs, ft=ft), "viswr" + dest_suffix(d)))
        # COP2 <-> EE core
        ft, base = pick(), 9           # t1 holds a quadword address
        off = rng.choice([0, 16, 32, 48])
        cases.append((lqc2(ft, off, base), dict(k="lqc2", ft=ft, addr=0x2000 + off, base=base), "lqc2"))
        cases.append((sqc2(ft, off, base), dict(k="sqc2", ft=ft, addr=0x2000 + off, base=base), "sqc2"))
        rt, vf = rng.randint(0, 31), pick()
        cases.append((cop2_move(1, rt, vf), dict(k="qmfc2", rt=rt, fs=vf), "qmfc2"))
        cases.append((cop2_move(5, rt, vf), dict(k="qmtc2", rt=rt, fs=vf), "qmtc2"))
        cc = rng.randint(0, 31)
        cases.append((cop2_move(2, rt, cc), dict(k="cfc2", rt=rt, cc=cc, opaque=cc not in EXACT_CC), "cfc2"))
        cases.append((cop2_move(6, rt, cc), dict(k="ctc2", rt=rt, cc=cc), "ctc2"))
    return cases

# ----------------------------------------------------------------- driver

def build_elf(words, path):
    code = b"".join(struct.pack("<I", w) for w in words)
    eh, ph = 52, 32
    head = b"\x7fELF\x01\x01\x01\x00" + b"\0" * 8
    head += struct.pack("<HHIIIIIHHHHHH", 2, 8, 1, BASE, eh, 0, 0x20924001, eh, ph, 1, 40, 0, 0)
    prog = struct.pack("<8I", 1, eh + ph, BASE, BASE, len(code), len(code), 5, 0x1000)
    Path(path).write_bytes(head + prog + code)

def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)

VAR = re.compile(r"^(\w+):([0-9a-f]+):(\d+)$")
def parse_var(text):
    m = VAR.match(text.strip())
    return (m.group(1), int(m.group(2), 16), int(m.group(3)))

def ir_dump(elf, addrs):
    out = run([CLI, "ir-dump", elf, ",".join(f"{a:x}" for a in addrs)])
    if out.returncode:
        raise SystemExit(f"ir-dump failed: {out.stderr[-400:]}")
    blocks, cur = {}, None
    for line in out.stdout.splitlines():
        if line.startswith("0x"):
            cur = int(line.split()[0], 16); blocks[cur] = []
        elif line.startswith("  "):
            name, rest = line.strip().split(" ", 1)
            outv, ins = rest.split(" <- ")
            blocks[cur].append((name, None if outv == "-" else parse_var(outv), [parse_var(v) for v in ins.split(", ") if v]))
    return blocks

def check_semantics(cases, rng):
    failures, calls = [], 0
    with tempfile.TemporaryDirectory(prefix="vu0-") as tmp:
        for start in range(0, len(cases), 400):
            chunk = cases[start:start + 400]
            elf = Path(tmp) / "t.elf"
            words = [c[0] for c in chunk] + [JR_RA, NOP]
            build_elf(words, elf)
            blocks = ir_dump(elf, [BASE + 4 * i for i in range(len(chunk))])
            for i, (word, spec, mnem) in enumerate(chunk):
                ops = blocks[BASE + 4 * i]
                others = sum(1 for o in ops if o[0] == "CALLOTHER")
                if spec.get("opaque"):
                    if others != 1: failures.append((word, mnem, spec, [f"{others} CALLOTHER ops, wanted one opaque read"]))
                    continue
                calls += others
                st = Ref(rng)
                if spec.get("positive"):
                    for n in (1, 2, 3):
                        st.vf[n] = [bits(f32(abs(fl(v)) + 0.5)) for v in st.vf[n]]
                if "base" in spec:
                    st.gpr[spec["base"]] = 0x2000   # the base register; the instruction adds its offset
                m = Machine(); load_state(m, st)
                m.run(ops)
                ref_exec(st, spec)
                bad = diff_state(m, st, spec, word)
                if bad:
                    failures.append((word, mnem, spec, bad[:4]))
    return failures, calls

def check_decode(cases):
    bad = []
    with tempfile.TemporaryDirectory(prefix="vu0-") as tmp:
        seen = {}
        for word, spec, mnem in cases:
            seen.setdefault(mnem, word)
        items = sorted(seen.items())
        for start in range(0, len(items), 100):
            chunk = items[start:start + 100]
            words = [w for _, w in chunk] + [JR_RA, NOP]
            elf = Path(tmp) / "d.elf"; build_elf(words, elf)
            out = run([CLI, "disasm", elf, f"{BASE:x}", "-n", str(len(chunk))])
            lines = out.stdout.strip().splitlines()
            if out.returncode or len(lines) < len(chunk):
                bad.append(("disasm", (out.stderr or out.stdout)[-200:])); continue
            for (mnem, word), line in zip(chunk, lines):
                # the disassembler glues a literal `ACC` operand to the dest suffix; only the
                # mnemonic and the dest letters count here
                got = re.match(r"[a-z0-9]+(?:\.[xyzw]+)?", line.split(":", 1)[1].strip()).group(0)
                if got != mnem: bad.append((f"{word:08x}", f"expected {mnem}, disassembled {got}"))
    return bad, len(seen)

OPAQUE = re.compile(r"\b_(?:v[a-z0-9]+|lqc2|sqc2|cfc2|ctc2|qmfc2|qmtc2)\s*\(")

def check_decompile():
    """A ps2sdk-style routine: matrix times vector, then a lane-masked blend."""
    words = [
        lqc2(1, 0, 4), lqc2(2, 16, 4), lqc2(3, 32, 4), lqc2(4, 48, 4), lqc2(5, 0, 5),
        upper(0x00, 0xF, 5, 1, 6),                                         # vaddx.xyzw vf6, vf1, vf5
        upper(0x29, 0xF, 3, 2, 6),                                         # vmadd.xyzw vf6, vf2, vf3
        upper(0x2A, 0x8, 4, 3, 7),                                         # vmul.x vf7, vf3, vf4
        special(48, 0x7, 7, 6),                                            # vmove.yzw vf7, vf6
        special(56, 0b0001, 4, 1),                                         # vdiv Q, vf1x, vf4y
        upper(0x1C, 0xF, 6, 7, 6),                                         # vmulq.xyzw vf6, vf7, Q
        sqc2(6, 0, 6), JR_RA, sqc2(7, 16, 6),
    ]
    with tempfile.TemporaryDirectory(prefix="vu0-") as tmp:
        elf, proj, out = Path(tmp) / "f.elf", Path(tmp) / "proj", Path(tmp) / "out"
        build_elf(words, elf)
        imp = run([CLI, "import", elf, "--name", "f", "--project", proj])
        dec = run([CLI, "export-c", elf, "f", out, "--address", f"{BASE:x}", "--project", proj])
        if imp.returncode or dec.returncode:
            return None, (imp.stderr + dec.stderr)[-400:]
        text = "\n".join(p.read_text() for p in sorted(out.glob("*.c")))
        return text, None

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", type=int, default=6, help="random cases per op family variant")
    ap.add_argument("--seed", type=int, default=20261009)
    args = ap.parse_args()
    if not CLI.is_file():
        sys.exit(f"missing {CLI}: cargo build --release -p romwright-cli")
    rng = random.Random(args.seed)
    cases = make_cases(rng, args.cases)
    ok = True

    gen = run([sys.executable, ROOT / "native" / "languages" / "r5900" / "gen_vu.py", "--check"])
    print("generator:", (gen.stdout + gen.stderr).strip())
    ok &= gen.returncode == 0

    dbad, kinds = check_decode(cases)
    print(f"decode: {kinds} mnemonic/dest forms, {len(dbad)} mismatches")
    for b in dbad[:8]: print("  ", b)
    ok &= not dbad

    fails, callothers = check_semantics(cases, rng)
    print(f"semantics: {len(cases)} instructions, {len(fails)} differ from the reference, "
          f"{callothers} CALLOTHER ops in their p-code")
    for word, mnem, spec, bad in fails[:10]:
        print(f"   {word:08x} {mnem} {spec}\n      {bad}")
    ok &= not fails and callothers == 0

    text, err = check_decompile()
    if text is None:
        print("decompile: FAILED", err); ok = False
    else:
        opaque = OPAQUE.findall(text)
        # structure: float lanes, loads from param_1 (as pointer arithmetic or, since the stage 4
        # struct evidence, as `param_1->field_0x..`), stores through param_3, a Q divide
        shapes = [r"\bfloat\b", r"\(float \*\)\(param_1 \+ 0x|param_1->field_0x", r"param_3\[1\]", r" / "]
        missing = [s for s in shapes if not re.search(s, text)]
        print(f"decompile: {len(opaque)} unknown VU calls, missing shapes {missing or 'none'}")
        if opaque or missing:
            print(text); ok = False
    print("p4-3 VU0 macro mode:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
