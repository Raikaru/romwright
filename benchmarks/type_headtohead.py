#!/usr/bin/env python3
"""Type recovery scored against DWARF truth, romwright vs stock Ghidra.

`dwarf_gate.py` scores *which functions* each tool finds. This scores *what
type each tool recovers* for the parameters and return — the axis where a
decompiler is actually better or worse than Ghidra, not just at parity.

Both producers read the same STRIPPED binary: Ghidra through the Stage-1
bridge's decompiler (its inferred prototype, not a DWARF-read signature),
romwright through `infer-types`. Truth is the compiler's own `DW_AT_type`
from the unstripped twin, projected to comparable classes by
`dwarf_types.py`.

A type is scored per parameter and per return:
  exact   — kind, width and sign all match truth.
  partial — right family and width but the sign is unresolved (`num32`
            where truth says `int32`), or a code/data pointer distinction.
  wrong   — anything else: unknown, wrong width, or a pointer read as an
            integer (the `long param_1` that is really a `struct *`).

The report records both tools' scores and the per-class breakdown so the
delta is evidence, not anecdote. The gate asserts romwright's score holds
its recorded floor; the Ghidra column is the baseline it is measured
against, exactly as m3-002 froze the function-recovery baseline.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import dwarf_types  # noqa: E402

CLI = ROOT / "target/release/romwright-cli"
# A fixture that exercises every recoverable class: signed and unsigned
# integers at several widths, floats, and pointers used as scalars, struct
# bases, and arrays. -fno-inline keeps each function's own signature.
# Freestanding so clang can cross-compile it for any target without a
# sysroot — `main` returns a checksum of the calls rather than printing.
FIXTURE = r"""
struct Point { float x; float y; int id; };
struct Node { struct Node *next; long value; };
int add_ints(int a, int b) { return a + b; }
int sub_ints(int a, int b) { return a - b; }
unsigned int mix_uint(unsigned int a, unsigned int b) { return (a ^ b) + (a & b); }
unsigned long shift_ul(unsigned long v, int s) { return v >> s; }
float scale(float v, float s) { return v * s; }
double widen(double d, double e) { return d * e; }
int deref(struct Point *p) { return p->id; }
float point_x(struct Point *p) { return p->x; }
long sum_arr(long *arr, int n) { long s=0; for(int i=0;i<n;i++) s+=arr[i]; return s; }
int field2(struct Point *p) { return p->id + (int)p->y; }
struct Node *next_node(struct Node *n) { return n->next; }
long node_val(struct Node *n) { return n->value; }
char first_char(char *s) { return s[0]; }
int is_neg(int v) { return v < 0; }
void noop(void) {}
int main(void) {
    struct Point p = {1.0f, 2.0f, 7};
    struct Node n = {0, 42};
    long a[3] = {1,2,3};
    char s[] = "hi";
    noop();
    return add_ints(2,3) + sub_ints(5,1) + (int)mix_uint(5,6)
        + (int)shift_ul(8,1) + (int)scale(1.5f,2.0f) + (int)widen(3.0,4.0)
        + deref(&p) + (int)point_x(&p) + (int)sum_arr(a,3) + field2(&p)
        + (next_node(&n) != 0) + (int)node_val(&n) + first_char(s) + is_neg(-1);
}
"""

# Per-target compile recipes. Each maps a target name to the commands that
# build the unstripped and stripped executables. clang is a native
# multi-target cross-compiler, so a freestanding fixture needs no sysroot.
TARGETS = {
    "x86_64": {
        "cc": ["gcc", "-g", "-O0", "-fno-inline"],
        "cc_strip": ["gcc", "-O0", "-fno-inline"],
        "strip": ["strip", "--strip-all"],
    },
    "mips32le": {
        "cc": ["clang", "-target", "mipsel-linux-gnu", "-g", "-O0",
               "-fno-inline", "-nostdlib", "-static", "-Wl,-e,main",
               "-fuse-ld=lld"],
        "cc_strip": ["clang", "-target", "mipsel-linux-gnu", "-O0",
                     "-fno-inline", "-nostdlib", "-static", "-Wl,-e,main",
                     "-fuse-ld=lld"],
        "strip": ["llvm-strip", "--strip-all"],
    },
    "mips32be": {
        "cc": ["clang", "-target", "mips-linux-gnu", "-g", "-O0",
               "-fno-inline", "-nostdlib", "-static", "-Wl,-e,main",
               "-fuse-ld=lld"],
        "cc_strip": ["clang", "-target", "mips-linux-gnu", "-O0",
                     "-fno-inline", "-nostdlib", "-static", "-Wl,-e,main",
                     "-fuse-ld=lld"],
        "strip": ["llvm-strip", "--strip-all"],
    },
    "aarch64": {
        "cc": ["clang", "-target", "aarch64-linux-gnu", "-g", "-O0",
               "-fno-inline", "-nostdlib", "-static", "-Wl,-e,main",
               "-fuse-ld=lld"],
        "cc_strip": ["clang", "-target", "aarch64-linux-gnu", "-O0",
                     "-fno-inline", "-nostdlib", "-static", "-Wl,-e,main",
                     "-fuse-ld=lld"],
        "strip": ["llvm-strip", "--strip-all"],
    },
}

# --- normalization to (kind, width) -------------------------------------
# kind in {int, uint, num, float, ptr, code, void, bool, aggregate, unknown}
# width in bits, None where the kind carries none.

def norm_truth(t):
    m = re.fullmatch(r"(int|uint|float)(\d+)", t or "")
    if m:
        return (m.group(1), int(m.group(2)))
    return (t or "unknown", None)


def norm_ours(t):
    t = (t or "unknown").strip()
    if t.startswith("*") or "[stride" in t:
        return ("ptr", None)
    # `opaque<N>` is a loaded value of known width and unproven kind — the
    # same information Ghidra's `undefined<N>` carries, scored as a number.
    m = re.fullmatch(r"(int|uint|num|float|opaque)(\d+)", t)
    if m:
        kind = "num" if m.group(1) == "opaque" else m.group(1)
        return (kind, int(m.group(2)))
    if t in ("ptr", "code", "void", "bool"):
        return (t, 8 if t == "bool" else None)
    return ("unknown", None)


GHIDRA_INT = {
    "int": ("int", 32), "long": ("int", 64), "long long": ("int", 64),
    "short": ("int", 16), "char": ("int", 8), "schar": ("int", 8),
    "uint": ("uint", 32), "ulong": ("uint", 64), "unsigned long": ("uint", 64),
    "unsigned int": ("uint", 32), "ushort": ("uint", 16), "uchar": ("uint", 8),
    "byte": ("uint", 8), "unsigned char": ("uint", 8),
    "float": ("float", 32), "double": ("float", 64),
    "bool": ("bool", 8), "void": ("void", None),
}


def norm_ghidra(t):
    t = (t or "undefined").strip()
    if t.endswith("*") or "*" in t:
        return ("ptr", None)
    m = re.fullmatch(r"undefined(\d+)", t)
    if m:
        return ("num", int(m.group(1)) * 8)
    if t == "undefined":
        return ("unknown", None)
    return GHIDRA_INT.get(t, ("unknown", None))


# IDA spells integers by width: `__int64`/`_QWORD` are signed 64, `_DWORD`
# 32, `_WORD` 16, `_BYTE`/`char` 8. A `*` anywhere is a pointer; `void` is
# void. Calling-convention words are stripped before the type is read.
IDA_INT = {
    "__int64": ("int", 64), "_qword": ("int", 64), "longlong": ("int", 64),
    "long": ("int", 64), "__int32": ("int", 32), "_dword": ("int", 32),
    "int": ("int", 32), "long int": ("int", 32),
    "__int16": ("int", 16), "_word": ("int", 16), "short": ("int", 16),
    "__int8": ("int", 8), "_byte": ("int", 8), "char": ("int", 8),
    "unsigned __int64": ("uint", 64), "unsigned int": ("uint", 32),
    "unsigned __int32": ("uint", 32), "unsigned short": ("uint", 16),
    "unsigned char": ("uint", 8), "unsigned __int16": ("uint", 16),
    "unsigned __int8": ("uint", 8), "uint": ("uint", 32),
    "float": ("float", 32), "double": ("float", 64),
    "bool": ("bool", 8), "void": ("void", None),
}
IDA_CC = {"__fastcall", "__stdcall", "__cdecl", "__thiscall", "__usercall",
          "__userpurge", "__noreturn", "__ptr64", "__ptr32", "__spoils"}


def norm_ida(t):
    t = (t or "").strip()
    if not t:
        return ("unknown", None)
    if "*" in t:
        return ("ptr", None)
    # strip calling-convention and qualifier words
    words = [w for w in t.split() if w not in IDA_CC]
    t = " ".join(words)
    return IDA_INT.get(t, IDA_INT.get(t.lower(), ("unknown", None)))


def parse_ida_signature(sig):
    """`__int64 __fastcall(int a1, char **a2)` -> (return, [params])."""
    if not sig:
        return ("", [])
    m = re.match(r"\s*(.+?)\s*\((.*)\)\s*$", sig)
    if not m:
        return (sig, [])
    ret, params = m.group(1).strip(), m.group(2).strip()
    if params in ("", "void"):
        plist = []
    else:
        plist = []
        for p in params.split(","):
            p = p.strip()
            if p == "...":
                continue
            # drop the parameter name (a trailing `aN`/`vN` identifier)
            p = re.sub(r"\b[a-zA-Z_]\w*\s*$", "", p).strip()
            plist.append(p)
    return (ret, plist)


def score(truth, got):
    """(exact, partial, wrong) for one slot."""
    tk, tw = truth
    gk, gw = got
    if tk == "unknown":
        return (0, 0, 0)  # absent truth is not scored
    if gk == "unknown":
        return (0, 0, 1)
    if gk == tk and gw == tw:
        return (1, 0, 0)
    # right family+width, sign unresolved
    if tk in ("int", "uint") and gk == "num" and gw == tw:
        return (0, 1, 0)
    # pointer vs code pointer
    if tk == "ptr" and gk in ("ptr", "code"):
        return (1, 0, 0)
    if tk == "code" and gk == "ptr":
        return (0, 1, 0)
    return (0, 0, 1)


def parse_ghidra_signature(sig):
    """`int FUN_x(int a,long *b)` -> (return, [params])."""
    if not sig:
        return ("undefined", [])
    m = re.match(r"\s*(.+?)\s+\w+\s*\((.*)\)", sig)
    if not m:
        return ("undefined", [])
    ret, params = m.group(1).strip(), m.group(2).strip()
    if params in ("", "void"):
        plist = []
    else:
        plist = []
        for p in params.split(","):
            p = p.strip()
            if p == "...":
                continue
            # drop the parameter name (last identifier); keep the type
            p = re.sub(r"\b\w+\s*$", "", p).strip()
            plist.append(p if p else "undefined")
    return (ret, plist)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, **kw)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", type=Path, default=None)
    ap.add_argument("--target", default="x86_64", choices=sorted(TARGETS),
                    help="processor target to compile the fixture for")
    ap.add_argument("--floor", type=float, default=0.0,
                    help="minimum romwright weighted score")
    args = ap.parse_args()
    recipe = TARGETS[args.target]

    run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"], check=True)

    with tempfile.TemporaryDirectory(prefix="typeh2h-") as td:
        work = Path(td)
        src = work / "fixture.c"
        src.write_text(FIXTURE)
        unstripped = work / "fixture"
        stripped = work / "fixture_s"
        run(recipe["cc"] + ["-o", str(unstripped), str(src)], check=True)
        run(recipe["cc_strip"] + ["-o", str(stripped), str(src)], check=True)
        run(recipe["strip"] + [str(stripped)], check=True)
        # The projected truth: concrete subprogram types from the twin.
        truth_json = json.loads(run(
            [sys.executable, str(ROOT / "benchmarks/dwarf_types.py"),
             str(unstripped)], check=True).stdout)
        truth_fns = truth_json["functions"]

        # our inference on the stripped binary
        proj = work / "proj"
        prog = stripped.stem
        run([str(CLI), "import", str(stripped), "--name", prog,
             "--project", str(proj)], check=True)
        addrs = ",".join(truth_fns.keys())
        ours = {}
        res = run([str(CLI), "infer-types", str(stripped), prog, addrs,
                   "--project", str(proj), "--json"])
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                d = json.loads(line)
                ours[d["entry"]] = d

        # Ghidra's inferred signatures on the stripped binary. The bridge
        # names the program by the binary's basename, so decompile uses it.
        run([str(CLI), "import", str(stripped), "--oracle", "--name", prog,
             "--project", str(proj)], check=True)
        ghidra = {}
        for addr in truth_fns:
            res = run([str(CLI), "decompile", prog, f"0x{addr}",
                       "--oracle", "--project", str(proj)])
            sig = ""
            for line in res.stdout.splitlines():
                line = line.strip()
                if re.match(r".*\bFUN_[0-9a-f]+\s*\(", line) or re.match(
                        r"^\w[\w\s\*]*\w+\s*\(", line):
                    sig = line
                    break
            ghidra[addr] = parse_ghidra_signature(sig)

        # IDA's inferred signatures on the stripped binary, via idalib +
        # Hex-Rays. Skipped when IDA is not installed.
        ida = {}
        ida_script = ROOT / "benchmarks/ida_signatures.py"
        ida_env = dict(os.environ)
        ida_env["PYTHONPATH"] = (
            "/home/raikaru/ida-pro-9.4/idalib/python:"
            "/home/raikaru/ida-pro-9.4/python")
        try:
            res = subprocess.run(
                [sys.executable, str(ida_script), str(stripped)],
                capture_output=True, text=True, cwd=ROOT, env=ida_env,
                timeout=180)
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    raw = json.loads(line)
                    for ea, s in raw.items():
                        ida[f"{int(ea, 16):08x}"] = parse_ida_signature(s)
        except Exception:
            pass

    # score
    rows = []
    tot = {"ours": [0, 0, 0], "ghidra": [0, 0, 0], "ida": [0, 0, 0]}
    for addr, f in truth_fns.items():
        tparams = [norm_truth(p) for p in f["parameters"]]
        tret = norm_truth(f["returns"])
        o = ours.get(addr, {})
        # our params: structural, falling back to float_parameters for
        # float slots (the solver keeps float regs in a separate list)
        oparams = []
        sp = o.get("structural", [])
        fp = o.get("float_parameters", [])
        for i in range(len(tparams)):
            cand = sp[i] if i < len(sp) else "unknown"
            if norm_ours(cand)[0] == "unknown" and i < len(fp):
                cand = fp[i]
            oparams.append(norm_ours(cand))
        oret = norm_ours(o.get("returns"))
        gret_s, gparams_s = ghidra.get(addr, ("undefined", []))
        gparams = [norm_ghidra(p) for p in gparams_s]
        gret = norm_ghidra(gret_s)
        iret_s, iparams_s = ida.get(addr, ("", []))
        iparams = [norm_ida(p) for p in iparams_s]
        iret = norm_ida(iret_s)

        row = {"entry": addr, "name": f["name"],
               "ours": [], "ghidra": [], "ida": []}
        for i, tp in enumerate(tparams):
            og = oparams[i] if i < len(oparams) else ("unknown", None)
            gg = gparams[i] if i < len(gparams) else ("unknown", None)
            ig = iparams[i] if i < len(iparams) else ("unknown", None)
            so = score(tp, og)
            sg = score(tp, gg)
            si = score(tp, ig)
            for k in range(3):
                tot["ours"][k] += so[k]
                tot["ghidra"][k] += sg[k]
                tot["ida"][k] += si[k]
            row["ours"].append({"truth": f["parameters"][i], "got": sp[i] if i < len(sp) else "unknown", "score": so})
            row["ghidra"].append({"truth": f["parameters"][i], "got": gparams_s[i] if i < len(gparams_s) else "undefined", "score": sg})
            row["ida"].append({"truth": f["parameters"][i], "got": iparams_s[i] if i < len(iparams_s) else "", "score": si})
        so = score(tret, oret)
        sg = score(tret, gret)
        si = score(tret, iret)
        for k in range(3):
            tot["ours"][k] += so[k]
            tot["ghidra"][k] += sg[k]
            tot["ida"][k] += si[k]
        row["ours"].append({"truth": f["returns"], "got": o.get("returns", "unknown"), "score": so, "return": True})
        row["ghidra"].append({"truth": f["returns"], "got": gret_s, "score": sg, "return": True})
        row["ida"].append({"truth": f["returns"], "got": iret_s, "score": si, "return": True})
        rows.append(row)

    def weighted(v):
        e, p, w = v
        return e + 0.5 * p
    total_slots = sum(sum(r[k] for k in range(3)) for r in tot.values()) // 3
    report = {
        "id": "type-headtohead",
        "slots": total_slots,
        "ours": {"exact": tot["ours"][0], "partial": tot["ours"][1],
                 "wrong": tot["ours"][2], "score": weighted(tot["ours"])},
        "ghidra": {"exact": tot["ghidra"][0], "partial": tot["ghidra"][1],
                   "wrong": tot["ghidra"][2], "score": weighted(tot["ghidra"])},
        "ida": {"exact": tot["ida"][0], "partial": tot["ida"][1],
                "wrong": tot["ida"][2], "score": weighted(tot["ida"])},
        "rows": rows,
    }
    out = json.dumps(report, indent=1)
    if args.report:
        args.report.write_text(out + "\n")
    print(f"romwright  exact={tot['ours'][0]} partial={tot['ours'][1]} "
          f"wrong={tot['ours'][2]}  score={weighted(tot['ours'])}")
    print(f"ghidra     exact={tot['ghidra'][0]} partial={tot['ghidra'][1]} "
          f"wrong={tot['ghidra'][2]}  score={weighted(tot['ghidra'])}")
    print(f"ida        exact={tot['ida'][0]} partial={tot['ida'][1]} "
          f"wrong={tot['ida'][2]}  score={weighted(tot['ida'])}")
    return 0 if weighted(tot["ours"]) >= args.floor else 1


if __name__ == "__main__":
    sys.exit(main())
