#!/usr/bin/env python3
"""Truth fixtures for Windows PE images (the `pc` platform of the console research harness).

A fixture is a directory `<corpus>/pc-<slug>/` in the truth contract of docs/console-research.md:
the *stripped* PE as `image`, `truth/functions.tsv`, `truth/meta.json`, and the unstripped build
(with the PDB or the DWARF) under `truth/build/` so the truth is reproducible from the staged files.

Two truth readers, both from the compiler's own output and never from the importer:

* `--kind pdb`   an MSVC link with `/DEBUG`: `S_GPROC32` / `S_LPROC32` records (start and exact code
  size, also for the CRT objects whose libs carry debug info) read with `llvm-pdbutil`, plus the
  PDB's public function symbols for the code that has no debug info (assembly CRT helpers: size 0
  unless the section contribution at the same address names one), and the 5-byte `jmp` entries of an
  incremental link table (the `* Linker *` module's contribution), each a thunk of its own.
* `--kind coff`  an old MSVC (4.x) link with `/DEBUG /DEBUGTYPE:COFF` (its PDB is the unreadable 2.0 format):
  the COFF symbol table's function-typed symbols are the starts (values are image-relative there); a
  function runs to the next symbol of the code section, less the trailing `int3`/`nop` fill (read from the
  staged image). `--image` names the release link staged as the fixture image (same layout, no symbols;
  the `.text` bytes are compared).
* `--kind dwarf` a MinGW-w64 GCC `-g` link: `DW_TAG_subprogram` (low/high pc) from `llvm-dwarfdump`,
  plus the COFF symbol table's function-typed symbols (type 0x20: the CRT objects have no DWARF; size 0),
  its untyped *external* symbols in code (hand-written assembly labels, import-library `jmp [__imp_X]`
  stubs) and the `.cold` halves GCC splits off a function (a symbol of their own; size 0).

`verified` is 1 for every row: the boundary is the compiler's / linker's, not an analysis.

    pc_truth.py --kind pdb --exe built.exe --pdb built.pdb --out CORPUS/pc-foo --id pc-foo --game "Foo" \\
        --compiler "MSVC 14.00.50727 (VS2005)" --flags "/O2 /MT /Zi" --repo URL --commit SHA --license GPL-2.0

The text output of `llvm-pdbutil` / `llvm-dwarfdump` is what is parsed (LLVM 22).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

TSV_HEADER = "start\tsize\tname\tmodule\tverified"


class Pe:
    """The few PE facts the readers need."""

    def __init__(self, path: Path):
        data = path.read_bytes()
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError(f"{path}: not a PE")
        self.machine, nsec, self.timestamp, self.symtab, self.nsyms, optsize, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
        opt = pe + 24
        self.magic = struct.unpack_from("<H", data, opt)[0]
        self.pe32plus = self.magic == 0x20B
        self.image_base = struct.unpack_from("<Q", data, opt + 24)[0] if self.pe32plus else struct.unpack_from("<I", data, opt + 28)[0]
        self.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        self.linker = (data[opt + 2], data[opt + 3])
        self.sections = []
        at = opt + optsize
        for i in range(nsec):
            name, vsize, rva, rawsize, rawptr, *_rest, flags = struct.unpack_from("<8sIIIIIIHHI", data, at + i * 40)
            self.sections.append({"name": name.rstrip(b"\0").decode("latin1"), "vsize": vsize, "rva": rva,
                                  "rawsize": rawsize, "rawptr": rawptr, "flags": flags})

    def va_of(self, section: int, offset: int) -> int:
        """1-based section number + offset (PDB/COFF style) -> virtual address."""
        return self.image_base + self.sections[section - 1]["rva"] + offset

    def executable(self) -> list[tuple[int, int]]:
        return [(self.image_base + s["rva"], self.image_base + s["rva"] + max(s["vsize"], s["rawsize"]))
                for s in self.sections if s["flags"] & 0x20000000]

    def in_code(self, va: int) -> bool:
        return any(lo <= va < hi for lo, hi in self.executable())

    def coff_symbols(self, with_class: bool = False) -> list[tuple]:
        """(va, name, is_function) of the COFF symbols defined in a section. The value is the offset in the
        section for a GNU ld link and the image-relative address for a Microsoft link: told apart by whether
        every function value lies at or above the section's RVA."""
        if not self.symtab or not self.nsyms:
            return []
        strings = self.symtab + self.nsyms * 18
        raw_syms, i = [], 0
        while i < self.nsyms:
            raw = self.data[self.symtab + i * 18: self.symtab + i * 18 + 18]
            name8, value, section, typ, cls, naux = struct.unpack("<8sIhHBB", raw)
            if name8[:4] == b"\0\0\0\0":
                off = struct.unpack_from("<I", name8, 4)[0]
                end = self.data.index(b"\0", strings + off)
                name = self.data[strings + off:end].decode("latin1")
            else:
                name = name8.rstrip(b"\0").decode("latin1")
            if 0 < section <= len(self.sections) and cls in (2, 3):
                raw_syms.append((section, value, name, (typ >> 4) == 2, cls))
            i += 1 + naux
        funcs = [(sec, v) for sec, v, _n, f, _c in raw_syms if f]
        rva_mode = bool(funcs) and all(v >= self.sections[sec - 1]["rva"] for sec, v in funcs)
        out = []
        for sec, v, name, f, cls in raw_syms:
            va = self.image_base + v if rva_mode else self.va_of(sec, v)
            out.append((va, name, f, cls) if with_class else (va, name, f))
        return out

    def coff_function_symbols(self) -> list[tuple[int, str]]:
        """(va, name) of the COFF symbols typed as functions (derived type 2 in bits 4..7 of `type`)."""
        return [(va, name) for va, name, f in self.coff_symbols() if f]

    def read_va(self, va: int, n: int) -> bytes:
        for s in self.sections:
            lo = self.image_base + s["rva"]
            if lo <= va < lo + s["rawsize"]:
                off = s["rawptr"] + va - lo
                return self.data[off:off + n]
        return b""


def run(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def dwarf_functions(exe: Path, pe: Pe) -> dict[int, tuple[int, str]]:
    """{va: (size, name)} of concrete `DW_TAG_subprogram`s with a low/high pc; `.cold` parts are left out."""
    out: dict[int, tuple[int, str]] = {}
    attrs: dict[str, str] = {}

    def flush() -> None:
        if "low" in attrs and "high" in attrs:
            low = int(attrs["low"], 16)
            high = int(attrs["high"], 16)
            name = attrs.get("name", "")
            if high > low and not name.endswith(".cold"):
                out[low] = (high - low, name)

    in_sub = False
    proc = subprocess.Popen(["llvm-dwarfdump", "--debug-info", str(exe)], stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        if re.match(r"^0x[0-9a-f]+:", line):
            if in_sub:
                flush()
            in_sub = "DW_TAG_subprogram" in line
            attrs = {}
            continue
        if not in_sub:
            continue
        m = re.match(r"\s+DW_AT_(low_pc|high_pc|name|linkage_name)\s+\((.*)\)", line)
        if not m:
            continue
        key, value = m.groups()
        if key == "low_pc":
            attrs["low"] = value.split()[0]
        elif key == "high_pc":
            attrs["high"] = value.split()[0]
        elif key == "name":
            attrs["name"] = value.strip('"')
    if in_sub:
        flush()
    proc.wait()
    return out


def pdb_functions(exe: Path, pdb: Path, pe: Pe) -> dict[int, tuple[int, str]]:
    out: dict[int, tuple[int, str]] = {}
    sym = run(["llvm-pdbutil", "dump", "-symbols", str(pdb)])
    for m in re.finditer(r"S_[GL]PROC32 \[size = \d+\] `([^`]*)`\n\s+parent = \d+, end = \d+, addr = (\d+):(\d+), code size = (\d+)", sym):
        name, seg, off, size = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
        va = pe.va_of(seg, off)
        if pe.in_code(va) and size:
            old = out.get(va)
            if old is None or old[0] < size:
                out[va] = (size, name)
    contrib: dict[int, int] = {}
    for m in re.finditer(r"SC\[[^\]]*\]\s+\| mod = \d+, (\d+):(\d+), size = (\d+)", run(["llvm-pdbutil", "dump", "-section-contribs", str(pdb)])):
        contrib[pe.va_of(int(m.group(1)), int(m.group(2)))] = int(m.group(3))
    # An incremental link (`/INCREMENTAL`, the Debug default) starts `.text` with the linker's incremental link table:
    # one `jmp rel32` per function, the module `* Linker *` owning that contribution. Each entry is a thunk.
    modules = run(["llvm-pdbutil", "dump", "-modules", str(pdb)])
    linker = re.search(r"Mod (\d+) \| `\* Linker \*`", modules)
    if linker:
        index = int(linker.group(1))
        for m in re.finditer(r"SC\[[^\]]*\]\s+\| mod = (\d+), (\d+):(\d+), size = (\d+)", run(["llvm-pdbutil", "dump", "-section-contribs", str(pdb)])):
            if int(m.group(1)) != index:
                continue
            base, length = pe.va_of(int(m.group(2)), int(m.group(3))), int(m.group(4))
            for at in range(0, length - 4, 5):
                if pe.in_code(base + at) and pe.read_va(base + at, 1) == b"\xe9":
                    out.setdefault(base + at, (5, f"ILT+{at}"))
    pub = run(["llvm-pdbutil", "dump", "-publics", str(pdb)])
    for m in re.finditer(r"S_PUB32 \[size = \d+\] `([^`]*)`\n\s+flags = ([^,\n]*)(?:[^\n]*), addr = (\d+):(\d+)", pub):
        name, flags, seg, off = m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
        if "function" not in flags or seg < 1 or seg > len(pe.sections):
            continue
        va = pe.va_of(seg, off)
        if pe.in_code(va) and va not in out:
            out[va] = (contrib.get(va, 0), name)
    return out


def coff_functions(exe: Path, pe: Pe, image: Pe) -> dict[int, tuple[int, str]]:
    """{va: (size, name)} from the COFF symbols of a Microsoft `/DEBUGTYPE:COFF` link: starts exact, ends by the
    next code-section symbol with the trailing fill (`int3`, `nop`) removed, read from `image`."""
    syms = [(va, name, f) for va, name, f in pe.coff_symbols() if pe.in_code(va)]
    # A function runs to the next *function* symbol: the labels inside hand-written assembly (the CRT's
    # floating-point helpers) are untyped symbols of the same function.
    starts = sorted({va for va, _n, f in syms if f})
    out: dict[int, tuple[int, str]] = {}
    for va, name, is_func in sorted(syms):
        if not is_func or va in out:
            continue
        later = [s for s in starts if s > va]
        limit = later[0] if later else next(hi for lo, hi in pe.executable() if lo <= va < hi)
        body = image.read_va(va, limit - va)
        size = len(body.rstrip(b"\xcc\x90"))
        out[va] = (size, name)
    return out


def write_fixture(args, rows: dict[int, tuple[int, str]], pe: Pe) -> None:
    out = Path(args.out)
    (out / "truth" / "build").mkdir(parents=True, exist_ok=True)
    stripped = out / args.image_name
    exe = Path(args.exe)
    shutil.copy2(exe, out / "truth" / "build" / exe.name)
    for extra in args.keep:
        shutil.copy2(extra, out / "truth" / "build" / Path(extra).name)
    if args.pdb:
        shutil.copy2(args.pdb, out / "truth" / "build" / Path(args.pdb).name)
    if args.kind == "dwarf":
        subprocess.run([args.strip or "llvm-strip", "--strip-all", "-o", str(stripped), str(exe)], check=True)
    elif args.kind == "coff":
        shutil.copy2(args.image, stripped)
    else:
        # An MSVC link carries no symbols in the image: the PDB is the only debug file. Stage it as is.
        shutil.copy2(exe, stripped)
    ordered = sorted(rows.items())
    with open(out / "truth" / "functions.tsv", "w") as handle:
        handle.write(TSV_HEADER + "\n")
        for va, (size, name) in ordered:
            handle.write(f"0x{va:08x}\t{size}\t{name}\tmain\t1\n")
    spe = Pe(stripped)
    meta = {
        "id": args.id, "game": args.game, "platform": "pc", "image": args.image_name,
        "truth_kind": {"pdb": "pdb", "dwarf": "dwarf+coff", "coff": "coff"}[args.kind], "compiler": args.compiler, "flags": args.flags,
        "arch": "x86-64" if pe.pe32plus else "x86", "image_base": f"0x{pe.image_base:x}",
        "repo": args.repo, "commit": args.commit, "license": args.license,
        "version_match": True, "strip": False, "sha256": hashlib.sha256(stripped.read_bytes()).hexdigest(),
        "ranges": [[f"0x{lo:x}", f"0x{hi:x}"] for lo, hi in spe.executable()],
        "function_count": len(ordered), "sized": sum(1 for _, (size, _n) in ordered if size),
        "provenance": args.provenance,
    }
    (out / "truth" / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(json.dumps({k: meta[k] for k in ("id", "function_count", "sized", "arch", "sha256")}))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kind", choices=("pdb", "dwarf", "coff"), required=True)
    ap.add_argument("--image", help="--kind coff: the release link to stage (no symbols)")
    ap.add_argument("--exe", required=True, help="the unstripped build (carries the DWARF/COFF symbols; with --kind pdb the linked image)")
    ap.add_argument("--pdb")
    ap.add_argument("--out", required=True)
    ap.add_argument("--id", required=True)
    ap.add_argument("--game", required=True)
    ap.add_argument("--compiler", required=True)
    ap.add_argument("--flags", required=True)
    ap.add_argument("--repo", default="")
    ap.add_argument("--commit", default="")
    ap.add_argument("--license", default="")
    ap.add_argument("--provenance", default="")
    ap.add_argument("--image-name", default=None)
    ap.add_argument("--strip", default=None)
    ap.add_argument("--keep", nargs="*", default=[], help="more build products to keep under truth/build/ (map files, release link)")
    args = ap.parse_args()
    args.image_name = args.image_name or Path(args.exe).name
    exe = Path(args.exe)
    pe = Pe(exe)
    if args.kind == "pdb":
        if not args.pdb:
            ap.error("--pdb is required with --kind pdb")
        rows = pdb_functions(exe, Path(args.pdb), pe)
    elif args.kind == "coff":
        if not args.image:
            ap.error("--image is required with --kind coff")
        image = Pe(Path(args.image))
        for a, b in zip(pe.sections, image.sections):
            if a["name"] != ".text":
                continue
            x = pe.data[a["rawptr"]:a["rawptr"] + a["rawsize"]]
            y = image.data[b["rawptr"]:b["rawptr"] + b["rawsize"]]
            # the two links lay .text out alike; only the 4-byte operands that point into .rdata/.data move
            # (the debug directory shifts what follows it), so the bytes are not equal but nearly all are
            if a["rva"] != b["rva"] or len(x) != len(y) or sum(1 for p, q in zip(x, y) if p != q) > len(x) // 50:
                ap.error("the symbol link and the release link differ in .text")
        rows = coff_functions(exe, pe, image)
    else:
        rows = dict(dwarf_functions(exe, pe))
        for va, name, is_function, cls in pe.coff_symbols(with_class=True):
            if not pe.in_code(va):
                continue
            # A symbol of no function type is a function when it is an external label of hand-written assembly
            # (`___chkstk_ms`, an import library's `jmp [__imp_X]` stub): the linker resolves calls to it by name.
            # The `.cold` half GCC splits off a function has its own function symbol: a start of code the compiler
            # emitted, so a row (size 0).
            if not is_function and cls != 2:
                continue
            if va not in rows:
                rows[va] = (0, name)
            elif not rows[va][1]:
                rows[va] = (rows[va][0], name)
        rows = {va: (size, name or f"sub_{va:x}") for va, (size, name) in rows.items()}
    write_fixture(args, rows, pe)
    return 0


if __name__ == "__main__":
    sys.exit(main())
