#!/usr/bin/env python3
"""Struct recovery audit: what the inferred layouts are worth, and what blocks printing them.

Measurement only: it changes no product code. Three questions (docs/console-research.md,
"Struct recovery audit"):

  Q1  Accuracy of the layouts `subtype.rs` / `types_infer.rs` infer for pointer parameters,
      against the truth type of the parameter (DWARF where a debug build exists, otherwise the
      donor decompilation's headers and function definitions), per game: field-offset precision
      and recall, width/class agreement, the share of truth struct-pointer parameters that get
      any `Ty::Struct`, the false-struct rate on truth non-struct pointers, how the
      interprocedural merge unifies or fragments one truth struct, how much nesting the
      monomorphic `Field` loses, and what polymorphic callees do to merged layouts.
  Q2  Which struct types of matched functions are shared (same name AND layout hash) by at
      least two independent donors, per platform.
  Q3  Whether rewriting field access as `*(T *)((char *)p + off)` changes the bytes of an exact
      MWCC recompile (20 m22-002 Persona 4 functions).

Stages (`python3 benchmarks/struct_inference_audit.py STAGE [GAME...] [--work DIR]`; each writes JSON under --work and can be
rerun; the donor and DWARF stages need the venv with tree-sitter that benchmarks/fact_pack/extract_prototypes.py documents):

  donor-truth [GAME]   parse the donor repo: struct layouts, per-function parameter truth, the fields the bodies
                       access, call-site argument types, with the PS2 ABI
  dwarf-truth [GAME]   the same from the compiler's debug info (Metrowerks DWARF 1, ee-gcc DWARF 2)
  host-run GAME        on the analysis host, in a synced checkout (--root): build, strip the image, import it, and run
                       benchmarks/struct_audit_dump.rs (copied into crates/romwright-core/examples/, so no product file
                       changes) over every function the import found; writes dump-GAME.json. The runs of the report
                       used `--strong-entries` for the larger images (the driver's docstring says what that changes)
  score [GAME]         join truth and the dump -> scores/GAME.json (cheap, memory is the size of the dump)
  transfer [GAME]      Q2 over the donors in benchmarks/fact_pack/donors.json (their repos under ~/ventris-scratch/factpack)
  exactness            Q3 on a prepared m22-002 work dir (`--work`/q3work/{p4repo,verify_report.json}, see
                       tests/m22-002_ps2_c_output.py `ensure_repo`/`verify_report`); needs /var/tmp/p4ci, wibo
  validate-layouts     the layout engine against MWCC `sizeof` / member-address assertions (same work dir)
  report               benchmarks/reports/struct_inference_audit.{json,md} from everything above
  selftest             layout engine, rewriter and parsers on small inputs, no tools

Clean room: donor repositories are data. Only facts (names, offsets, sizes, hashes) leave them;
no code is copied.
"""
import argparse
import collections
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fact_pack"))

HOME = Path.home()
SCRATCH = HOME / "ventris-scratch" / "factpack"
CORPUS = HOME / "ventris-corpus" / "extracted"
WORK = HOME / "ventris-scratch" / "structaudit"


def log(message):
    print(message, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# C type model
# ---------------------------------------------------------------------------
# A type is a tuple:
#   ("prim", name)            name in PRIMS
#   ("ptr", T)
#   ("code",)                 pointer to function
#   ("arr", T, n_or_None)
#   ("agg", key)              struct / union definition, key into Defs.aggs
#   ("enum", name)
#   ("named", name)           typedef name, resolved through Defs.typedefs
#   ("bad", why)              unresolvable

ABIS = {
    # size, align per primitive; `ptr` bytes. long width follows the compiler's target.
    "ps2": dict(char=(1, 1), short=(2, 2), int=(4, 4), long=(8, 8), longlong=(8, 8), float=(4, 4),
                double=(8, 8), i128=(16, 16), ptr=(4, 4)),
    "ps2-gcc": dict(char=(1, 1), short=(2, 2), int=(4, 4), long=(8, 8), longlong=(8, 8), float=(4, 4),
                    double=(8, 8), i128=(16, 16), ptr=(4, 4)),
    "mips32": dict(char=(1, 1), short=(2, 2), int=(4, 4), long=(4, 4), longlong=(8, 8), float=(4, 4),
                   double=(8, 8), i128=(16, 16), ptr=(4, 4)),
    "ppc32": dict(char=(1, 1), short=(2, 2), int=(4, 4), long=(4, 4), longlong=(8, 8), float=(4, 4),
                  double=(8, 8), i128=(16, 16), ptr=(4, 4)),
    "arm32": dict(char=(1, 1), short=(2, 2), int=(4, 4), long=(4, 4), longlong=(8, 8), float=(4, 4),
                  double=(8, 8), i128=(16, 16), ptr=(4, 4)),
    "gba": dict(char=(1, 1), short=(2, 2), int=(4, 4), long=(4, 4), longlong=(8, 4), float=(4, 4),
                double=(8, 4), i128=(16, 4), ptr=(4, 4)),
}
PLATFORM_ABI = {"ps2": "ps2", "gc": "ppc32", "wii": "ppc32", "n64": "mips32", "psx": "mips32",
                "nds": "arm32", "gba": "gba"}

PRIM_CLASS = {"char": "int", "schar": "int", "uchar": "uint", "short": "int", "ushort": "uint",
              "int": "int", "uint": "uint", "long": "int", "ulong": "uint", "longlong": "int",
              "ulonglong": "uint", "float": "float", "double": "float", "bool": "uint",
              "i128": "int", "u128": "uint", "void": "void"}
PRIM_KIND = {"char": "char", "schar": "char", "uchar": "char", "short": "short", "ushort": "short",
             "int": "int", "uint": "int", "long": "long", "ulong": "long", "longlong": "longlong",
             "ulonglong": "longlong", "float": "float", "double": "double", "bool": "char",
             "i128": "i128", "u128": "i128"}

FALLBACK_TYPEDEFS = {
    "u8": ("prim", "uchar"), "uint8_t": ("prim", "uchar"), "U8": ("prim", "uchar"), "BYTE": ("prim", "uchar"),
    "UCHAR": ("prim", "uchar"), "uchar": ("prim", "uchar"), "u_char": ("prim", "uchar"),
    "s8": ("prim", "schar"), "int8_t": ("prim", "schar"), "S8": ("prim", "schar"),
    "u16": ("prim", "ushort"), "uint16_t": ("prim", "ushort"), "U16": ("prim", "ushort"),
    "WORD": ("prim", "ushort"), "USHORT": ("prim", "ushort"), "ushort": ("prim", "ushort"),
    "u_short": ("prim", "ushort"),
    "s16": ("prim", "short"), "int16_t": ("prim", "short"), "S16": ("prim", "short"),
    "u32": ("prim", "uint"), "uint32_t": ("prim", "uint"), "U32": ("prim", "uint"),
    "DWORD": ("prim", "uint"), "UINT": ("prim", "uint"), "uint": ("prim", "uint"), "u_int": ("prim", "uint"),
    "size_t": ("prim", "uint"), "uintptr_t": ("prim", "uint"),
    "s32": ("prim", "int"), "int32_t": ("prim", "int"), "S32": ("prim", "int"), "INT": ("prim", "int"),
    "ptrdiff_t": ("prim", "int"), "intptr_t": ("prim", "int"), "ssize_t": ("prim", "int"),
    "BOOL": ("prim", "int"), "f32": ("prim", "float"), "f64": ("prim", "double"),
    "float32": ("prim", "float"), "float64": ("prim", "double"),
    "va_list": ("ptr", ("prim", "void")), "wchar_t": ("prim", "ushort"),
}
FALLBACK_64 = {   # 64-bit integer names (width fixed whatever `long` is)
    "u64": ("prim", "ulonglong"), "uint64_t": ("prim", "ulonglong"), "U64": ("prim", "ulonglong"),
    "s64": ("prim", "longlong"), "int64_t": ("prim", "longlong"), "S64": ("prim", "longlong"),
    "ULONG": ("prim", "ulonglong"),
}
FALLBACK_PS2 = {  # SCE SDK / PS2 names the donors use without defining them in-tree
    "u_long": ("prim", "ulong"), "u_long128": ("prim", "u128"), "long128": ("prim", "i128"),
    "u128": ("prim", "u128"), "s128": ("prim", "i128"), "qword": ("prim", "u128"),
    "sceVu0FVECTOR": ("arr", ("prim", "float"), 4, 16), "sceVu0IVECTOR": ("arr", ("prim", "int"), 4, 16),
    "sceVu0FMATRIX": ("arr", ("arr", ("prim", "float"), 4), 4, 16),
    "sceVu0IMATRIX": ("arr", ("arr", ("prim", "int"), 4), 4, 16),
}
FALLBACK_COMMON = {"u_long": ("prim", "ulong"), "u_long128": ("prim", "u128")}

QUAL = {"const", "volatile", "static", "extern", "inline", "register", "restrict", "__restrict",
        "__restrict__", "__inline", "__inline__", "__const", "__extension__", "signed_", "auto"}


# ---------------------------------------------------------------------------
# Scanning struct / union / enum / typedef / macro definitions (tree-sitter-c)
# ---------------------------------------------------------------------------

_TS = {}


def ts_parser():
    if "p" not in _TS:
        import tree_sitter_c
        from tree_sitter import Language, Parser
        _TS["p"] = Parser(Language(tree_sitter_c.language()))
    return _TS["p"]


DEFINE_RE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(\([^)]*\))?[ \t]*(.*?)[ \t]*$", re.M)
INT_WORDS = {"unsigned", "signed", "long", "short", "char", "int", "float", "double", "void", "_Bool",
             "bool", "__int64", "__int32", "__int16", "__int8"}


def prim_of_words(words):
    """Canonical primitive name from specifier words, or None."""
    words = [w for w in words if w not in QUAL]
    unsigned = "unsigned" in words
    signed = "signed" in words
    longs = words.count("long")
    base = next((w for w in words if w not in ("unsigned", "signed", "long", "short")), None)
    if base in ("_Bool", "bool"):
        return "bool"
    if base == "void":
        return "void"
    if base == "float":
        return "float"
    if base == "double":
        return "double"
    if base == "char":
        return "uchar" if unsigned else "schar" if signed else "char"
    if base == "__int64":
        return "ulonglong" if unsigned else "longlong"
    if base == "__int16":
        return "ushort" if unsigned else "short"
    if base == "__int8":
        return "uchar" if unsigned else "schar"
    if base in (None, "int", "__int32"):
        if "short" in words:
            return "ushort" if unsigned else "short"
        if longs >= 2:
            return "ulonglong" if unsigned else "longlong"
        if longs == 1:
            return "ulong" if unsigned else "long"
        return "uint" if unsigned else "int"
    return None


class AggDef:
    __slots__ = ("key", "kind", "members", "file", "complete", "packed", "complex")

    def __init__(self, key, kind, members, file, complete=True, packed=False, complex_=False):
        self.key, self.kind, self.members, self.file = key, kind, members, file
        self.complete, self.packed, self.complex = complete, packed, complex_


class FileScan:
    """The definitions one source file holds."""

    def __init__(self, src, rel):
        self.src, self.rel = src, rel
        self.aggs = []          # AggDef
        self.typedefs = []      # (name, type)
        self.enums = []         # (name, expr_text or None)
        self.enum_tags = set()
        self.agg_tags = set()
        self._anon = 0
        self.vars = []          # (name, type): file-scope object declarations

    def t(self, n):
        return self.src[n.start_byte:n.end_byte].decode("utf8", "replace")

    def anon_key(self, n):
        return f"<anon:{self.rel}:{n.start_byte}>"

    # -- type specifiers ----------------------------------------------------
    def spec(self, n, want_body_register=True):
        """A declaration's type specifier node -> type (registering any body it defines)."""
        if n is None:
            return ("bad", "no-type")
        k = n.type
        if k in ("primitive_type", "sized_type_specifier"):
            words = self.t(n).split()
            prim = prim_of_words(words)
            if prim:
                return ("prim", prim)
            names = [w for w in words if w not in QUAL]
            return ("named", names[0]) if len(names) == 1 else ("bad", self.t(n))
        if k == "type_identifier":
            return ("named", self.t(n))
        if k in ("struct_specifier", "union_specifier", "class_specifier"):
            return self.agg_spec(n)
        if k == "enum_specifier":
            return self.enum_spec(n)
        if k == "macro_type_specifier":
            return ("bad", "macro-type")
        return ("bad", k)

    def agg_spec(self, n):
        name = n.child_by_field_name("name")
        body = n.child_by_field_name("body")
        kind = "union" if n.type == "union_specifier" else "struct"
        key = self.t(name) if name is not None else None
        if body is None:
            if key:
                self.agg_tags.add(key)
                return ("agg", key)
            return ("bad", "anonymous-no-body")
        if key is None:
            key = self.anon_key(n)
        members = self.members(body)
        packed = b"packed" in self.src[n.start_byte:n.end_byte] and "__attribute__" in self.t(n)
        # a C++ class with bases or virtual members has a layout this audit does not model
        cxx = any(ch.type == "base_class_clause" for ch in n.children) or any(
            sub.type == "virtual" or sub.type == "virtual_function_specifier"
            for ch in body.children for sub in ch.children)
        self.aggs.append(AggDef(key, kind, members, self.rel, True, packed, cxx))
        self.agg_tags.add(key)
        return ("agg", key)

    def enum_spec(self, n):
        name = n.child_by_field_name("name")
        body = n.child_by_field_name("body")
        if body is not None:
            for ch in body.named_children:
                if ch.type == "enumerator":
                    nm = ch.child_by_field_name("name")
                    val = ch.child_by_field_name("value")
                    self.enums.append((self.t(nm), self.t(val) if val is not None else None))
        key = self.t(name) if name is not None else "<anon-enum>"
        self.enum_tags.add(key)
        return ("enum", key)

    # -- declarators --------------------------------------------------------
    def inner(self, d):
        c = d.child_by_field_name("declarator")
        if c is not None:
            return c
        for ch in d.children:
            if ch.is_named and ch.type not in ("type_qualifier", "attribute_specifier", "comment",
                                                "ms_pointer_modifier", "ms_based_modifier"):
                return ch
        return None

    def declare(self, base, d):
        """Apply a declarator chain to `base`: (type, name)."""
        ops = []
        name = None
        while d is not None:
            k = d.type
            if k in ("pointer_declarator", "abstract_pointer_declarator"):
                ops.append(("ptr",))
                d = self.inner(d)
            elif k in ("array_declarator", "abstract_array_declarator"):
                size = d.child_by_field_name("size")
                ops.append(("arr", self.t(size) if size is not None else None))
                d = d.child_by_field_name("declarator")
            elif k in ("function_declarator", "abstract_function_declarator"):
                ops.append(("func",))
                d = d.child_by_field_name("declarator")
            elif k in ("parenthesized_declarator", "abstract_parenthesized_declarator",
                       "attributed_declarator", "init_declarator"):
                d = self.inner(d)
            elif k in ("identifier", "field_identifier", "type_identifier"):
                name = self.t(d)
                break
            else:
                break
        ty = base
        # C declarators read outside-in: `*a[3]` is an array of pointers (the pointer op is seen
        # first and applied to the base first), `(*a)[3]` a pointer to an array.
        for op in ops:
            if op[0] == "ptr":
                ty = ("code",) if ty == ("func",) else ("ptr", ty)
            elif op[0] == "arr":
                ty = ("arr", ty, op[1])
            elif op[0] == "func":
                ty = ("func",)
        if ops and ops[-1][0] == "func":
            ty = ("fdecl",)          # a function declaration (a C++ method, a prototype)
        elif ty == ("func",):
            ty = ("code",)
        return ty, name

    # -- struct bodies ------------------------------------------------------
    def members(self, body):
        out = []
        for ch in body.children:
            if ch.type == "field_declaration":
                if any(sub.type == "storage_class_specifier" for sub in ch.children):
                    continue                       # a static member takes no space
                base = self.spec(ch.child_by_field_name("type"))
                decls = ch.children_by_field_name("declarator")
                bits = None
                for sub in ch.children:
                    if sub.type == "bitfield_clause":
                        bits = self.t(sub).lstrip(":").strip()
                if not decls:
                    if base[0] == "agg":     # anonymous member (C11): its fields join this level
                        out.append((None, base, bits))
                    continue
                for d in decls:
                    ty, name = self.declare(base, d)
                    if ty == ("fdecl",):
                        continue
                    out.append((name, ty, bits))
            elif ch.type in ("preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif",
                             "preproc_elifdef", "field_declaration_list"):
                # both branches of a conditional member list are listed; the layout engine takes
                # the first branch only (an `#else` holds the alternative).
                sub = self.members(ch) if ch.type != "preproc_else" else []
                out.extend(sub)
        return out

    # -- file walk ----------------------------------------------------------
    def walk(self, n):
        for ch in n.children:
            self.visit(ch)

    def visit(self, n):
        k = n.type
        if k == "type_definition":
            base = self.spec(n.child_by_field_name("type"))
            for d in n.children_by_field_name("declarator"):
                ty, name = self.declare(base, d)
                if ty == ("fdecl",):
                    ty = ("code",)
                if name:
                    if ty[0] == "agg" and ty[1].startswith("<anon:"):
                        # a typedef names an anonymous aggregate: rename its key to the typedef
                        for a in self.aggs:
                            if a.key == ty[1]:
                                a.key = name
                        ty = ("agg", name)
                    self.typedefs.append((name, ty))
        elif k in ("declaration", "field_declaration"):
            ty = n.child_by_field_name("type")
            if ty is not None and k == "field_declaration" and ty.type in (
                    "struct_specifier", "union_specifier", "enum_specifier", "class_specifier"):
                self.spec(ty)
            if k == "declaration" and ty is not None:
                base = self.spec(ty)
                for d in n.children_by_field_name("declarator"):
                    if d.type == "init_declarator":
                        d = d.child_by_field_name("declarator")
                    vt, vname = self.declare(base, d)
                    if vname and vt != ("fdecl",) and vt[0] != "bad":
                        self.vars.append((vname, vt))
        elif k in ("struct_specifier", "union_specifier", "enum_specifier", "class_specifier"):
            self.spec(n)
        elif k in ("preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif", "preproc_elifdef",
                   "linkage_specification", "declaration_list", "translation_unit", "namespace_definition"):
            self.walk(n)
        elif k == "template_declaration":
            pass
        elif k == "ERROR":
            self.walk(n)


def scan_c_file(job):
    path, rel, lang = job
    try:
        src = Path(path).read_bytes()
    except OSError:
        return None
    if len(src) > 8_000_000:
        return None
    import extract_prototypes as EP
    src = EP.blank_text(src)
    tree = (EP.parser_for("cpp") if lang == "cpp" else ts_parser()).parse(src)
    fs = FileScan(src, rel)
    fs.walk(tree.root_node)
    macros = {}
    for name, args, value in DEFINE_RE.findall(src.decode("utf8", "replace")):
        if not args and name not in macros:
            macros[name] = value
    return {"file": rel, "aggs": fs.aggs, "typedefs": fs.typedefs, "enums": fs.enums, "vars": fs.vars,
            "macros": macros, "enum_tags": fs.enum_tags, "agg_tags": fs.agg_tags}


def scan_repo_defs(repo, jobs=4, cpp=False):
    """Parse every C/C++ source and header of a repo -> per-file definition lists."""
    import extract_prototypes as EP
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor
    files = EP.list_sources(repo)
    files = [f for f in files if os.path.splitext(f)[1].lower() in (".c", ".h", ".cc", ".cpp", ".hpp")]
    obj, fn, expand = EP.collect_blank_macros(files)
    EP.install_blank(obj, fn, expand)
    work = [(f, os.path.relpath(f, repo),
             "cpp" if cpp or os.path.splitext(f)[1].lower() in (".cc", ".cpp", ".hpp") else "c") for f in files]
    results = []
    with ProcessPoolExecutor(jobs, mp_context=multiprocessing.get_context("fork")) as pool:
        for r in pool.map(scan_c_file, work, chunksize=16):
            if r:
                results.append(r)
    return results


class Defs:
    """All definitions of one program (repo or preprocessed unit) and the ABI to lay them out in."""

    def __init__(self, results, abi="ps2"):
        self.abi = ABIS[abi]
        self.abi_name = abi
        self.aggs = collections.defaultdict(list)    # key -> [AggDef]
        self.typedefs = collections.defaultdict(list)
        self.macros = {}
        self.enum_values = {}     # name -> expr text
        self.enum_tags = set()
        self.agg_tags = set()
        self.globals = {}         # file-scope object name -> declared type
        for r in results:
            for a in r["aggs"]:
                self.aggs[a.key].append(a)
            for name, ty in r["typedefs"]:
                self.typedefs[name].append(ty)
            for name, val in r["macros"].items():
                self.macros.setdefault(name, val)
            for name, expr in r["enums"]:
                self.enum_values.setdefault(name, expr)
            self.enum_tags |= r["enum_tags"]
            self.agg_tags |= r["agg_tags"]
            for name, vty in r.get("vars", ()):
                self.globals.setdefault(name, vty)
        self._layout = {}
        self._enum_cache = {}
        self._enum_order = None
        self.fallback = dict(FALLBACK_TYPEDEFS)
        self.fallback.update(FALLBACK_64)
        if abi.startswith("ps2"):
            self.fallback.update(FALLBACK_PS2)
        else:
            self.fallback.update(FALLBACK_COMMON)
        self.unresolved = collections.Counter()

    # -- constants ----------------------------------------------------------
    def enum_const(self, name, depth=0):
        if name in self._enum_cache:
            return self._enum_cache[name]
        if name not in self.enum_values or depth > 12:
            return None
        expr = self.enum_values[name]
        val = self.const(expr, depth + 1) if expr is not None else None
        self._enum_cache[name] = val
        return val

    def const(self, text, depth=0):
        """Evaluate an integer constant expression: literals, macros, enum constants, sizeof."""
        if text is None:
            return None
        text = re.sub(r"/\*.*?\*/", " ", text)
        text = re.sub(r"//.*", " ", text)
        if depth > 12:
            return None

        def sub_sizeof(m):
            inner = m.group(1).strip()
            ty = self.parse_type_text(inner)
            if ty is None:
                return "None"
            lay = self.size_align(ty)
            return str(lay[0]) if lay else "None"

        text = re.sub(r"sizeof\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)", sub_sizeof, text)

        def sub_ident(m):
            w = m.group(0)
            if w in ("None",):
                return w
            if w in self.macros:
                v = self.const(self.macros[w], depth + 1)
                return "None" if v is None else f"({v})"
            v = self.enum_const(w, depth + 1)
            return "None" if v is None else f"({v})"

        text = re.sub(r"\b0[xX][0-9a-fA-F]+[uUlL]*\b|\b\d+[uUlL]*\b", lambda m: str(int(m.group(0).rstrip("uUlL"), 0))
                      if not (m.group(0).lstrip("0") == "" and len(m.group(0)) > 1) else "0", text)
        text = re.sub(r"\([A-Za-z_][\w ]*\)\s*(?=[\d(])", "", text)      # casts
        text = re.sub(r"[A-Za-z_]\w*", sub_ident, text)
        if "None" in text or not re.fullmatch(r"[\d\s()+\-*/%<>&|^~!]*", text):
            return None
        try:
            val = eval(text.replace("/", "//"), {"__builtins__": {}}, {})
        except Exception:
            return None
        return val if isinstance(val, int) else None

    def parse_type_text(self, text):
        words = re.findall(r"[A-Za-z_]\w*|\*", text)
        if not words:
            return None
        depth = words.count("*")
        words = [w for w in words if w != "*" and w not in QUAL]
        if words and words[0] in ("struct", "union"):
            ty = ("agg", words[1]) if len(words) > 1 else None
        elif words and words[0] == "enum":
            ty = ("enum", words[1] if len(words) > 1 else "")
        elif all(w in INT_WORDS for w in words):
            p = prim_of_words(words)
            ty = ("prim", p) if p else None
        elif len(words) == 1:
            ty = ("named", words[0])
        else:
            ty = None
        if ty is None:
            return None
        for _ in range(depth):
            ty = ("ptr", ty)
        return ty

    # -- resolution ---------------------------------------------------------
    def resolve(self, ty, depth=0):
        """Strip typedefs/qualifiers: -> a type with no ('named', ...) head."""
        while ty[0] == "named":
            depth += 1
            if depth > 24:
                return ("bad", "typedef-cycle")
            name = ty[1]
            if name in self.typedefs:
                cands = self.typedefs[name]
                nxt = cands[0]
                if nxt == ty:
                    return ("bad", "self-typedef")
                ty = nxt
                continue
            if name in self.fallback:
                fb = self.fallback[name]
                return fb if fb[0] != "named" else self.resolve(fb, depth)
            if name in self.aggs or name in self.agg_tags:
                return ("agg", name)
            if name in self.enum_tags:
                return ("enum", name)
            self.unresolved[name] += 1
            return ("bad", f"unresolved:{name}")
        return ty

    def best_agg(self, key):
        defs = self.aggs.get(key)
        if not defs:
            return None
        return max(defs, key=lambda a: len(a.members))

    # -- size / alignment ---------------------------------------------------
    def size_align(self, ty, stack=()):
        ty = self.resolve(ty)
        k = ty[0]
        if k == "prim":
            if ty[1] == "void":
                return None
            kind = PRIM_KIND.get(ty[1])
            return self.abi[kind] if kind else None
        if k in ("ptr", "code"):
            return self.abi["ptr"]
        if k == "enum":
            return (4, 4)
        if k == "arr":
            elem = self.size_align(ty[1], stack)
            n = self.const(ty[2]) if isinstance(ty[2], (str, type(None))) and ty[2] is not None else ty[2]
            if elem is None or n is None or n < 0:
                return None
            align = ty[3] if len(ty) > 3 else elem[1]
            return (elem[0] * n, max(elem[1], align))
        if k == "agg":
            lay = self.layout(ty[1], stack)
            return (lay["size"], lay["align"]) if lay and lay["ok"] else None
        return None

    def layout(self, key, stack=()):
        if key in self._layout:
            return self._layout[key]
        if key in stack:
            return None
        d = self.best_agg(key)
        if d is None:
            return None
        stack = stack + (key,)
        lay = self._lay_agg(d, stack)
        self._layout[key] = lay
        return lay

    def _lay_agg(self, d, stack):
        """Lay out one aggregate: members with offsets, flattened leaves and array spans."""
        union = d.kind == "union"
        if d.complex:
            return {"ok": False, "why": "cxx-class", "size": 0, "align": 1, "members": [], "leaves": [], "spans": []}
        off = 0
        align = 1
        size = 0
        bit_unit = None      # (unit_offset, unit_size, bit_pos)
        members = []
        leaves = []
        spans = []
        ok = True
        why = None
        has_bits = False
        taken_branch = False
        for name, ty, bits in d.members:
            if bits is not None:
                has_bits = True
                width = self.const(bits)
                base = self.size_align(ty, stack)
                if width is None or base is None:
                    ok, why = False, f"bitfield:{name}"
                    break
                bsize, balign = base
                if width == 0:
                    if bit_unit:
                        off = bit_unit[0] + bit_unit[1]
                        bit_unit = None
                    off = (off + balign - 1) // balign * balign
                    continue
                if union:
                    start = 0
                    bit_unit = None
                    leaves.append(dict(off=0, size=bsize, cls="bits", target=None, path=name or "?"))
                    size = max(size, bsize)
                    align = max(align, balign)
                    continue
                if bit_unit and bit_unit[1] == bsize and bit_unit[2] + width <= bsize * 8:
                    bit_unit = (bit_unit[0], bsize, bit_unit[2] + width)
                else:
                    unit_off = (off + balign - 1) // balign * balign
                    if bit_unit and bit_unit[1] == bsize and bit_unit[0] + bsize <= off:
                        unit_off = bit_unit[0] + bsize
                    bit_unit = (unit_off, bsize, width)
                    leaves.append(dict(off=unit_off, size=bsize, cls="bits", target=None, path=name or "?"))
                    members.append((name, unit_off, ("prim", "uint")))
                align = max(align, balign)
                off = bit_unit[0] + (bit_unit[2] + 7) // 8
                off = max(off, bit_unit[0] + 1)
                size = max(size, off)
                continue
            bit_unit = None
            r = self.resolve(ty)
            sa = self.size_align(r, stack)
            if sa is None:
                ok, why = False, f"member:{name}:{r}"
                break
            msize, malign = sa
            if d.packed:
                malign = 1
            if union:
                moff = 0
                size = max(size, msize)
            else:
                moff = (off + malign - 1) // malign * malign
                off = moff + msize
                size = off
            align = max(align, malign)
            members.append((name, moff, r))
            self._flatten(name or "?", moff, r, leaves, spans, stack)
        if not ok:
            return {"ok": False, "why": why, "size": 0, "align": 1, "members": members, "leaves": leaves, "spans": spans}
        size = (size + align - 1) // align * align
        return {"ok": True, "why": None, "size": size, "align": align, "members": members,
                "leaves": sorted(leaves, key=lambda l: (l["off"], l["size"])), "spans": spans,
                "has_bits": has_bits, "kind": d.kind}

    LEAF_CAP = 4096

    def _flatten(self, path, off, ty, leaves, spans, stack):
        ty = self.resolve(ty)
        k = ty[0]
        if len(leaves) > self.LEAF_CAP:
            return
        if k == "prim":
            sa = self.size_align(ty)
            if sa:
                leaves.append(dict(off=off, size=sa[0], cls=PRIM_CLASS[ty[1]], target=None, path=path))
        elif k == "enum":
            leaves.append(dict(off=off, size=4, cls="int", target=None, path=path))
        elif k == "code":
            leaves.append(dict(off=off, size=self.abi["ptr"][0], cls="code", target=None, path=path))
        elif k == "ptr":
            tgt = self.resolve(ty[1])
            target = None
            if tgt[0] == "agg":
                target = tgt[1]
            leaves.append(dict(off=off, size=self.abi["ptr"][0], cls="ptr", target=target,
                               path=path, depth=1 + (1 if tgt[0] == "ptr" else 0), pointee=tgt[0]))
        elif k == "arr":
            elem = self.resolve(ty[1])
            esa = self.size_align(elem, stack)
            n = self.const(ty[2]) if ty[2] is not None and isinstance(ty[2], str) else ty[2]
            if esa is None or n is None:
                return
            spans.append((off, off + esa[0] * n, esa[0]))
            for i in range(min(n, 16)):
                self._flatten(f"{path}[{i}]", off + i * esa[0], elem, leaves, spans, stack)
        elif k == "agg":
            lay = self.layout(ty[1], stack)
            if lay and lay["ok"]:
                for lf in lay["leaves"]:
                    l2 = dict(lf)
                    l2["off"] = off + lf["off"]
                    l2["path"] = path + "." + lf["path"]
                    leaves.append(l2)
                for s in lay["spans"]:
                    spans.append((off + s[0], off + s[1], s[2]))


def layout_hash(lay):
    """Name-free layout identity: size and the (offset, size, class) of every leaf."""
    parts = [str(lay["size"])]
    for lf in lay["leaves"]:
        parts.append(f"{lf['off']}:{lf['size']}:{lf['cls']}")
    return hashlib.sha1(";".join(parts).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Function bodies: typed member access, rooted at a parameter
# ---------------------------------------------------------------------------

def member_info(defs, key, name, depth=0):
    """(offset, type) of member `name` of aggregate `key`, looking through anonymous members."""
    lay = defs.layout(key)
    if not lay or not lay["ok"] or depth > 6:
        return None
    for mname, off, ty in lay["members"]:
        if mname == name:
            return off, ty
    for mname, off, ty in lay["members"]:
        if mname is None and ty[0] == "agg":
            got = member_info(defs, ty[1], name, depth + 1)
            if got:
                return off + got[0], got[1]
    return None


class BodyTyper:
    """Evaluates the member-access expressions of one function body.

    An expression is ('val', type, root, off, src) -- a value; for a pointer value `root`/`off`
    say it equals parameter `root`'s pointer plus `off`, and `src` is the (root, off) of the
    memory it was loaded from -- or ('mem', type, root, off) -- an lvalue at `off` bytes into the
    object `root` points at -- or None (opaque)."""

    def __init__(self, defs, fs):
        self.defs, self.fs = defs, fs
        self.env = {}
        self.roots = {}
        self.params = set()
        self.access = []       # dict(root, off, size, cls)
        self.nested = []       # dict(root, off, key, noff, size)
        self.calls = []        # dict(callee, args)
        self.seen = set()

    def size_of(self, ty):
        sa = self.defs.size_align(ty)
        return sa[0] if sa else None

    def pointee(self, ty):
        ty = self.defs.resolve(ty)
        if ty[0] == "ptr":
            return self.defs.resolve(ty[1])
        if ty[0] == "arr":
            return self.defs.resolve(ty[1])
        return None

    def type_desc(self, n):
        if n is None:
            return ("bad", "no-type")
        base = self.fs.spec(n.child_by_field_name("type"))
        d = n.child_by_field_name("declarator")
        if d is None:
            return base
        return self.fs.declare(base, d)[0]

    def record(self, res):
        if not res or res[0] != "mem" or res[2] is None:
            return
        ty = self.defs.resolve(res[1])
        size = self.size_of(ty) or 0
        cls = "agg" if ty[0] == "agg" else PRIM_CLASS.get(ty[1], "int") if ty[0] == "prim" else \
            "ptr" if ty[0] in ("ptr", "arr") else "code" if ty[0] == "code" else "int"
        self.access.append(dict(root=res[2], off=res[3], size=size, cls=cls,
                                ptr_to=(self.pointee(ty)[1] if ty[0] == "ptr" and self.pointee(ty)
                                        and self.pointee(ty)[0] == "agg" else None)))

    def ev(self, n, sub=False):
        """Evaluate `n`. `sub`: the caller consumes it as a subobject (so it is not itself read)."""
        self.seen.add(n.id)
        k = n.type
        try:
            res = self._ev(n, k, sub)
        except RecursionError:
            res = None
        return res

    def _ev(self, n, k, sub):
        t = self.fs.t
        if k == "identifier":
            name = t(n)
            ty = self.env.get(name)
            if ty is None:
                ty = self.defs.globals.get(name)
            if ty is None:
                return None
            r = self.defs.resolve(ty)
            root, off = self.roots.get(name, (None, 0))
            if r[0] in ("agg", "arr"):
                return ("mem", ty, None, 0)
            return ("val", ty, root, off, None)
        if k == "parenthesized_expression":
            for ch in n.named_children:
                return self.ev(ch, sub)
        if k == "cast_expression":
            inner = self.ev(n.child_by_field_name("value"))
            ty = self.type_desc(n.child_by_field_name("type"))
            if inner and inner[0] == "val":
                return ("val", ty, inner[2], inner[3], inner[4])
            if inner and inner[0] == "mem":
                return ("val", ty, None, 0, None)
            return ("val", ty, None, 0, None)
        if k == "pointer_expression":
            op = t(n.child_by_field_name("operator")) if n.child_by_field_name("operator") is not None else ""
            arg = n.child_by_field_name("argument")
            if op == "&":
                inner = self.ev(arg, True)
                if inner and inner[0] == "mem":
                    return ("val", ("ptr", inner[1]), inner[2], inner[3], None)
                return None
            if op == "*":
                inner = self.val_of(self.ev(arg))
                if inner and inner[0] == "val":
                    p = self.pointee(inner[1])
                    if p:
                        res = ("mem", p, inner[2], inner[3]) if inner[2] is not None else \
                            ("mem", p, None, 0)
                        if inner[2] is None and inner[4]:
                            self.nested_mark(inner, 0, p)
                        if not sub:
                            self.record(res)
                        return res
            return None
        if k == "field_expression":
            arg = n.child_by_field_name("argument")
            field = n.child_by_field_name("field")
            arrow = any(ch.type == "->" for ch in n.children)
            if field is None:
                return None
            fname = t(field)
            if arrow:
                base = self.val_of(self.ev(arg))
                if not base or base[0] != "val":
                    return None
                p = self.pointee(base[1])
                if not p or p[0] != "agg":
                    return None
                got = member_info(self.defs, p[1], fname)
                if not got:
                    return None
                off, fty = got
                if base[2] is not None:
                    res = ("mem", fty, base[2], base[3] + off)
                else:
                    res = ("mem", fty, None, 0)
                    if base[4]:
                        self.nested.append(dict(root=base[4][0], off=base[4][1], key=p[1], noff=off,
                                                size=self.size_of(fty) or 0))
            else:
                base = self.ev(arg, True)
                if not base or base[0] != "mem":
                    return None
                p = self.defs.resolve(base[1])
                if p[0] != "agg":
                    return None
                got = member_info(self.defs, p[1], fname)
                if not got:
                    return None
                off, fty = got
                res = ("mem", fty, base[2], base[3] + off if base[2] is not None else 0)
            if not sub:
                self.record(res)
            return res
        if k == "subscript_expression":
            arg = n.child_by_field_name("argument")
            idx = n.child_by_field_name("index")
            if idx is not None:
                self.visit(idx)
            base = self.ev(arg, True)
            if base is None:
                return None
            if base[0] == "mem":
                r = self.defs.resolve(base[1])
                if r[0] != "arr":
                    return None
                elem = self.defs.resolve(r[1])
                res = ("mem", elem, base[2], base[3] if base[2] is not None else 0)
            else:
                p = self.pointee(base[1])
                if not p:
                    return None
                res = ("mem", p, base[2], base[3]) if base[2] is not None else ("mem", p, None, 0)
                if base[2] is None and base[4]:
                    self.nested_mark(base, 0, p)
            if not sub:
                self.record(res)
            return res
        if k == "binary_expression":
            op = n.child_by_field_name("operator")
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            a, b = self.val_of(self.ev(left)), self.val_of(self.ev(right))
            if op is not None and t(op) in ("+", "-") and a and a[0] == "val" and a[2] is not None \
                    and right is not None and right.type == "number_literal":
                p = self.pointee(a[1])
                c = self.defs.const(t(right))
                size = self.size_of(p) if p else None
                if c is not None and size:
                    return ("val", a[1], a[2], a[3] + (c if t(op) == "+" else -c) * size, None)
            return None
        if k == "call_expression":
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            row = []
            if args is not None:
                for a in args.named_children:
                    r = self.val_of(self.ev(a))
                    kind = self.arg_kind(r)
                    # `f((void *)p)`: the argument's own type is what the caller holds; look through casts
                    inner = a
                    while inner is not None and inner.type in ("cast_expression", "parenthesized_expression"):
                        inner = inner.child_by_field_name("value") if inner.type == "cast_expression" else \
                            next(iter(inner.named_children), None)
                    if inner is not None and inner is not a:
                        r0 = self.val_of(self.ev(inner))
                        k0 = self.arg_kind(r0)
                        if k0["kind"] == "struct_ptr" and kind["kind"] != "struct_ptr":
                            kind = dict(k0, via_cast=True)
                    row.append(kind)
            if fn is not None and fn.type == "identifier":
                self.calls.append(dict(callee=t(fn), args=row))
            else:
                if fn is not None:
                    self.visit(fn)
            return None
        return None

    def nested_mark(self, base, noff, p):
        if base[4]:
            self.nested.append(dict(root=base[4][0], off=base[4][1],
                                    key=p[1] if p[0] == "agg" else None, noff=noff, size=0))

    def val_of(self, res):
        """An rvalue use: a `mem` becomes a value (arrays decay; a loaded pointer remembers where)."""
        if res is None or res[0] == "val":
            return res
        ty = self.defs.resolve(res[1])
        if ty[0] == "arr":
            return ("val", ("ptr", ty[1]), res[2], res[3], None)
        if ty[0] == "ptr":
            src = (res[2], res[3]) if res[2] is not None else None
            return ("val", ty, None, 0, src)
        return ("val", ty, None, 0, None)

    def arg_kind(self, r):
        if not r or r[0] != "val":
            return {"kind": "other"}
        ty = self.defs.resolve(r[1])
        if ty[0] != "ptr":
            return {"kind": "scalar"}
        p = self.defs.resolve(ty[1])
        out = {"kind": "scalar_ptr"}
        if p[0] == "agg":
            out = {"kind": "struct_ptr", "key": p[1]}
        elif p[0] == "prim" and p[1] == "void":
            out = {"kind": "void_ptr"}
        if r[2] is not None:
            out["root"], out["off"] = r[2], r[3]     # the argument is parameter `root` + off
        return out

    # -- walking ------------------------------------------------------------
    def visit(self, n):
        if n.id in self.seen:
            return
        k = n.type
        if k == "declaration":
            self.declaration(n)
            return
        if k in ("field_expression", "subscript_expression", "call_expression", "cast_expression") or \
                (k == "pointer_expression" and any(c.type == "*" for c in n.children)):
            self.ev(n)
            # children not on the evaluated spine (call arguments were evaluated; others may remain)
            for ch in n.children:
                if ch.id not in self.seen:
                    self.visit(ch)
            return
        for ch in n.children:
            self.visit(ch)

    def declaration(self, n):
        base = self.fs.spec(n.child_by_field_name("type"))
        for d in n.children_by_field_name("declarator"):
            init = None
            if d.type == "init_declarator":
                init = d.child_by_field_name("value")
                d = d.child_by_field_name("declarator")
            ty, name = self.fs.declare(base, d)
            if not name:
                continue
            self.env[name] = ty
            if init is not None:
                res = self.val_of(self.ev(init))
                if res and res[0] == "val" and res[2] is not None:
                    self.roots[name] = (res[2], res[3])
                self.visit(init)


def analyse_function(defs, fs, fnode):
    """Typed accesses of one function_definition node -> dict(params, access, nested, calls)."""
    typer = BodyTyper(defs, fs)
    decl = fnode.child_by_field_name("declarator")
    while decl is not None and decl.type in ("pointer_declarator", "parenthesized_declarator", "attributed_declarator"):
        decl = fs.inner(decl)
    if decl is None or decl.type != "function_declarator":
        return None
    plist = decl.child_by_field_name("parameters")
    names = []
    if plist is not None:
        for ch in plist.named_children:
            if ch.type == "parameter_declaration":
                base = fs.spec(ch.child_by_field_name("type"))
                d = ch.child_by_field_name("declarator")
                if d is None:
                    continue
                ty, name = fs.declare(base, d)
                if name:
                    if ty[0] == "arr":
                        ty = ("ptr", ty[1])
                    typer.env[name] = ty
                    typer.roots[name] = (name, 0)
                    typer.params.add(name)
                    names.append(name)
    body = fnode.child_by_field_name("body")
    if body is not None:
        typer.visit(body)
    return {"param_names": names, "access": typer.access, "nested": typer.nested, "calls": typer.calls}


def function_defs_in(fs_root, fs):
    """name -> function_definition node, for every top-level definition in a parse tree."""
    out = {}

    def walk(n):
        for ch in n.children:
            if ch.type == "function_definition":
                d = ch.child_by_field_name("declarator")
                while d is not None and d.type in ("pointer_declarator", "parenthesized_declarator", "attributed_declarator"):
                    d = fs.inner(d)
                if d is not None and d.type == "function_declarator":
                    nm = d.child_by_field_name("declarator")
                    if nm is not None and nm.type == "identifier":
                        out.setdefault(fs.t(nm), []).append(ch)
            elif ch.type in ("preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif", "linkage_specification",
                             "declaration_list", "ERROR"):
                walk(ch)
    walk(fs_root)
    return out


# ---------------------------------------------------------------------------
# Donor truth
# ---------------------------------------------------------------------------

EP_PRIM = {"char": "char", "byte": "uchar", "sbyte": "schar", "short": "short", "ushort": "ushort", "int": "int",
           "uint": "uint", "long": "long", "ulong": "ulong", "longlong": "longlong", "ulonglong": "ulonglong",
           "float": "float", "double": "double", "bool": "bool", "void": "void"}


def ep_type(t):
    kind, name, depth = t
    if kind == "p":
        base = ("prim", EP_PRIM.get(name, "int"))
    elif kind == "n":
        base = ("named", name)
    elif kind == "a":
        base = ("agg", name) if name else ("bad", "anonymous")
    elif kind == "e":
        base = ("enum", name)
    else:
        base = ("bad", name)
    for _ in range(depth):
        base = ("ptr", base)
    return base


def classify_param(defs, ty):
    """-> dict(kind, key, depth) for one declared parameter type."""
    r = defs.resolve(ty)
    k = r[0]
    if k == "ptr":
        depth = 1
        inner = defs.resolve(r[1])
        while inner[0] == "ptr":
            depth += 1
            inner = defs.resolve(inner[1])
        if depth > 1:
            return dict(kind="ptr_ptr")
        if inner[0] == "agg":
            lay = defs.layout(inner[1])
            if lay and lay["ok"]:
                return dict(kind="struct_ptr", key=inner[1])
            return dict(kind="struct_ptr_nolayout", key=inner[1], why=(lay or {}).get("why", "undefined"))
        if inner[0] == "prim" and inner[1] == "void":
            return dict(kind="void_ptr")
        if inner[0] == "code" or inner[0] == "func":
            return dict(kind="code_ptr")
        if inner[0] == "arr":
            return dict(kind="scalar_ptr")
        if inner[0] == "bad":
            return dict(kind="unknown_ptr", why=inner[1])
        return dict(kind="scalar_ptr", pointee=inner[1] if inner[0] == "prim" else inner[0])
    if k == "code":
        return dict(kind="code_ptr")
    if k == "prim":
        if r[1] in ("float", "double"):
            return dict(kind="float", bytes=4 if r[1] == "float" else 8)
        if r[1] in ("i128", "u128"):
            return dict(kind="wide")
        return dict(kind="int", bytes=defs.size_align(r)[0] if defs.size_align(r) else 4)
    if k == "enum":
        return dict(kind="int", bytes=4)
    if k == "agg":
        return dict(kind="byvalue")
    if k == "arr":
        return dict(kind="scalar_ptr")
    return dict(kind="unknown")


def leaf_view(lay):
    return {"size": lay["size"], "leaves": [{k: lf[k] for k in ("off", "size", "cls", "target") if k in lf}
                                              | ({"depth": lf["depth"]} if "depth" in lf else {})
                                              for lf in lay["leaves"]],
            "spans": lay["spans"], "hash": layout_hash(lay), "has_bits": lay.get("has_bits", False),
            "kind": lay.get("kind", "struct")}


def read_truth_tsv(game):
    rows = []
    with open(CORPUS / game / "truth" / "functions.tsv") as f:
        next(f)
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 3:
                rows.append(dict(start=int(p[0], 16), size=int(p[1] or 0), name=p[2],
                                 module=p[3] if len(p) > 3 else "main", verified=p[4] if len(p) > 4 else "0"))
    return rows


def build_donor_truth(game, jobs=4):
    import extract_prototypes as EP
    donors = json.loads((HERE / "fact_pack" / "donors.json").read_text())["donors"]
    donor = next(d for d in donors if d["game"] == game)
    platform = donor["platform"]
    repo = SCRATCH / "repos" / game
    abi = PLATFORM_ABI[platform]
    log(f"{game}: scanning definitions ({abi})")
    defs = Defs(scan_repo_defs(repo, jobs), abi)
    data = EP.scan_repo(game, repo, SCRATCH / "cache", jobs, False)
    index = collections.defaultdict(list)
    for r in data["results"]:
        for e in r["entries"]:
            if "scope" in e and not e["scope"]:
                index[e["name"]].append(e)
    rows = read_truth_tsv(game)
    by_name = collections.defaultdict(list)
    for r in rows:
        if r["module"] == "main":
            by_name[r["name"]].append(r)
    # functions with a unique truth address and one agreed source signature
    chosen = {}
    skipped = collections.Counter()
    for name, rs in by_name.items():
        if len(rs) != 1:
            skipped["duplicate-truth-name"] += 1
            continue
        group = [e for e in index.get(name, []) if not e.get("err")]
        if not group:
            skipped["no-source"] += 1
            continue
        defs_e = [e for e in group if e["def"]]
        tier = defs_e or group
        sigs = {tuple(tuple(p[1]) if p[1] else None for p in e["params"]) for e in tier}
        if len(sigs) != 1:
            skipped["ambiguous-signature"] += 1
            continue
        e = tier[0]
        if e["variadic"]:
            skipped["variadic"] += 1
            continue
        if any(p[1] is None for p in e["params"]):
            skipped["knr"] += 1
            continue
        chosen[name] = (rs[0], e, defs_e[0] if defs_e else None)
    # bodies: parse each file that holds a chosen definition
    files = collections.defaultdict(list)
    for name, (row, e, d) in chosen.items():
        if d is not None:
            files[d["file"]].append(name)
    allfiles = EP.list_sources(repo)
    obj, fn, expand = EP.collect_blank_macros(allfiles)
    EP.install_blank(obj, fn, expand)
    bodies = {}
    log(f"{game}: {len(chosen)} functions with a source signature; parsing {len(files)} files for bodies")
    for rel, names in files.items():
        try:
            src = EP.blank_text((repo / rel).read_bytes())
        except OSError:
            continue
        tree = ts_parser().parse(src)
        fs = FileScan(src, rel)
        found = function_defs_in(tree.root_node, fs)
        for name in names:
            nodes = found.get(name, [])
            if len(nodes) != 1:
                continue
            try:
                got = analyse_function(defs, fs, nodes[0])
            except Exception as exc:     # a body the typer cannot read is a body without truth
                log(f"  {name}: {exc!r}")
                continue
            if got:
                bodies[name] = got
    functions = {}
    used = set()
    for name, (row, e, d) in chosen.items():
        params = []
        slot = 0
        float_before = False
        for pi, (pname, pty) in enumerate(e["params"]):
            ty = ep_type(pty)
            c = classify_param(defs, ty)
            c["i"] = pi
            c["name"] = pname
            if c["kind"] not in ("float", "wide"):
                c["slot"] = slot
                c["slot_clean"] = not float_before
                slot += 1
            else:
                float_before = True
            params.append(c)
            if c.get("key"):
                used.add(c["key"])
        body = bodies.get(name)
        rec = dict(name=name, params=params, has_body=body is not None, size=row["size"],
                   ret=ep_type(e["ret"]) if e.get("ret") else None)
        if body:
            # map accessed roots to parameter indices
            idx = {p["name"]: p["i"] for p in params if p.get("name")}
            acc = collections.defaultdict(list)
            for a in body["access"]:
                if a["root"] in idx:
                    acc[idx[a["root"]]].append([a["off"], a["size"], a["cls"], a.get("ptr_to")])
            rec["access"] = {str(k): v for k, v in acc.items()}
            nest = collections.defaultdict(list)
            for a in body["nested"]:
                if a["root"] in idx:
                    nest[idx[a["root"]]].append([a["off"], a["key"], a["noff"], a["size"]])
            rec["nested"] = {str(k): v for k, v in nest.items()}
            calls = []
            for c in body["calls"]:
                args = c["args"]
                calls.append(dict(callee=c["callee"], args=args))
                for a in args:
                    if a.get("root") in idx:
                        a["param"] = idx[a["root"]]
                    a.pop("root", None)
                    if a.get("key"):
                        used.add(a["key"])
            rec["calls"] = calls
        functions[f"{row['start']:08x}"] = rec
    # layouts of every struct a parameter, a call argument or a nested pointer touches
    structs = {}
    todo = list(used)
    while todo:
        key = todo.pop()
        if key in structs:
            continue
        lay = defs.layout(key)
        if not lay or not lay["ok"]:
            structs[key] = {"ok": False, "why": (lay or {}).get("why", "undefined")}
            continue
        structs[key] = dict(ok=True, **leaf_view(lay))
        for lf in lay["leaves"]:
            if lf.get("target") and lf["target"] not in structs:
                todo.append(lf["target"])
    addr_by_name = {name: f"{rs[0]['start']:08x}" for name, rs in by_name.items() if len(rs) == 1}
    return {"game": game, "platform": platform, "abi": abi, "compiler": donor["compiler"],
            "repo": donor["repo"], "commit": donor["commit"], "structs": structs, "functions": functions,
            "addr_by_name": addr_by_name,
            "skipped": dict(skipped), "unresolved_names": dict(defs.unresolved.most_common(30))}


# ---------------------------------------------------------------------------
# DWARF truth (Metrowerks DWARF 1 through dwarf1_types, DWARF 2 through readelf)
# ---------------------------------------------------------------------------

def _int_attr(attrs, name):
    v = attrs.get(name)
    if v is None:
        return None
    m = re.search(r"DW_OP_(?:plus_uconst|constu):\s*(\d+)", v)
    if m:
        return int(m.group(1))
    if "(dwarf1)" in v:
        raw = bytes(int(x, 16) for x in v.split("bytes:")[1].split())
        if len(raw) == 6 and raw[0] == 4 and raw[5] == 7:
            return int.from_bytes(raw[1:5], "little")
        return None
    m = re.search(r"(0x[0-9a-fA-F]+|\d+)", re.sub(r"^\([^)]*\)\s*", "", v))
    return int(m.group(1), 0) if m else None


def _name_attr(attrs):
    v = attrs.get("DW_AT_name")
    if v is None:
        return None
    from dwarf_arity import payload
    if v.startswith("(string)"):
        return v[len("(string)"):].strip() or None
    return payload(v) or None


def _ref(v):
    m = re.search(r"<(?:0x)?([0-9a-fA-F]+)>", v or "")
    return int(m.group(1), 16) if m else None


class DwarfTruth:
    """Struct layouts and parameter types straight from a DIE graph (offsets are the compiler's)."""

    def __init__(self, nodes, abi):
        self.nodes = nodes
        self.abi = ABIS[abi]
        self.cache = {}
        self.structs = {}        # key -> view
        self.keys_by_name = collections.defaultdict(dict)   # name -> {hash: key}
        self.die_key = {}        # struct die offset -> key
        self.ptr_size = self.abi["ptr"][0]

    def strip(self, off):
        """Follow typedef/const/volatile to the underlying DIE (offset or None for void)."""
        for _ in range(24):
            if off is None or off not in self.nodes:
                return off
            node = self.nodes[off]
            if node["tag"] in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                               "DW_TAG_restrict_type"):
                off = _ref(node["attributes"].get("DW_AT_type"))
                continue
            return off
        return None

    def size_of(self, off):
        off = self.strip(off)
        if off is None or off not in self.nodes:
            return None
        node = self.nodes[off]
        tag, a = node["tag"], node["attributes"]
        if tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_subroutine_type"):
            return self.ptr_size
        if tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type", "DW_TAG_base_type",
                   "DW_TAG_enumeration_type", "DW_TAG_array_type"):
            return _int_attr(a, "DW_AT_byte_size")
        return None

    def leaf_class(self, off):
        off = self.strip(off)
        if off is None or off not in self.nodes:
            return None, None
        node = self.nodes[off]
        tag, a = node["tag"], node["attributes"]
        if tag == "DW_TAG_pointer_type" or tag == "DW_TAG_reference_type":
            tgt = self.strip(_ref(a.get("DW_AT_type")))
            if tgt is not None and tgt in self.nodes:
                tt = self.nodes[tgt]["tag"]
                if tt == "DW_TAG_subroutine_type":
                    return "code", None
                if tt in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                    return "ptr", tgt
            return "ptr", None
        if tag == "DW_TAG_subroutine_type":
            return "code", None
        if tag == "DW_TAG_enumeration_type":
            return "int", None
        if tag == "DW_TAG_base_type":
            enc = a.get("DW_AT_encoding", "")
            m = re.search(r"\)\s*(\d+)", enc) or re.search(r"(\d+)", enc)
            e = int(m.group(1)) if m else -1
            if e == 4:
                return "float", None
            if e in (7, 8, 2):
                return "uint", None
            if e in (5, 6):
                return "int", None
            return "int", None
        return None, None

    def flatten(self, off, base, leaves, spans, path, depth=0):
        off = self.strip(off)
        if off is None or off not in self.nodes or depth > 8 or len(leaves) > Defs.LEAF_CAP:
            return
        node = self.nodes[off]
        tag = node["tag"]
        if tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
            key = self.struct_key(off)
            view = self.structs.get(key)
            if view and view.get("ok"):
                for lf in view["leaves"]:
                    l2 = dict(lf)
                    l2["off"] = base + lf["off"]
                    leaves.append(l2)
                for s in view["spans"]:
                    spans.append([base + s[0], base + s[1], s[2]])
            return
        if tag == "DW_TAG_array_type":
            elem = self.strip(_ref(node["attributes"].get("DW_AT_type")))
            esz = self.size_of(elem)
            total = _int_attr(node["attributes"], "DW_AT_byte_size")
            if esz and total:
                spans.append([base, base + total, esz])
                for i in range(min(total // esz, 16)):
                    self.flatten(elem, base + i * esz, leaves, spans, path, depth + 1)
            return
        cls, tgt = self.leaf_class(off)
        sz = self.size_of(off)
        if cls and sz:
            lf = dict(off=base, size=sz, cls=cls, target=None)
            if tgt is not None:
                lf["target"] = self.struct_key(tgt)
            leaves.append(lf)

    def struct_key(self, off):
        off = self.strip(off)
        if off in self.die_key:
            return self.die_key[off]
        node = self.nodes[off]
        a = node["attributes"]
        name = _name_attr(a) or f"anon@{off:x}"
        size = _int_attr(a, "DW_AT_byte_size") or 0
        self.die_key[off] = f"{name}#pending{off}"        # break cycles through pointers
        members = [self.nodes[c] for c in node["children"] if self.nodes[c]["tag"] == "DW_TAG_member"]
        leaves, spans = [], []
        locs = []
        for m in members:
            ma = m["attributes"]
            loc = _int_attr(ma, "DW_AT_data_member_location")
            if loc is None:
                loc = _int_attr(ma, "DW_AT_location")      # DWARF 1: OP_CONST c4, OP_ADD
            locs.append(0 if loc is None and node["tag"] == "DW_TAG_union_type" else loc)
        ok = size > 0 and all(l is not None for l in locs)
        if ok:
            for idx, (m, loc) in enumerate(zip(members, locs)):
                ma = m["attributes"]
                mt = _ref(ma.get("DW_AT_type"))
                if "DW_AT_bit_size" in ma:
                    bsz = _int_attr(ma, "DW_AT_byte_size") or self.size_of(mt) or 4
                    leaves.append(dict(off=loc, size=bsz, cls="bits", target=None))
                    continue
                st = self.strip(mt)
                if st in self.nodes and self.nodes[st]["tag"] == "DW_TAG_array_type" and \
                        _int_attr(self.nodes[st]["attributes"], "DW_AT_byte_size") is None:
                    # DWARF 1 states no bounds: the array runs to the next member (or the end)
                    nxt = [l for l in locs[idx + 1:] if l > loc]
                    end = min(nxt) if nxt else size
                    elem = self.strip(_ref(self.nodes[st]["attributes"].get("DW_AT_type")))
                    esz = self.size_of(elem)
                    if esz:
                        n = max((end - loc) // esz, 1)
                        spans.append([loc, loc + n * esz, esz])
                        for i in range(min(n, 16)):
                            self.flatten(elem, loc + i * esz, leaves, spans, "", 1)
                    continue
                self.flatten(mt, loc, leaves, spans, "")
        leaves.sort(key=lambda l: (l["off"], l["size"]))
        view = {"ok": ok, "size": size, "leaves": leaves, "spans": spans, "has_bits": any(l["cls"] == "bits" for l in leaves),
                "kind": "union" if node["tag"] == "DW_TAG_union_type" else "struct", "name": name}
        if ok:
            view["hash"] = hashlib.sha1((str(size) + ";" + ";".join(f"{l['off']}:{l['size']}:{l['cls']}" for l in leaves)).encode()).hexdigest()[:16]
        else:
            view["why"] = "no-size-or-offsets" if size <= 0 or None in locs else "?"
        # a name used by differently laid out structs gets the hash suffix
        h = view.get("hash", "x")
        seen = self.keys_by_name[name]
        if h in seen:
            key = seen[h]
        else:
            key = name if not seen else f"{name}#{h[:8]}"
            seen[h] = key
        self.die_key[off] = key
        self.structs.setdefault(key, view)
        return key


def build_dwarf_truth(game, binary, reader, abi):
    """Per-function parameter truth and struct layouts of a debug build."""
    if reader == "dwarf1":
        import dwarf1_types
        nodes = dwarf1_types.nodes(binary)
    else:
        import subprocess
        import dwarf_types
        from dwarf_arity import dwarf_dump_tool
        data = Path(binary).read_bytes()
        out = subprocess.run([*dwarf_dump_tool(data), str(binary)], text=True, capture_output=True, check=True,
                             env=dict(os.environ, LC_ALL="C"), timeout=300)
        nodes = dwarf_types.parse(out.stdout)
    dt = DwarfTruth(nodes, abi)
    functions = {}
    for off, node in nodes.items():
        if node["tag"] != "DW_TAG_subprogram":
            continue
        a = node["attributes"]
        low = a.get("DW_AT_low_pc")
        if low is None:
            continue
        m = re.search(r"0x([0-9a-fA-F]+)", low)
        if not m:
            continue
        addr = int(m.group(1), 16)
        params = []
        slot = 0
        float_before = False
        for ci in node["children"]:
            c = nodes[ci]
            if c["tag"] != "DW_TAG_formal_parameter":
                continue
            ty = dt.strip(_ref(c["attributes"].get("DW_AT_type")))
            p = {"i": len(params), "name": _name_attr(c["attributes"])}
            if ty is None or ty not in nodes:
                p["kind"] = "unknown"
            else:
                tn = nodes[ty]
                tag = tn["tag"]
                if tag == "DW_TAG_pointer_type" or tag == "DW_TAG_reference_type":
                    tgt = dt.strip(_ref(tn["attributes"].get("DW_AT_type")))
                    if tgt is None or tgt not in nodes:
                        p["kind"] = "void_ptr"
                    else:
                        tt = nodes[tgt]["tag"]
                        if tt in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                            key = dt.struct_key(tgt)
                            view = dt.structs[key]
                            if view["ok"]:
                                p.update(kind="struct_ptr", key=key)
                            else:
                                p.update(kind="struct_ptr_nolayout", key=key, why=view.get("why"))
                        elif tt == "DW_TAG_pointer_type":
                            p["kind"] = "ptr_ptr"
                        elif tt == "DW_TAG_subroutine_type":
                            p["kind"] = "code_ptr"
                        elif tt == "DW_TAG_base_type" and _int_attr(nodes[tgt]["attributes"], "DW_AT_byte_size") in (0, None):
                            p["kind"] = "void_ptr"
                        else:
                            p["kind"] = "scalar_ptr"
                elif tag == "DW_TAG_subroutine_type":
                    p["kind"] = "code_ptr"
                elif tag == "DW_TAG_base_type":
                    cls, _ = dt.leaf_class(ty)
                    sz = dt.size_of(ty) or 4
                    p["kind"] = "float" if cls == "float" else "wide" if sz > 8 else "int"
                    p["bytes"] = sz
                elif tag == "DW_TAG_enumeration_type":
                    p.update(kind="int", bytes=4)
                elif tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type", "DW_TAG_array_type"):
                    p["kind"] = "byvalue"
                else:
                    p["kind"] = "unknown"
            if p["kind"] not in ("float", "wide"):
                p["slot"] = slot
                p["slot_clean"] = not float_before
                slot += 1
            else:
                float_before = True
            params.append(p)
        key = f"{addr:08x}"
        rec = dict(name=_name_attr(a), params=params, has_body=False, size=0)
        if key not in functions or len(params) > len(functions[key]["params"]):
            functions[key] = rec
    structs = {}
    for key, view in dt.structs.items():
        structs[key] = view
    return {"game": game, "platform": "ps2", "abi": abi, "reader": reader, "structs": structs, "functions": functions}


# ---------------------------------------------------------------------------
# Scoring inferred layouts against truth
# ---------------------------------------------------------------------------

VARIANTS = ("iso", "fwd", "whatif", "shipped")
NON_STRUCT_KINDS = ("scalar_ptr", "void_ptr", "ptr_ptr", "code_ptr")


def cls_info(c):
    """Inferred Class (serde form) -> (family, bits)."""
    if isinstance(c, str):
        return {"ptr": ("ptr", 32), "code": ("code", 32)}.get(c, (None, 0))
    (k, v), = c.items()
    return ("float" if k == "float" else "int"), v


def truth_family(cls):
    return {"int": "int", "uint": "int", "bits": "int", "float": "float", "ptr": "ptr", "code": "code"}.get(cls)


def parse_inferred(ty):
    """Serialized `Ty` -> dict(kind, fields {offset: (size_bytes, family, bits)})."""
    if ty == "unknown" or ty is None:
        return dict(kind="unknown", fields={})
    if "scalar" in ty:
        fam, bits = cls_info(ty["scalar"])
        return dict(kind="ptr_bare" if fam == "ptr" else "scalar" if fam else "unknown", fields={})
    if "ptr" in ty:
        inner = ty["ptr"]
        if inner == "unknown":
            return dict(kind="ptr_bare", fields={})
        if "struct" in inner:
            return dict(kind="struct", fields={int(o): (f["size"], *cls_info(f["class"])) for o, f in inner["struct"].items()})
        if "scalar" in inner:
            fam, bits = cls_info(inner["scalar"])
            if fam is None:
                return dict(kind="ptr_bare", fields={})
            return dict(kind="ptr_scalar", fields={0: (max(bits // 8, 1), fam, bits)})
        if "array" in inner:
            return dict(kind="array", fields={})
        return dict(kind="ptr_bare", fields={})
    if "struct" in ty:
        return dict(kind="struct", fields={int(o): (f["size"], *cls_info(f["class"])) for o, f in ty["struct"].items()})
    if "array" in ty:
        return dict(kind="array", fields={})
    return dict(kind="unknown", fields={})


class StructIndex:
    """Fast offset -> truth leaf queries for one struct view."""

    def __init__(self, view):
        self.view = view
        self.size = view["size"]
        self.at = collections.defaultdict(list)
        for lf in view["leaves"]:
            self.at[lf["off"]].append(lf)
        self.spans = view["spans"]
        self.leaves = view["leaves"]
        self.starts = sorted(self.at)

    def match(self, off):
        """-> ('exact', size, family) | ('interior',) | ('gap',) | ('out',)"""
        if off in self.at:
            sizes = {lf["size"] for lf in self.at[off]}
            return ("exact", sizes, {truth_family(lf["cls"]) for lf in self.at[off]})
        for s in self.spans:
            if s[0] <= off < s[1] and (off - s[0]) % s[2] == 0:
                return ("exact", {s[2]}, {None})
        if off < 0 or off >= self.size:
            return ("out",)
        for lf in self.leaves:
            if lf["off"] < off < lf["off"] + lf["size"]:
                return ("interior",)
        return ("gap",)

    def valid(self, off):
        return self.match(off)[0] == "exact"

    def offsets(self):
        """Distinct leaf start offsets, with array-span elements beyond the expanded cap included."""
        out = set(self.at)
        for s in self.spans:
            if (s[1] - s[0]) // max(s[2], 1) <= 64:
                out.update(range(s[0], s[1], s[2]))
        return out


def jaccard(a, b):
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def pct(n, d):
    return round(100.0 * n / d, 2) if d else None


def mean(xs):
    xs = list(xs)
    return round(sum(xs) / len(xs), 4) if xs else None


def score_game(truth, dump, variants):
    """The Q1 numbers for one game from the truth JSON and the harness dump."""
    funcs = {r["entry"]: r for r in dump["functions"]}
    nslots = len(dump["int_slots"])
    sidx = {k: StructIndex(v) for k, v in truth["structs"].items() if v.get("ok")}
    sig = dump.get("whatif_signatures", {})
    reg_of_slot = dump["int_slots"]
    out = {"functions_truth": len(truth["functions"]),
           "functions_scored": 0, "variants": {}}
    # --- parameter population
    params = []      # (addr, func_truth, param_truth)
    for addr, ft in truth["functions"].items():
        row = funcs.get(addr)
        if row is None:
            continue
        out["functions_scored"] += 1
        for p in ft["params"]:
            if "slot" not in p or not p.get("slot_clean") or p["slot"] >= nslots:
                continue
            params.append((addr, ft, p))
    pop = collections.Counter(p["kind"] for _, _, p in params)
    out["param_population"] = dict(pop)
    out["struct_params_with_body"] = sum(1 for _, ft, p in params if p["kind"] == "struct_ptr" and ft.get("access", {}).get(str(p["i"])))

    def inferred(addr, p, v):
        row = funcs[addr]
        seq = row.get(v)
        if seq is None:
            return None
        return parse_inferred(seq[p["slot"]])

    for v in variants:
        if not any(v in r for r in funcs.values()):
            continue
        R = collections.Counter()
        kinds = collections.Counter()
        fp = collections.Counter()           # field position classes
        width = collections.Counter()
        fam = collections.Counter()
        matrix = collections.Counter()        # "truth family->inferred family" over fields on a truth field
        prec_macro, rec_all_macro, rec_acc_macro = [], [], []
        rec_all_hit = rec_all_den = rec_acc_hit = rec_acc_den = 0
        false_struct = collections.defaultdict(collections.Counter)
        added = collections.Counter()
        by_key = collections.defaultdict(list)
        nested_counter = collections.Counter()
        for addr, ft, p in params:
            inf = inferred(addr, p, v)
            if inf is None:
                continue
            if p["kind"] in NON_STRUCT_KINDS:
                false_struct[p["kind"]][inf["kind"]] += 1
                false_struct[p["kind"]]["n"] += 1
                continue
            if p["kind"] != "struct_ptr":
                continue
            S = sidx.get(p["key"])
            if S is None:
                continue
            kinds[inf["kind"]] += 1
            R["n"] += 1
            fields = inf["fields"]
            offs = set(fields)
            if inf["kind"] == "struct":
                by_key[p["key"]].append((addr, p["i"], offs))
            # fields added by the interprocedural variants relative to isolated solves
            if v != "iso":
                iso = inferred(addr, p, "iso")
                iso_offs = set(iso["fields"]) if iso else set()
                for o in offs - iso_offs:
                    added["fields"] += 1
                    m = S.match(o)
                    added[m[0]] += 1
                added["params_changed"] += int(offs != iso_offs)
                added["params"] += 1
            if not fields:
                continue
            exact = 0
            for o, (size, family, bits) in fields.items():
                m = S.match(o)
                fp[m[0]] += 1
                if m[0] == "exact":
                    exact += 1
                    width["n"] += 1
                    if size in m[1]:
                        width["exact"] += 1
                    tf = next(iter(m[2])) if len(m[2]) == 1 else "mixed"
                    matrix[f"{tf}->{family}"] += 1
                    if family is not None:
                        fam["known"] += 1
                        if family in m[2] or (None in m[2]):
                            fam["agree"] += 1
            prec_macro.append(exact / len(fields))
            # recall against every truth field
            truth_offs = S.offsets()
            hit = len(truth_offs & offs)
            rec_all_hit += hit
            rec_all_den += len(truth_offs)
            rec_all_macro.append(hit / len(truth_offs) if truth_offs else 1.0)
            acc = [a for a in ft.get("access", {}).get(str(p["i"]), []) if a[2] != "agg"]
            if acc:
                want = {a[0] for a in acc}
                got = 0
                for a in want:
                    if a in offs:
                        got += 1
                        continue
                    # an array element at an unknown index: any boundary of the same span counts
                    for s in S.spans:
                        if s[0] <= a < s[1] and any(s[0] <= o < s[1] and (o - s[0]) % s[2] == 0 for o in offs):
                            got += 1
                            break
                rec_acc_hit += got
                rec_acc_den += len(want)
                rec_acc_macro.append(got / len(want))
            # nesting: pointer-to-struct leaves the function accesses (donor) or the inferred layout holds
            for lf in S.leaves:
                if lf["cls"] == "ptr" and lf.get("target"):
                    accessed = any(a[0] == lf["off"] and a[2] == "ptr" for a in acc)
                    if acc and not accessed:
                        continue
                    mode = "acc" if acc else "all"
                    nested_counter[mode + ".truth_nested_ptr_leaves"] += 1
                    if acc and any(n_[0] == lf["off"] for n_ in ft.get("nested", {}).get(str(p["i"]), [])):
                        nested_counter[mode + ".dereferenced_in_body"] += 1
                    f_ = fields.get(lf["off"])
                    if f_ is None:
                        nested_counter[mode + ".no_field_inferred"] += 1
                    elif f_[1] == "ptr":
                        nested_counter[mode + ".inferred_as_ptr"] += 1
                    elif f_[1] == "code":
                        nested_counter[mode + ".inferred_as_code"] += 1
                    else:
                        nested_counter[mode + ".inferred_not_pointer"] += 1
        # --- cross-function unification of one truth struct
        uni = {"structs": 0, "params": 0, "pairs": 0, "mean_jaccard": None, "identical_pairs": 0,
               "distinct_layouts_per_struct": []}
        jac = []
        for key, items in by_key.items():
            if len(items) < 2:
                continue
            uni["structs"] += 1
            uni["params"] += len(items)
            uni["distinct_layouts_per_struct"].append(len({frozenset(i[2]) for i in items}) / len(items))
            n = len(items)
            pairs = [(a, b) for a in range(n) for b in range(a + 1, n)]
            if len(pairs) > 300:
                import random
                rnd = random.Random(7)
                pairs = rnd.sample(pairs, 300)
            for a, b in pairs:
                j = jaccard(items[a][2], items[b][2])
                jac.append(j)
                uni["identical_pairs"] += int(items[a][2] == items[b][2])
        uni["pairs"] = len(jac)
        uni["mean_jaccard"] = mean(jac)
        uni["jaccard_sum"] = round(sum(jac), 6)
        uni["mean_distinct_layout_ratio"] = mean(uni.pop("distinct_layouts_per_struct"))
        nfs = {}
        for k, c in false_struct.items():
            n = c["n"]
            nfs[k] = {"n": n, "struct": c["struct"], "ptr_scalar": c["ptr_scalar"], "array": c["array"],
                      "struct_pct": pct(c["struct"], n), "struct_or_scalar_ptr_pct": pct(c["struct"] + c["ptr_scalar"], n)}
        n_struct = R["n"]
        out["variants"][v] = {
            "struct_params": n_struct,
            "assigned": dict(kinds),
            "gets_struct_pct": pct(kinds["struct"], n_struct),
            "gets_struct_or_scalar_ptr_pct": pct(kinds["struct"] + kinds["ptr_scalar"], n_struct),
            "gets_any_pointer_pct": pct(kinds["struct"] + kinds["ptr_scalar"] + kinds["ptr_bare"] + kinds["array"], n_struct),
            "fields": dict(fp),
            "field_precision_exact_pct": pct(fp["exact"], sum(fp.values())),
            "field_precision_exact_macro_pct": pct(sum(prec_macro), len(prec_macro)),
            "field_interior_pct": pct(fp["interior"], sum(fp.values())),
            "field_gap_or_out_pct": pct(fp["gap"] + fp["out"], sum(fp.values())),
            "width_exact_of_hits_pct": pct(width["exact"], width["n"]),
            "class_family_agree_of_known_pct": pct(fam["agree"], fam["known"]),
            "recall_all_pooled_pct": pct(rec_all_hit, rec_all_den),
            "recall_all_macro_pct": pct(sum(rec_all_macro), len(rec_all_macro)),
            "recall_accessed_pooled_pct": pct(rec_acc_hit, rec_acc_den),
            "recall_accessed_macro_pct": pct(sum(rec_acc_macro), len(rec_acc_macro)),
            "recall_accessed_params": len(rec_acc_macro),
            "false_struct": nfs,
            "added_by_interprocedural": dict(added) if v != "iso" else None,
            "added_valid_pct": pct(added["exact"], added["fields"]) if v != "iso" else None,
            "unification": uni,
            "nesting": dict(nested_counter),
            "class_matrix": dict(matrix),
            "raw": {"width": dict(width), "family": dict(fam), "recall_all": [rec_all_hit, rec_all_den],
                    "recall_accessed": [rec_acc_hit, rec_acc_den]},
        }
    return out


# ---------------------------------------------------------------------------
# Q2: struct types of matched functions, shared across independent donors
# ---------------------------------------------------------------------------

SDK_PREFIXES = {   # name families of vendor SDKs, for the breakdown only (sharing is by name + layout hash)
    "ps2": re.compile(r"^(?:sce|Sce|SCE|_sce|sif|Sif|SIF|sceVu|sceGs|sceDma|sceGif|sceVif|sceCd|sceSif|sceMc|scePad|sceIpu|rw|Rw|Rp|Rt|Rs|RW|Rx|Ps2)"),
    "gc": re.compile(r"^(?:OS|GX|DVD|PAD|VI|AX|AI|CARD|EXI|SI|DSP|MTX|Mtx|Vec|Quaternion|QUAT|TEX|ARQ|ARC|MIX|SND|DB|THP|DEMO|PPCWG|__)"),
    "wii": re.compile(r"^(?:OS|GX|DVD|PAD|VI|AX|AI|CARD|EXI|SI|DSP|MTX|Mtx|Vec|Quaternion|QUAT|TEX|ARQ|ARC|MIX|SND|DB|THP|DEMO|WPAD|KPAD|NAND|FS|IPC|IOS|RFL|NW4R|nw4r|EGG|JKR|JSU|J3D|J2D|JUT)"),
    "n64": re.compile(r"^(?:OS|Gfx|Vtx|Mtx|Gfx|Light|Hilite|Lights|Viewport|Vp|Tri|Lookat|N_|ALB|AL|Acmd|Acmd|ADPCM|Wav|MQ|NU|u[A-Z]|Sprite|Bitmap|Color|Unk)"),
    "nds": re.compile(r"^(?:OS|GX|G2|G3|MI|FS|CARD|PXI|SND|NNS|NN|Nitro|NNs|DWC|WM|CTRDG|SPI|RTC|FX|MTX|VEC|PM|TP|TS|TEX|CP|DGT|SVC)"),
    "gba": re.compile(r"^(?:Sound|Music|MPlay|SoundInfo|CgbChannel|Dma|Bg|Oam|Obj|Sio|Rfu|Link|Flash|Agb)"),
    "psx": re.compile(r"^(?:GsOT|GsIMAGE|GsDOBJ|Gs|Gt|Gp|RECT|DR_|POLY_|TILE|SPRT|LINE_|DRAWENV|DISPENV|SVECTOR|VECTOR|CVECTOR|MATRIX|LMATRIX|TMD|PMD|RECT|CdlFILE|CdlLOC|Cd|Pad|SPU|Spu|Sp|Ps|PS|EvCB|ThCB|Tcb|TCB)"),
}


def struct_summary(defs, key):
    lay = defs.layout(key)
    if lay and lay["ok"]:
        return {"ok": True, "hash": layout_hash(lay), "size": lay["size"], "bits": lay.get("has_bits", False)}
    return {"ok": False, "why": (lay or {}).get("why", "undefined")}


def donor_struct_usage(game, donor, jobs=4):
    """Struct types in the signatures of the donor's matched functions: name -> {hash, size, functions}."""
    import extract_prototypes as EP
    platform = donor["platform"]
    repo = SCRATCH / "repos" / game
    data = EP.scan_repo(game, repo, SCRATCH / "cache", jobs, False)
    cpp = data["cpp_repo"]
    defs = Defs(scan_repo_defs(repo, jobs, cpp), PLATFORM_ABI[platform])
    types = EP.Types(data["results"], 8 if platform == "ps2" else 4)
    total, all_names = EP.read_truth(game)
    uniq = list(dict.fromkeys(all_names))
    named = [n for n in uniq if not EP.is_generic(n)]
    index = collections.defaultdict(list)
    for r in data["results"]:
        for e in r["entries"]:
            if "scope" in e:
                index[("::".join(e["scope"]), e["name"])].append(e)
    rows, reasons = EP.match_names(named, data["results"], types, platform, cpp)
    # re-derive each matched name's entry group (the same lookup match_names did)
    import itanium_names
    import mwcc_names
    itan = itanium_names.demangle_many(named)
    usage = collections.defaultdict(lambda: {"functions": 0})
    nmatched = 0
    for name in rows:
        dm = itan.get(name) or (mwcc_names.demangle(name) if cpp else None)
        if dm is not None:
            cands = index.get(("::".join(dm.scope), dm.name), [])
        else:
            cands = index.get(("", name), [])
        cands = [e for e in cands if not e.get("err")]
        if not cands:
            continue
        e = next((c for c in cands if c["def"]), cands[0])
        nmatched += 1
        keys = set()
        tys = [t for _, t in e["params"]] + ([e["ret"]] if e.get("ret") else [])
        for t in tys:
            r = defs.resolve(ep_type(t))
            while r[0] in ("ptr", "arr"):
                r = defs.resolve(r[1])
            if r[0] == "agg":
                keys.add(r[1])
        if e.get("in_class") or (dm is not None and dm.scope):
            scope = e["scope"][-1] if e.get("scope") else (dm.scope[-1] if dm is not None and dm.scope else None)
            if scope and (scope in defs.aggs or scope in defs.agg_tags):
                keys.add(scope)
        for k in keys:
            usage[k]["functions"] += 1
    out = {}
    for k, u in usage.items():
        s = struct_summary(defs, k)
        out[k] = dict(u, **s)
    return {"game": game, "platform": platform, "matched_functions": nmatched, "named_truth": len(named),
            "emitted": len(rows), "cpp": cpp, "structs": out, "defined_structs": len([k for k in defs.aggs if not k.startswith("<anon")])}


def transfer_summary(per_donor, donors):
    """Join the donors' struct usage into the per-platform transferability table."""
    tg = {d["game"]: d.get("twin_group") for d in donors}

    def independent(a, b):
        return a != b and not (tg.get(a) and tg.get(a) == tg.get(b))

    by_platform = collections.defaultdict(list)
    for u in per_donor.values():
        by_platform[u["platform"]].append(u)
    # who defines which (name, hash)? and who uses it in a matched function
    summary = {}
    all_rows = []
    for platform, us in sorted(by_platform.items()):
        defining = collections.defaultdict(set)    # (name, hash) -> games using it
        names = collections.defaultdict(lambda: collections.defaultdict(set))   # name -> hash -> games
        for u in us:
            for k, s in u["structs"].items():
                h = s.get("hash") if s["ok"] else None
                if h:
                    defining[(k, h)].add(u["game"])
                names[k][h or "?"].add(u["game"])
        tot = collections.Counter()
        wt = collections.Counter()
        shared_names = collections.Counter()
        fam = collections.Counter()
        per_game = {}
        sdk_re = SDK_PREFIXES.get(platform)
        for u in us:
            g = u["game"]
            c = collections.Counter()
            for k, s in u["structs"].items():
                n_f = s["functions"]
                h = s.get("hash") if s["ok"] else None
                other_hash = h and any(independent(g, o) for o in defining[(k, h)])
                other_name = any(independent(g, o) for hh, gs in names[k].items() for o in gs)
                if h and other_hash:
                    cat = "shared_name_and_layout"
                    shared_names[k] += 1
                elif other_name and h:
                    cat = "same_name_different_layout"
                elif other_name:
                    cat = "same_name_layout_unknown"
                elif h:
                    cat = "game_specific"
                else:
                    cat = "game_specific_layout_unknown"
                c[cat] += 1
                c["total"] += 1
                wt[cat] += n_f
                wt["total"] += n_f
                tot[cat] += 1
                tot["total"] += 1
                if sdk_re and sdk_re.match(k):
                    fam["sdk_named_total"] += 1
                    if cat == "shared_name_and_layout":
                        fam["sdk_named_shared"] += 1
                if cat == "shared_name_and_layout":
                    fam["shared"] += 1
                    if sdk_re and not sdk_re.match(k):
                        fam["shared_not_sdk_named"] += 1
            per_game[g] = dict(c) | {"matched_functions": u["matched_functions"]}
        summary[platform] = {
            "donors": [u["game"] for u in us],
            "independent_donors": len({tg.get(u["game"]) or u["game"] for u in us}),
            "struct_types_used": tot["total"],
            "by_type": {k: v for k, v in tot.items() if k != "total"},
            "shared_pct": pct(tot["shared_name_and_layout"], tot["total"]),
            "types_with_layout": tot["shared_name_and_layout"] + tot["same_name_different_layout"] + tot["game_specific"],
            "shared_pct_of_types_with_layout": pct(
                tot["shared_name_and_layout"],
                tot["shared_name_and_layout"] + tot["same_name_different_layout"] + tot["game_specific"]),
            "shared_pct_function_use_of_types_with_layout": pct(
                wt["shared_name_and_layout"],
                wt["shared_name_and_layout"] + wt["same_name_different_layout"] + wt["game_specific"]),
            "by_function_use": {k: v for k, v in wt.items() if k != "total"},
            "shared_pct_function_use": pct(wt["shared_name_and_layout"], wt["total"]),
            "same_name_any_layout_pct": pct(tot["shared_name_and_layout"] + tot["same_name_different_layout"] + tot["same_name_layout_unknown"], tot["total"]),
            "sdk_named": dict(fam),
            "top_shared_names": [n for n, _ in shared_names.most_common(15)],
            "per_game": per_game,
        }
    return summary


# ---------------------------------------------------------------------------
# Q3: field access as `*(T *)((char *)p + off)` -- does the compiler's output change?
# ---------------------------------------------------------------------------

class Unsupported(Exception):
    pass


C_PRIM_TEXT = {"char": "char", "schar": "signed char", "uchar": "unsigned char", "short": "short",
               "ushort": "unsigned short", "int": "int", "uint": "unsigned int", "long": "long",
               "ulong": "unsigned long", "longlong": "long long", "ulonglong": "unsigned long long",
               "float": "float", "double": "double", "void": "void", "bool": "char"}


def c_decl(defs, ty, inner=""):
    """C declaration text of `ty` around the declarator `inner` (typedef names are kept as written)."""
    k = ty[0]
    if k == "prim":
        return f"{C_PRIM_TEXT[ty[1]]} {inner}".rstrip()
    if k == "named":
        return f"{ty[1]} {inner}".rstrip()
    if k == "agg":
        if ty[1].startswith("<anon"):
            raise Unsupported("anonymous aggregate type")
        d = defs.best_agg(ty[1])
        return f"{d.kind if d else 'struct'} {ty[1]} {inner}".rstrip()
    if k == "enum":
        if ty[1] in ("", "<anon-enum>"):
            raise Unsupported("anonymous enum type")
        return f"enum {ty[1]} {inner}".rstrip()
    if k == "ptr":
        t = defs.resolve(ty[1]) if ty[1][0] == "named" and False else ty[1]
        wrap = f"(*{inner})" if t[0] in ("arr", "code") else f"*{inner}"
        return c_decl(defs, t, wrap)
    if k == "arr":
        if ty[2] is None:
            raise Unsupported("unsized array")
        return c_decl(defs, ty[1], f"{inner}[{ty[2]}]")
    raise Unsupported(f"type {k}")


def member_raw(defs, key, name, depth=0):
    """(offset, raw member type, is_bitfield) of member `name`, typedef names unresolved."""
    lay = defs.layout(key)
    d = defs.best_agg(key)
    if not lay or not lay["ok"] or d is None or depth > 6:
        return None
    raw = {m[0]: m for m in d.members if m[0] is not None}
    offs = {m[0]: m[1] for m in lay["members"] if m[0] is not None}
    if name in raw and name in offs:
        return offs[name], raw[name][1], raw[name][2] is not None
    for m in lay["members"]:
        if m[0] is None and m[2][0] == "agg":
            got = member_raw(defs, m[2][1], name, depth + 1)
            if got:
                return m[1] + got[0], got[1], got[2]
    return None


class FieldRewriter:
    """Rewrites every `a->f` / `a.f` of one function as `(*(T *)((char *)(a) + off))`."""

    def __init__(self, defs, fs, fnode):
        self.defs, self.fs = defs, fs
        self.typer = BodyTyper(defs, fs)
        decl = fnode.child_by_field_name("declarator")
        while decl is not None and decl.type in ("pointer_declarator", "parenthesized_declarator", "attributed_declarator"):
            decl = fs.inner(decl)
        plist = decl.child_by_field_name("parameters") if decl is not None else None
        if plist is not None:
            for ch in plist.named_children:
                if ch.type == "parameter_declaration":
                    base = fs.spec(ch.child_by_field_name("type"))
                    d = ch.child_by_field_name("declarator")
                    if d is None:
                        continue
                    ty, name = fs.declare(base, d)
                    if name:
                        self.typer.env[name] = ("ptr", ty[1]) if ty[0] == "arr" else ty
        self.fnode = fnode
        self.typer.visit(fnode.child_by_field_name("body"))
        self.count = 0

    def rewrite(self):
        return self.text_of(self.fnode)

    def text_of(self, n):
        if n.type == "field_expression":
            return self.field(n)
        if not n.children:
            return self.fs.src[n.start_byte:n.end_byte].decode("utf8", "replace")
        out, pos = [], n.start_byte
        for ch in n.children:
            out.append(self.fs.src[pos:ch.start_byte].decode("utf8", "replace"))
            out.append(self.text_of(ch))
            pos = ch.end_byte
        out.append(self.fs.src[pos:n.end_byte].decode("utf8", "replace"))
        return "".join(out)

    def field(self, n):
        arg = n.child_by_field_name("argument")
        fname = self.fs.t(n.child_by_field_name("field"))
        arrow = any(ch.type == "->" for ch in n.children)
        base_text = self.text_of(arg)
        if arrow:
            res = self.typer.val_of(self.typer.ev(arg))
            if not res or res[0] != "val":
                raise Unsupported(f"type of `{self.fs.t(arg)}` unknown")
            p = self.typer.pointee(res[1])
            addr = f"(char *)({base_text})"
        else:
            res = self.typer.ev(arg, True)
            if not res or res[0] != "mem":
                raise Unsupported(f"type of `{self.fs.t(arg)}` unknown")
            p = self.defs.resolve(res[1])
            addr = f"(char *)&({base_text})"
        if not p or p[0] != "agg":
            raise Unsupported(f"base of `.{fname}` is not an aggregate")
        got = member_raw(self.defs, p[1], fname)
        if got is None:
            raise Unsupported(f"member {fname} of {p[1]} not found")
        off, raw, bits = got
        if bits:
            raise Unsupported(f"bit-field {fname}")
        self.count += 1
        cast = c_decl(self.defs, ("ptr", raw))
        return f"(*({cast})({addr} + {off}))"


def unit_defs(text):
    """Definitions of one preprocessed translation unit (MWCC, PS2 ABI)."""
    src = text.encode("utf8", "replace")
    tree = ts_parser().parse(src)
    fs = FileScan(src, "unit")
    fs.walk(tree.root_node)
    macros = {}
    res = {"aggs": fs.aggs, "typedefs": fs.typedefs, "enums": fs.enums, "vars": fs.vars, "macros": macros,
           "enum_tags": fs.enum_tags, "agg_tags": fs.agg_tags}
    return Defs([res], "ps2")


def rewrite_chunk(defs, chunk_text):
    """-> (rewritten function text, field accesses rewritten). Raises Unsupported."""
    src = chunk_text.encode("utf8", "replace")
    tree = ts_parser().parse(src)
    fs = FileScan(src, "fn")
    found = None
    for ch in tree.root_node.children:
        if ch.type == "function_definition":
            found = ch
            break
    if found is None:
        raise Unsupported("no function definition parsed")
    if tree.root_node.has_error:
        raise Unsupported("syntax the C grammar does not parse")
    rw = FieldRewriter(defs, fs, found)
    out = rw.rewrite()
    return out, rw.count


# `mwccps2 -E` prints its own banner and warnings on stdout; only real directives belong to the unit.
PP_DIRECTIVE = re.compile(r"#\s*(?:pragma|define|undef|if|ifdef|ifndef|else|elif|endif|line|error|include)\b")
def load_m22():
    import importlib.util
    spec = importlib.util.spec_from_file_location("m22_002", REPO / "tests" / "m22-002_ps2_c_output.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["m22_002"] = m
    spec.loader.exec_module(m)
    return m


def run_exactness(work, n=20, seed=20261012, sample_report=None, toolchain=Path("/var/tmp/p4ci")):
    """Q3 on a prepared m22-002 work dir (`work/p4repo`, `work/verify_report.json`): `n` functions of the
    m22-002 sample with field access, compiled as the unit's preprocessed text with the target function as is
    and with every field access rewritten; counts byte-identical objects."""
    import random
    from types import SimpleNamespace
    m = load_m22()
    repo = work / "p4repo"
    bindir = m.write_wrappers(work, toolchain)
    env = m.p4_env(work, toolchain, bindir)
    project = m.Project(repo, env)
    report = json.loads((work / "verify_report.json").read_text())
    rows = {int(r["addr"], 16): r for r in report["results"] if r["status"] == "MATCH"}
    sample = json.loads((sample_report or REPO / "benchmarks" / "reports" / "m22-ps2_p4.json").read_text())["functions"]
    addresses = sorted(int(k, 16) for k in sample)
    random.Random(seed).shuffle(addresses)
    args = SimpleNamespace(compiler="mwcc")
    tmp = work / "q3"
    tmp.mkdir(exist_ok=True)
    out, rejected = [], collections.Counter()
    defs_cache = {}
    for address_ in addresses:
        if len(out) >= n:
            break
        r = rows.get(address_)
        if r is None:
            rejected["not a MATCH row of the verify report"] += 1
            continue
        name = r["name"]
        unit = project.unit(r["file"])
        if unit is None:
            rejected["unit does not preprocess"] += 1
            continue
        chunk = next((c for c in unit["chunks"] if c["kind"] == "funcdef" and c.get("name") == name), None)
        if chunk is None:
            rejected["no definition in the preprocessed unit"] += 1
            continue
        if re.search(r"\basm\b|__asm", chunk["body"]):
            rejected["inline assembly"] += 1
            continue
        if not re.search(r"->|\.\s*[A-Za-z_]", chunk["body"]):
            rejected["no member access in the body"] += 1
            continue
        live = [c for c in unit["chunks"] if c["kind"] != "pp" or PP_DIRECTIVE.match(c["text"])]
        full = "\n".join(c["text"] for c in live)
        if r["file"] not in defs_cache:
            defs_cache[r["file"]] = unit_defs(full)
        try:
            new_text, sites = rewrite_chunk(defs_cache[r["file"]], chunk["text"])
        except Unsupported as exc:
            rejected["rewrite: " + re.sub(r"`[^`]*`|\b\d+\b", "X", str(exc))[:60]] += 1
            continue
        except Exception as exc:     # noqa: BLE001 -- a function the typer cannot read is not a sample
            rejected[f"rewrite error: {type(exc).__name__}"] += 1
            continue
        if sites == 0:
            rejected["no field access rewritten"] += 1
            continue
        address = int(r["addr"], 16)
        retail_row = {"address": address, "window": r["window"], "size": r["object_size"]}
        padded = project.retail.bytes_at(address, r["window"])
        row = {"unit_path": unit["path"]}
        results = {}
        for label, text in (("control", chunk["text"]), ("rewritten", new_text)):
            pieces = [new_text if (c is chunk and label == "rewritten") else c["text"] for c in live]
            source = tmp / f"{name}.{label}.c"
            source.write_text("\n".join(pieces) + "\n")
            output = tmp / f"{name}.{label}.o"
            result, errors = m.compile_candidate(project, source, output, row, args)
            entry = {"compiled": False}
            if result["exit"] == 0 and output.exists():
                try:
                    body, relocations = project.V.ObjectFile(output).function(name)
                    differences, _ = project.V.compare(body, relocations, padded)
                    entry.update(compiled=True, size=len(body), byte_differences_vs_retail=differences,
                                 exact=differences == 0 and len(body) == r["object_size"] and len(body) <= len(padded)
                                 and not any(padded[len(body):]),
                                 body=body.hex(), relocations=json.dumps(sorted(
                                     [json.dumps(x, sort_keys=True, default=str) for x in relocations])))
                except (KeyError, ValueError, OSError) as exc:
                    entry["error"] = f"no symbol {name}: {exc}"
            else:
                entry["error"] = "; ".join(errors[:2]) or (result["stderr"] + result["stdout"])[-300:].strip()
            results[label] = entry
        c, w = results["control"], results["rewritten"]
        if not c.get("compiled") or not c.get("exact"):
            why = "does not compile" if not c.get("compiled") else "differs from retail"
            log(f"control {name} ({r['file']}): {why}: {c.get('error') or c.get('byte_differences_vs_retail')}")
            rejected["control (truth as is) is not exact through this harness: " + why] += 1
            continue
        item = {"name": name, "file": r["file"], "size": r["object_size"], "field_accesses_rewritten": sites,
                "compiler": ("b119" if "b119" in str(unit["compiler"]) else "b210") + " " + " ".join(f for f in unit["flags"] if f.startswith("-O")),
                "rewritten_compiled": w.get("compiled", False), "rewritten_exact": bool(w.get("exact")),
                "identical_object": bool(w.get("compiled") and w["body"] == c["body"] and w["relocations"] == c["relocations"]),
                "identical_bytes": bool(w.get("compiled") and w["body"] == c["body"]),
                "rewritten_size": w.get("size"), "byte_differences_vs_retail": w.get("byte_differences_vs_retail"),
                "error": w.get("error"), "example": re.findall(r"\(\*\([^()]*\)\([^;]*?\)\)", new_text)[:2]}
        out.append(item)
        log(f"{name}: sites {sites} identical={item['identical_object']} rewritten_exact={item['rewritten_exact']}")
    return {"requested": n, "seed": seed, "functions": out, "rejected": dict(rejected),
            "pool": len(addresses), "identical_objects": sum(1 for x in out if x["identical_object"]),
            "rewritten_exact": sum(1 for x in out if x["rewritten_exact"]),
            "rewritten_compiled": sum(1 for x in out if x["rewritten_compiled"]),
            "identical_bytes": sum(1 for x in out if x["identical_bytes"])}


# ---------------------------------------------------------------------------
# Q1(a) nesting loss, Q1(b) polymorphic callees
# ---------------------------------------------------------------------------

def nesting_layout_stats(truth, dump, names_only=False):
    """Pointer-to-struct fields of the truth structs the scored parameters point at, and recursion."""
    funcs = {r["entry"] for r in dump["functions"]}
    keys = set()
    for addr, ft in truth["functions"].items():
        if addr not in funcs:
            continue
        for p in ft["params"]:
            if p["kind"] == "struct_ptr" and p.get("slot_clean"):
                keys.add(p["key"])
    structs = {k: truth["structs"][k] for k in keys if truth["structs"].get(k, {}).get("ok")}
    leaves = ptr_leaves = struct_ptr_leaves = self_ptr = 0
    with_struct_ptr = recursive = 0
    graph = {}
    for k, s in truth["structs"].items():
        if not s.get("ok"):
            continue
        graph[k] = {lf["target"] for lf in s["leaves"] if lf["cls"] == "ptr" and lf.get("target") in truth["structs"]}
    for k, s in structs.items():
        leaves += len(s["leaves"])
        pl = [lf for lf in s["leaves"] if lf["cls"] == "ptr"]
        ptr_leaves += len(pl)
        sp = [lf for lf in pl if lf.get("target")]
        struct_ptr_leaves += len(sp)
        self_ptr += sum(1 for lf in sp if lf["target"] == k)
        with_struct_ptr += int(bool(sp))
        # reachable back to itself through pointers
        seen, todo = set(), list(graph.get(k, ()))
        while todo:
            t = todo.pop()
            if t == k:
                recursive += 1
                break
            if t in seen:
                continue
            seen.add(t)
            todo.extend(graph.get(t, ()))
    return {"structs": len(structs), "leaves": leaves, "pointer_leaves": ptr_leaves,
            "pointer_to_struct_leaves": struct_ptr_leaves, "self_pointer_leaves": self_ptr,
            "structs_with_pointer_to_struct": with_struct_ptr, "structs_recursive_via_pointers": recursive,
            "pointer_to_struct_pct_of_pointer_leaves": pct(struct_ptr_leaves, ptr_leaves),
            "structs_with_pointer_to_struct_pct": pct(with_struct_ptr, len(structs)),
            "structs_recursive_pct": pct(recursive, len(structs))}


def poly_analysis(truth, dump):
    """Callees that call sites reach with different truth structs, and what merging does to them."""
    funcs = {r["entry"]: r for r in dump["functions"]}
    slots = dump["int_slots"]
    sidx = {k: StructIndex(v) for k, v in truth["structs"].items() if v.get("ok")}
    a2n = truth.get("addr_by_name", {})
    sites = collections.defaultdict(list)       # (callee addr, slot) -> [(caller addr, arg dict)]
    for caddr, ft in truth["functions"].items():
        if caddr not in funcs:
            continue
        for call in ft.get("calls", []):
            ca = a2n.get(call["callee"])
            if ca is None or ca not in funcs:
                continue
            tparams = truth["functions"].get(ca, {}).get("params")
            for i, arg in enumerate(call["args"]):
                if tparams is None:
                    # a callee without donor source (a library helper such as memcpy): the i-th argument is
                    # taken to be the i-th integer slot, for the first four
                    if i > 3:
                        continue
                    sites[(ca, i)].append((caddr, arg, {"kind": "no_source", "slot": i}))
                    continue
                if i >= len(tparams) or "slot" not in tparams[i] or not tparams[i].get("slot_clean") or tparams[i]["slot"] >= len(slots):
                    continue
                sites[(ca, tparams[i]["slot"])].append((caddr, arg, tparams[i]))
    sig = dump.get("whatif_signatures", {})
    joins = collections.defaultdict(list)
    for j in dump.get("whatif_joins", []):
        joins[(j["callee"], j["reg"])].append(j)
    out = {"call_sites_with_struct_args": 0, "callee_slots_with_struct_args": 0, "polymorphic_slots": 0,
           "by_callee_param_kind": collections.Counter(), "callees": [], "total_call_sites_poly": 0}
    mixed = merged_fields = wrong_pairs = total_pairs = 0
    added_fields = added_wrong = added_pairs = 0
    iso_nonempty = 0
    cross_contrib = 0
    caller_push = collections.Counter()
    for (ca, slot), lst in sites.items():
        keys = [a["key"] for _, a, _ in lst if a.get("kind") == "struct_ptr" and a.get("key") in sidx]
        if not keys:
            continue
        out["callee_slots_with_struct_args"] += 1
        out["call_sites_with_struct_args"] += len(keys)
        K = sorted(set(keys))
        if len(K) < 2:
            continue
        out["polymorphic_slots"] += 1
        out["total_call_sites_poly"] += len(keys)
        tp = lst[0][2]
        out["by_callee_param_kind"][tp["kind"]] += 1
        reg = slots[slot]
        merged = None
        for r_, ty in sig.get(ca, {}).get("params", []):
            if r_ == reg:
                merged = parse_inferred(ty)
        iso = parse_inferred(funcs[ca]["iso"][slot])
        iso_offs = set(iso["fields"])
        m_offs = set(merged["fields"]) if merged else set()
        valid_sets = {o: {k for k in K if sidx[k].valid(o)} for o in m_offs}
        n_wrong = sum(len(K) - len(v) for v in valid_sets.values())
        mixed_here = any(0 < len(v) < len(K) for v in valid_sets.values()) or any(len(v) == 0 for v in valid_sets.values())
        mixed += int(mixed_here)
        merged_fields += len(m_offs)
        wrong_pairs += n_wrong
        total_pairs += len(m_offs) * len(K)
        add = m_offs - iso_offs
        added_fields += len(add)
        added_wrong += sum(len(K) - len(valid_sets[o]) for o in add)
        added_pairs += len(add) * len(K)
        iso_nonempty += int(bool(iso_offs))
        # who contributed the added fields: callers whose truth struct differs
        contrib_keys = set()
        for j in joins.get((ca, reg), []):
            added_here = j.get("added")
            if added_here is None:      # the first driver logged whole types before/after the join
                added_here = set(parse_inferred(j.get("after"))["fields"]) - set(parse_inferred(j.get("before"))["fields"])
            if added_here:
                for caddr, arg, _ in lst:
                    if caddr[:8] == j["caller"][:8] and arg.get("key"):
                        contrib_keys.add(arg["key"])
        cross_contrib += int(len(contrib_keys) >= 2)
        # push back into callers: the caller's own parameter that is passed straight through
        for caddr, arg, _ in lst:
            if arg.get("param") is None or arg.get("off") not in (0, None):
                continue
            ft = truth["functions"][caddr]
            cp = next((p for p in ft["params"] if p["i"] == arg["param"]), None)
            if not cp or cp["kind"] != "struct_ptr" or not cp.get("slot_clean") or cp["slot"] >= len(slots):
                continue
            S = sidx.get(cp["key"])
            if S is None:
                continue
            base = set(parse_inferred(funcs[caddr]["iso"][cp["slot"]])["fields"])
            now = set(parse_inferred(funcs[caddr]["whatif"][cp["slot"]])["fields"])
            caller_push["params"] += 1
            new = now - base
            caller_push["params_with_added_fields"] += int(bool(new))
            caller_push["added_fields"] += len(new)
            caller_push["added_wrong"] += sum(1 for o in new if not S.valid(o))
        if len(out["callees"]) < 25:
            nm = next((n for n, a in a2n.items() if a == ca), ca)
            out["callees"].append({"callee": nm, "slot": slot, "param_kind": tp["kind"], "truth_structs": K[:6],
                                   "n_truth_structs": len(K), "call_sites": len(keys),
                                   "merged_fields": len(m_offs), "iso_fields": len(iso_offs),
                                   "wrong_of_pairs": f"{n_wrong}/{len(m_offs) * len(K)}"})
    out["by_callee_param_kind"] = dict(out["by_callee_param_kind"])
    ps = out["polymorphic_slots"]
    out.update({
        "merged_layout_has_fields_foreign_to_some_call_site": mixed,
        "merged_layout_cross_struct_pct": pct(mixed, ps),
        "merged_fields_total": merged_fields,
        "wrong_field_pairs": wrong_pairs, "field_call_site_pairs": total_pairs,
        "wrong_field_share_pct": pct(wrong_pairs, total_pairs),
        "fields_added_by_merging": added_fields,
        "added_wrong_share_pct": pct(added_wrong, added_pairs),
        "added_wrong_pairs": added_wrong, "added_pairs": added_pairs,
        "callee_slots_with_nonempty_isolated_layout": iso_nonempty,
        "slots_with_two_or_more_distinct_truth_struct_contributors": cross_contrib,
        "caller_pushback": dict(caller_push),
        "caller_pushback_wrong_pct": pct(caller_push["added_wrong"], caller_push["added_fields"]),
        "shipped_join_events": len(dump.get("shipped_joins", [])),
        "whatif_join_events": len(dump.get("whatif_joins", [])),
    })
    return out


def unification_deltas(truth, dump, variants):
    """Pairs of functions taking the same truth struct: does a variant's layout agree more than isolated ones?"""
    import random
    funcs = {r["entry"]: r for r in dump["functions"]}
    nslots = len(dump["int_slots"])
    groups = collections.defaultdict(list)
    for addr, ft in truth["functions"].items():
        if addr not in funcs:
            continue
        for p in ft["params"]:
            if p["kind"] == "struct_ptr" and p.get("slot_clean") and p["slot"] < nslots \
                    and truth["structs"].get(p["key"], {}).get("ok"):
                groups[p["key"]].append((addr, p["slot"]))

    def offs(addr, slot, v):
        return set(parse_inferred(funcs[addr][v][slot])["fields"])

    out = {}
    for v in variants:
        if v == "iso" or not any(v in r for r in funcs.values()):
            continue
        c = collections.Counter()
        for key in sorted(groups):
            items = groups[key]
            if len(items) < 2:
                continue
            pairs = [(a, b) for a in range(len(items)) for b in range(a + 1, len(items))]
            if len(pairs) > 300:
                pairs = random.Random(sum(map(ord, key))).sample(pairs, 300)
            for a, b in pairs:
                ia, ib = offs(*items[a], "iso"), offs(*items[b], "iso")
                va, vb = offs(*items[a], v), offs(*items[b], v)
                if not (ia or ib or va or vb):
                    continue
                j0, j1 = jaccard(ia, ib), jaccard(va, vb)
                c["pairs"] += 1
                c["more_unified"] += j1 > j0 + 1e-9
                c["less_unified"] += j1 < j0 - 1e-9
                c["same"] += abs(j1 - j0) <= 1e-9
                c["jaccard_iso_sum"] += j0
                c["jaccard_variant_sum"] += j1
                c["identical_iso"] += ia == ib
                c["identical_variant"] += va == vb
        out[v] = {"pairs": c["pairs"], "more_unified": c["more_unified"], "same": c["same"],
                  "less_unified": c["less_unified"],
                  "mean_jaccard_iso": round(c["jaccard_iso_sum"] / c["pairs"], 4) if c["pairs"] else None,
                  "mean_jaccard_variant": round(c["jaccard_variant_sum"] / c["pairs"], 4) if c["pairs"] else None,
                  "identical_pairs_iso": c["identical_iso"], "identical_pairs_variant": c["identical_variant"]}
    return out


GAMES = {
    # game -> (truth source, image used for the host run)
    "ps2-persona-4": "donor", "ps2-fatal-frame": "donor", "ps2-god-hand": "donor",
    "ps2-ratchet-clank": "donor", "ps2-digital-devil-saga": "donor",
    "ps2-capcom-fighting-evolution": "dwarf1", "ps2-dungeon-game": "dwarf2",
}
DWARF_IMAGES = {"ps2-capcom-fighting-evolution": ("ps2-capcom-fighting-evolution/SLUS_209.50", "dwarf1"),
                "ps2-dungeon-game": ("ps2-dungeon-game/dungeon_game.elf", "dwarf2")}
IMAGE_FILES = {"ps2-persona-4": "SLUS_217.82", "ps2-fatal-frame": "SLUS_203.88", "ps2-god-hand": "SLUS_215.03",
               "ps2-ratchet-clank": "SCUS_971.99", "ps2-digital-devil-saga": "SLUS_209.74",
               "ps2-capcom-fighting-evolution": "SLUS_209.50", "ps2-dungeon-game": "dungeon_game.elf"}


def host_run(game, root, work, threads=4, strong_entries=None):
    """On the analysis host: build, strip, import and dump. `root` is the synced checkout, `work` a scratch dir;
    the dump lands in `work/dump` (what `score` reads). `strong_entries`: decompile only those entries (hex, one per line)."""
    import shutil
    import sqlite3
    import subprocess
    env = dict(os.environ, ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1")
    example = root / "crates" / "romwright-core" / "examples"
    example.mkdir(exist_ok=True)
    shutil.copy(HERE / "struct_audit_dump.rs", example / "struct_audit_dump.rs")
    subprocess.run(["cargo", "build", "--release", "-p", "romwright-cli", "-p", "romwright-worker", "-p", "romwright-api",
                    "-p", "romwright-core", "--example", "struct_audit_dump"], cwd=root, check=True, env=env)
    src = CORPUS / (DWARF_IMAGES[game][0] if game in DWARF_IMAGES else f"{game}/{IMAGE_FILES[game]}")
    img = work / "images" / game / "image.elf"
    img.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["llvm-strip", "--strip-all", "-o", str(img), str(src)], check=True)
    proj = work / "proj" / game
    shutil.rmtree(proj, ignore_errors=True)
    proj.mkdir(parents=True)
    subprocess.run([str(root / "target/release/romwright-cli"), "import", str(img), "--name", "main", "--project", str(proj),
                    "--timings"], check=True, env=env)
    db = sqlite3.connect(proj / "project.sqlite")
    entries = work / "out" / f"entries-{game}.txt"
    entries.parent.mkdir(parents=True, exist_ok=True)
    entries.write_text("\n".join(r[0] for r in db.execute("select entry from functions")) + "\n")
    out = work / "dump" / f"dump-{game}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    command = [str(root / "target/release/examples/struct_audit_dump"), "--project", str(proj), "--binary", str(img),
               "--program", "main", "--language", "r5900:LE:32:default", "--entries", str(entries), "--out", str(out),
               "--strong", "--threads", str(threads)]
    if strong_entries:
        command += ["--strong-entries", str(strong_entries)]
    subprocess.run(command, check=True, env=env)
    return out


def game_report(game, truth_path, dump_path):
    truth = json.loads(Path(truth_path).read_text())
    dump = json.loads(Path(dump_path).read_text())
    variants = [v for v in VARIANTS if any(v in r for r in dump["functions"])]
    q1 = score_game(truth, dump, variants)
    q1["nesting_layout"] = nesting_layout_stats(truth, dump)
    q1["unification_vs_isolated"] = unification_deltas(truth, dump, variants)
    q1["polymorphism"] = poly_analysis(truth, dump) if any(f.get("calls") for f in truth["functions"].values()) else None
    q1["truth"] = {"source": "DWARF" if truth.get("reader") else "donor headers + function definitions",
                   "compiler": truth.get("compiler") or ("MWCC DWARF 1" if truth.get("reader") == "dwarf1" else "ee-gcc DWARF 2"),
                   "repo": truth.get("repo"), "structs_with_layout": sum(1 for s in truth["structs"].values() if s.get("ok")),
                   "structs_without_layout": sum(1 for s in truth["structs"].values() if not s.get("ok")),
                   "skipped": truth.get("skipped"), "unresolved_type_names": truth.get("unresolved_names")}
    q1["image_functions"] = len(dump["functions"])
    return q1


def pooled_poly(games):
    t = collections.Counter()
    for g in games.values():
        p = g.get("polymorphism")
        if not p:
            continue
        for k in ("callee_slots_with_struct_args", "polymorphic_slots", "call_sites_with_struct_args", "total_call_sites_poly",
                  "merged_fields_total", "wrong_field_pairs", "field_call_site_pairs", "fields_added_by_merging",
                  "added_wrong_pairs", "added_pairs", "merged_layout_has_fields_foreign_to_some_call_site",
                  "slots_with_two_or_more_distinct_truth_struct_contributors", "whatif_join_events", "shipped_join_events"):
            t[k] += p[k]
        for k, v in p["caller_pushback"].items():
            t["pushback_" + k] += v
    return {**dict(t),
            "polymorphic_slot_pct": pct(t["polymorphic_slots"], t["callee_slots_with_struct_args"]),
            "polymorphic_call_site_pct": pct(t["total_call_sites_poly"], t["call_sites_with_struct_args"]),
            "merged_layout_foreign_field_pct_of_poly_slots": pct(t["merged_layout_has_fields_foreign_to_some_call_site"], t["polymorphic_slots"]),
            "wrong_field_share_pct": pct(t["wrong_field_pairs"], t["field_call_site_pairs"]),
            "added_wrong_share_pct": pct(t["added_wrong_pairs"], t["added_pairs"]),
            "pushback_wrong_pct": pct(t["pushback_added_wrong"], t["pushback_added_fields"])}


def pooled_variant(games, v):
    rows = [g["variants"][v] for g in games.values() if v in g["variants"]]
    n = sum(r["struct_params"] for r in rows)
    assigned = collections.Counter()
    fields = collections.Counter()
    width = collections.Counter()
    fam = collections.Counter()
    matrix = collections.Counter()
    rec_all = [0, 0]
    rec_acc = [0, 0]
    false = collections.defaultdict(collections.Counter)
    nest = collections.Counter()
    uni = collections.Counter()
    added = collections.Counter()
    for r in rows:
        assigned.update(r["assigned"])
        fields.update(r["fields"])
        width.update(r["raw"]["width"])
        fam.update(r["raw"]["family"])
        matrix.update(r["class_matrix"])
        rec_all[0] += r["raw"]["recall_all"][0]
        rec_all[1] += r["raw"]["recall_all"][1]
        rec_acc[0] += r["raw"]["recall_accessed"][0]
        rec_acc[1] += r["raw"]["recall_accessed"][1]
        for k, d in r["false_struct"].items():
            false[k].update({"n": d["n"], "struct": d["struct"], "ptr_scalar": d["ptr_scalar"]})
        nest.update(r["nesting"])
        if r.get("added_by_interprocedural"):
            added.update({k: x for k, x in r["added_by_interprocedural"].items() if isinstance(x, int)})
        u = r["unification"]
        uni.update({"pairs": u["pairs"], "identical": u["identical_pairs"], "jaccard_sum": u["jaccard_sum"]})
    tot_f = sum(fields.values())
    return {
        "struct_params": n, "assigned": dict(assigned),
        "gets_struct_pct": pct(assigned["struct"], n),
        "gets_struct_or_scalar_ptr_pct": pct(assigned["struct"] + assigned["ptr_scalar"], n),
        "field_precision_exact_pct": pct(fields["exact"], tot_f), "fields": dict(fields),
        "field_interior_pct": pct(fields["interior"], tot_f),
        "field_gap_or_out_pct": pct(fields["gap"] + fields["out"], tot_f),
        "width_exact_of_hits_pct": pct(width["exact"], width["n"]),
        "class_family_agree_pct": pct(fam["agree"], fam["known"]),
        "class_matrix": dict(matrix),
        "recall_all_pct": pct(*rec_all), "recall_accessed_pct": pct(*rec_acc),
        "false_struct": {k: {"n": c["n"], "struct_pct": pct(c["struct"], c["n"]),
                             "struct_or_scalar_ptr_pct": pct(c["struct"] + c["ptr_scalar"], c["n"])} for k, c in false.items()},
        "nesting": dict(nest),
        "added_by_interprocedural": dict(added) if added else None,
        "added_valid_pct": pct(added["exact"], added["fields"]) if added else None,
        "unification": {"pairs": uni["pairs"], "mean_jaccard": round(uni["jaccard_sum"] / uni["pairs"], 4) if uni["pairs"] else None,
                        "identical_pct": pct(uni["identical"], uni["pairs"])},
    }


def validate_mwcc_layouts(work, units=12, toolchain=Path("/var/tmp/p4ci")):
    """Does this module's layout engine agree with MWCC? Every struct of the busiest units, checked with
    compile-time `sizeof` / member-address assertions through the repo's own compile command."""
    from types import SimpleNamespace
    m = load_m22()
    repo = work / "p4repo"
    bindir = m.write_wrappers(work, toolchain)
    env = m.p4_env(work, toolchain, bindir)
    project = m.Project(repo, env)
    report = json.loads((work / "verify_report.json").read_text())
    files = collections.Counter(r["file"] for r in report["results"] if r["status"] == "MATCH" and not r["file"].startswith("src/promoted"))
    args = SimpleNamespace(compiler="mwcc")
    tmp = work / "q3"
    tmp.mkdir(exist_ok=True)
    totals = collections.Counter()
    bad = []
    done_types = set()
    for rel, _ in files.most_common(units * 3):
        if totals["units"] >= units:
            break
        unit = project.unit(rel)
        if unit is None:
            continue
        live = [c for c in unit["chunks"] if c["kind"] != "pp" or PP_DIRECTIVE.match(c["text"])]
        text = "\n".join(c["text"] for c in live)
        defs = unit_defs(text)
        checks = []
        for key, lst in defs.aggs.items():
            if key.startswith("<anon") or key in done_types:
                continue
            d = defs.best_agg(key)
            lay = defs.layout(key)
            if not lay or not lay["ok"] or lay.get("has_bits") or d.kind != "struct":
                totals["skipped_no_layout_or_bitfield"] += 1
                continue
            tname = f"struct {key}" if key in defs.agg_tags else key
            idx = len(checks)
            checks.append((key, f"typedef char chk_{idx}_size[(sizeof({tname}) == {lay['size']}) ? 1 : -1];"))
            for mi, (mname, off, ty) in enumerate(lay["members"]):
                if mname is None:
                    continue
                checks.append((key, f"typedef char chk_{idx}_{mi}[((char *)&((({tname} *)0)->{mname}) - (char *)0 == {off}) ? 1 : -1];"))
            done_types.add(key)
        if not checks:
            continue
        source = tmp / "layout_check.c"
        source.write_text(text + "\n" + "\n".join(c for _, c in checks)
                          + "\ntypedef char chk_canary_size[(sizeof(int) == 5) ? 1 : -1];\n")
        output = tmp / "layout_check.o"
        result, errors = m.compile_candidate(project, source, output, {"unit_path": unit["path"]}, args)
        out_text = result["stdout"] + result["stderr"]
        failing = set(re.findall(r"typedef char (chk_\d+(?:_\w+)?)\[", out_text))
        if "chk_canary_size" not in set(re.findall(r"typedef char (chk_\w+)\[", out_text)):
            raise RuntimeError("the compiler did not report the canary assertion: failures would be invisible")
        sizes = [c for _, c in checks if "_size" in c]
        totals["units"] += 1
        totals["structs_checked"] += len(sizes)
        totals["members_checked"] += len(checks) - len(sizes)
        name_of = {}
        for key, c in checks:
            mm = re.match(r"typedef char (chk_\d+(?:_\w+)?)\[", c)
            name_of[mm.group(1)] = key
        for f in failing:
            bad.append((rel, name_of.get(f, f), f))
        totals["failed_checks"] += len(failing)
        totals["unit_compile_exit_nonzero"] += int(result["exit"] != 0)
        log(f"{rel}: {len(checks)} checks, {len(failing)} failing")
    totals["structs_with_a_failing_check"] = len({(r, k) for r, k, _ in bad})
    return {"units": totals["units"], "totals": dict(totals), "failing": bad[:40]}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

PLUMBING = [
    ("inference result", "crates/romwright-core/src/lib.rs:1457-1584 (`infer_types`: pass 1 Inferred signatures, FuncProto asserted Strong at "
     ":1512-1537, caller->callee joins only for Inferred facts at :1560-1575); the job path is "
     "crates/romwright-core/src/types_infer/prototypes.rs:558-776 (`parameter_types`: one solve per function against "
     "the decompiler's signatures, no joins). Both keep `Ty::Ptr(Ty::Struct(..))` per integer slot."),
    ("erased at the job boundary", "crates/romwright-core/src/types_infer/prototypes.rs:276-310 (`upgrade`: every Ptr/Struct/Array "
     "evidence becomes `pointer()` at :332, a pointee-less `DecompType`) and types_infer.rs:96-104 (`Ty::c_name` -> `void *`)."),
    ("where the decompiler asks for a type", "third_party/ghidra/decompiler/typegrp_ghidra.cc:20-35 `TypeFactoryGhidra::findById` -> "
     "ghidra_arch.cc:675-689 `ArchitectureGhidra::getDataType`, which sends a `getDataType(name, id)` query to the client "
     "and `decodeType`s the `<type>` element that comes back; a prototype's C text reaches it through "
     "native/ghidra-opt-sleigh.patch:~779-835 `SetFunctionSignature::rawAction` -> `parse_protopieces(pieces, input, ghidra)`, "
     "which resolves every named type in the text through that same callback."),
    ("where romwright answers", "crates/romwright-worker/src/provider.rs:1077 dispatches `GETDATATYPE` to `answer_datatype` "
     "(provider.rs:1380-1431): a language base type (:1388-1407) or a named `provider.datatypes` entry, answered as a "
     "1-byte placeholder whose metatype is guessed from the definition text (`datatype_metatype`, :2168). No `<field>` child "
     "is ever encoded, so a struct cannot reach the TypeFactory as a struct."),
    ("what feeds `provider.datatypes`", "provider.rs:443 reads `db.datatypes(pid)` (name -> definition string). The tables that hold "
     "layouts, `type_defs` / `type_fields` (crates/romwright-db/src/lib.rs:366/378; `type_defs()` :2899, `type_fields()` :2965), "
     "are written by fact_sync.rs and `replace_type_fields` (crates/romwright-core/src/lib.rs:664) and read by nothing in the worker."),
    ("wire encoding that is missing", "crates/romwright-worker/src/wire.rs:667-710 has `encode_typeref`, `encode_array_type`, "
     "`encode_pointer_type`, `encode_basic_type`; there is no struct encoder. The decoder it must satisfy is "
     "third_party/ghidra/decompiler/type.cc:2104-2260 (`TypeStruct::decodeField` / `decodeFields`: a field needs a name, an "
     "offset and a non-void type; a nested struct is a `<typeref>`)."),
    ("printing side already there", "native/romwright_printir.hh:932-975 writes every `TypeStruct` and its fields into the print IR, and "
     "crates/romwright-worker/src/printc/{tree.rs:95 `FieldDesc`, pretty.rs:207 `FieldRef`, render.rs:595 `findTruncation`} "
     "consume them, so `p->field` printing needs only the typed parameter; emitting the struct *definitions* next to the "
     "function (the context header) is not done."),
]

RECOMMENDATION = (
    "Order: **plumbing, then DWARF layouts, then inferred layouts (bottom-up only, gated), then donor SDK layouts; "
    "no solver upgrade before printing.**\n\n"
    "1. **Plumbing first.** Nothing prints a struct until `answer_datatype` (provider.rs:1380) can encode a `<type "
    "metatype=\"struct\">` with fields and the prototype text can name it; every layout source below needs that one path, "
    "and the print IR/printer already carry struct fields.\n"
    "2. **DWARF layouts second.** Exact by construction (the compiler's own offsets), no inference risk, and the cheapest way to prove "
    "the plumbing: Capcom's debug build gives 4,460 scored truth struct-pointer parameters with exact layouts (5,221 functions carry debug info).\n"
    "3. **Inferred layouts third, per function and bottom-up, not merged.** Isolated solves are 95.6% precise on offsets and "
    "95.8% on widths (donor-truth games), and callee -> caller injection alone (`fwd`) adds 8.5 points of coverage at -0.6 "
    "points of precision with 93.7% of the added fields real. Gate the printing: 47.7% of truth `void *` and 56.4% of truth "
    "scalar-pointer parameters (24% on the DWARF games) also get a `Ty::Struct`, and a pointer used only at constant offsets cannot be told "
    "from a struct; the layout of one truth struct differs from function to function (mean Jaccard 0.33), so print per-function "
    "anonymous structs rather than a shared type, until a unification step exists. Two defects to fix with it: a loaded field is "
    "never given class `Ptr` (0% of accessed pointer-to-struct fields come out as pointers: 81% are `num`, 19% absent), and "
    "the 25% of those that the same body dereferences lose their pointee.\n"
    "4. **Donor layouts last, and only the shared SDK part.** Types shared (same name and layout hash) by at least two independent "
    "donors are 24% of the struct types used by matched functions on N64, 12% on PSX, 8% on GC and on Wii (31% of the types that have "
    "a layout), 4% on PS2, 2% on GBA, 1% on NDS; weighted by the matched functions that use them: 14% N64, 6% PSX, 5% GC, 3% Wii, "
    "3% GBA, 2% PS2, 1% NDS. Game-specific structs do not transfer; ship the shared set (libultra, PsyQ, Dolphin SDK, `sce*`) and "
    "keep the rest per game.\n\n"
    "**Solver upgrade (algebraic subtyping): not before printing.** (a) Nesting: 15-66% of the truth structs contain a pointer to a "
    "struct, 25-88% of their pointer fields do, 0-16% are recursive; a recovered nested pointer today is a `num` field, and a "
    "pointee needs a global type-variable graph (recursive types), not a per-function `Field`. (b) Polymorphism: 7.0% of callee "
    "parameter slots that receive truth structs are reached with different structs (25.7% of those call sites, since the shared "
    "helpers are the hot ones). The damage is done by the caller -> callee joins, not by a missing scheme: with them (`whatif`) "
    "precision falls from 95.6% to 46.2% (donor games; 67.8% on DWARF) for +1.8 points of coverage over `fwd`, and 65.9% of "
    "the fields that merging adds at polymorphic slots are wrong for some call site. `shipped` is immune only because the decompiler's "
    "FuncProto overrides the inference, which is also why it propagates no structure at all (it equals `iso` to 0.1 point). "
    "Dropping the joins removes the harm; per-call-site schemes would recover at most the +1.8 points and the identity of "
    "types across functions, which is a separate (unification) problem.")

LIMITS = [
    "Truth is the donor repository's source declarations for the five donor games (Persona 4, Fatal Frame, God Hand, Ratchet & Clank, "
    "Digital Devil Saga) and the compiler's debug info for Capcom Fighting Evolution (MWCC DWARF 1, `benchmarks/dwarf1_types.py` reader) "
    "and the Dungeon game image (ee-gcc DWARF 2, 10 struct-pointer parameters only). No GameCube/MWCC image with debug info exists in the "
    "corpus (the GC donors are decomp-symbols maps), so there is no GC row in Q1; GC and Wii are covered by Q2 from headers.",
    "Persona 4's repo is partly m2c-shaped, so its 'non-struct pointer' truth (`s32 *`, `u8 *`) is a guess in places: its false-struct "
    "rates are inflated; Fatal Frame, Ratchet & Clank, Digital Devil Saga and the DWARF games are hand-written C or compiler truth.",
    "Donor layouts are computed by this script with the PS2 ABI (`long` 8, pointers 4; `long` = 8 confirmed on the ee-gcc DWARF 2 "
    "image; Capcom's DWARF 1 measures 8 for MWCC). Only the MWCC side is checked against a compiler: 113 structs / 637 members "
    "of 14 Persona 4 units asserted with `sizeof` / member-address checks through the repo's own compile command (canary assertion "
    "proves the compiler reports failures): 1 struct disagrees. ee-gcc and SN ProDG layouts are not compiler-checked (the i386 ee-gcc "
    "cannot run on the hosts). Bit-field packing is approximate. C++ donors (Dark Cloud, Dark Chronicle) are not in Q1; classes "
    "with bases or virtuals have no layout in Q2.",
    "Only parameters with no floating-point parameter before them are scored (the integer slot is then unambiguous); structs passed "
    "by value, variadic functions and names with several differing source signatures are dropped.",
    "'Accessed fields' are the members the body reaches through the parameter or a local alias (typed with this script's own "
    "member-access typer); accesses through a callee are not counted, so recall vs accessed is a small upper bound. Recall vs all "
    "fields is bounded by use and is low by construction.",
    "`shipped` decompiles every entry for Fatal Frame, Ratchet & Clank and the Dungeon image, and only a subset for the rest "
    "(Persona 4 355, Digital Devil Saga 1,111, God Hand 350, Capcom 350 functions, struct-pointer ones): the other functions then "
    "have no callee signature. The decompiler's signatures carry no structure, so this changes only scalar caps; the three full runs "
    "and the subset runs agree with `iso` to 0.1 point.",
    "Polymorphic callees are found from call-site argument types in the donor source (casts to `void *` looked through); callees "
    "without donor source (memcpy, memset) assume the i-th argument is integer slot i for i <= 3. Counts are lower bounds.",
    "Q3: the 20 are drawn (seed 20261012) from the 200-function m22-002 sample; only 24 of the 200 have member access, parse and compile as "
    "the unit's preprocessed text with the control exact against retail through this harness; the whole eligible pool is reported too. "
    "Typedef names are kept in the cast types; a member declared `volatile`/`const` would lose its qualifier (none of the 24 does).",
]


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join("" if c is None else str(c) for c in r) + " |")
    return "\n".join(out)


def render_markdown(rep):
    L = ["# Struct recovery audit", "",
         f"Generated by `benchmarks/struct_inference_audit.py` ({rep['generated']}). Measurement only; no product code changed.", ""]
    q1 = rep["q1"]
    games = q1["games"]
    L += ["## Q1. Accuracy of the inferred layouts", "",
          "Variants: `iso` = every function solved alone; `fwd` = callee -> caller injection only; `whatif` = the full "
          "`infer_types` fixpoint with every signature `Inferred` (the decompiler's FuncProto not overriding); "
          "`shipped` = `infer_types` as it runs (FuncProto asserted `Strong`, joins only touch `Inferred` facts).", ""]
    for v in ("iso", "fwd", "whatif", "shipped"):
        rows = []
        for g, r in games.items():
            x = r["variants"].get(v)
            if not x:
                continue
            rows.append([g, r["truth"]["compiler"][:34], x["struct_params"], x["gets_struct_pct"], x["gets_struct_or_scalar_ptr_pct"],
                         x["field_precision_exact_pct"], x["field_interior_pct"], x["field_gap_or_out_pct"],
                         x["width_exact_of_hits_pct"], x["class_family_agree_of_known_pct"],
                         x["recall_all_pooled_pct"], x["recall_accessed_pooled_pct"]])
        for label, key in (("**pooled, all**", "pooled"), ("**pooled, donor-source truth**", "pooled_donor"),
                           ("**pooled, DWARF truth**", "pooled_dwarf")):
            p = (q1.get(key) or {}).get(v)
            if p:
                rows.append([label, "", p["struct_params"], p["gets_struct_pct"], p["gets_struct_or_scalar_ptr_pct"],
                             p["field_precision_exact_pct"], p["field_interior_pct"], p["field_gap_or_out_pct"],
                             p["width_exact_of_hits_pct"], p["class_family_agree_pct"], p["recall_all_pct"], p["recall_accessed_pct"]])
        if rows:
            L += [f"### Variant `{v}`", "", md_table(
                ["game", "compiler", "truth struct-ptr params", "gets Ty::Struct %", "Struct or scalar-ptr %",
                 "field precision (offset on a truth field) %", "interior %", "gap/out %", "width equal %", "class family agrees %",
                 "recall vs all fields %", "recall vs fields the body accesses %"], rows), ""]
    L += ["### False-struct rate (truth non-struct pointers that get a `Ty::Struct`)", ""]
    rows = []
    for g, r in games.items():
        for v in ("iso", "shipped"):
            x = r["variants"].get(v)
            if not x:
                continue
            for k, d in x["false_struct"].items():
                rows.append([g, v, k, d["n"], d["struct_pct"], d["struct_or_scalar_ptr_pct"]])
    L += [md_table(["game", "variant", "truth type", "params", "Struct %", "Struct or scalar-ptr %"], rows), ""]
    L += ["### Cross-function unification of one truth struct (pairs of functions taking the same struct)", ""]
    rows = []
    for g, r in games.items():
        for v, d in r["unification_vs_isolated"].items():
            rows.append([g, v, d["pairs"], d["more_unified"], d["same"], d["less_unified"], d["mean_jaccard_iso"],
                         d["mean_jaccard_variant"], d["identical_pairs_iso"], d["identical_pairs_variant"]])
    L += [md_table(["game", "variant", "pairs", "more unified", "same", "less unified", "mean Jaccard iso", "mean Jaccard variant",
                    "identical layouts iso", "identical layouts variant"], rows), ""]
    L += ["### Fields added by interprocedural merging (versus `iso`), and whether they are real", ""]
    rows = []
    for g, r in games.items():
        for v in ("fwd", "whatif", "shipped"):
            x = r["variants"].get(v)
            if x and x["added_by_interprocedural"] is not None:
                a = x["added_by_interprocedural"]
                rows.append([g, v, a.get("params", 0), a.get("params_changed", 0), a.get("fields", 0), a.get("exact", 0),
                             x["added_valid_pct"]])
    L += [md_table(["game", "variant", "struct params", "params whose layout changed", "fields added", "of them on a truth field",
                    "valid %"], rows), ""]
    L += ["### (a) Nesting: pointer-to-struct fields", "",
          "`Field` is `{offset, size, class}`: it cannot name a pointee. Counted per (struct-pointer parameter, truth "
          "pointer-to-struct field): `acc` = fields the function body accesses (donor truth), `all` = every such field "
          "(DWARF truth, or a body not parsed). A field is *recovered as pointer* only if the inferred layout holds a "
          "field there whose class is `Ptr`.", ""]
    rows = []
    for g, r in games.items():
        nl = r["nesting_layout"]
        v = r["variants"].get("shipped") or r["variants"].get("whatif") or r["variants"]["iso"]
        n = v["nesting"]
        for mode in ("acc", "all"):
            tot = n.get(mode + ".truth_nested_ptr_leaves", 0)
            if not tot:
                continue
            rows.append([g, mode, nl["structs"], nl["structs_with_pointer_to_struct_pct"],
                         nl["pointer_to_struct_pct_of_pointer_leaves"], nl["self_pointer_leaves"], nl["structs_recursive_pct"],
                         tot, n.get(mode + ".dereferenced_in_body", "-"),
                         pct(n.get(mode + ".no_field_inferred", 0), tot),
                         pct(n.get(mode + ".inferred_not_pointer", 0) + n.get(mode + ".inferred_as_code", 0), tot),
                         pct(n.get(mode + ".inferred_as_ptr", 0), tot)])
    L += [md_table(["game", "mode", "truth structs", "% with a ptr-to-struct field", "% of pointer fields that point at a struct",
                    "self-pointer fields", "% recursive (via pointers)", "scored ptr-to-struct fields",
                    "dereferenced in the body", "% with no field inferred", "% inferred as a non-pointer (num/int)",
                    "% recovered as `Ptr`"], rows), ""]
    L += ["### (b) Polymorphic callees (call sites reaching one parameter with different truth structs)", ""]
    rows = []
    for g, r in games.items():
        p = r.get("polymorphism")
        if not p:
            continue
        rows.append([g, p["callee_slots_with_struct_args"], p["polymorphic_slots"], p["total_call_sites_poly"],
                     p["merged_layout_cross_struct_pct"], p["merged_fields_total"], p["wrong_field_share_pct"],
                     p["fields_added_by_merging"], p["added_wrong_share_pct"], p["slots_with_two_or_more_distinct_truth_struct_contributors"],
                     p["caller_pushback"].get("params", 0), p["caller_pushback"].get("added_fields", 0), p["caller_pushback_wrong_pct"],
                     p["whatif_join_events"], p["shipped_join_events"]])
    L += [md_table(["game", "callee slots with struct args", "polymorphic (>=2 truth structs)", "call sites",
                    "% merged layout has a field foreign to some call site", "merged fields", "wrong field/call-site share %",
                    "fields added by merging", "of which wrong %", "slots merged from >=2 truth structs",
                    "caller params fed back", "fields pushed back", "pushed-back wrong %", "whatif join events", "shipped join events"], rows), ""]
    pp = q1.get("pooled_polymorphism") or {}
    if pp:
        L += ["Pooled: " + "; ".join(f"{k} {v}" for k, v in pp.items() if k.endswith("_pct")) + ".", ""]
    L += ["## Q2. Donor struct transferability (name + layout hash)", ""]
    rows = []
    for plat, x in rep["q2"].items():
        b = x["by_type"]
        rows.append([plat, len(x["donors"]), x["independent_donors"], x["struct_types_used"], x["types_with_layout"],
                     b.get("shared_name_and_layout", 0), b.get("same_name_different_layout", 0), b.get("same_name_layout_unknown", 0),
                     b.get("game_specific", 0), b.get("game_specific_layout_unknown", 0), x["shared_pct"],
                     x["shared_pct_of_types_with_layout"], x["shared_pct_function_use"], x["shared_pct_function_use_of_types_with_layout"],
                     x["same_name_any_layout_pct"]])
    L += [md_table(["platform", "donors", "independent", "struct types used by matched fns (donor x type)", "with a layout",
                    "shared (name+hash)", "same name, other layout", "same name, layout unknown", "game-specific",
                    "game-specific, layout unknown", "shared %", "shared % of laid-out types", "shared % by function use",
                    "shared % by function use, laid-out types", "same name any layout %"], rows), ""]
    L += ["## Q3. Exactness: field access versus `*(T *)((char *)p + off)` (MWCC, Persona 4)", ""]
    q3 = rep["q3"]
    t = q3["first_20"]
    L += [f"First {len(t['functions'])} functions of the seeded draw: byte-identical object {t['identical_objects']}, exact vs retail "
          f"{t['rewritten_exact']}. Whole eligible pool of the m22-002 sample: {q3['pool']['identical_objects']} of "
          f"{len(q3['pool']['functions'])} identical.", ""]
    lv = q3.get("layout_validation_mwcc")
    if lv:
        t_ = lv["totals"]
        L += [f"Layout engine against MWCC: {t_.get('structs_checked', 0)} structs and {t_.get('members_checked', 0)} members of "
              f"{lv['units']} units asserted at compile time; {t_.get('structs_with_a_failing_check', 0)} struct(s) disagree "
              f"({', '.join(sorted({k for _, k, _ in lv['failing']})) or 'none'}).", ""]
    rows = [[f["name"], f["size"], f["field_accesses_rewritten"], f["compiler"], "yes" if f["identical_object"] else "no",
             f["rewritten_size"], f["byte_differences_vs_retail"]] for f in t["functions"]]
    L += [md_table(["function", "bytes", "accesses rewritten", "compiler", "identical object", "rewritten bytes", "byte diffs vs retail"], rows), ""]
    L += ["## What blocks printing inferred structs (exact path)", ""]
    for k, v in rep["plumbing"]:
        L.append(f"- **{k}**: {v}")
    L += ["", "## Recommendation", "", rep["recommendation"], "", "## Limits", ""]
    L += [f"- {x}" for x in rep["limits"]]
    L.append("")
    return "\n".join(L)


def build_report(work, out_json, out_md, recommendation=None):
    import datetime
    games = {}
    for game in GAMES:
        cached = work / "scores" / f"{game}.json"
        t, d = work / "truth" / f"{game}.json", work / "dump" / f"dump-{game}.json"
        if cached.exists():
            games[game] = json.loads(cached.read_text())
        elif t.exists() and d.exists():
            log(f"scoring {game}")
            games[game] = game_report(game, t, d)
    pooled = {v: pooled_variant(games, v) for v in VARIANTS if any(v in g["variants"] for g in games.values())}
    by_source = {k: {g: x for g, x in games.items() if (GAMES[g] == "donor") == (k == "donor")} for k in ("donor", "dwarf")}
    pooled_groups = {k: {v: pooled_variant(grp, v) for v in VARIANTS if any(v in g["variants"] for g in grp.values())}
                     for k, grp in by_source.items() if grp}
    donors = json.loads((HERE / "fact_pack" / "donors.json").read_text())["donors"]
    per = {d["game"]: json.loads((work / "transfer" / f"{d['game']}.json").read_text()) for d in donors
           if (work / "transfer" / f"{d['game']}.json").exists()}
    q2 = transfer_summary(per, donors)
    q3 = {}
    for name, key in (("first_20", "q3-result-20.json"), ("pool", "q3-result-1000.json")):
        p = work / key
        if p.exists():
            q3[name] = json.loads(p.read_text())
    p = work / "layout-validation.json"
    if p.exists():
        q3["layout_validation_mwcc"] = json.loads(p.read_text())
    rep = {"schema": 1, "generated": datetime.date.today().isoformat(),
           "q1": {"games": games, "pooled": pooled, "pooled_donor": pooled_groups.get("donor"),
                  "pooled_dwarf": pooled_groups.get("dwarf"), "pooled_polymorphism": pooled_poly(games)},
           "q2": q2, "q3": q3, "plumbing": PLUMBING,
           "recommendation": recommendation or RECOMMENDATION, "limits": LIMITS}
    out_json.write_text(json.dumps(rep, indent=1, sort_keys=False))
    out_md.write_text(render_markdown(rep))
    return rep


def selftest():
    """Checks of the layout engine, the field rewriter and the layout parser on small inputs (no tools needed)."""
    text = """
typedef unsigned char u8; typedef unsigned int u32;
typedef struct A { char c; int i; short s[3]; struct A *next; float f; } A;
typedef union U { int i; char c[5]; } U;
typedef struct B { A a; u8 x; u32 flags : 3; u32 more : 5; } B;
enum { N = 4 };
typedef struct C { int v[N * 2]; void (*cb)(int); long long w; } C;
int f(A *p) { return p->i + p->next->i + p->s[1]; }
"""
    defs = unit_defs(text)
    la, lu, lb, lc = (defs.layout(k) for k in ("A", "U", "B", "C"))
    assert (la["size"], la["align"]) == (24, 4), la
    assert [m[:2] for m in la["members"]] == [("c", 0), ("i", 4), ("s", 8), ("next", 16), ("f", 20)]
    assert lu["size"] == 8 and lu["leaves"][0]["off"] == 0, lu
    assert lb["size"] == 32 and lb["members"][1][:2] == ("x", 24), lb
    assert [l["off"] for l in lb["leaves"]] == [l["off"] for l in sorted(lb["leaves"], key=lambda l: l["off"])]
    assert lc["size"] == 48 and any(l["cls"] == "code" for l in lc["leaves"]), lc      # 32 + 4 (+4 pad) + 8
    assert layout_hash(la) == layout_hash(defs.layout("A"))
    chunk = text[text.index("int f("):]
    out, sites = rewrite_chunk(defs, chunk)
    assert sites == 4 and "(*(int *)((char *)(p) + 4))" in out and "(*(struct A **)((char *)(p) + 16))" in out, out
    assert parse_inferred({"ptr": {"struct": {"0": {"offset": 0, "size": 4, "class": {"int": 32}},
                                              "8": {"offset": 8, "size": 4, "class": "ptr"}}}})["fields"] == {
        0: (4, "int", 32), 8: (4, "ptr", 32)}
    assert parse_inferred({"ptr": {"scalar": "unknown"}})["kind"] == "ptr_bare"
    sidx = StructIndex(leaf_view(la))
    assert sidx.match(4)[0] == "exact" and sidx.match(1)[0] == "gap" and sidx.match(5)[0] == "interior" \
        and sidx.match(10)[0] == "exact" and sidx.match(99)[0] == "out"
    assert round(jaccard({1, 2, 3}, {2, 3, 4}), 2) == 0.5
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("stage", choices=["donor-truth", "dwarf-truth", "host-run", "score", "transfer", "exactness",
                                      "validate-layouts", "report", "selftest"])
    ap.add_argument("games", nargs="*")
    ap.add_argument("--work", type=Path, default=WORK)
    ap.add_argument("--root", type=Path, help="host-run: the synced checkout the build happens in")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--strong-entries", type=Path, help="host-run: decompile only the entries listed in this file")
    ap.add_argument("--threads", type=int, default=4, help="host-run: decompile threads")
    ap.add_argument("--out", type=Path, default=REPO / "benchmarks" / "reports" / "struct_inference_audit.json")
    args = ap.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    for sub in ("truth", "dump", "transfer", "scores"):
        (args.work / sub).mkdir(exist_ok=True)
    if args.stage == "donor-truth":
        for g in args.games or [g for g, k in GAMES.items() if k == "donor"]:
            (args.work / "truth" / f"{g}.json").write_text(json.dumps(build_donor_truth(g, args.jobs)))
    elif args.stage == "dwarf-truth":
        for g in args.games or [g for g, k in GAMES.items() if k != "donor"]:
            path, reader = DWARF_IMAGES[g]
            (args.work / "truth" / f"{g}.json").write_text(json.dumps(build_dwarf_truth(g, CORPUS / path, reader, "ps2")))
    elif args.stage == "host-run":
        for g in args.games:
            host_run(g, args.root, args.work, args.threads, args.strong_entries)
    elif args.stage == "transfer":
        donors = json.loads((HERE / "fact_pack" / "donors.json").read_text())["donors"]
        for d in donors:
            p = args.work / "transfer" / f"{d['game']}.json"
            if not p.exists() and (not args.games or d["game"] in args.games):
                p.write_text(json.dumps(donor_struct_usage(d["game"], d, args.jobs)))
    elif args.stage == "exactness":
        res = run_exactness(args.work / "q3work", n=args.n)
        (args.work / f"q3-result-{args.n}.json").write_text(json.dumps(res, indent=1))
    elif args.stage == "validate-layouts":
        (args.work / "layout-validation.json").write_text(json.dumps(validate_mwcc_layouts(args.work / "q3work"), indent=1))
    elif args.stage == "score":
        for g in args.games or list(GAMES):
            t, d = args.work / "truth" / f"{g}.json", args.work / "dump" / f"dump-{g}.json"
            if t.exists() and d.exists():
                (args.work / "scores" / f"{g}.json").write_text(json.dumps(game_report(g, t, d)))
    elif args.stage == "selftest":
        selftest()
    elif args.stage == "report":
        build_report(args.work, args.out, args.out.with_suffix(".md"))
        print(f"wrote {args.out} and {args.out.with_suffix('.md')}")


if __name__ == "__main__":
    main()
