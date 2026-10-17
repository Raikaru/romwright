#!/usr/bin/env python3
"""Per-donor prototype tables for the universal fact pack (maintainer tool).

For every function a donor's `truth/functions.tsv` names, find the C/C++
declaration or definition in the donor's repo (fetched by `fetch_donors.py`)
and write `<out>/<game>.tsv` with rows `name<TAB>decl`:

* `name` is the truth name verbatim (an MWCC-mangled symbol stays mangled);
* `decl` is one C declaration in the form `library_types::signature` writes
  and the decompiler's C parser accepts: `int printf(char * param_1, ...)`.

Only the signature is read from source: no bodies, no comments, no code are
copied. Types are mapped onto the names the decompiler's languages declare
(`char byte sbyte short ushort int uint longlong ulonglong float double bool
void`, plus pointers to them). The parser knows nothing of repo types, so:

* a pointer to a struct/class/union/typedef'd aggregate degrades to `void *`
  (arity and pointer-ness survive), as `qualified_prototypes::c_type` does;
* function pointers and arrays become `void *`; enums become `int`;
* a by-value aggregate parameter/return or an unresolved type drops the row;
* C++ members take a leading `void * this` (static members do not).

Rebuild from scratch (needs `c++filt` from binutils for `_Z` names):
    python3 -m venv ~/ventris-scratch/factpack/venv
    ~/ventris-scratch/factpack/venv/bin/pip install tree-sitter tree-sitter-c tree-sitter-cpp
    python3 fetch_donors.py                       # repos/<game> at the pinned commits
    ~/ventris-scratch/factpack/venv/bin/python extract_prototypes.py [GAME...]
    ~/ventris-scratch/factpack/venv/bin/python extract_prototypes.py --table   # per-game report
Rows the native C parser rejects are listed by the throwaway validator in
`--rejects DIR/<game>.tsv` (name<TAB>error) and dropped on the next run.
"""
import argparse
import json
import multiprocessing
import os
import pickle
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser

sys.path.insert(0, str(Path(__file__).parent))
import itanium_names  # noqa: E402
import mwcc_names  # noqa: E402

SCRATCH = Path.home() / "ventris-scratch" / "factpack"
CORPUS = Path.home() / "ventris-corpus" / "extracted"
EXTS_C = {".c"}
EXTS_CPP = {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}
EXTS_H = {".h"}
SKIP_DIRS = {".git", "tools", "tool", "build", "test", "tests", "docs", "scripts", ".github"}

# ---- types ---------------------------------------------------------------
# A type is (kind, name, depth): kind 'p' primitive (name canonical, see
# PRIMS), 'n' unresolved named type, 'a' struct/union/class, 'e' enum,
# 'x' unrepresentable (decltype, template, ...).
PRIMS = {"char", "byte", "sbyte", "short", "ushort", "int", "uint", "long", "ulong",
         "longlong", "ulonglong", "float", "double", "bool", "void"}
QUALIFIERS = {"const", "volatile", "static", "extern", "inline", "register", "restrict",
              "__restrict", "__restrict__", "__inline", "__inline__", "__const", "typename",
              "struct", "union", "enum", "class", "__extension__", "mutable", "constexpr"}
# Names only used when the repo itself declares no typedef of that name.
FALLBACK_TYPEDEFS = {
    "u8": ("p", "byte"), "uint8_t": ("p", "byte"), "U8": ("p", "byte"), "BYTE": ("p", "byte"),
    "UCHAR": ("p", "byte"), "uchar": ("p", "byte"), "u_char": ("p", "byte"),
    "s8": ("p", "sbyte"), "int8_t": ("p", "sbyte"), "S8": ("p", "sbyte"),
    "u16": ("p", "ushort"), "uint16_t": ("p", "ushort"), "U16": ("p", "ushort"),
    "WORD": ("p", "ushort"), "USHORT": ("p", "ushort"), "ushort": ("p", "ushort"),
    "s16": ("p", "short"), "int16_t": ("p", "short"), "S16": ("p", "short"),
    "u32": ("p", "uint"), "uint32_t": ("p", "uint"), "U32": ("p", "uint"),
    "DWORD": ("p", "uint"), "UINT": ("p", "uint"), "uint": ("p", "uint"), "size_t": ("p", "uint"),
    "uintptr_t": ("p", "uint"),
    "s32": ("p", "int"), "int32_t": ("p", "int"), "S32": ("p", "int"), "INT": ("p", "int"),
    "ptrdiff_t": ("p", "int"), "intptr_t": ("p", "int"), "ssize_t": ("p", "int"),
    "BOOL": ("p", "int"),
    "u64": ("p", "ulonglong"), "uint64_t": ("p", "ulonglong"), "U64": ("p", "ulonglong"),
    "s64": ("p", "longlong"), "int64_t": ("p", "longlong"), "S64": ("p", "longlong"),
    "f32": ("p", "float"), "F32": ("p", "float"), "float32_t": ("p", "float"),
    "f64": ("p", "double"), "F64": ("p", "double"), "float64_t": ("p", "double"),
    "wchar_t": ("p", "ushort"),
    "va_list": ("p", "void", 1), "__va_list": ("p", "void", 1), "__builtin_va_list": ("p", "void", 1),
}
RESERVED = {"auto", "break", "case", "const", "continue", "default", "do", "else", "enum",
            "extern", "for", "goto", "if", "inline", "register", "return", "signed", "sizeof",
            "static", "struct", "switch", "typedef", "union", "unsigned", "volatile", "while",
            "long", "char", "short", "int", "float", "double", "void", "bool", "byte", "sbyte",
            "uint", "ushort", "ulong", "longlong", "ulonglong", "this", "restrict"}
GENERIC = re.compile(
    r"^(?:(?:func|FUN|sub|fn|lbl|loc|unk|Func|FUNC|nullsub|jumptable|switch|LAB|DAT|dat|"
    r"thunk|_?_?func)_?[0-9A-Fa-f]{5,8}"
    r"|.*_(?:0x)?[0-9A-Fa-f]{7,8}(?:_[A-Za-z0-9]+)?"
    r"|[A-Za-z]+[0-9a-f]{8})$")


def is_generic(name):
    if GENERIC.match(name):
        return True
    return bool(re.search(r"(?:^|_)(?:80|0x?0?)[0-9a-fA-F]{6}(?:$|_)", name)) and bool(re.search(r"[0-9]{3}", name))


def prim_from_words(words):
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
        return "double"  # `long double` is 8 bytes on every donor target here
    if base == "char":
        return "byte" if unsigned else "sbyte" if signed else "char"
    if base in ("__int64",):
        return "ulonglong" if unsigned else "longlong"
    if base in (None, "int", "__int32"):
        if "short" in words:
            return "ushort" if unsigned else "short"
        if longs >= 2:
            return "ulonglong" if unsigned else "longlong"
        if longs == 1:
            return "ulong" if unsigned else "long"
        return "uint" if unsigned else "int"
    return None


def emit_prim(name, long_width):
    if name == "long":
        return "int" if long_width == 4 else "longlong"
    if name == "ulong":
        return "uint" if long_width == 4 else "ulonglong"
    return name


# ---- per-file scanning ---------------------------------------------------

_PARSERS = {}


def parser_for(lang):
    if lang not in _PARSERS:
        mod = tree_sitter_cpp if lang == "cpp" else tree_sitter_c
        _PARSERS[lang] = Parser(Language(mod.language()))
    return _PARSERS[lang]


class Scan:
    def __init__(self, src, lang, relpath):
        self.src = src
        self.lang = lang
        self.rel = relpath
        self.entries = []
        self.typedefs = []   # (name, type)
        self.macros = []     # (name, value text)
        self.aggs = set()
        self.enums = set()

    def t(self, n):
        return self.src[n.start_byte:n.end_byte].decode("utf8", "replace")

    # -- types
    def spec_ty(self, n):
        if n is None:
            return None
        k = n.type
        if k in ("primitive_type", "sized_type_specifier"):
            words = self.t(n).split()
            p = prim_from_words([w for w in words if w not in QUALIFIERS])
            if p:
                return ("p", p, 0)
            names = [w for w in words if w not in QUALIFIERS]
            # tree-sitter-c lexes size_t, uintptr_t, int32_t ... as primitive types
            return ("n", names[0], 0) if len(names) == 1 else ("x", self.t(n), 0)
        if k in ("type_identifier", "qualified_identifier", "namespace_identifier"):
            return ("n", re.sub(r"\s+", "", self.t(n)).lstrip(":"), 0)
        if k == "template_type":
            return ("x", "template", 0)
        if k in ("struct_specifier", "union_specifier", "class_specifier"):
            name = n.child_by_field_name("name")
            return ("a", self.t(name) if name else "", 0)
        if k == "enum_specifier":
            name = n.child_by_field_name("name")
            if name is not None:
                self.enums.add(self.t(name))
            return ("e", self.t(name) if name else "", 0)
        return ("x", k, 0)

    def inner(self, d):
        c = d.child_by_field_name("declarator")
        if c is not None:
            return c
        for ch in d.children:
            if ch.is_named and ch.type not in ("type_qualifier", "attribute_specifier",
                                                "ms_based_modifier", "ms_pointer_modifier",
                                                "comment"):
                return ch
        return None

    def declarator_ty(self, base, d):
        """Applies a (non-function) declarator chain to `base`: (type, name)."""
        depth = 0
        name = None
        fn = False
        while d is not None:
            k = d.type
            if k in ("pointer_declarator", "abstract_pointer_declarator", "reference_declarator",
                     "abstract_reference_declarator", "array_declarator",
                     "abstract_array_declarator"):
                depth += 1
                d = self.inner(d)
            elif k in ("parenthesized_declarator", "abstract_parenthesized_declarator",
                       "attributed_declarator", "init_declarator", "optional_parameter_declaration"):
                d = self.inner(d)
            elif k in ("function_declarator", "abstract_function_declarator"):
                fn = True
                d = self.inner(d)
            elif k in ("identifier", "field_identifier", "type_identifier"):
                name = self.t(d)
                break
            else:
                break
        if base is None:
            return None, name
        if fn:
            return ("p", "void", 1), name
        return (base[0], base[1], base[2] + depth), name

    def parse_params(self, plist):
        params, variadic, err = [], False, False
        if plist is None:
            return params, variadic, True
        for ch in plist.named_children:
            if ch.type in ("parameter_declaration", "optional_parameter_declaration"):
                base = self.spec_ty(ch.child_by_field_name("type"))
                ty, name = self.declarator_ty(base, ch.child_by_field_name("declarator"))
                if ty is None or ch.has_error:
                    err = True
                    continue
                params.append((name, ty))
            elif ch.type == "identifier":
                params.append((self.t(ch), None))      # K&R: type comes from the declarations
            elif ch.type == "variadic_parameter" or self.t(ch) == "...":
                variadic = True
            elif ch.type == "comment":
                continue
            else:
                err = True
        if len(params) == 1 and params[0][1] == ("p", "void", 0) and params[0][0] is None:
            params = []
        return params, variadic, err

    # -- declarations
    def func_entry(self, node, scope, declarator, type_node, is_def, in_class, template):
        # peel pointer/reference declarators wrapping the function declarator
        depth = 0
        d = declarator
        while d is not None and d.type in ("pointer_declarator", "reference_declarator",
                                           "attributed_declarator", "parenthesized_declarator"):
            if d.type in ("pointer_declarator", "reference_declarator"):
                depth += 1
            d = self.inner(d)
        if d is None or d.type != "function_declarator":
            return None
        name_node = d.child_by_field_name("declarator")
        if name_node is None:
            return None
        chain = list(scope)
        nk = name_node.type
        if nk == "qualified_identifier":
            parts = []
            cur = name_node
            while cur is not None and cur.type == "qualified_identifier":
                s = cur.child_by_field_name("scope")
                if s is not None:
                    if s.type == "template_type":
                        template = True
                    parts.append(re.sub(r"<.*", "", self.t(s)).strip())
                cur = cur.child_by_field_name("name")
            chain.extend(p.lstrip(":") for p in parts if p)
            name_node = cur
            nk = name_node.type if name_node is not None else ""
        if name_node is None:
            return None
        if nk in ("identifier", "field_identifier"):
            name = self.t(name_node)
        elif nk == "destructor_name":
            name = re.sub(r"\s+", "", self.t(name_node))
        elif nk == "operator_name":
            name = re.sub(r"\s+", "", self.t(name_node))
            name = re.sub(r"^operator(new|delete)", r"operator \1", name)
        elif nk in ("template_function", "template_method"):
            name = self.t(name_node)
            template = True
        else:
            return None
        if d.has_error and d.child_by_field_name("parameters").has_error:
            return {"name": name, "err": "parse"}
        params, variadic, perr = self.parse_params(d.child_by_field_name("parameters"))
        if any(ty is None for _, ty in params):
            declared = {}
            for ch in node.children:
                if ch.type == "declaration":
                    base = self.spec_ty(ch.child_by_field_name("type"))
                    for dd in ch.children_by_field_name("declarator"):
                        ty, pname = self.declarator_ty(base, dd)
                        if pname and ty:
                            declared[pname] = ty
            params = [(n_, ty if ty is not None else declared.get(n_, ("p", "int", 0))) for n_, ty in params]
        ret = None
        if type_node is not None:
            base = self.spec_ty(type_node)
            ret = (base[0], base[1], base[2] + depth)
        text = re.sub(r"/\*.*?\*/|//[^\n]*", "", self.t(d.child_by_field_name("parameters")), flags=re.S)
        text = re.sub(r"\s+", "", text)
        const = any(ch.type == "type_qualifier" and self.t(ch) == "const" for ch in d.children)
        static = virtual = False
        for ch in node.children:
            if ch.type == "storage_class_specifier" and self.t(ch) == "static":
                static = True
            elif ch.type in ("virtual_function_specifier",) or self.t(ch) == "virtual":
                virtual = True
        return {
            "name": name, "scope": tuple(chain), "ret": ret, "params": params,
            "variadic": variadic, "err": "parse" if perr or (type_node is not None and type_node.has_error) else None,
            "unspecified": self.lang == "c" and text == "()",
            "def": is_def, "static": static, "const": const, "virtual": virtual,
            "template": template, "in_class": in_class, "file": self.rel,
        }

    def add_func(self, *args):
        e = self.func_entry(*args)
        if e is not None:
            self.entries.append(e)

    def visit(self, n, scope, template=False, in_class=False):
        k = n.type
        if k == "function_definition":
            self.add_func(n, scope, n.child_by_field_name("declarator"),
                          n.child_by_field_name("type"), True, in_class, template)
        elif k in ("declaration", "field_declaration"):
            ty = n.child_by_field_name("type")
            if ty is not None and ty.type in ("struct_specifier", "union_specifier", "class_specifier",
                                              "enum_specifier"):
                self.visit_spec(ty, scope)
            for d in n.children_by_field_name("declarator"):
                self.add_func(n, scope, d, ty, False, in_class, template)
        elif k == "type_definition":
            ty = n.child_by_field_name("type")
            if ty is not None and ty.type in ("struct_specifier", "union_specifier", "class_specifier",
                                              "enum_specifier"):
                self.visit_spec(ty, scope)
            base = self.spec_ty(ty)
            for d in n.children_by_field_name("declarator"):
                tyd, name = self.declarator_ty(base, d)
                if name and tyd:
                    if tyd[0] in ("a", "e") and not tyd[1]:
                        tyd = (tyd[0], name, tyd[2])
                    self.typedefs.append((name, tyd))
        elif k == "alias_declaration":
            name = n.child_by_field_name("name")
            ty = n.child_by_field_name("type")
            if name is not None and ty is not None:
                tdesc = ty.child_by_field_name("type")
                base = self.spec_ty(tdesc)
                tyd, _ = self.declarator_ty(base, ty.child_by_field_name("declarator"))
                if tyd:
                    self.typedefs.append((self.t(name), tyd))
        elif k == "preproc_def":
            name = n.child_by_field_name("name")
            value = n.child_by_field_name("value")
            if name is not None and value is not None:
                self.macros.append((self.t(name), self.t(value).strip()))
        elif k == "namespace_definition":
            name = n.child_by_field_name("name")
            body = n.child_by_field_name("body")
            if body is not None:
                self.walk(body, scope + ((self.t(name),) if name is not None else ()), template)
        elif k in ("struct_specifier", "union_specifier", "class_specifier", "enum_specifier"):
            self.visit_spec(n, scope)
        elif k == "template_declaration":
            for ch in n.children:
                if ch.type not in ("template_parameter_list",):
                    self.visit(ch, scope, True, in_class)
        elif k == "ERROR":
            self.salvage(n, scope, template, in_class)
        elif k in ("linkage_specification", "declaration_list", "field_declaration_list",
                   "translation_unit", "preproc_if", "preproc_ifdef", "preproc_else",
                   "preproc_elif", "preproc_elifdef", "labeled_statement"):
            self.walk(n, scope, template, in_class)
        elif k in ("access_specifier",):
            pass

    SPEC_TYPES = ("primitive_type", "sized_type_specifier", "type_identifier",
                  "struct_specifier", "union_specifier", "enum_specifier", "qualified_identifier")

    def salvage(self, n, scope, template, in_class):
        """An ERROR node (typically an unbalanced `#if` inside a body) still
        holds `type declarator` pairs: recover the signatures, visit the rest."""
        kids = n.children
        for i, ch in enumerate(kids):
            d = ch
            while d is not None and d.type in ("pointer_declarator", "reference_declarator"):
                d = self.inner(d)
            if d is not None and d.type == "function_declarator" and i > 0:
                prev = next((p for p in reversed(kids[:i]) if p.type in self.SPEC_TYPES), None)
                nxt = kids[i + 1] if i + 1 < len(kids) else None
                if prev is not None and prev.end_byte <= ch.start_byte and \
                        self.src[prev.end_byte:ch.start_byte].strip(b" \t*&\r\n") == b"":
                    self.add_func(n, scope, ch, prev, nxt is not None and nxt.type == "{",
                                  in_class, template)
                    continue
            self.visit(ch, scope, template, in_class)

    def visit_spec(self, spec, scope):
        name = spec.child_by_field_name("name")
        body = spec.child_by_field_name("body")
        if name is not None:
            (self.enums if spec.type == "enum_specifier" else self.aggs).add(re.sub(r"\s+", "", self.t(name)))
        if body is None:
            return
        if spec.type == "enum_specifier":
            return
        if name is not None:
            nm = re.sub(r"<.*", "", self.t(name)).strip()
            inner = scope + tuple(p for p in nm.split("::") if p)
            tmpl = "<" in self.t(name)
        else:
            inner, tmpl = scope, False
        for ch in body.children:
            self.visit(ch, inner, tmpl, True)

    def walk(self, n, scope, template=False, in_class=False):
        for ch in n.children:
            self.visit(ch, scope, template, in_class)


IDENT_CALL = re.compile(rb"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
DEFINE = re.compile(rb"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(\([^)]*\))?[ \t]*(.*?)[ \t]*$", re.M)
BLANK_VALUE = re.compile(rb"^(?:(?://.*|/\*.*?\*/)?|(?:__attribute__|__declspec|__asm|asm|_Pragma|__pragma)\b.*|"
                         rb"(?:__inline__|__inline|inline|__extension__)(?:\s*(?://.*|/\*.*?\*/))?)$")
_BLANK = {"obj": None, "fn": None, "expand": {}, "expand_re": None}
TYPE_BODY = re.compile(rb"^[A-Za-z_*\s][A-Za-z0-9_*\s]*$")
DECL_BODY = re.compile(rb"^[A-Za-z_*][A-Za-z0-9_*\s(),\[\]]*$")


def collect_blank_macros(files):
    """Macros every definition of which expands to nothing or to an attribute:
    declaration noise (`UNUSED`, `ALIGNED(8)`) the C grammar cannot see
    through. Blanked from the source before parsing, as the preprocessor would."""
    blank_obj, blank_fn, solid = set(), set(), set()
    expand = {}
    for f in files:
        try:
            src = Path(f).read_bytes()
        except OSError:
            continue
        if len(src) > 8_000_000 or b"define" not in src:
            continue
        for name, args, value in DEFINE.findall(src):
            name = name.decode()
            if BLANK_VALUE.match(value):
                (blank_fn if args else blank_obj).add(name)
            else:
                solid.add(name)
                params = [a.strip().decode() for a in args[1:-1].split(b",")] if args else []
                text = value.decode("utf8", "replace")
                declares = any(re.search(rf"\b{re.escape(q)}\s*\(", text) for q in params if q)
                if args and 1 <= len(params) <= 3 and (TYPE_BODY.match(value) or (declares and DECL_BODY.match(value))):
                    uses = any(re.search(rf"\b{re.escape(q)}\b", text) for q in params if q)
                    # a body that spells the argument beats a constant one
                    if name not in expand or (uses and not expand[name][2]):
                        expand[name] = (params, text, uses)
    return blank_obj - solid, blank_fn - solid, {k: v for k, v in expand.items() if v[2]}


def install_blank(obj, fn, expand):
    _BLANK["expand"] = expand
    _BLANK["expand_re"] = re.compile(rb"\b(?:" + b"|".join(n.encode() for n in sorted(expand)) + rb")\s*\(") if expand else None
    _BLANK["obj"] = re.compile(rb"\b(?:" + b"|".join(map(lambda n: n.encode(), sorted(obj))) + rb")\b") if obj else None
    _BLANK["fn"] = re.compile(rb"\b(?:" + b"|".join(map(lambda n: n.encode(), sorted(fn))) + rb")\s*\(") if fn else None


def split_args(text):
    args, depth, cur = [], 0, []
    for ch in text:
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            continue
        depth += (ch in "([{") - (ch in ")]}")
        cur.append(ch)
    args.append("".join(cur).strip())
    return args


def expand_line(line, rx, table):
    for _ in range(4):
        m = rx.search(line)
        if not m:
            return line
        depth, i = 1, m.end()
        while i < len(line) and depth:
            depth += (line[i] == 0x28) - (line[i] == 0x29)
            i += 1
        if depth:
            return line
        name = m.group()[:-1].strip().decode()
        params, words, _ = table[name.rstrip("(").strip()] if name in table else table[re.sub(rb"\s*\($", b"", m.group()).decode()]
        args = split_args(line[m.end():i - 1].decode("utf8", "replace"))
        if len(args) != len(params):
            return line
        sub = dict(zip(params, args))
        text = re.sub(r"[A-Za-z_]\w*", lambda w: sub.get(w.group(), w.group()), words)
        line = line[:m.start()] + text.encode() + line[i:]
    return line


def blank_text(src):
    obj, fn, ex = _BLANK["obj"], _BLANK["fn"], _BLANK["expand_re"]
    if obj is None and fn is None and ex is None:
        return src
    out = []
    for line in src.split(b"\n"):
        if not line.lstrip().startswith(b"#"):
            if ex is not None:
                line = expand_line(line, ex, _BLANK["expand"])
            if obj is not None:
                line = obj.sub(lambda m: b" " * len(m.group()), line)
            if fn is not None:
                while True:
                    m = fn.search(line)
                    if not m:
                        break
                    depth, i = 1, m.end()
                    while i < len(line) and depth:
                        depth += (line[i] == 0x28) - (line[i] == 0x29)
                        i += 1
                    if depth:
                        break
                    line = line[:m.start()] + b" " * (i - m.start()) + line[i:]
        out.append(line)
    return b"\n".join(out)


def scan_file(job):
    path, rel, lang = job
    try:
        src = Path(path).read_bytes()
    except OSError:
        return None
    if len(src) > 8_000_000:
        return None
    src = blank_text(src)
    tree = parser_for(lang).parse(src)
    scan = Scan(src, lang, rel)
    scan.walk(tree.root_node, ())
    names = {m.decode() for m in IDENT_CALL.findall(src)}
    return {"entries": scan.entries, "typedefs": scan.typedefs, "macros": scan.macros,
            "aggs": scan.aggs, "enums": scan.enums, "names": names, "file": rel}


def list_sources(repo):
    files = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            ext = os.path.splitext(n)[1].lower()
            if ext in EXTS_C or ext in EXTS_CPP or ext in EXTS_H:
                files.append(os.path.join(root, n))
    files.sort()
    return files


def scan_repo(game, repo, cache_dir, jobs, rescan):
    commit = (repo / ".git" / "HEAD").read_text().strip()
    cache = cache_dir / f"{game}.pkl"
    if cache.exists() and not rescan:
        data = pickle.loads(cache.read_bytes())
        if data["commit"] == commit and data["version"] == SCAN_VERSION:
            return data
    files = list_sources(repo)
    cppish = sum(1 for f in files if os.path.splitext(f)[1].lower() in EXTS_CPP)
    cfam = sum(1 for f in files if os.path.splitext(f)[1].lower() in EXTS_C | EXTS_CPP)
    cpp_repo = cfam > 0 and cppish * 10 >= cfam
    work = []
    for f in files:
        ext = os.path.splitext(f)[1].lower()
        lang = "cpp" if ext in EXTS_CPP or (ext in EXTS_H and cpp_repo) else "c"
        work.append((f, os.path.relpath(f, repo), lang))
    obj, fn, expand = collect_blank_macros(files)
    install_blank(obj, fn, expand)
    results = []
    with ProcessPoolExecutor(jobs, mp_context=multiprocessing.get_context("fork")) as pool:
        for r in pool.map(scan_file, work, chunksize=16):
            if r:
                results.append(r)
    data = {"commit": commit, "version": SCAN_VERSION, "cpp_repo": cpp_repo,
            "files": len(files), "blank_macros": len(obj) + len(fn) + len(expand), "results": results}
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(pickle.dumps(data))
    return data


SCAN_VERSION = 13

# ---- resolution ----------------------------------------------------------


def looks_like_type(value):
    return bool(value) and len(value) < 80 and not re.sub(r"[A-Za-z_][A-Za-z0-9_]*|\*|\s+", "", value) \
        and bool(re.search(r"[A-Za-z_]", value))


class Types:
    def __init__(self, results, long_width):
        self.long_width = long_width
        td = defaultdict(list)
        mac = defaultdict(list)
        self.aggs = set()
        self.enums = set()
        self.agg_tails = set()
        for r in results:
            self.enums |= {e.split("::")[-1] for e in r["enums"]}
            self.agg_tails |= {e.split("::")[-1] for e in r["aggs"]}
            for name, ty in r["typedefs"]:
                td[name].append(ty)
            for name, val in r["macros"]:
                if looks_like_type(val):
                    mac[name].append(val)
            self.aggs |= r["aggs"]
        self.typedefs = {}
        self.conflicts = 0
        for name, tys in td.items():
            c = Counter(tys)
            if len(c) > 1:
                self.conflicts += 1
            self.typedefs[name] = c.most_common(1)[0][0]
        for name, vals in mac.items():
            if name in self.typedefs:
                continue
            ty = self.macro_ty(vals[0])
            if ty:
                self.typedefs[name] = ty

    def macro_ty(self, value):
        words = [w for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\*", value) if w not in QUALIFIERS]
        depth = words.count("*")
        words = [w for w in words if w != "*"]
        p = prim_from_words(words) if words and all(
            w in ("unsigned", "signed", "long", "short", "char", "int", "float", "double", "void",
                  "bool", "_Bool") for w in words) else None
        if p:
            return ("p", p, depth)
        if len(words) == 1:
            return ("n", words[0], depth)
        return None

    def resolve(self, ty):
        for _ in range(24):
            if ty is None or ty[0] != "n":
                return ty
            name = ty[1]
            td = self.typedefs.get(name) or self.typedefs.get(name.split("::")[-1])
            if td is None:
                fb = FALLBACK_TYPEDEFS.get(name)
                if fb is None:
                    if name.split("::")[-1] in self.enums:
                        return ("e", name, ty[2])
                    if name.split("::")[-1] in self.agg_tails:
                        return ("a", name, ty[2])
                    return ty
                td = (fb[0], fb[1], fb[2] if len(fb) > 2 else 0)
            if td == ty:
                return ty
            ty = (td[0], td[1], td[2] + ty[2])
        return ("x", "typedef-cycle", 0)

    def canon(self, ty):
        """(base, depth) for matching against a demangled parameter."""
        ty = self.resolve(ty)
        k, name, depth = ty
        if k == "p":
            return (emit_prim(name, self.long_width), depth)
        if k in ("a", "e", "n"):
            return (name.split("::")[-1], depth)
        return ("?", depth)

    def emit(self, ty, ret=False):
        """-> (text, degraded, error)."""
        ty = self.resolve(ty)
        k, name, depth = ty
        stars = " " + " ".join("*" * depth) if depth else ""
        if k == "p":
            if name == "void" and depth == 0 and not ret:
                return None, False, "void-value"
            return emit_prim(name, self.long_width) + stars, False, None
        if k == "e":
            return "int" + stars, False, None
        if k in ("a", "n"):
            if depth > 0:
                return "void" + stars, True, None
            return None, False, ("by-value-aggregate" if (k == "a" or name in self.aggs)
                                 else f"unresolved-type")
        return None, False, "unrepresentable-type"


def usable_name(name, used):
    if not name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or name in RESERVED or name in used:
        return None
    return name


def c_identifier(name):
    text = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if text in RESERVED:
        text += "_"
    if not text:
        return "member"
    if text[0].isdigit():
        text = "_" + text
    return text


def build_decl(entry, types, cname, receiver, ctor=False):
    """(decl, degraded_count, error)"""
    degraded = 0
    if entry.get("err"):
        return None, 0, "parse-error"
    if entry["unspecified"] and not entry["def"]:
        return None, 0, "unprototyped"
    if ctor:
        ret_text = "void *"
    elif entry["ret"] is None:
        return None, 0, "no-return-type"
    else:
        ret_text, d, err = types.emit(entry["ret"], ret=True)
        if err:
            return None, 0, "ret-" + err
        degraded += d
    parts = []
    used = {cname}
    if receiver:
        parts.append("void * this")
        used.add("this")
    for i, (pname, ty) in enumerate(entry["params"]):
        text, d, err = types.emit(ty)
        if err:
            return None, 0, "param-" + err
        degraded += d
        ident = usable_name(pname, used) or f"param_{i + 1 + (1 if receiver else 0)}"
        while ident in used:
            ident += "_"
        used.add(ident)
        parts.append(f"{text} {ident}")
    if entry["variadic"]:
        if not parts:
            return None, 0, "variadic-only"
        parts.append("...")
    return f"{ret_text} {cname}({', '.join(parts) if parts else 'void'})", degraded, None


def sig_key(decl):
    """The declaration with parameter names erased, for agreement checks."""
    return re.sub(r"\b(?:param_\d+|[A-Za-z_]\w*)(?=[,)])", "", decl) if decl else decl


# ---- the join ------------------------------------------------------------


def choose(group, builder):
    """Among all source entries for one name, the single declaration to emit:
    definitions win; when they disagree, the declaration the headers agree on
    breaks the tie. -> (decl, degraded, reason)"""
    outcomes = []
    for tier in ([e for e in group if e["def"]], [e for e in group if not e["def"]]):
        if tier:
            distinct = {}
            for decl, deg, err in map(builder, tier):
                distinct.setdefault(sig_key(decl) if decl else "ERR:" + err, (decl, deg, err))
            outcomes.append(list(distinct.values()))
    if not outcomes:
        return None, 0, "no-source"
    first = outcomes[0]
    if len(first) == 1:
        return first[0]
    if len(outcomes) > 1 and len(outcomes[1]) == 1 and outcomes[1][0][0]:
        want = sig_key(outcomes[1][0][0])
        hit = [o for o in first if o[0] and sig_key(o[0]) == want]
        if hit:
            return hit[0]
    return None, 0, "ambiguous"


def match_names(truth_names, results, types, platform, cpp_repo):
    index = defaultdict(list)   # (scope_str, name) -> entries
    for r in results:
        for e in r["entries"]:
            if "scope" not in e:
                continue
            index[("::".join(e["scope"]), e["name"])].append(e)
    tokens = set()
    for r in results:
        tokens |= r["names"]

    rows, reasons, degraded_rows = {}, {}, 0
    itanium = itanium_names.demangle_many(truth_names)
    if not itanium_names.available() and any(n.startswith("_Z") for n in truth_names):
        print("warning: c++filt not found; _Z names will not be joined", file=sys.stderr)
    for name in truth_names:
        dm = itanium.get(name) or (mwcc_names.demangle(name) if cpp_repo else None)
        if dm is not None:
            group, note = member_group(dm, index, types)
            if note:
                reasons[name] = note
                continue
            if not group:
                reasons[name] = "no-source" if dm.name.split("::")[-1] in tokens else "no-source-absent"
                continue
            # a namespace function has no receiver; a class member that is not static has one
            is_member = any(e["in_class"] for e in group) or (bool(dm.scope) and dm.scope[-1] in types.agg_tails)
            receiver = is_member and not any(e["static"] for e in group)
            # ARM EABI constructors and destructors return `this`; so do MWCC constructors
            returns_this = dm.ctor or dm.dtor

            def builder(e, receiver=receiver, ctor=returns_this,
                        cname=c_identifier("dtor" if dm.dtor else dm.name)):
                return build_decl(e, types, cname, receiver, ctor)

            decl, deg, err = choose(group, builder)
        else:
            group = index.get(("", name), [])
            if not group:
                reasons[name] = "no-source" if name in tokens else "no-source-absent"
                continue

            def builder(e, cname=c_identifier(name)):
                return build_decl(e, types, cname, False)

            decl, deg, err = choose(group, builder)
        if decl:
            rows[name] = (decl, deg)
        else:
            reasons[name] = err or "no-source"
    return rows, reasons


def member_group(dm, index, types):
    """The source entries a demangled member name selects: (entries, note)."""
    if dm.template:
        return None, "template"
    if dm.dtor and dm.abi == "mwcc":
        return None, "dtor-implicit-args"      # MWCC passes a hidden delete-flag argument
    cands = index.get(("::".join(dm.scope), dm.name), [])
    if not cands:
        return [], None
    variadic = any(b == "..." for b, _ in dm.params)
    want = []
    for base, depth in dm.params:
        if base == "...":
            continue
        if base in ("fn", "member"):
            want.append(("void", max(depth, 1)))
        else:
            want.append((emit_prim(base, types.long_width), depth))
    usable = [e for e in cands if not e.get("err")]
    if not usable:
        return cands, None            # build_decl reports the parse error
    arity = [e for e in usable if len(e["params"]) == len(want) and bool(e["variadic"]) == variadic]
    exact = [e for e in arity if [types.canon(t) for _, t in e["params"]] == want]
    if exact:
        return exact, None
    if arity and len({sig_key_entry(e, types) for e in arity}) == 1:
        return arity, None            # one overload of this arity; spelling differs only by alias
    return None, "ambiguous" if arity else "overload-not-found"


def sig_key_entry(e, types):
    return tuple(types.canon(t) for _, t in e["params"])


# ---- driver --------------------------------------------------------------


def read_truth(game):
    names = []
    total = 0
    with open(CORPUS / game / "truth" / "functions.tsv") as f:
        next(f)
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            total += 1
            names.append(parts[2])
    return total, names


def process(game, donor, args):
    repo = args.repos / game
    total, all_names = read_truth(game)
    uniq = list(dict.fromkeys(all_names))
    generic = [n for n in uniq if is_generic(n)]
    named = [n for n in uniq if not is_generic(n)]
    data = scan_repo(game, repo, args.cache, args.jobs, args.rescan)
    results = data["results"]
    platform = donor["platform"]
    types = Types(results, 8 if platform == "ps2" else 4)
    rows, reasons = match_names(named, results, types, platform, data["cpp_repo"])
    rejects = {}
    rj = args.rejects / f"{game}.tsv"
    if rj.exists():
        for line in rj.read_text().splitlines():
            if "\t" in line:
                n, why = line.split("\t", 1)
                rejects[n] = why
    out_rows, native_dropped = [], Counter()
    for name in named:
        if name in rows:
            if name in rejects:
                native_dropped["native-parser-rejected"] += 1
            else:
                out_rows.append((name, rows[name][0]))
    args.out.mkdir(parents=True, exist_ok=True)
    with open(args.out / f"{game}.tsv", "w") as f:
        for name, decl in out_rows:
            f.write(f"{name}\t{decl}\n")
    reason_counts = Counter(r for n, r in reasons.items())
    reason_counts.update(native_dropped)
    found = len(rows) + sum(v for k, v in reason_counts.items()
                            if k not in ("no-source", "no-source-absent", "template", "dtor-implicit-args", "overload-not-found"))
    degraded = sum(1 for n in rows if rows[n][1])
    return {
        "game": game, "files": data["files"], "cpp_repo": data["cpp_repo"],
        "truth_rows": total, "truth_names": len(uniq), "generic": len(generic), "named": len(named),
        "found": found, "emitted": len(rows), "written": len(out_rows),
        "degraded_struct_ptr": degraded, "typedef_conflicts": types.conflicts,
        "dropped": dict(reason_counts),
    }


def print_table(report):
    cols = ["no-source", "no-source-absent", "ambiguous", "template", "dtor-implicit-args",
            "overload-not-found", "param-by-value-aggregate", "ret-by-value-aggregate",
            "param-unrepresentable-type", "ret-unrepresentable-type", "param-unresolved-type",
            "ret-unresolved-type", "unprototyped", "parse-error", "native-parser-rejected"]
    print("| game | truth rows | generic | named | found | parsed OK | " + " | ".join(cols) + " | other | struct* degraded |")
    print("|" + "---|" * (9 + len(cols)))
    for r in report:
        d = r["dropped"]
        other = sum(v for k, v in d.items() if k not in cols)
        print(f"| {r['game']} | {r['truth_rows']} | {r['generic']} | {r['named']} | {r['found']} | "
              f"{r['written']} | " + " | ".join(str(d.get(c, 0)) for c in cols) +
              f" | {other} | {r['degraded_struct_ptr']} |")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("games", nargs="*")
    ap.add_argument("--licenses", default=str(SCRATCH / "licenses.json"))
    ap.add_argument("--repos", type=Path, default=SCRATCH / "repos")
    ap.add_argument("--out", type=Path, default=SCRATCH / "prototypes")
    ap.add_argument("--cache", type=Path, default=SCRATCH / "cache")
    ap.add_argument("--rejects", type=Path, default=SCRATCH / "validation")
    ap.add_argument("--report", type=Path, default=SCRATCH / "prototypes" / "report.json")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--rescan", action="store_true")
    ap.add_argument("--table", action="store_true", help="print the markdown table from --report and exit")
    args = ap.parse_args()
    if args.table:
        print_table(json.loads(args.report.read_text()))
        return
    donors = {d["game"]: d for d in json.load(open(args.licenses))}
    games = args.games or sorted(donors)
    report = []
    for game in games:
        if not (args.repos / game / ".git").exists():
            print(f"{game}: not fetched", file=sys.stderr)
            continue
        try:
            r = process(game, donors[game], args)
        except Exception as error:  # one donor's quirks must not stop the rest
            print(f"{game}: FAILED {error!r}", file=sys.stderr, flush=True)
            continue
        report.append(r)
        print(f"{game}: named={r['named']} found={r['found']} written={r['written']} "
              f"dropped={r['dropped']}", flush=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
