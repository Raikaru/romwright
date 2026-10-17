"""Itanium-ABI (`_Z...`, GCC / ARM EABI) names for the prototype extractor.

`c++filt` (binutils) does the demangling; this module reads its rendered text
back into the same `Demangled` shape `mwcc_names` produces: scope chain, bare
name, parameters reduced to `(base, pointer_depth)`.
"""
import re
import shutil
import subprocess

from mwcc_names import Demangled

PRIMS = {
    "void": "void", "bool": "bool", "char": "char", "signed char": "sbyte",
    "unsigned char": "byte", "short": "short", "unsigned short": "ushort",
    "int": "int", "unsigned int": "uint", "unsigned": "uint", "long": "long",
    "unsigned long": "ulong", "long long": "longlong", "unsigned long long": "ulonglong",
    "float": "float", "double": "double", "long double": "double", "wchar_t": "ushort",
    "short int": "short", "long int": "long", "unsigned short int": "ushort",
    "unsigned long int": "ulong", "long unsigned int": "ulong", "long long int": "longlong",
    "long long unsigned int": "ulonglong", "short unsigned int": "ushort",
}


def available():
    return shutil.which("c++filt") is not None


def demangle_many(names):
    """name -> Demangled for every `_Z` name that decodes to a plain function."""
    names = [n for n in names if n.startswith("_Z")]
    if not names or not available():
        return {}
    out = subprocess.run(["c++filt"], input="\n".join(names) + "\n", capture_output=True,
                         text=True, check=True).stdout.split("\n")
    result = {}
    for name, text in zip(names, out):
        if text == name:
            continue
        parsed = parse_rendered(text)
        if parsed is not None:
            result[name] = parsed
    return result


def _split_top(text, sep):
    parts, depth, cur, i = [], 0, [], 0
    while i < len(text):
        c = text[i]
        if c in "(<[":
            depth += 1
        elif c in ")>]":
            depth -= 1
        if depth == 0 and text.startswith(sep, i):
            parts.append("".join(cur))
            cur = []
            i += len(sep)
            continue
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _param(text):
    text = text.strip()
    if text == "...":
        return ("...", 0)
    if re.search(r"\(\s*[*&]", text):
        return ("fn", 1)
    if "::*" in text:
        return ("member", 0)
    depth = 0
    while True:
        m = re.search(r"\s*\[[^\]]*\]\s*$", text)
        if not m:
            break
        text = text[:m.start()]
        depth += 1
    text = re.sub(r"\b(?:const|volatile)\b", " ", text)
    depth += text.count("*") + text.count("&")
    text = text.replace("*", " ").replace("&", " ")
    text = re.sub(r"\s+", " ", text).strip()
    if text in PRIMS:
        return (PRIMS[text], depth)
    base = text.split("<", 1)[0]
    return (_split_top(base, "::")[-1].strip() or "?", depth)


def parse_rendered(text):
    t = text.strip()
    is_const = False
    while True:
        m = re.search(r"\s+(const|volatile|&|&&)$", t)
        if not m:
            break
        is_const |= m.group(1) == "const"
        t = t[:m.start()]
    if not t.endswith(")"):
        return None
    depth, i = 0, len(t) - 1
    while i >= 0:
        if t[i] == ")":
            depth += 1
        elif t[i] == "(":
            depth -= 1
            if depth == 0:
                break
        i -= 1
    if i <= 0:
        return None
    params_text, head = t[i + 1:-1], t[:i].rstrip()
    if " " in head.replace("operator ", "operator_").replace("(anonymous namespace)", "ANON") \
            and not head.startswith("operator"):
        # a return type is only rendered for templates; anything else with a
        # space is not a plain function name
        if "<" not in head:
            return None
    parts = [p.strip() for p in _split_top(head, "::")]
    name = parts[-1]
    scope = [re.sub(r"<.*", "", p) for p in parts[:-1]]
    template = any("<" in p for p in parts[:-1]) or ("<" in name and not name.startswith("operator"))
    scope = [s for s in scope if not s.startswith("(anonymous")]
    if template:
        return Demangled(scope=tuple(scope), name=name, params=[], template=True, abi="itanium")
    params = [] if params_text.strip() in ("", "void") else [_param(p) for p in _split_top(params_text, ",")]
    ctor = bool(scope) and name == scope[-1]
    dtor = name.startswith("~")
    return Demangled(scope=tuple(scope), name=name, params=params, is_const=is_const,
                     ctor=ctor, dtor=dtor, template=False, abi="itanium")
