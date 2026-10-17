"""MWCC (CodeWarrior) symbol demangling for the prototype extractor.

A Python reading of the gcc-2-style grammar `crates/romwright-core/src/
qualified_prototypes/mwcc_demangle.rs` decodes (`name__<scope>[C]F<params>`).
It keeps only what the join with decomp sources needs: the scope chain, the
bare name, and each parameter reduced to `(base, pointer_depth)`.
"""
from dataclasses import dataclass, field

BUILTIN = {
    "v": "void", "b": "bool", "c": "char", "s": "short", "i": "int",
    "l": "long", "x": "longlong", "f": "float", "d": "double", "w": "ushort",
    "e": "...",
}

OPERATORS = {
    "nw": "operator new", "nwa": "operator new[]", "dl": "operator delete",
    "dla": "operator delete[]", "pl": "operator+", "mi": "operator-",
    "ml": "operator*", "dv": "operator/", "md": "operator%", "er": "operator^",
    "ad": "operator&", "or": "operator|", "co": "operator~", "nt": "operator!",
    "as": "operator=", "lt": "operator<", "gt": "operator>", "apl": "operator+=",
    "ami": "operator-=", "amu": "operator*=", "adv": "operator/=",
    "amd": "operator%=", "aer": "operator^=", "aad": "operator&=",
    "aor": "operator|=", "ls": "operator<<", "rs": "operator>>",
    "ars": "operator>>=", "als": "operator<<=", "eq": "operator==",
    "ne": "operator!=", "le": "operator<=", "ge": "operator>=",
    "aa": "operator&&", "oo": "operator||", "pp": "operator++",
    "mm": "operator--", "cl": "operator()", "vc": "operator[]",
    "rf": "operator->", "cm": "operator,", "rm": "operator->*",
}


@dataclass
class Demangled:
    scope: tuple          # class/namespace chain, template args kept in the segment
    name: str             # bare name: method, operator spelling, class name for ctors
    params: list          # [(base, depth)]
    is_const: bool = False
    ctor: bool = False
    dtor: bool = False
    template: bool = False
    has_params: bool = True
    abi: str = "mwcc"      # "itanium" for names decoded through c++filt


class _Fail(Exception):
    pass


def _split_name(body):
    depth = 0
    i = 0
    while i + 1 < len(body):
        c = body[i]
        if c == "<":
            depth += 1
        elif c == ">":
            depth = max(0, depth - 1)
        elif c == "_" and depth == 0 and body[i + 1] == "_":
            split = i
            while split + 2 < len(body) and body[split + 2] == "_":
                split += 1
            rest = body[split + 2:]
            if not rest:
                return None
            return body[:split], rest
        i += 1
    return None


def _segment(s):
    n = 0
    while n < len(s) and s[n].isdigit():
        n += 1
    if n == 0:
        raise _Fail
    length = int(s[:n])
    rest = s[n:]
    if length == 0 or length > len(rest):
        raise _Fail
    return rest[:length], rest[length:]


def _class(s):
    if s.startswith("Q"):
        if len(s) < 2 or not ("1" <= s[1] <= "9"):
            raise _Fail
        rest = s[2:]
        out = []
        for _ in range(int(s[1])):
            seg, rest = _segment(rest)
            out.append(seg)
        return tuple(out), rest
    seg, rest = _segment(s)
    return (seg,), rest


def _count(s):
    if not s or not s[0].isdigit():
        raise _Fail
    n = 0
    while n < len(s) and s[n].isdigit():
        n += 1
    if n > 1 and n < len(s) and s[n] == "_":
        return int(s[:n]), s[n + 1:]
    return int(s[0]), s[1:]


def _type(s):
    """-> ((base, depth), rest)"""
    if not s:
        raise _Fail
    c, rest = s[0], s[1:]
    if c in "PR":
        (base, depth), rest = _type(rest)
        return (base, depth + 1), rest
    if c in "CV":
        return _type(rest)
    if c in "US":
        (base, depth), rest = _type(rest)
        if depth == 0:
            if c == "U":
                base = {"char": "byte", "short": "ushort", "int": "uint", "long": "ulong",
                        "longlong": "ulonglong"}.get(base, base)
            else:
                base = {"char": "sbyte"}.get(base, base)
        return (base, depth), rest
    if c == "A":
        n = 0
        while n < len(rest) and rest[n].isdigit():
            n += 1
        if n == 0 or n >= len(rest) or rest[n] != "_":
            raise _Fail
        (base, depth), rest = _type(rest[n + 1:])
        return (base, depth + 1), rest
    if c == "F":
        _, rest = _params(rest)
        if not rest.startswith("_"):
            raise _Fail
        _, rest = _type(rest[1:])
        return ("fn", 0), rest
    if c == "M":
        _, rest = _class(rest)
        if not rest.startswith("F"):
            raise _Fail
        rest = rest[1:]
        if rest.startswith("PCvPCv"):
            rest = rest[6:]
        elif rest.startswith("PCvPv"):
            rest = rest[5:]
        else:
            raise _Fail
        _, rest = _params(rest)
        if not rest.startswith("_"):
            raise _Fail
        _, rest = _type(rest[1:])
        return ("member", 0), rest
    if c == "Q" or c.isdigit():
        scope, rest = _class(s)
        return (scope[-1], 0), rest
    if c in BUILTIN:
        return (BUILTIN[c], 0), rest
    raise _Fail


def _params(s):
    params = []
    while s and s[0] != "_":
        c = s[0]
        if c == "T":
            idx, s = _count(s[1:])
            if idx >= len(params):
                raise _Fail
            params.append(params[idx])
        elif c == "N":
            cnt, s2 = _count(s[1:])
            idx, s = _count(s2)
            if idx >= len(params) or not (0 < cnt <= 64):
                raise _Fail
            params.extend([params[idx]] * cnt)
        else:
            t, s = _type(s)
            params.append(t)
    return params, s


def _template_name(raw):
    return raw.split("<", 1)[0], "<" in raw


def demangle(mangled):
    """Demangles an MWCC function symbol, or None."""
    if not mangled or not mangled.isascii() or mangled.startswith("@") or "$" in mangled:
        return None
    special = mangled.startswith("__")
    body = mangled[2:] if special else mangled
    split = _split_name(body)
    if split is None:
        return None
    raw, rest = split
    if not raw and not special:
        return None
    try:
        scope = ()
        if rest.startswith("Q") or rest[:1].isdigit():
            scope, rest = _class(rest)
        is_const = False
        if scope and rest.startswith("C"):
            is_const = True
            rest = rest[1:]
        if not rest.startswith("F"):
            return None  # data member / vtable / RTTI
        params, rest = _params(rest[1:])
        if rest.startswith("_"):
            _, rest = _type(rest[1:])
        if rest:
            return None
    except _Fail:
        return None
    template = any("<" in seg for seg in scope) or "<" in raw
    base, _ = _template_name(raw)
    ctor = dtor = False
    if special:
        if base == "ct":
            ctor = True
            name = _template_name(scope[-1])[0] if scope else ""
        elif base == "dt":
            dtor = True
            name = "~" + (_template_name(scope[-1])[0] if scope else "")
        elif base in OPERATORS:
            name = OPERATORS[base]
        elif base.startswith("op") or base in ("vt", "RTTI"):
            return None
        else:
            name = "__" + base
    else:
        name = base
    if params == [("void", 0)]:
        params = []
    return Demangled(
        scope=tuple(_template_name(seg)[0] for seg in scope),
        name=name, params=params, is_const=is_const, ctor=ctor, dtor=dtor,
        template=template,
    )
