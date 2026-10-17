//! Full MWCC (CodeWarrior) symbol demangler.
//!
//! MWCC mangles C++ names in the gcc-2 style: `name__<scope>[C]F<params>[_<ret>]`.
//! This module decodes every form the GameCube/Wii-era compilers emit: free
//! functions (`DrawFontChar__Fiiii`), members (`Update__8UberBondFv`), const
//! members (`C`), constructors/destructors (`__ct__`/`__dt__`), operators
//! (`__as__`, `__nw__`, `__opi__`), `Q`-qualified nested scopes, template
//! arguments in class and function names (`Container<i>`), vtables
//! (`__vt__`), RTTI descriptors (`__RTTI__`), `@off@` thunk names, data
//! members (no `F` list), `T`/`N` repeated-parameter back-references, and
//! template return types (`_<type>` after the parameter list).
//!
//! The rendered text (`Demangled::text`) is the spelling `dtk demangle`
//! produces, so a name resolves to the same string here as in a decomp
//! project's symbol list. The format and its edge cases were derived from
//! cwdemangle (https://github.com/encounter/cwdemangle, the library behind
//! `dtk demangle`; MIT OR Apache-2.0) and checked against `dtk demangle`
//! over the GC symbol corpora (`benchmarks/mwcc_demangle_diff.py`); no code
//! is copied. The `T`/`N` back-references follow the gcc-2 mangling
//! description and are an extension: `dtk demangle` refuses them.

/// What a demangled symbol names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A function: `F` parameter list present (possibly empty).
    Function,
    /// A data member or other symbol without a parameter list.
    Data,
    /// `__vt__<class>`.
    VTable,
    /// `__RTTI__<class>`.
    Rtti,
    /// `var$localstatic<N>$<function>`: a function-local static (or its
    /// `init$` guard), not a member of the enclosing class.
    LocalStatic,
}

/// One demangled MWCC symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demangled {
    /// The full spelling, identical to `dtk demangle`.
    pub text: String,
    pub kind: Kind,
    /// Enclosing class/namespace scope as rendered (`"std::vector<int>"`),
    /// empty for a free function.
    pub scope: String,
    /// Unqualified name: `Update`, `operator=`, `~Class`, `Class` (ctor),
    /// `__vtable`.
    pub name: String,
    /// Rendered parameter types; empty for `()`/`(void)` and for data.
    pub parameters: Vec<String>,
    /// True when the symbol carries a parameter list (even an empty one).
    pub has_parameter_list: bool,
    /// Return type, only mangled for template instances (`_<type>`).
    pub return_type: Option<String>,
    pub is_const: bool,
    pub is_constructor: bool,
    pub is_destructor: bool,
}

/// Demangler dialect switches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Expand `T<i>` / `N<n><i>` repeated-parameter back-references. MWCC
    /// emits them (`FP7obj_tagT0`), `dtk demangle` refuses them.
    pub back_references: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { back_references: true }
    }
}

impl Options {
    /// Exactly the names `dtk demangle` accepts, for the differential gate.
    pub const DTK: Options = Options { back_references: false };
}

/// Demangles an MWCC symbol, or returns `None` for anything that is not a
/// well-formed MWCC C++ name (plain C names, garbage, trailing text such as
/// `.NON_MATCHING`).
pub fn demangle(mangled: &str) -> Option<Demangled> {
    demangle_with(mangled, Options::default())
}

/// [`demangle`] with an explicit dialect.
pub fn demangle_with(mangled: &str, options: Options) -> Option<Demangled> {
    demangle_inner(mangled, options.back_references)
}

fn demangle_inner(mangled: &str, br: bool) -> Option<Demangled> {
    if !mangled.is_ascii() || mangled.is_empty() {
        return None;
    }
    // Wii-era CodeWarrior function statics: `@LOCAL@<function>@<var>` and
    // `@GUARD@<function>@<var>` (the init flag).
    let guard = mangled.starts_with("@GUARD@");
    if guard || mangled.starts_with("@LOCAL@") {
        let inner = &mangled[7..];
        let at = inner.rfind('@')?;
        let variable = &inner[at + 1..];
        if variable.is_empty() {
            return None;
        }
        let mut function = demangle_inner(&inner[..at], br)?;
        let suffix = if guard { format!("{variable} guard") } else { variable.to_string() };
        function.text = format!("{}::{suffix}", function.text);
        function.kind = Kind::LocalStatic;
        return Some(function);
    }
    if let Some((variable, rest)) = mangled.split_once('$')
        && rest.starts_with("localstatic") {
            return demangle_local_static(variable, rest, br);
        }
    let (special, body) = match mangled.strip_prefix("__") {
        Some(rest) => (true, rest),
        None => (false, mangled),
    };
    let (raw_name, rest) = split_name(body)?;
    if raw_name.is_empty() && !special {
        return None;
    }
    // `$` marks compiler-generated names (`_GLOBAL_$I$f__Fv` static-init
    // stubs); only `localstatic` forms, handled above, are decoded.
    if raw_name.contains('$') {
        return None;
    }

    let mut scope: Vec<Segment> = Vec::new();
    let mut rest = rest;
    if rest.starts_with('Q') || rest.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        let (segments, after) = parse_class(rest, br)?;
        scope = segments;
        rest = after;
    }
    let mut is_const = false;
    if !scope.is_empty()
        && let Some(after) = rest.strip_prefix('C') {
            is_const = true;
            rest = after;
        }

    let mut parameters = Vec::new();
    let mut has_parameter_list = false;
    let mut return_type = None;
    let mut return_ty: Option<Ty> = None;
    if let Some(after) = rest.strip_prefix('F') {
        has_parameter_list = true;
        let (params, after) = parse_parameters(after, br)?;
        parameters = params;
        rest = after;
    }
    if let Some(after) = rest.strip_prefix('_') {
        let (ret, after) = parse_type(after, br)?;
        return_type = Some(render(&ret)?);
        return_ty = Some(ret);
        rest = after;
    }
    if !rest.is_empty() {
        return None;
    }

    let class_base = scope.last().map(|s| s.base.clone());
    let mut kind = if has_parameter_list { Kind::Function } else { Kind::Data };
    let mut is_constructor = false;
    let mut is_destructor = false;
    let name = if special {
        match special_name(raw_name, class_base.as_deref(), br)? {
            Special::Constructor(name) => {
                is_constructor = true;
                name
            }
            Special::Destructor(name) => {
                is_destructor = true;
                name
            }
            Special::VTable => {
                kind = Kind::VTable;
                "__vtable".to_string()
            }
            Special::Rtti => {
                kind = Kind::Rtti;
                "__RTTI".to_string()
            }
            Special::Named(name) => name,
        }
    } else {
        render_name(raw_name, br)?
    };

    let scope_text = scope.iter().map(Segment::render).collect::<Vec<_>>().join("::");
    let omit_void = parameters.len() == 1 && parameters[0] == "void";
    let shown: Vec<String> = if omit_void { Vec::new() } else { parameters.clone() };

    let mut declarator = String::new();
    if !scope_text.is_empty() {
        declarator.push_str(&scope_text);
        declarator.push_str("::");
    }
    declarator.push_str(&name);
    if has_parameter_list {
        declarator.push('(');
        declarator.push_str(&shown.join(", "));
        declarator.push(')');
    }
    if is_const {
        declarator.push_str(" const");
    }
    // A return type wraps the declarator: `int f()`, but also
    // `float (* f())(int)` and `T f()[4]`.
    let text = match &return_ty {
        Some(ret) => apply_declarator(ret, &declarator)?,
        None => declarator,
    };
    Some(Demangled {
        text,
        kind,
        scope: scope_text,
        name,
        parameters: shown,
        has_parameter_list,
        return_type,
        is_const,
        is_constructor,
        is_destructor,
    })
}

/// `<var>$localstatic<N>$<function>`: the function demangles normally and the
/// variable follows it (`Get()::fgRefCounter`); the `init` guard flag spells
/// `localstatic<N> guard`.
fn demangle_local_static(variable: &str, rest: &str, br: bool) -> Option<Demangled> {
    let numbered = rest.strip_prefix("localstatic")?;
    let digits = numbered.bytes().take_while(u8::is_ascii_digit).count();
    let function = numbered[digits..].strip_prefix('$')?;
    if variable.is_empty() {
        return None;
    }
    let mut inner = demangle_inner(function, br)?;
    let suffix = if variable == "init" {
        format!("localstatic{} guard", &numbered[..digits])
    } else {
        variable.to_string()
    };
    inner.text = format!("{}::{suffix}", inner.text);
    inner.kind = Kind::LocalStatic;
    Some(inner)
}

/// Splits `name__rest`: the name is everything before the first `__` that is
/// outside template brackets; further underscores belong to the name
/// (`foo___Fv` is `foo_` + `Fv`). The remainder must be non-empty.
fn split_name(body: &str) -> Option<(&str, &str)> {
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    while index + 1 < bytes.len() {
        match bytes[index] {
            b'<' => depth += 1,
            b'>' => depth = depth.saturating_sub(1),
            b'_' if depth == 0 && bytes[index + 1] == b'_' => {
                let mut split = index;
                while bytes.get(split + 2) == Some(&b'_') {
                    split += 1;
                }
                let rest = &body[split + 2..];
                return (!rest.is_empty()).then(|| (&body[..split], rest));
            }
            _ => {}
        }
        index += 1;
    }
    None
}

enum Special {
    Constructor(String),
    Destructor(String),
    VTable,
    Rtti,
    Named(String),
}

/// Operator codes after the leading `__` of a special name.
const OPERATORS: &[(&str, &str)] = &[
    ("nw", "operator new"),
    ("nwa", "operator new[]"),
    ("dl", "operator delete"),
    ("dla", "operator delete[]"),
    ("pl", "operator+"),
    ("mi", "operator-"),
    ("ml", "operator*"),
    ("dv", "operator/"),
    ("md", "operator%"),
    ("er", "operator^"),
    ("ad", "operator&"),
    ("or", "operator|"),
    ("co", "operator~"),
    ("nt", "operator!"),
    ("as", "operator="),
    ("lt", "operator<"),
    ("gt", "operator>"),
    ("apl", "operator+="),
    ("ami", "operator-="),
    ("amu", "operator*="),
    ("adv", "operator/="),
    ("amd", "operator%="),
    ("aer", "operator^="),
    ("aad", "operator&="),
    ("aor", "operator|="),
    ("ls", "operator<<"),
    ("rs", "operator>>"),
    ("ars", "operator>>="),
    ("als", "operator<<="),
    ("eq", "operator=="),
    ("ne", "operator!="),
    ("le", "operator<="),
    ("ge", "operator>="),
    ("aa", "operator&&"),
    ("oo", "operator||"),
    ("pp", "operator++"),
    ("mm", "operator--"),
    ("cl", "operator()"),
    ("vc", "operator[]"),
    ("rf", "operator->"),
    ("cm", "operator,"),
    ("rm", "operator->*"),
];

/// The rendered template arguments of a function name (`ct<i>` -> `<int>`).
fn name_template(raw: &str, br: bool) -> Option<(&str, String)> {
    match raw.find('<') {
        None if raw.contains('>') => None,
        None => Some((raw, String::new())),
        Some(open) => {
            let (args, _) = template_args(&raw[open..], br)?;
            Some((&raw[..open], format!("<{args}>")))
        }
    }
}

fn special_name(raw: &str, class_base: Option<&str>, br: bool) -> Option<Special> {
    // `__op<type>__`: conversion operator. The type is parsed from the
    // name text; trailing text after the type is ignored (as `dtk` does).
    if let Some(type_text) = raw.strip_prefix("op")
        && !OPERATORS.iter().any(|(code, _)| *code == raw) {
            let (ty, _) = parse_type(type_text, br)?;
            return Some(Special::Named(format!("operator {}", render(&ty)?)));
        }
    let (base, templates) = name_template(raw, br)?;
    let class = class_base.unwrap_or("");
    Some(match base {
        "ct" => Special::Constructor(format!("{class}{templates}")),
        "dt" => Special::Destructor(format!("~{class}{templates}")),
        "vt" => Special::VTable,
        "RTTI" => Special::Rtti,
        _ => match OPERATORS.iter().find(|(code, _)| *code == base) {
            Some((_, spelling)) => Special::Named(format!("{spelling}{templates}")),
            None => Special::Named(format!("__{}", render_name(raw, br)?)),
        },
    })
}

/// A function name with template arguments rendered (`foo<i>` -> `foo<int>`).
fn render_name(raw: &str, br: bool) -> Option<String> {
    let (base, templates) = name_template(raw, br)?;
    Some(format!("{base}{templates}"))
}

/// One length-prefixed scope segment, template arguments split out.
#[derive(Clone, Debug)]
struct Segment {
    /// Name without template arguments (what a constructor is called).
    base: String,
    /// Rendered arguments, between the brackets.
    args: Option<String>,
}

impl Segment {
    fn render(&self) -> String {
        match &self.args {
            Some(args) => format!("{}<{args}>", self.base),
            None => self.base.clone(),
        }
    }
}

/// Reads `<len><text>`; `len` must be non-zero and fit.
fn parse_segment(s: &str, br: bool) -> Option<(Segment, &str)> {
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let len: usize = s[..digits].parse().ok()?;
    let rest = &s[digits..];
    if len == 0 || len > rest.len() {
        return None;
    }
    let text = &rest[..len];
    let segment = match text.find('<') {
        None => Segment { base: text.to_string(), args: None },
        Some(open) => {
            let (args, _) = template_args(&text[open..], br)?;
            Segment { base: text[..open].to_string(), args: Some(args) }
        }
    };
    Some((segment, &rest[len..]))
}

/// A class scope: one segment (`8UberBond`) or `Q<n>` followed by `n` segments.
fn parse_class(s: &str, br: bool) -> Option<(Vec<Segment>, &str)> {
    if let Some(rest) = s.strip_prefix('Q') {
        let count = *rest.as_bytes().first()?;
        if !(b'1'..=b'9').contains(&count) {
            return None;
        }
        let mut rest = &rest[1..];
        let mut segments = Vec::new();
        for _ in 0..(count - b'0') {
            let (segment, after) = parse_segment(rest, br)?;
            segments.push(segment);
            rest = after;
        }
        Some((segments, rest))
    } else {
        let (segment, rest) = parse_segment(s, br)?;
        Some((vec![segment], rest))
    }
}

/// Parses `<a,b,...>` at the start of `text` (which must open with `<`):
/// the rendered, `, `-joined arguments and the text after the matching `>`.
fn template_args(text: &str, br: bool) -> Option<(String, &str)> {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'<') {
        return None;
    }
    let mut depth = 0usize;
    let mut close = None;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let inner = &text[1..close];
    let mut pieces = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (index, byte) in inner.bytes().enumerate() {
        match byte {
            b'<' => depth += 1,
            b'>' => depth = depth.checked_sub(1)?,
            b',' if depth == 0 => {
                pieces.push(&inner[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    pieces.push(&inner[start..]);
    let mut rendered = Vec::with_capacity(pieces.len());
    for piece in pieces {
        rendered.push(render_template_arg(piece, br)?);
    }
    Some((rendered.join(", "), &text[close + 1..]))
}

fn render_template_arg(piece: &str, br: bool) -> Option<String> {
    if piece.is_empty() {
        return Some(String::new());
    }
    let digits = piece.strip_prefix('-').unwrap_or(piece);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        return Some(piece.to_string());
    }
    let (ty, rest) = parse_type(piece, br)?;
    rest.is_empty().then(|| render(&ty)).flatten()
}

/// A parsed type, rendered on demand so declarators (`(*)`, `[3]`) land in
/// the right place.
#[derive(Clone, Debug)]
enum Ty {
    Name(String),
    Ptr(Box<Ty>),
    Ref(Box<Ty>),
    /// A leading keyword modifier: `const`, `volatile`, `unsigned`, `signed`.
    Qual(&'static str, Box<Ty>),
    Array(String, Box<Ty>),
    Func(Vec<String>, Box<Ty>),
    /// Pointer to member function: class, parameters, return type, const.
    Member(String, Vec<String>, Box<Ty>, bool),
}

fn builtin(code: u8) -> Option<&'static str> {
    Some(match code {
        b'v' => "void",
        b'b' => "bool",
        b'c' => "char",
        b's' => "short",
        b'i' => "int",
        b'l' => "long",
        b'x' => "long long",
        b'f' => "float",
        b'd' => "double",
        b'w' => "wchar_t",
        b'e' => "...",
        _ => return None,
    })
}

/// Reads a gcc-2 count: one digit, or several digits closed by `_`.
fn parse_count(s: &str) -> Option<(usize, &str)> {
    let bytes = s.as_bytes();
    let first = *bytes.first()?;
    if !first.is_ascii_digit() {
        return None;
    }
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits > 1 && bytes.get(digits) == Some(&b'_') {
        let count = s[..digits].parse().ok()?;
        return Some((count, &s[digits + 1..]));
    }
    Some(((first - b'0') as usize, &s[1..]))
}

fn parse_type(s: &str, br: bool) -> Option<(Ty, &str)> {
    let first = *s.as_bytes().first()?;
    let rest = &s[1..];
    match first {
        b'P' => {
            let (inner, rest) = parse_type(rest, br)?;
            Some((Ty::Ptr(Box::new(inner)), rest))
        }
        b'R' => {
            let (inner, rest) = parse_type(rest, br)?;
            Some((Ty::Ref(Box::new(inner)), rest))
        }
        b'C' | b'V' | b'U' | b'S' => {
            let keyword = match first {
                b'C' => "const",
                b'V' => "volatile",
                b'U' => "unsigned",
                _ => "signed",
            };
            let (inner, rest) = parse_type(rest, br)?;
            Some((Ty::Qual(keyword, Box::new(inner)), rest))
        }
        b'A' => {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 || rest.as_bytes().get(digits) != Some(&b'_') {
                return None;
            }
            let length = rest[..digits].to_string();
            let (inner, rest) = parse_type(&rest[digits + 1..], br)?;
            Some((Ty::Array(length, Box::new(inner)), rest))
        }
        b'F' => {
            let (params, rest) = parse_parameters(rest, br)?;
            let rest = rest.strip_prefix('_')?;
            let (ret, rest) = parse_type(rest, br)?;
            Some((Ty::Func(params, Box::new(ret)), rest))
        }
        b'M' => {
            let (segments, rest) = parse_class(rest, br)?;
            let class = segments.iter().map(Segment::render).collect::<Vec<_>>().join("::");
            // MWCC passes the object and adjustment as `const void*` pairs.
            let rest = rest.strip_prefix('F')?;
            let (konst, rest) = if let Some(rest) = rest.strip_prefix("PCvPCv") {
                (true, rest)
            } else {
                (false, rest.strip_prefix("PCvPv")?)
            };
            let (params, rest) = parse_parameters(rest, br)?;
            let rest = rest.strip_prefix('_')?;
            let (ret, rest) = parse_type(rest, br)?;
            Some((Ty::Member(class, params, Box::new(ret), konst), rest))
        }
        b'Q' | b'0'..=b'9' => {
            let (segments, rest) = parse_class(s, br)?;
            let name = segments.iter().map(Segment::render).collect::<Vec<_>>().join("::");
            Some((Ty::Name(name), rest))
        }
        code => Some((Ty::Name(builtin(code)?.to_string()), rest)),
    }
}

/// Parameter list up to `_` or the end. With `br`, `T<i>` repeats parameter
/// `i` (0-based over the expanded list) and `N<n><i>` repeats it `n` times.
fn parse_parameters(mut s: &str, br: bool) -> Option<(Vec<String>, &str)> {
    let mut params: Vec<String> = Vec::new();
    while let Some(&byte) = s.as_bytes().first() {
        match byte {
            b'_' => break,
            b'T' if br => {
                let (index, rest) = parse_count(&s[1..])?;
                params.push(params.get(index)?.clone());
                s = rest;
            }
            b'N' if br => {
                let (count, rest) = parse_count(&s[1..])?;
                let (index, rest) = parse_count(rest)?;
                let repeated = params.get(index)?.clone();
                if count == 0 || count > 64 {
                    return None;
                }
                for _ in 0..count {
                    params.push(repeated.clone());
                }
                s = rest;
            }
            _ => {
                let (ty, rest) = parse_type(s, br)?;
                params.push(render(&ty)?);
                s = rest;
            }
        }
    }
    Some((params, s))
}

fn array_parts(ty: &Ty) -> (&Ty, String) {
    let mut dims = String::new();
    let mut current = ty;
    while let Ty::Array(length, inner) = current {
        dims.push('[');
        dims.push_str(length);
        dims.push(']');
        current = inner;
    }
    (current, dims)
}

fn render(ty: &Ty) -> Option<String> {
    match ty {
        Ty::Name(name) => Some(name.clone()),
        Ty::Qual(keyword, inner) => {
            let inner = render(inner)?;
            if inner.ends_with('*') || inner.ends_with('&') {
                Some(format!("{inner} {keyword}"))
            } else {
                Some(format!("{keyword} {inner}"))
            }
        }
        Ty::Ptr(inner) => match &**inner {
            Ty::Func(..) | Ty::Member(..) => apply_declarator(ty, ""),
            Ty::Qual("const", func) if matches!(**func, Ty::Func(..)) => apply_declarator(ty, ""),
            Ty::Array(..) => {
                let (base, dims) = array_parts(inner);
                Some(format!("{}(*){dims}", render(base)?))
            }
            _ => Some(format!("{}*", render(inner)?)),
        },
        Ty::Ref(inner) => match &**inner {
            Ty::Func(..) => None,
            Ty::Array(..) => {
                let (base, dims) = array_parts(inner);
                Some(format!("{}(&){dims}", render(base)?))
            }
            _ => Some(format!("{}&", render(inner)?)),
        },
        Ty::Array(..) => {
            let (base, dims) = array_parts(ty);
            Some(format!("{}{dims}", render(base)?))
        }
        Ty::Func(..) => None,
        Ty::Member(..) => apply_declarator(ty, ""),
    }
}

/// Renders `ty` around the declarator text `declarator` (a name with its
/// parameter list, or the inner part of a nested function pointer).
fn apply_declarator(ty: &Ty, declarator: &str) -> Option<String> {
    match ty {
        Ty::Ptr(inner) => match &**inner {
            Ty::Func(params, ret) => function_pointer(params, ret, declarator, false),
            Ty::Member(class, params, ret, konst) => {
                member_pointer(class, "**", params, ret, *konst, declarator)
            }
            Ty::Qual("const", func) => match &**func {
                Ty::Func(params, ret) => function_pointer(params, ret, declarator, true),
                _ => Some(format!("{} {declarator}", render(ty)?)),
            },
            Ty::Array(..) => {
                let (base, dims) = array_parts(inner);
                Some(format!("{}(*) {declarator}{dims}", render(base)?))
            }
            _ => Some(format!("{} {declarator}", render(ty)?)),
        },
        Ty::Ref(inner) => match &**inner {
            Ty::Func(..) => None,
            Ty::Array(..) => {
                let (base, dims) = array_parts(inner);
                Some(format!("{}(&) {declarator}{dims}", render(base)?))
            }
            _ => Some(format!("{} {declarator}", render(ty)?)),
        },
        Ty::Array(..) => {
            let (base, dims) = array_parts(ty);
            Some(format!("{} {declarator}{dims}", render(base)?))
        }
        Ty::Func(..) => None,
        Ty::Member(class, params, ret, konst) => {
            member_pointer(class, "*", params, ret, *konst, declarator)
        }
        _ => Some(format!("{} {declarator}", render(ty)?)),
    }
}

/// `ret (Class::*declarator)(params) [const]`.
fn member_pointer(
    class: &str,
    stars: &str,
    params: &[String],
    ret: &Ty,
    konst: bool,
    declarator: &str,
) -> Option<String> {
    let list = params.join(", ");
    let tail = if konst { " const" } else { "" };
    let inner = if declarator.is_empty() {
        format!("({class}::{stars})({list}){tail}")
    } else {
        format!("({class}::{stars} {declarator})({list}){tail}")
    };
    apply_declarator(ret, &inner)
}

/// `ret (*declarator)(params)`, nesting when `ret` is itself a function
/// pointer (`void (* (*)(int))(void)`).
fn function_pointer(params: &[String], ret: &Ty, declarator: &str, konst: bool) -> Option<String> {
    let list = params.join(", ");
    let inner = match (declarator.is_empty(), konst) {
        (true, false) => format!("(*)({list})"),
        (true, true) => format!("(*const )({list})"),
        (false, _) => format!("(* {declarator})({list})"),
    };
    apply_declarator(ret, &inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(mangled: &str) -> Option<String> {
        demangle(mangled).map(|d| d.text)
    }

    #[test]
    fn free_functions_and_parameter_types() {
        assert_eq!(text("foo__Fv").as_deref(), Some("foo()"));
        assert_eq!(
            text("DrawFontChar__Fiiii").as_deref(),
            Some("DrawFontChar(int, int, int, int)")
        );
        assert_eq!(
            text("SafeRead__FP11DVDFileInfoPvii").as_deref(),
            Some("SafeRead(DVDFileInfo*, void*, int, int)")
        );
        assert_eq!(
            text("Menu_AddRow__FUcUiUiUiUiScSc").as_deref(),
            Some("Menu_AddRow(unsigned char, unsigned int, unsigned int, unsigned int, unsigned int, signed char, signed char)")
        );
        assert_eq!(text("foo__FRCPCc").as_deref(), Some("foo(const char* const&)"));
        assert_eq!(text("foo__FPPc").as_deref(), Some("foo(char**)"));
        assert_eq!(text("foo__Fx").as_deref(), Some("foo(long long)"));
        assert_eq!(text("foo__Fe").as_deref(), Some("foo(...)"));
        assert_eq!(text("foo__Fvi").as_deref(), Some("foo(void, int)"));
        // The `_` start a return type, so a bare trailing `_` is malformed.
        assert_eq!(text("foo__Fv_"), None);
        assert_eq!(text("foo__Fv.x"), None);
        assert_eq!(text("foo__Fv.NON_MATCHING"), None);
    }

    #[test]
    fn arrays_and_function_pointers() {
        assert_eq!(text("foo__FA3_i").as_deref(), Some("foo(int[3])"));
        assert_eq!(text("foo__FPA4_f").as_deref(), Some("foo(float(*)[4])"));
        assert_eq!(text("foo__FRA4_f").as_deref(), Some("foo(float(&)[4])"));
        assert_eq!(text("foo__FPA3_A4_i").as_deref(), Some("foo(int(*)[3][4])"));
        assert_eq!(text("Foo__FPFi_v").as_deref(), Some("Foo(void (*)(int))"));
        assert_eq!(text("Foo__FPFv_v").as_deref(), Some("Foo(void (*)(void))"));
        assert_eq!(text("foo__FPCFv_v").as_deref(), Some("foo(void (*const )(void))"));
        assert_eq!(text("foo__FRFv_v"), None);
    }

    #[test]
    fn qualifiers_follow_the_pointer_rule() {
        assert_eq!(text("foo__FCi").as_deref(), Some("foo(const int)"));
        assert_eq!(text("foo__FCPCi").as_deref(), Some("foo(const int* const)"));
        assert_eq!(text("foo__FVi").as_deref(), Some("foo(volatile int)"));
        assert_eq!(text("foo__FCVi").as_deref(), Some("foo(const volatile int)"));
        assert_eq!(text("foo__FPCUc").as_deref(), Some("foo(const unsigned char*)"));
        assert_eq!(text("foo__FCPUc").as_deref(), Some("foo(unsigned char* const)"));
    }

    #[test]
    fn members_const_and_data() {
        let member = demangle("Update__8UberBondFv").unwrap();
        assert_eq!(member.text, "UberBond::Update()");
        assert_eq!((member.scope.as_str(), member.name.as_str()), ("UberBond", "Update"));
        assert!(member.parameters.is_empty() && member.has_parameter_list && !member.is_const);
        assert_eq!(
            text("crc16__8UberBondFPCvi").as_deref(),
            Some("UberBond::crc16(const void*, int)")
        );
        let constant = demangle("GetName__10ASmackableCFv").unwrap();
        assert_eq!(constant.text, "ASmackable::GetName() const");
        assert!(constant.is_const);
        // No `F` list: a data member, rendered without parentheses.
        let data = demangle("fNumBumperCameras__13RPlayerCamera").unwrap();
        assert_eq!(data.text, "RPlayerCamera::fNumBumperCameras");
        assert_eq!(data.kind, Kind::Data);
        assert!(!data.has_parameter_list);
        assert_eq!(text("foo__3FooC").as_deref(), Some("Foo::foo const"));
        assert_eq!(text("foo__3BarF").as_deref(), Some("Bar::foo()"));
    }

    #[test]
    fn qualified_nested_scopes() {
        assert_eq!(
            text("Decode__Q23SND12CEAXABLKDecfFPPfi").as_deref(),
            Some("SND::CEAXABLKDecf::Decode(float**, int)")
        );
        assert_eq!(
            text("GetContext__22RTextureContextManagerFQ222RTextureContextManager18TextureContextType")
                .as_deref(),
            Some("RTextureContextManager::GetContext(RTextureContextManager::TextureContextType)")
        );
        assert_eq!(
            text("sDevice__Q212JUTAssertion23@unnamed@JUTAssert_cpp@").as_deref(),
            Some("JUTAssertion::@unnamed@JUTAssert_cpp@::sDevice")
        );
        assert_eq!(text("foo__Q13FooFv").as_deref(), Some("Foo::foo()"));
        assert_eq!(text("foo__Q03FooFv"), None);
        assert_eq!(text("foo__Q33FooFv"), None);
        assert_eq!(text("foo__9ShortFv"), None);
    }

    #[test]
    fn templates_in_class_function_and_argument_positions() {
        assert_eq!(
            text("AddObject__12Container<i>FRCi").as_deref(),
            Some("Container<int>::AddObject(const int&)")
        );
        assert_eq!(
            text("AddObject__31Container<P17WeaponSetLocation>FRCP17WeaponSetLocation").as_deref(),
            Some("Container<WeaponSetLocation*>::AddObject(WeaponSetLocation* const&)")
        );
        assert_eq!(
            text("balance_erase__Q23std19__red_black_tree<1>FPQ33std19__red_black_tree<1>9node_base")
                .as_deref(),
            Some("std::__red_black_tree<1>::balance_erase(std::__red_black_tree<1>::node_base*)")
        );
        assert_eq!(
            text("ReverseBytesInPlace<i>__FRCi").as_deref(),
            Some("ReverseBytesInPlace<int>(const int&)")
        );
        assert_eq!(
            text("J2DDrawFrame__FRCQ29JGeometry8TBox2<f>Q28JUtility6TColorUc").as_deref(),
            Some("J2DDrawFrame(const JGeometry::TBox2<float>&, JUtility::TColor, unsigned char)")
        );
        assert_eq!(
            text("__ct__Q23std13allocator<Pv>FRCQ23std13allocator<Pv>").as_deref(),
            Some("std::allocator<void*>::allocator(const std::allocator<void*>&)")
        );
        assert_eq!(text("foo<i,3>__Fv").as_deref(), Some("foo<int, 3>()"));
        assert_eq!(text("foo<3Bar,-1>__Fv").as_deref(), Some("foo<Bar, -1>()"));
        // Template instances mangle their return type after the list.
        assert_eq!(text("foo<i>__Fv_i").as_deref(), Some("int foo<int>()"));
        assert_eq!(text("foo<i>__3BarFv_i").as_deref(), Some("int Bar::foo<int>()"));
        assert_eq!(text("foo__12Container<i").as_deref(), None);
        assert_eq!(
            text("__ct<P14ActionConsumer>__Q23std13allocator<Pv>FRCQ23std28allocator<P14ActionConsumer>")
                .as_deref(),
            Some("std::allocator<void*>::allocator<ActionConsumer*>(const std::allocator<ActionConsumer*>&)")
        );
    }

    #[test]
    fn constructors_destructors_vtables_and_rtti() {
        let ctor = demangle("__ct__8UberBondFv").unwrap();
        assert_eq!(ctor.text, "UberBond::UberBond()");
        assert!(ctor.is_constructor && !ctor.is_destructor);
        let dtor = demangle("__dt__8UberBondFv").unwrap();
        assert_eq!(dtor.text, "UberBond::~UberBond()");
        assert!(dtor.is_destructor);
        assert_eq!(
            text("__ct__26MemPool<15CParticleSprite>FiiPCci").as_deref(),
            Some("MemPool<CParticleSprite>::MemPool(int, int, const char*, int)")
        );
        assert_eq!(
            text("__dt__18MemPool<8C_NCSkin>Fv").as_deref(),
            Some("MemPool<C_NCSkin>::~MemPool()")
        );
        assert_eq!(text("__ct__3Foo").as_deref(), Some("Foo::Foo"));
        let vtable = demangle("__vt__10BackWheels").unwrap();
        assert_eq!((vtable.text.as_str(), vtable.kind), ("BackWheels::__vtable", Kind::VTable));
        assert_eq!(
            text("__vt__25MemPool<14CParticleGroup>").as_deref(),
            Some("MemPool<CParticleGroup>::__vtable")
        );
        let rtti = demangle("__RTTI__7JKRAram").unwrap();
        assert_eq!((rtti.text.as_str(), rtti.kind), ("JKRAram::__RTTI", Kind::Rtti));
        assert_eq!(text("__RTTI__Q23foo3Bar").as_deref(), Some("foo::Bar::__RTTI"));
        assert_eq!(text("__vt__"), None);
        assert_eq!(text("__ct__"), None);
    }

    #[test]
    fn operators_and_conversions() {
        assert_eq!(
            text("__as__3strFPCc").as_deref(),
            Some("str::operator=(const char*)")
        );
        assert_eq!(text("__nw__9ActorTaskFUl").as_deref(), Some("ActorTask::operator new(unsigned long)"));
        assert_eq!(text("__dl__12SmallNodeArrFPv").as_deref(), Some("SmallNodeArr::operator delete(void*)"));
        assert_eq!(text("__dla__FPv").as_deref(), Some("operator delete[](void*)"));
        assert_eq!(text("__nwa__3FooFUl").as_deref(), Some("Foo::operator new[](unsigned long)"));
        assert_eq!(text("__vc__8aflags_cFUi").as_deref(), Some("aflags_c::operator[](unsigned int)"));
        assert_eq!(text("__ls__FR7ostreami").as_deref(), Some("operator<<(ostream&, int)"));
        assert_eq!(text("__eq__3FooCFRC3Foo").as_deref(), Some("Foo::operator==(const Foo&) const"));
        assert_eq!(text("__cl__3FooFv").as_deref(), Some("Foo::operator()()"));
        assert_eq!(text("__rm__3FooFv").as_deref(), Some("Foo::operator->*()"));
        assert_eq!(text("__pp__3FooFi").as_deref(), Some("Foo::operator++(int)"));
        assert_eq!(text("__opPCc__3FooCFv").as_deref(), Some("Foo::operator const char*() const"));
        assert_eq!(text("__opi__3FooFv").as_deref(), Some("Foo::operator int()"));
        assert_eq!(text("__op3Bar__3FooFv").as_deref(), Some("Foo::operator Bar()"));
        // An unknown `__` name is kept, not guessed at.
        assert_eq!(text("__initialize__Fv").as_deref(), Some("__initialize()"));
        assert_eq!(text("__foo__3BarFv").as_deref(), Some("Bar::__foo()"));
        assert_eq!(text("foo___Fv").as_deref(), Some("foo_()"));
    }

    #[test]
    fn thunk_names_keep_their_offset_marker() {
        assert_eq!(
            text("@64@GetVelocity__9ActWeaponCFv").as_deref(),
            Some("ActWeapon::@64@GetVelocity() const")
        );
        assert_eq!(
            text("@64@TransformPointToWorldSpace__9ActWeaponCFR6COORD4").as_deref(),
            Some("ActWeapon::@64@TransformPointToWorldSpace(COORD4&) const")
        );
    }

    #[test]
    fn member_function_pointers_and_wii_function_statics() {
        assert_eq!(
            text("foo__FM3FooFPCvPCv_v").as_deref(),
            Some("foo(void (Foo::*)() const)")
        );
        assert_eq!(text("foo__FM3FooFPCvPv_v").as_deref(), Some("foo(void (Foo::*)())"));
        assert_eq!(
            text("foo__FM3FooFPCvPCvi_v").as_deref(),
            Some("foo(void (Foo::*)(int) const)")
        );
        assert_eq!(text("foo__FPM3FooFPCvPv_v").as_deref(), Some("foo(void (Foo::**)())"));
        assert_eq!(
            text("foo__3BarFM3FooFPCvPv_v").as_deref(),
            Some("Bar::foo(void (Foo::*)())")
        );
        assert_eq!(text("foo__FM3Fooi"), None);
        assert_eq!(text("@LOCAL@Get__3FooFv@x").as_deref(), Some("Foo::Get()::x"));
        assert_eq!(text("@GUARD@Get__3FooFv@x").as_deref(), Some("Foo::Get()::x guard"));
        assert_eq!(text("@LOCAL@Get__Fv@x").as_deref(), Some("Get()::x"));
        assert_eq!(demangle("@LOCAL@Get__3FooFv@x").unwrap().kind, Kind::LocalStatic);
        // Thunks start with `@<offset>@` and are functions.
        assert_eq!(demangle("@64@Get__3FooFv").unwrap().kind, Kind::Function);
    }

    #[test]
    fn function_pointer_returns_nest_their_declarators() {
        assert_eq!(text("Update__Fi_PF_d").as_deref(), Some("double (* Update(int))()"));
        assert_eq!(
            text("Update__F_PFdv_CPc").as_deref(),
            Some("char* const (* Update())(double, void)")
        );
        assert_eq!(text("foo__FPFPFv_v_v").as_deref(), Some("foo(void (*)(void (*)(void)))"));
        assert_eq!(text("foo__FPFv_PFv_v").as_deref(), Some("foo(void (* (*)(void))(void))"));
        assert_eq!(text("Update__F_A6_9JUTAssert").as_deref(), Some("JUTAssert Update()[6]"));
        assert_eq!(text("Update__FPFd_A7_f").as_deref(), Some("Update(float (*)(double)[7])"));
    }

    #[test]
    fn repeated_parameters_expand_back_references() {
        // Extension over `dtk demangle`, which refuses `T`/`N`.
        assert_eq!(
            text("MulMatrix0__FPC6MATRIXT0P6MATRIX").as_deref(),
            Some("MulMatrix0(const MATRIX*, const MATRIX*, MATRIX*)")
        );
        assert_eq!(
            text("Plane_PlaneEq__FP13plane_equ_tagPC7_VECTORN21").as_deref(),
            Some("Plane_PlaneEq(plane_equ_tag*, const _VECTOR*, const _VECTOR*, const _VECTOR*)")
        );
        assert_eq!(text("foo__FiT1"), None);
        assert_eq!(text("foo__FiT0").as_deref(), Some("foo(int, int)"));
        // Indices count builtin parameters and earlier expansions too.
        assert_eq!(
            text("BOT_init__FsP7_VECTORT1P7obj_tagP5MPBOTSc").as_deref(),
            Some("BOT_init(short, _VECTOR*, _VECTOR*, obj_tag*, MPBOT*, signed char)")
        );
        assert_eq!(
            text("PS2Sinf3__FfffPfN23").as_deref(),
            Some("PS2Sinf3(float, float, float, float*, float*, float*)")
        );
        assert_eq!(
            text("Sprite_BuildList__FUsPUiN21").as_deref(),
            Some("Sprite_BuildList(unsigned short, unsigned int*, unsigned int*, unsigned int*)")
        );
        // The dtk dialect refuses them.
        assert_eq!(
            demangle_with("foo__FiT0", Options::DTK).map(|d| d.text),
            None
        );
        assert_eq!(demangle_with("foo__Fii", Options::DTK).unwrap().text, "foo(int, int)");
    }

    #[test]
    fn function_local_statics_follow_their_function() {
        let local = demangle("fgRefCounter$localstatic0$Get__14URefCounter<c>Fv").unwrap();
        assert_eq!(local.text, "URefCounter<char>::Get()::fgRefCounter");
        assert_eq!(local.kind, Kind::LocalStatic);
        assert_eq!(
            text("init$localstatic1$NullStr__3strFv").as_deref(),
            Some("str::NullStr()::localstatic1 guard")
        );
        assert_eq!(
            text("blk_tbl$localstatic3$get_blk_wd_ht__FUiPUiPUi").as_deref(),
            Some("get_blk_wd_ht(unsigned int, unsigned int*, unsigned int*)::blk_tbl")
        );
        // `$` only opens a `localstatic` form; other `$` names are compiler stubs.
        assert_eq!(text("x$notstatic$Get__3FooFv"), None);
        assert_eq!(text("_GLOBAL_$I$HUD_Init__FP6BLDataP7obj_tag"), None);
    }

    #[test]
    fn non_mangled_names_are_refused() {
        for name in ["printf", "", "__CARDBlock", "__sinit_foo_cpp", "main", "foo__", "_GLOBAL_$I$x"] {
            assert_eq!(text(name), None, "{name}");
        }
        assert_eq!(text("caf\u{e9}__Fv"), None);
    }
}
