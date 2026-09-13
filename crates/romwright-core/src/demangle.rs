//! Itanium C++ ABI names for the data the ABI itself defines, demangled to the
//! shape Ghidra applies at the address.
//!
//! What stock does with `_ZTIi`, from the pinned tree: every symbol that is not
//! `DEFAULT` and is parented globally is handed to the demangler
//! (`AbstractDemanglerAnalyzer.demangleSymbols`, :124-171, `skipSymbol`,
//! :205-233) after `SymbolUtilities.getCleanSymbolName` strips any address
//! suffix (:333-335). The demangled text `typeinfo for int` is matched against
//! `ADDRESS_TABLE_PREFIXES` (`GnuDemanglerParser`, :65-66, :502-514) and built
//! by `AddressTableHandler` (:1877-1913): the applied **name** is the prefix up
//! to its last space with spaces turned into dashes (`typeinfo`), and the
//! namespace is the type the name is *for* (`int`). `typeinfo name for` takes
//! the sibling path (`TypeInfoNameHandler`, :1856-1875, applied by
//! `DemangledString.applyTo` :72-99 as the name `typeinfo-name`). Both are
//! applied with `SourceType.ANALYSIS` and made **primary**
//! (`DemangledAddressTable.applyTo`, :74-90;
//! `DemangledObject.applyDemangledName`, :527-555), which is why the primary --
//! the name a decompiler prints -- is `typeinfo` and not `_ZTIi`.
//!
//! ## Covered
//!
//! The four ABI data names (`<special-name> ::= TV | TT | TI | TS <type>`) over
//! the type grammar this module parses: builtin types, class and enum names
//! (nested, `std`-scoped, and template instantiations), substitutions
//! (sequential and the standard `St`/`Sa`/`Sb`/`Ss`/`Si`/`So`/`Sd`), pointers,
//! lvalue and rvalue references, `const`/`volatile`/`restrict`, arrays,
//! function types, and integer or boolean template literals.
//!
//! ## Refused
//!
//! Everything else returns `None` rather than a guess: function and variable
//! encodings (a name needs a corpus row that carries one, and II.1 reserves
//! adding corpus rows), construction vtables (`TC`), covariant and virtual
//! thunks (`Tc`/`Th`/`Tv`), guard variables, expressions in template
//! arguments, lambdas, operator and constructor names, and any name whose type
//! this module does not parse to its very last byte.
//!
//! Renderings were checked against the GNU demangler the pinned install ships
//! (`c++filt`, binutils 2.4x): `_ZTIPKc` is `char const*`, `_ZTIPFvvE` is
//! `void (*)()`, `_ZTISt6vectorIiSaIiEE` is
//! `std::vector<int, std::allocator<int> >`.

/// A mangled name, demangled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demangled {
    /// The symbol name Ghidra applies at the address: `typeinfo`, `vtable`,
    /// `VTT`, `typeinfo-name`.
    pub name: String,
    /// The type the name is *for*, which is the namespace Ghidra applies the
    /// name in: `int` for `_ZTIi`.
    pub namespace: String,
    /// The full demangled text: `typeinfo for int`.
    pub text: String,
}

/// Demangles a name the ABI defines for data, or refuses it.
pub fn demangle(mangled: &str) -> Option<Demangled> {
    let rest = mangled.strip_prefix("_Z")?;
    let (prefix, name, rest) = match rest.as_bytes() {
        [b'T', b'V', ..] => ("vtable for", "vtable", &rest[2..]),
        [b'T', b'T', ..] => ("VTT for", "VTT", &rest[2..]),
        [b'T', b'I', ..] => ("typeinfo for", "typeinfo", &rest[2..]),
        [b'T', b'S', ..] => ("typeinfo name for", "typeinfo-name", &rest[2..]),
        _ => return None,
    };
    let mut parser = Parser::new(rest);
    let ty = parser.ty()?;
    if !parser.done() {
        return None;
    }
    let namespace = render(&ty);
    Some(Demangled {
        name: name.to_string(),
        text: format!("{prefix} {namespace}"),
        namespace,
    })
}

/// A parsed type, kept as a tree because rendering is not concatenation: a
/// pointer to a function is `void (*)()`, not `void ()*`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ty {
    /// A builtin, class, enum, or already-rendered leaf.
    Leaf(String),
    Ptr(Box<Ty>),
    Ref(Box<Ty>),
    RvalueRef(Box<Ty>),
    /// `const`, `volatile`, `restrict`, rendered after the type it qualifies.
    Qualified(Box<Ty>, &'static str),
    Array(Box<Ty>, String),
    Function {
        result: Box<Ty>,
        parameters: Vec<Ty>,
    },
}

fn render(ty: &Ty) -> String {
    match ty {
        Ty::Leaf(text) => text.clone(),
        Ty::Qualified(inner, qualifier) => format!("{} {qualifier}", render(inner)),
        Ty::Ptr(inner) => declarator(inner, "*"),
        Ty::Ref(inner) => declarator(inner, "&"),
        Ty::RvalueRef(inner) => declarator(inner, "&&"),
        Ty::Array(inner, count) => format!("{} [{count}]", render(inner)),
        Ty::Function { result, parameters } => {
            format!("{} ({})", render(result), parameter_list(parameters))
        }
    }
}

/// Renders a pointer or reference. A declarator binding tighter than the type
/// it points at needs parentheses, which is the whole reason types are a tree:
/// `PFvvE` is `void (*)()` and `PA3_i` is `int (*) [3]`.
fn declarator(inner: &Ty, operator: &str) -> String {
    match inner {
        Ty::Function { result, parameters } => format!(
            "{} ({operator})({})",
            render(result),
            parameter_list(parameters)
        ),
        Ty::Array(element, count) => {
            format!("{} ({operator}) [{count}]", render(element))
        }
        _ => format!("{}{operator}", render(inner)),
    }
}

fn parameter_list(parameters: &[Ty]) -> String {
    parameters.iter().map(render).collect::<Vec<_>>().join(", ")
}

/// One mangled name, consumed left to right with the ABI's substitution table.
struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    /// Substitution candidates in order of first appearance (`S_`, `S0_`, ...).
    /// Builtin types and substitutions themselves are never candidates
    /// (Itanium C++ ABI 5.1.5.1).
    substitutions: Vec<Ty>,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self { bytes: text.as_bytes(), at: 0, substitutions: Vec::new() }
    }

    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.at += 1;
            return true;
        }
        false
    }

    fn remember(&mut self, ty: &Ty) {
        if !self.substitutions.contains(ty) {
            self.substitutions.push(ty.clone());
        }
    }

    /// `<type>`, with every candidate it produces recorded.
    fn ty(&mut self) -> Option<Ty> {
        let ty = match self.peek()? {
            b'P' => {
                self.at += 1;
                Ty::Ptr(Box::new(self.ty()?))
            }
            b'R' => {
                self.at += 1;
                Ty::Ref(Box::new(self.ty()?))
            }
            b'O' => {
                self.at += 1;
                Ty::RvalueRef(Box::new(self.ty()?))
            }
            b'K' | b'V' | b'r' => {
                let qualifier = match self.bytes[self.at] {
                    b'K' => "const",
                    b'V' => "volatile",
                    _ => "restrict",
                };
                self.at += 1;
                Ty::Qualified(Box::new(self.ty()?), qualifier)
            }
            b'A' => {
                self.at += 1;
                let count = self.digits();
                if !self.eat(b'_') {
                    return None;
                }
                Ty::Array(Box::new(self.ty()?), count)
            }
            b'F' => {
                self.at += 1;
                let result = self.ty()?;
                let mut parameters = Vec::new();
                loop {
                    match self.peek()? {
                        b'E' => {
                            self.at += 1;
                            break;
                        }
                        // A lone `v` is the empty parameter list.
                        b'v' if parameters.is_empty() => {
                            self.at += 1;
                        }
                        _ => parameters.push(self.ty()?),
                    }
                }
                Ty::Function { result: Box::new(result), parameters }
            }
            b'S' => {
                // A substitution is not itself a candidate, and a standard one
                // (`St`, `Sa`, ...) may still carry template arguments.
                let named = self.substitution()?;
                return self.maybe_template(named, false);
            }
            b'N' => {
                let nested = self.nested_name()?;
                return self.maybe_template(nested, false);
            }
            byte if byte.is_ascii_digit() => {
                let name = self.source_name()?;
                return self.maybe_template(Ty::Leaf(name), true);
            }
            _ => {
                let builtin = self.builtin()?;
                // Builtin types are never substitution candidates.
                return Some(builtin);
            }
        };
        self.remember(&ty);
        Some(ty)
    }

    /// `<template-args>` applied to a name, when they follow it. `candidate`
    /// records the bare name itself, which an unscoped template name is
    /// (a nested name's prefixes are recorded while they are parsed).
    fn maybe_template(&mut self, base: Ty, candidate: bool) -> Option<Ty> {
        if candidate {
            self.remember(&base);
        }
        if self.peek() != Some(b'I') {
            return Some(base);
        }
        let arguments = self.template_arguments()?;
        let applied = Ty::Leaf(format!("{}<{}>", render(&base), arguments));
        self.remember(&applied);
        Some(applied)
    }

    /// `I <template-arg>+ E`, rendered as the ABI's own text: a trailing `>`
    /// keeps a space so `>>` never closes two levels at once.
    fn template_arguments(&mut self) -> Option<String> {
        if !self.eat(b'I') {
            return None;
        }
        let mut rendered: Vec<String> = Vec::new();
        loop {
            match self.peek()? {
                b'E' => {
                    self.at += 1;
                    break;
                }
                b'L' => {
                    self.at += 1;
                    rendered.push(self.literal()?);
                }
                _ => rendered.push(render(&self.ty()?)),
            }
        }
        if rendered.is_empty() {
            return None;
        }
        let mut text = rendered.join(", ");
        if text.ends_with('>') {
            text.push(' ');
        }
        Some(text)
    }

    /// `L <type> <value> E`: an integer or boolean template argument. Anything
    /// else -- an address, an expression -- is refused.
    fn literal(&mut self) -> Option<String> {
        let ty = self.builtin()?;
        let boolean = ty == Ty::Leaf("bool".to_string());
        let negative = self.eat(b'n');
        let digits = self.digits();
        if digits.is_empty() || !self.eat(b'E') {
            return None;
        }
        if boolean {
            return match digits.as_str() {
                "0" => Some("false".to_string()),
                "1" => Some("true".to_string()),
                _ => None,
            };
        }
        Some(if negative { format!("-{digits}") } else { digits })
    }

    /// `N [<CV-qualifiers>] <prefix> <unqualified-name> E`. Every prefix is a
    /// substitution candidate, in order (`foo`, then `foo::bar`).
    fn nested_name(&mut self) -> Option<Ty> {
        if !self.eat(b'N') {
            return None;
        }
        // A CV-qualified nested name belongs to a member function, which this
        // module does not demangle.
        if matches!(self.peek()?, b'K' | b'V' | b'r' | b'R' | b'O') {
            return None;
        }
        let mut path: Option<Ty> = None;
        loop {
            match self.peek()? {
                b'E' => {
                    self.at += 1;
                    break;
                }
                b'I' => {
                    let base = path.take()?;
                    let arguments = self.template_arguments()?;
                    let applied = Ty::Leaf(format!("{}<{}>", render(&base), arguments));
                    self.remember(&applied);
                    path = Some(applied);
                }
                b'S' => {
                    if path.is_some() {
                        return None;
                    }
                    path = Some(self.substitution()?);
                }
                byte if byte.is_ascii_digit() => {
                    let component = self.source_name()?;
                    let joined = match &path {
                        Some(head) => Ty::Leaf(format!("{}::{component}", render(head))),
                        None => Ty::Leaf(component),
                    };
                    self.remember(&joined);
                    path = Some(joined);
                }
                _ => return None,
            }
        }
        path
    }

    /// `S <seq-id>? _`, or one of the standard substitutions the ABI predefines.
    fn substitution(&mut self) -> Option<Ty> {
        if !self.eat(b'S') {
            return None;
        }
        let standard = match self.peek()? {
            b't' => Some("std"),
            b'a' => Some("std::allocator"),
            b'b' => Some("std::basic_string"),
            b's' => Some(
                "std::basic_string<char, std::char_traits<char>, std::allocator<char> >",
            ),
            b'i' => Some("std::basic_istream<char, std::char_traits<char> >"),
            b'o' => Some("std::basic_ostream<char, std::char_traits<char> >"),
            b'd' => Some("std::basic_iostream<char, std::char_traits<char> >"),
            _ => None,
        };
        if let Some(text) = standard {
            self.at += 1;
            // `St` is the namespace itself: a name follows it.
            if text == "std" {
                let component = match self.peek()? {
                    byte if byte.is_ascii_digit() => self.source_name()?,
                    _ => return None,
                };
                let joined = Ty::Leaf(format!("std::{component}"));
                self.remember(&joined);
                return Some(joined);
            }
            return Some(Ty::Leaf(text.to_string()));
        }
        // `S_` is the first candidate, `S0_` the second: the sequence id is
        // base 36 and one less than the index (Itanium C++ ABI 5.1.5.1).
        let mut sequence: Option<usize> = None;
        while let Some(byte) = self.peek() {
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'A'..=b'Z' => u32::from(byte - b'A') + 10,
                _ => break,
            };
            sequence = Some(sequence.unwrap_or(0) * 36 + digit as usize);
            self.at += 1;
        }
        if !self.eat(b'_') {
            return None;
        }
        let index = match sequence {
            None => 0,
            Some(value) => value + 1,
        };
        self.substitutions.get(index).cloned()
    }

    /// `<source-name> ::= <number> <identifier>`.
    fn source_name(&mut self) -> Option<String> {
        let digits = self.digits();
        let length: usize = digits.parse().ok()?;
        if length == 0 {
            return None;
        }
        let end = self.at.checked_add(length)?;
        let bytes = self.bytes.get(self.at..end)?;
        self.at = end;
        std::str::from_utf8(bytes).ok().map(str::to_string)
    }

    fn digits(&mut self) -> String {
        let start = self.at;
        while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
            self.at += 1;
        }
        String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned()
    }

    /// `<builtin-type>`, the ABI's own table (5.1.5.1).
    fn builtin(&mut self) -> Option<Ty> {
        let (text, width) = match self.bytes.get(self.at..)? {
            [b'D', b'n', ..] => ("decltype(nullptr)", 2),
            [b'D', b'i', ..] => ("char32_t", 2),
            [b'D', b's', ..] => ("char16_t", 2),
            [b'D', b'u', ..] => ("char8_t", 2),
            [b'D', b'a', ..] => ("auto", 2),
            [b'D', b'c', ..] => ("decltype(auto)", 2),
            [b'D', b'h', ..] => ("half", 2),
            [byte, ..] => (
                match byte {
                    b'v' => "void",
                    b'w' => "wchar_t",
                    b'b' => "bool",
                    b'c' => "char",
                    b'a' => "signed char",
                    b'h' => "unsigned char",
                    b's' => "short",
                    b't' => "unsigned short",
                    b'i' => "int",
                    b'j' => "unsigned int",
                    b'l' => "long",
                    b'm' => "unsigned long",
                    b'x' => "long long",
                    b'y' => "unsigned long long",
                    b'n' => "__int128",
                    b'o' => "unsigned __int128",
                    b'f' => "float",
                    b'd' => "double",
                    b'e' => "long double",
                    b'g' => "__float128",
                    b'z' => "...",
                    _ => return None,
                },
                1,
            ),
            [] => return None,
        };
        self.at += width;
        Some(Ty::Leaf(text.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(mangled: &str) -> Option<String> {
        demangle(mangled).map(|demangled| demangled.text)
    }

    /// Every expectation here is the GNU demangler's own output for the same
    /// name, which is the demangler stock runs.
    #[test]
    fn renders_the_names_the_abi_defines_for_data() {
        for (mangled, expected) in [
            ("_ZTIi", "typeinfo for int"),
            ("_ZTSi", "typeinfo name for int"),
            ("_ZTVi", "vtable for int"),
            ("_ZTTi", "VTT for int"),
            ("_ZTIv", "typeinfo for void"),
            ("_ZTIb", "typeinfo for bool"),
            ("_ZTIm", "typeinfo for unsigned long"),
            ("_ZTIe", "typeinfo for long double"),
            ("_ZTIDi", "typeinfo for char32_t"),
            ("_ZTIDn", "typeinfo for decltype(nullptr)"),
            ("_ZTIz", "typeinfo for ..."),
            ("_ZTIPi", "typeinfo for int*"),
            ("_ZTIRi", "typeinfo for int&"),
            ("_ZTIOi", "typeinfo for int&&"),
            ("_ZTIKc", "typeinfo for char const"),
            ("_ZTIPKc", "typeinfo for char const*"),
            ("_ZTIPKPi", "typeinfo for int* const*"),
            ("_ZTIA3_i", "typeinfo for int [3]"),
            ("_ZTIA0_i", "typeinfo for int [0]"),
            ("_ZTIPA3_i", "typeinfo for int (*) [3]"),
            ("_ZTIFivE", "typeinfo for int ()"),
            ("_ZTIPFvvE", "typeinfo for void (*)()"),
            ("_ZTSPi", "typeinfo name for int*"),
        ] {
            assert_eq!(text(mangled).as_deref(), Some(expected), "{mangled}");
        }
    }

    #[test]
    fn renders_class_names_through_the_substitution_table() {
        for (mangled, expected) in [
            ("_ZTIN3foo3barE", "typeinfo for foo::bar"),
            ("_ZTIN3foo3bar3bazE", "typeinfo for foo::bar::baz"),
            ("_ZTSN3foo3barE", "typeinfo name for foo::bar"),
            ("_ZTIN3fooIiE3barE", "typeinfo for foo<int>::bar"),
            ("_ZTIN3foo3barIiEE", "typeinfo for foo::bar<int>"),
            // `S_` is `foo`, `S0_` is `foo::bar`: every prefix is a candidate.
            ("_ZTIN3foo3barIS0_EE", "typeinfo for foo::bar<foo::bar>"),
            ("_ZTISt9exception", "typeinfo for std::exception"),
            ("_ZTVSt9bad_alloc", "vtable for std::bad_alloc"),
            (
                "_ZTIN10__cxxabiv117__class_type_infoE",
                "typeinfo for __cxxabiv1::__class_type_info",
            ),
            (
                "_ZTVN10__cxxabiv120__si_class_type_infoE",
                "vtable for __cxxabiv1::__si_class_type_info",
            ),
            (
                "_ZTISt6vectorIiSaIiEE",
                "typeinfo for std::vector<int, std::allocator<int> >",
            ),
            (
                "_ZTISt13basic_ostreamIcSt11char_traitsIcEE",
                "typeinfo for std::basic_ostream<char, std::char_traits<char> >",
            ),
            (
                "_ZTISs",
                "typeinfo for std::basic_string<char, std::char_traits<char>, \
                 std::allocator<char> >",
            ),
            (
                "_ZTISt6vectorIS_IiSaIiEESaIS_IiSaIiEEEE",
                "typeinfo for std::vector<std::vector<int, std::allocator<int> >, \
                 std::allocator<std::vector<int, std::allocator<int> > > >",
            ),
        ] {
            assert_eq!(text(mangled).as_deref(), Some(expected), "{mangled}");
        }
    }

    #[test]
    fn carries_the_namespace_the_name_is_applied_in() {
        // `AddressTableHandler` (:1877-1913) makes the type the namespace and
        // the prefix the name, so `_ZTIi` is `typeinfo` in `int`.
        let demangled = demangle("_ZTIi").unwrap();
        assert_eq!((demangled.name.as_str(), demangled.namespace.as_str()), ("typeinfo", "int"));
        let nested = demangle("_ZTVN10__cxxabiv117__class_type_infoE").unwrap();
        assert_eq!(
            (nested.name.as_str(), nested.namespace.as_str()),
            ("vtable", "__cxxabiv1::__class_type_info")
        );
    }

    #[test]
    fn names_the_symbol_ghidra_applies() {
        assert_eq!(demangle("_ZTIi").unwrap().name, "typeinfo");
        assert_eq!(demangle("_ZTSi").unwrap().name, "typeinfo-name");
        assert_eq!(demangle("_ZTVSt9bad_alloc").unwrap().name, "vtable");
        assert_eq!(demangle("_ZTTN3foo3barE").unwrap().name, "VTT");
    }

    #[test]
    fn refuses_what_it_cannot_prove() {
        for mangled in [
            // A function encoding: a name, then its parameters.
            "_ZN3Foo3barEi",
            "_Z3fooi",
            // Construction vtables carry an offset this module does not read.
            "_ZTCN3FooE0_N3BarE",
            // Thunks.
            "_ZTv0_n24_N3Foo3barEv",
            // Not a mangled name at all.
            "printf",
            "_ZTIi_extra",
            // A substitution with nothing to substitute.
            "_ZTIS_",
            // Truncated.
            "_ZTI",
            "_ZTIN3foo",
            "_ZTIA3i",
            // An expression as a template argument.
            "_ZTIN3fooIXadL_Z1xEEEE",
        ] {
            assert!(demangle(mangled).is_none(), "{mangled} should be refused");
        }
    }
}
