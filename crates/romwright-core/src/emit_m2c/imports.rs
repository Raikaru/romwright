//! Calls through the import table of a 32-bit Windows program.
//!
//! The decompiler prints `call [slot]` as a call through a pointer to Ghidra's function type, `(*(code *)PTR_<import>_<slot>)(...)`,
//! and a function type with an empty parameter list is `__cdecl` to the compiler: the caller pops the arguments the Win32 API
//! function already popped, and the compiled call is longer than the original (`add esp, N` after every API call). The imports
//! of every library but the C runtime are `__stdcall` (see `native::stdcall_import_slots`), so those casts name a `__stdcall`
//! function type (`ROMWRIGHT_EXPORT_STDCALL_IMPORTS=off` leaves them `__cdecl`).
use super::{conform, globals::GlobalRef};
use std::collections::BTreeSet;

pub(crate) fn stdcall_imports_enabled() -> bool {
    super::locals::enabled("ROMWRIGHT_EXPORT_STDCALL_IMPORTS")
}

const STDCALL_TYPE: &str = "romwright_stdcall_code";
const STDCALL_TYPEDEF: &str = "typedef int __stdcall romwright_stdcall_code();\n";
const BOTH_TYPEDEFS: &str = "typedef int romwright_code();\ntypedef int __stdcall romwright_stdcall_code();\n";

/// The body with every call through an import slot of `slots` cast to the `__stdcall` function type, and the typedef lines the
/// output needs (`uses_code`: the plain function type is already in use).
pub(super) fn stdcall_calls(body: String, globals: &[GlobalRef], slots: &BTreeSet<u64>, uses_code: bool) -> (String, &'static str) {
    let typedef = |stdcall: bool| match (uses_code, stdcall) {
        (true, true) => BOTH_TYPEDEFS,
        (true, false) => conform::CODE_TYPEDEF,
        (false, true) => STDCALL_TYPEDEF,
        (false, false) => "",
    };
    let mut body = body;
    let mut changed = false;
    for global in globals.iter().filter(|global| global.address.is_some_and(|address| slots.contains(&address))) {
        let call = format!("(*({} *){})(", conform::CODE_TYPE, global.name);
        if body.contains(&call) {
            body = body.replace(&call, &format!("(*({STDCALL_TYPE} *){})(", global.name));
            changed = true;
        }
    }
    (body, typedef(changed))
}
