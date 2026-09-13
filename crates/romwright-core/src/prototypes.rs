//! Inferred prototypes use the existing declaration store, not a second fact store.
use crate::{Core, CoreError, Result};
use romwright_model::{Address, DecompType, FactKind, FactProvenance, FuncProto, PrototypeRow};
use std::fmt::{Display, Write};

impl Core {
    /// Persists one completed recovery round against its input revision.
    /// The database retains assertions and advances only for changed facts.
    pub fn persist_inferred_prototypes(
        &self,
        program: &str,
        revision: u64,
        recovered: &[(Address, FuncProto)],
    ) -> Result<Vec<Address>> {
        let id = self.db.program_id(program)?;
        let mut rows = Vec::with_capacity(recovered.len());
        for (address, prototype) in recovered {
            let mut signature = String::new();
            function_prefix(
                &prototype.return_type,
                &prototype.calling_convention,
                &mut signature,
            )?;
            // The parser needs an identifier. Names remain owned by the function
            // table: native inferred application never applies this transport name.
            signature.push_str("__romwright_inferred");
            parameters(prototype, &mut signature)?;
            suffix(&prototype.return_type, &mut signature)?;
            let mut return_type = String::new();
            declaration(&prototype.return_type, "", &mut return_type)?;
            return_type.truncate(return_type.trim_end().len());
            rows.push(PrototypeRow {
                function: address.clone(),
                signature,
                calling_convention: convention(&prototype.calling_convention).map(str::to_owned),
                return_type: Some(return_type),
                provenance: FactProvenance {
                    kind: FactKind::Inferred,
                    // A pass that supplied the parameters owns the fact; the
                    // default recovery keeps its own name.
                    source: prototype
                        .parameter_source
                        .clone()
                        .unwrap_or_else(|| "native-decompiler prototype recovery".into()),
                    confidence: None,
                },
            });
        }
        Ok(self.db.merge_inferred_prototypes(id, revision, &rows)?)
    }
}

fn convention(name: &str) -> Option<&str> {
    match name {
        "" | "unknown" => None,
        name => Some(name),
    }
}

fn target(ty: &DecompType) -> Result<&DecompType> {
    ty.target
        .as_deref()
        .ok_or_else(|| CoreError::InvalidPrototype("pointer or array has no target type".into()))
}

fn compound(ty: &DecompType) -> bool {
    ty.metatype.as_deref() == Some("array")
        || (ty.metatype.as_deref() == Some("code") && ty.prototype.is_some())
}

// A prefix/suffix traversal emits nested C declarators directly into one buffer.
// In particular, pointer-to-array and pointer-to-function require parentheses;
// array-of-pointer and function-returning-pointer do not.
fn declaration(ty: &DecompType, name: impl Display, out: &mut String) -> Result<()> {
    prefix(ty, out)?;
    write!(out, "{name}").expect("writing to String");
    suffix(ty, out)
}

fn function_prefix(ty: &DecompType, model: &str, out: &mut String) -> Result<()> {
    if let Some(model) = convention(model) {
        out.push_str(model);
        out.push(' ');
    }
    prefix(ty, out)
}

fn prefix(ty: &DecompType, out: &mut String) -> Result<()> {
    match ty.metatype.as_deref() {
        Some("ptr") => {
            let target = target(ty)?;
            prefix(target, out)?;
            if compound(target) {
                out.push('(');
            }
            out.push('*');
        }
        Some("array") => prefix(target(ty)?, out)?,
        Some("code") if ty.prototype.is_some() => {
            let proto = ty.prototype.as_ref().expect("prototype checked");
            function_prefix(&proto.return_type, &proto.calling_convention, out)?;
        }
        _ => {
            let name = ty
                .name
                .as_deref()
                .filter(|name| !name.is_empty())
                .or_else(|| (ty.metatype.as_deref() == Some("void")).then_some("void"))
                .ok_or_else(|| CoreError::InvalidPrototype("unnamed atomic type".into()))?;
            out.push_str(name);
            out.push(' ');
        }
    }
    Ok(())
}

fn suffix(ty: &DecompType, out: &mut String) -> Result<()> {
    match ty.metatype.as_deref() {
        Some("ptr") => {
            let target = target(ty)?;
            if compound(target) {
                out.push(')');
            }
            suffix(target, out)?;
        }
        Some("array") => {
            let count = ty
                .element_count
                .ok_or_else(|| CoreError::InvalidPrototype("array has no element count".into()))?;
            write!(out, "[{count}]").expect("writing to String");
            suffix(target(ty)?, out)?;
        }
        Some("code") if ty.prototype.is_some() => {
            let proto = ty.prototype.as_ref().expect("prototype checked");
            parameters(proto, out)?;
            suffix(&proto.return_type, out)?;
        }
        _ => {}
    }
    Ok(())
}

fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'_' | b'a'..=b'z' | b'A'..=b'Z'))
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn parameters(proto: &FuncProto, out: &mut String) -> Result<()> {
    out.push('(');
    for (index, parameter) in proto.parameters.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        if identifier(&parameter.name) {
            declaration(&parameter.data_type, &parameter.name, out)?;
        } else {
            declaration(&parameter.data_type, format_args!("param_{index}"), out)?;
        }
    }
    if proto.variadic {
        if !proto.parameters.is_empty() {
            out.push_str(", ");
        }
        out.push_str("...");
    } else if proto.parameters.is_empty() {
        out.push_str("void");
    }
    out.push(')');
    Ok(())
}
