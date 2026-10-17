//! Local decomp.me multipart inputs. Target objects are retained verbatim;
//! linked disassembly is never presented as assembler-ready source.
use super::invalid;
use crate::{Core, Result, artifact::Artifact};
use object::{Object, ObjectSymbol};
use std::io::Read;
use std::path::Path;

/// Remote compiler selection is explicit; no platform-specific defaults apply.
pub struct ScratchExportOptions<'a> {
    pub compiler: &'a str,
    pub compiler_flags: &'a str,
    pub target_object: Option<&'a Path>,
    pub context: Option<&'a Path>,
}

// decomp.me's documented object-upload endpoint accepts at most 1000 KiB.
const MAX_TARGET_BYTES: usize = 1000 * 1024;

impl Core {
    fn scratch_target(&self, program: &str, symbol: &str, explicit: Option<&Path>) -> Result<(crate::artifact::SharedBytes, String)> {
        if let Some(path) = explicit {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?.take((MAX_TARGET_BYTES + 1) as u64).read_to_end(&mut bytes)?;
            if bytes.len() > MAX_TARGET_BYTES {
                return Err(invalid("decomp.me target objects must not exceed 1000 KiB"));
            }
            let digest = crate::import_cache::digest_bytes(&bytes);
            return Ok((bytes.into(), digest));
        }
        let mut selected = None;
        let mut after = 0;
        loop {
            let workspaces = self.matching_workspaces(program, after, 100)?;
            if workspaces.is_empty() { break; }
            for workspace in workspaces {
                after = workspace.id;
                if workspace.spec.symbol != symbol { continue; }
                if !workspace.spec.target.redistributable {
                    return Err(invalid("matching target is marked private; it cannot be included automatically in a scratch export"));
                }
                let digest = workspace.spec.target.digest;
                if selected.as_ref().is_some_and(|previous| previous != &digest) {
                    return Err(invalid("multiple reference objects match this function; select one with --target-object"));
                }
                selected = Some(digest);
            }
        }
        let digest = selected.ok_or_else(|| invalid("scratch export needs a relocation-bearing reference object: supply --target-object or a matching workspace with an exportable target"))?;
        let artifact = Artifact::open(self.db_path(), &digest)?;
        if artifact.bytes.len() > MAX_TARGET_BYTES {
            return Err(invalid("decomp.me target objects must not exceed 1000 KiB"));
        }
        Ok((artifact.bytes, digest))
    }

    /// Prepare local files only. Publishing is a separate, explicit user action.
    /// `scratch.json` contains scalar API fields; `target.o` is the multipart
    /// file field `target_obj`, not a JSON filename or fabricated assembly.
    pub fn export_scratch(
        &self,
        binary: &Path,
        program: &str,
        address: u64,
        outdir: &Path,
        options: &ScratchExportOptions<'_>,
    ) -> Result<serde_json::Value> {
        if options.compiler.trim().is_empty() {
            return Err(invalid("scratch export requires an explicit decomp.me compiler identifier"));
        }
        let function = self.functions(program)?.into_iter().find(|function| function.entry.offset == address)
            .ok_or_else(|| invalid(format!("no function at {address:#x}")))?;
        let (target, target_digest) = self.scratch_target(program, &function.name, options.target_object)?;
        let object = object::File::parse(target.as_ref()).map_err(|error| invalid(error.to_string()))?;
        if object.kind() != object::ObjectKind::Relocatable {
            return Err(invalid("scratch target must be an original relocatable object, not a linked image or raw binary"));
        }
        let supported = match object.format() {
            object::BinaryFormat::Elf => true,
            object::BinaryFormat::MachO => object.is_64() && object.is_little_endian(),
            object::BinaryFormat::Coff => matches!(object.architecture(), object::Architecture::I386 | object::Architecture::X86_64 | object::Architecture::PowerPc),
            _ => false,
        };
        if !supported {
            return Err(invalid("target object format is not supported by decomp.me's object-upload API"));
        }
        if !object.symbols().any(|symbol| symbol.is_definition() && symbol.kind() == object::SymbolKind::Text && symbol.name() == Ok(function.name.as_str())) {
            return Err(invalid(format!("target object has no defined function {}", function.name)));
        }
        let context = options.context.map(std::fs::read_to_string).transpose()?.unwrap_or_default();
        let unit = crate::native::linkmap::SplitExtent {
            tu: "source.c".into(), start: address,
            end: address.checked_add(1).ok_or_else(|| invalid("function address overflows"))?,
            name: String::new(), kind: "code".into(),
        };
        // A fresh directory prevents accidental replacement of earlier exports
        // or unrelated user files. export.json is written last on success.
        std::fs::create_dir(outdir)?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(outdir, std::fs::Permissions::from_mode(0o700))?;
        }
        let source_report = self.export_m2c(binary, program, outdir, Some(&[unit]), Some(address), &crate::emit_m2c::M2cOptions::default())?;
        let source = std::fs::read_to_string(outdir.join("source.c"))?;
        let fields = serde_json::json!({
            "name": function.name,
            "compiler": options.compiler,
            "compiler_flags": options.compiler_flags,
            "source_code": source,
            "context": context,
            "diff_label": function.name,
        });
        std::fs::write(outdir.join("target.o"), target.as_ref())?;
        std::fs::write(outdir.join("ctx.c"), context)?;
        std::fs::write(outdir.join("scratch.json"), serde_json::to_vec_pretty(&fields).map_err(|error| invalid(error.to_string()))?)?;
        let report = serde_json::json!({
            "encoding": "multipart/form-data",
            "fields": "scratch.json",
            "files": {"target_obj": "target.o"},
            "target_digest": target_digest,
            "target_bytes": target.len(),
            "target_relationship": "supplied reference object; correspondence to the linked input is not inferred",
            "source_compilation_verified": false,
            "source_export": source_report,
            "uploaded": false,
        });
        std::fs::write(outdir.join("export.json"), serde_json::to_vec_pretty(&report).map_err(|error| invalid(error.to_string()))?)?;
        Ok(report)
    }
}
