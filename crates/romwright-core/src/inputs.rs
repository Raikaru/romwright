//! The same immutable loader inputs serve memory, demand analysis and workers.
use crate::{Core, Result, artifact::Artifact, native, session::RuntimeConfig};
use romwright_model::ProgramInput;
use std::path::Path;

/// Captures the complete loader recipe before any analysis can observe it.
pub(crate) fn capture(
    project: &Path,
    source: &Path,
    bytes: std::sync::Arc<[u8]>,
    map: Option<std::sync::Arc<[u8]>>,
    raw: Option<(u64, &str)>,
    keys: &native::keys::KeyStore,
) -> Result<(Artifact, ProgramInput)> {
    let binary = Artifact::from_bytes(project, bytes)?;
    let map = map
        .map(|bytes| Artifact::from_bytes(project, bytes))
        .transpose()?;
    let keys = if keys.is_empty() {
        None
    } else {
        let bytes = serde_json::to_vec(keys)
            .map_err(|error| native::ImportError::Bad(error.to_string()))?;
        Some(Artifact::from_bytes(project, bytes.into())?)
    };
    let input = ProgramInput {
        source_path: source.canonicalize()?.to_string_lossy().into_owned(),
        binary_digest: binary.digest.clone(),
        image_selector: String::new(),
        map_digest: map.map(|artifact| artifact.digest),
        raw: raw.map(|(base, language)| (base, language.to_string())),
        keys_digest: keys.map(|artifact| artifact.digest),
    };
    Ok((binary, input))
}

fn keys(project: &Path, input: &ProgramInput) -> Result<native::keys::KeyStore> {
    match &input.keys_digest {
        None => Ok(native::keys::KeyStore::empty()),
        Some(digest) => {
            let artifact = Artifact::open(project, digest)?;
            serde_json::from_slice(&artifact.bytes)
                .map_err(|error| native::ImportError::Bad(error.to_string()).into())
        }
    }
}

fn select(
    images: Vec<(String, native::NativeImport)>,
    selector: &str,
) -> Result<native::NativeImport> {
    let mut selected = images.into_iter().filter(|(name, _)| name == selector);
    match (selected.next(), selected.next()) {
        (Some((_, image)), None) => Ok(image),
        _ => Err(native::ImportError::Bad(format!(
            "container does not contain exactly one image {selector:?}"
        ))
        .into()),
    }
}

pub fn parse(project: &Path, input: &ProgramInput) -> Result<(Artifact, native::NativeImport)> {
    let artifact = Artifact::open(project, &input.binary_digest)?;
    let keys = keys(project, input)?;
    let raw = input
        .raw
        .as_ref()
        .map(|(base, language)| (*base, language.as_str()));
    let image = select(
        native::parse_image_input(&artifact.bytes, raw, &keys)?,
        &input.image_selector,
    )?;
    Ok((artifact, image))
}

pub(crate) fn load(
    project: &Path,
    input: &ProgramInput,
    config: &RuntimeConfig,
) -> Result<native::NativeImport> {
    let artifact = Artifact::open(project, &input.binary_digest)?;
    let map = input
        .map_digest
        .as_ref()
        .map(|digest| Artifact::open(project, digest))
        .transpose()?;
    let keys = keys(project, input)?;
    let raw = input
        .raw
        .as_ref()
        .map(|(base, language)| (*base, language.as_str()));
    select(
        native::load_container_with(
            &artifact.path,
            &artifact.bytes,
            false,
            map.as_ref().map(|artifact| artifact.path.as_path()),
            raw,
            &keys,
            config,
        )?,
        &input.image_selector,
    )
}

impl Core {
    pub fn program_input(&self, program: &str) -> Result<ProgramInput> {
        Ok(self.db.program_input(self.db.program_id(program)?)?)
    }

    /// A path identifies the imported source; its current contents are not
    /// silently substituted for the bytes that produced the stored facts.
    /// A path mismatch is not a substitution when the bytes are identical:
    /// an import-cache restore replays the first import's `source_path`
    /// verbatim, so same bytes under a new path (or name) must still
    /// resolve. Identity is content, checked lazily only after both path
    /// comparisons fail.
    pub(crate) fn resolve_program_input(
        &self,
        binary: &Path,
        program: &str,
    ) -> Result<ProgramInput> {
        let input = self.program_input(program)?;
        let absolute = if binary.is_absolute() {
            binary.to_path_buf()
        } else {
            std::env::current_dir()?.join(binary)
        };
        let canonical = binary.canonicalize().unwrap_or(absolute);
        let stored = self.db_path().join("artifacts").join(&input.binary_digest);
        if canonical != Path::new(&input.source_path)
            && canonical != stored.canonicalize().unwrap_or(stored)
            && super::import_cache::digest(binary).as_deref() != Some(input.binary_digest.as_str())
        {
            return Err(native::ImportError::Bad(
                "binary does not identify this program's imported source".into(),
            )
            .into());
        }
        Ok(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_processors_use_the_stored_image_selector() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let project =
            std::env::temp_dir().join(format!("romwright-image-{}-{stamp}", std::process::id()));
        let mut bytes = vec![0u8; 0x4400];
        for (descriptor, file) in [(0x20, 0x4000u32), (0x30, 0x4100u32)] {
            for (index, word) in [file, 0x0200_0020, 0x0200_0000, 0x100]
                .into_iter()
                .enumerate()
            {
                bytes[descriptor + index * 4..descriptor + index * 4 + 4]
                    .copy_from_slice(&word.to_le_bytes());
            }
        }
        bytes[0x4000] = 0xa9;
        bytes[0x4100] = 0xa7;
        let artifact = Artifact::from_bytes(&project, bytes.into()).unwrap();
        let mut input = ProgramInput {
            source_path: "renamed-or-removed-source".into(),
            binary_digest: artifact.digest,
            image_selector: "arm9".into(),
            map_digest: None,
            raw: None,
            keys_digest: None,
        };
        let arm9 = crate::session::ProgramImage::open_input(&project, &input).unwrap();
        input.image_selector = "arm7".into();
        let arm7 = crate::session::ProgramImage::open_input(&project, &input).unwrap();
        assert_eq!(arm9.read(0x0200_0000, 1).unwrap(), [0xa9]);
        assert_eq!(arm7.read(0x0200_0000, 1).unwrap(), [0xa7]);
        input.image_selector = "missing".into();
        assert!(crate::session::ProgramImage::open_input(&project, &input).is_err());
        std::fs::remove_dir_all(project).unwrap();
    }
}
