//! Owned byte snapshots and content-addressed backing files for child processes.
//! The caller's mutable path is read once; hashing, parsing and worker input all
//! refer to those captured bytes. Published files are never updated in place.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct Artifact {
    pub digest: String,
    pub bytes: Arc<[u8]>,
    pub path: PathBuf,
}

impl Artifact {
    pub fn capture(project: &Path, source: &Path) -> crate::Result<Self> {
        Self::from_bytes(project, std::fs::read(source)?.into())
    }

    pub fn open(project: &Path, digest: &str) -> crate::Result<Self> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid artifact digest",
            )
            .into());
        }
        let path = project.join("artifacts").join(digest);
        let bytes: Arc<[u8]> = std::fs::read(&path)?.into();
        if crate::import_cache::digest_bytes(&bytes) != digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact digest mismatch",
            )
            .into());
        }
        Ok(Self {
            digest: digest.into(),
            bytes,
            path: path.canonicalize()?,
        })
    }

    pub fn from_bytes(project: &Path, bytes: Arc<[u8]>) -> crate::Result<Self> {
        let digest = crate::import_cache::digest_bytes(&bytes);
        let root = project.join("artifacts");
        std::fs::create_dir_all(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = root.join(&digest);
        match std::fs::read(&path) {
            Ok(existing) => {
                if existing.as_slice() != bytes.as_ref() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("corrupt immutable artifact {}", path.display()),
                    )
                    .into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let staging = root.join(format!(
                    ".capture-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                let outcome = (|| -> std::io::Result<()> {
                    let mut options = std::fs::OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    let mut file = options.open(&staging)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    let mut permissions = file.metadata()?.permissions();
                    permissions.set_readonly(true);
                    file.set_permissions(permissions)?;
                    // Hard-link publication is atomic and never overwrites a
                    // snapshot another process has already published.
                    match std::fs::hard_link(&staging, &path) {
                        Ok(()) => Ok(()),
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                            if std::fs::read(&path)?.as_slice() == bytes.as_ref() {
                                Ok(())
                            } else {
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "artifact publication collision",
                                ))
                            }
                        }
                        Err(error) => Err(error),
                    }
                })();
                let _ = std::fs::remove_file(&staging);
                outcome?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            digest,
            bytes,
            path: path.canonicalize()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_replacement_cannot_change_a_captured_artifact() {
        let root = std::env::temp_dir().join(format!(
            "romwright-artifact-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("input");
        std::fs::write(&source, b"original").unwrap();
        let first = Artifact::capture(&root, &source).unwrap();
        std::fs::write(&source, b"new").unwrap();
        let second = Artifact::capture(&root, &source).unwrap();
        assert_eq!(&*first.bytes, b"original");
        assert_eq!(std::fs::read(&first.path).unwrap(), b"original");
        assert_ne!(first.digest, second.digest);
        assert_eq!(std::fs::read(&second.path).unwrap(), b"new");
        std::fs::remove_dir_all(root).unwrap();
    }
}
