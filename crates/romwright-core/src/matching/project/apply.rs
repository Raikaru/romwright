//! Stage complete files before publication; never overwrite a concurrent edit
//! during rollback. Retain the journal and old inodes if recovery is ambiguous.
use super::super::{MatchWork, invalid};
use crate::{Core, Result, artifact::Artifact, exec::ExecutionRequest};
use romwright_model::matching::{PatchFile, ProjectPatch};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

fn state(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.is_file() => Ok(Some(crate::sha256::hex(
            crate::sha256::digest_reader(File::open(path)?)?,
        ))),
        Ok(_) => Err(invalid(format!(
            "patch path is no longer a regular file: {}",
            path.display()
        ))),
    }
}

struct StagedFile {
    spec: PatchFile,
    destination: PathBuf,
    replacement: PathBuf,
    backup: PathBuf,
    moved: bool,
    installed: bool,
}

pub(super) struct StagedPatch {
    work: Option<MatchWork>,
    files: Vec<StagedFile>,
    directories: Vec<PathBuf>,
    finished: bool,
}

impl StagedPatch {
    pub fn prepare(
        core: &Core,
        request: &ExecutionRequest,
        root: &Path,
        patch: &ProjectPatch,
    ) -> Result<Self> {
        let work = MatchWork::create(root)?;
        let mut files = Vec::new();
        for (index, spec) in patch.files.iter().enumerate() {
            request.cancel.checkpoint(request.deadline)?;
            let destination = super::source_path(root, &spec.path)?;
            if state(&destination)? != spec.before_digest {
                return Err(invalid("project source changed after patch review"));
            }
            let artifact = Artifact::open(core.db_path(), &spec.after_digest)?;
            let replacement = work.0.join(format!("{index}.new"));
            let mut file = File::create(&replacement)?;
            file.write_all(&artifact.bytes)?;
            if spec.before_digest.is_some() {
                file.set_permissions(fs::metadata(&destination)?.permissions())?;
            }
            file.sync_all()?;
            files.push(StagedFile {
                spec: spec.clone(),
                destination,
                replacement,
                backup: work.0.join(format!("{index}.old")),
                moved: false,
                installed: false,
            });
        }
        let mut journal = File::create(work.0.join("patch.json"))?;
        journal.write_all(
            &serde_json::to_vec_pretty(patch).map_err(|error| invalid(error.to_string()))?,
        )?;
        journal.sync_all()?;
        Ok(Self {
            work: Some(work),
            files,
            directories: Vec::new(),
            finished: false,
        })
    }

    fn install(&mut self) -> Result<()> {
        for file in &mut self.files {
            if state(&file.destination)? != file.spec.before_digest {
                return Err(invalid("concurrent project source edit; patch not applied"));
            }
            let mut missing = Vec::new();
            let mut parent = file
                .destination
                .parent()
                .ok_or_else(|| invalid("patch path has no parent"))?;
            while !parent.exists() {
                missing.push(parent.to_path_buf());
                parent = parent
                    .parent()
                    .ok_or_else(|| invalid("patch parent disappeared"))?;
            }
            for directory in missing.into_iter().rev() {
                match fs::create_dir(&directory) {
                    Ok(()) => self.directories.push(directory),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if file.spec.before_digest.is_some() {
                fs::rename(&file.destination, &file.backup)?;
                file.moved = true;
                if state(&file.backup)? != file.spec.before_digest {
                    return Err(invalid(
                        "concurrent source replacement caught during patch publication",
                    ));
                }
            }
            // Publishing a complete staged inode with link() refuses an
            // existing destination. Unlike rename-overwrite, it cannot erase
            // an editor's replacement created after the preceding check.
            fs::hard_link(&file.replacement, &file.destination)?;
            file.installed = true;
        }
        for file in &self.files {
            if state(&file.destination)?.as_ref() != Some(&file.spec.after_digest) {
                return Err(invalid("project source changed during patch publication"));
            }
        }
        Ok(())
    }

    fn rollback(&mut self) -> Option<PathBuf> {
        let mut complete = true;
        for file in self.files.iter_mut().rev() {
            if file.installed {
                match state(&file.destination) {
                    Ok(Some(digest)) if digest == file.spec.after_digest => {
                        if fs::remove_file(&file.destination).is_err() {
                            complete = false;
                            continue;
                        }
                    }
                    Ok(None) => {}
                    Ok(value) if value == file.spec.before_digest => {}
                    _ => {
                        complete = false;
                        continue;
                    }
                }
            }
            if file.moved {
                match fs::symlink_metadata(&file.destination) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if fs::hard_link(&file.backup, &file.destination).is_err() {
                            complete = false;
                        }
                    }
                    Ok(_)
                        if matches!((state(&file.destination), state(&file.backup)),
                        (Ok(Some(current)), Ok(Some(backup))) if current == backup) => {}
                    _ => complete = false,
                }
            }
        }
        for directory in self.directories.iter().rev() {
            let _ = fs::remove_dir(directory);
        }
        self.finished = true;
        if complete {
            None
        } else {
            let work = self.work.take().expect("unfinished patch owns its journal");
            let path = work.0.clone();
            // Keep backups rather than deleting somebody's concurrent edit.
            std::mem::forget(work);
            Some(path)
        }
    }

    /// Called inside the request's publication lock. The short filesystem
    /// commit and database transaction finish together or attempt rollback.
    pub fn commit<T>(mut self, publish: impl FnOnce() -> Result<T>) -> Result<T> {
        match self.install().and_then(|()| publish()) {
            Ok(value) => {
                self.finished = true;
                Ok(value)
            }
            Err(error) => {
                if let Some(path) = self.rollback() {
                    Err(invalid(format!(
                        "{error}; rollback preserved concurrent edits; recovery journal and backups: {}",
                        path.display()
                    )))
                } else {
                    Err(error)
                }
            }
        }
    }
}

impl Drop for StagedPatch {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.rollback();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(root: &Path) -> StagedPatch {
        fs::write(root.join("unit.c"), b"original source").unwrap();
        let work = MatchWork::create(root).unwrap();
        let mut files = Vec::new();
        for (index, name) in ["unit.c", "include/new.h"].into_iter().enumerate() {
            let destination = root.join(name);
            let replacement = work.0.join(format!("{index}.new"));
            fs::write(&replacement, b"candidate source").unwrap();
            files.push(StagedFile {
                spec: PatchFile {
                    path: name.into(),
                    before_digest: state(&destination).unwrap(),
                    after_digest: state(&replacement).unwrap().unwrap(),
                },
                destination,
                replacement,
                backup: work.0.join(format!("{index}.old")),
                moved: false,
                installed: false,
            });
        }
        fs::write(work.0.join("patch.json"), b"recovery journal").unwrap();
        StagedPatch {
            work: Some(work),
            files,
            directories: Vec::new(),
            finished: false,
        }
    }

    #[test]
    fn failed_publication_restores_sources_and_removes_new_headers() {
        let root = MatchWork::create(&std::env::temp_dir()).unwrap();
        let staged = stage(&root.0);
        let result = staged.commit::<()>(|| {
            assert_eq!(
                fs::read(root.0.join("unit.c")).unwrap(),
                b"candidate source"
            );
            assert_eq!(
                fs::read(root.0.join("include/new.h")).unwrap(),
                b"candidate source"
            );
            Err(invalid("database publication failed"))
        });
        assert!(result.is_err());
        assert_eq!(fs::read(root.0.join("unit.c")).unwrap(), b"original source");
        assert!(!root.0.join("include").exists());
    }

    #[test]
    fn rollback_preserves_concurrent_edits_and_recovery_preimages() {
        let root = MatchWork::create(&std::env::temp_dir()).unwrap();
        let staged = stage(&root.0);
        let recovery = staged.work.as_ref().unwrap().0.clone();
        let result = staged.commit::<()>(|| {
            fs::write(root.0.join("unit.c"), b"concurrent user edit")?;
            Err(invalid("database publication failed"))
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(root.0.join("unit.c")).unwrap(),
            b"concurrent user edit"
        );
        assert_eq!(
            fs::read(recovery.join("0.old")).unwrap(),
            b"original source"
        );
        assert!(recovery.join("patch.json").is_file());
        assert!(!root.0.join("include").exists());
    }
}
