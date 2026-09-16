//! Private filesystem snapshots, not a security sandbox for build commands.
use super::super::{MatchWork, invalid, resolve_path};
use crate::{
    Core, Result,
    exec::{ExecutionRequest, run_command},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Entry {
    pub kind: String,
    pub digest: String,
    pub size: u64,
    pub executable: bool,
}

pub(super) type Manifest = BTreeMap<String, Entry>;

pub(super) fn string(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| invalid("project paths must be UTF-8"))
}

fn git(request: &ExecutionRequest, root: &Path, arguments: &[&str]) -> Result<Output> {
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .args(arguments)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("LC_ALL", "C")
        .env("GIT_OPTIONAL_LOCKS", "0");
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
    run_command(&mut command, request, None, 16 * 1024 * 1024)
}

fn git_text(request: &ExecutionRequest, root: &Path, arguments: &[&str]) -> Result<String> {
    let output = git(request, root, arguments)?;
    if !output.status.success() {
        return Err(invalid(format!(
            "git snapshot preparation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout).map_err(|error| invalid(error.to_string()))
}

struct CheckedReader<'a> {
    file: File,
    copy: Option<File>,
    request: &'a ExecutionRequest,
}
impl Read for CheckedReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.request
            .cancel
            .checkpoint(self.request.deadline)
            .map_err(io::Error::other)?;
        let count = self.file.read(buffer)?;
        if let Some(copy) = &mut self.copy {
            copy.write_all(&buffer[..count])?;
        }
        Ok(count)
    }
}

pub(super) fn hash_file(path: &Path, request: &ExecutionRequest) -> Result<String> {
    let reader = CheckedReader {
        file: File::open(path)?,
        copy: None,
        request,
    };
    Ok(crate::sha256::hex(crate::sha256::digest_reader(reader)?))
}

fn executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn capture_file(
    source: &Path,
    destination: Option<&Path>,
    request: &ExecutionRequest,
) -> Result<Entry> {
    let file = File::open(source)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(invalid("snapshot input is not a regular file"));
    }
    let (copy, cloned) = if let Some(destination) = destination {
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| invalid("snapshot file has no parent"))?,
        )?;
        let output = File::create(destination)?;
        #[cfg(target_os = "linux")]
        let cloned = {
            use std::os::fd::AsRawFd;
            // Both descriptors are owned regular files. FICLONE creates private,
            // copy-on-write extents, never a mutable hard-link to the original.
            unsafe { libc::ioctl(output.as_raw_fd(), libc::FICLONE, file.as_raw_fd()) == 0 }
        };
        #[cfg(not(target_os = "linux"))]
        let cloned = false;
        if cloned {
            (None, true)
        } else {
            (Some(output), false)
        }
    } else {
        (None, false)
    };
    // Hash the actual private clone, not a potentially newer original inode.
    let file = if cloned {
        File::open(destination.unwrap())?
    } else {
        file
    };
    let mut reader = CheckedReader {
        file,
        copy,
        request,
    };
    let digest = crate::sha256::hex(crate::sha256::digest_reader(&mut reader)?);
    let after = fs::metadata(source)?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(invalid(format!(
            "project input changed while copying: {}",
            source.display()
        )));
    }
    if let Some(destination) = destination {
        let output = File::open(destination)?;
        output.set_permissions(before.permissions())?;
        output.set_times(fs::FileTimes::new().set_modified(before.modified()?))?;
    }
    Ok(Entry {
        kind: "file".into(),
        digest,
        size: before.len(),
        executable: executable(&before),
    })
}

fn protected(path: &Path, store: &Path) -> bool {
    path == store.join("artifacts")
        || path == store.join("project.sqlite")
        || path == store.join("project.sqlite-wal")
        || path == store.join("project.sqlite-shm")
        || path.file_name().is_some_and(|name| {
            name == ".git" || name == ".jj" || name.to_string_lossy().starts_with(".matching-")
        })
}

struct Collector<'a> {
    root: &'a Path,
    scope: &'a Path,
    destination: Option<&'a Path>,
    store: &'a Path,
    request: &'a ExecutionRequest,
    files: Manifest,
    bytes: u64,
}
impl Collector<'_> {
    fn collect(&mut self, path: &Path) -> Result<()> {
        self.request.cancel.checkpoint(self.request.deadline)?;
        let private_store = self.store != self.scope
            && self.store.starts_with(self.scope)
            && path.starts_with(self.store);
        if private_store
            || path
                .ancestors()
                .take_while(|ancestor| *ancestor != self.root)
                .any(|ancestor| protected(ancestor, self.store))
        {
            return Ok(());
        }
        let relative = path
            .strip_prefix(self.root)
            .map_err(|error| invalid(error.to_string()))?;
        let name = string(relative)?;
        if (std::path::MAIN_SEPARATOR != '\\' && name.contains('\\'))
            || name.contains(':')
            || name.chars().any(char::is_control)
        {
            return Err(invalid(
                "project snapshot paths must be unambiguous portable names",
            ));
        }
        let name = if std::path::MAIN_SEPARATOR == '\\' {
            name.replace('\\', "/")
        } else {
            name.to_owned()
        };
        if self.files.contains_key(&name) {
            return Ok(());
        }
        if self.files.len() >= 200_000 {
            return Err(invalid("project snapshot exceeds 200,000 entries"));
        }
        let metadata = fs::symlink_metadata(path)?;
        let destination = self.destination.map(|root| root.join(relative));
        let mut linked_target = None;
        let entry = if metadata.is_symlink() {
            let target = fs::read_link(path)?;
            let target = if target.is_absolute() {
                target
            } else {
                path.parent().unwrap().join(target)
            };
            let resolved = resolve_path(&target)?;
            let target = resolved.strip_prefix(self.root).map_err(|_| {
                invalid(format!(
                    "project symlink escapes the snapshot root: {}",
                    path.display()
                ))
            })?;
            if let Some(destination) = &destination {
                fs::create_dir_all(
                    destination
                        .parent()
                        .ok_or_else(|| invalid("symlink has no parent"))?,
                )?;
                let mut ancestor = relative.parent().unwrap_or(Path::new(""));
                let mut link = PathBuf::new();
                while !target.starts_with(ancestor) {
                    ancestor = ancestor.parent().unwrap_or(Path::new(""));
                    link.push("..");
                }
                link.push(
                    target
                        .strip_prefix(ancestor)
                        .map_err(|error| invalid(error.to_string()))?,
                );
                if link.as_os_str().is_empty() {
                    link.push(".");
                }
                let target = link;
                #[cfg(unix)]
                std::os::unix::fs::symlink(target, destination)?;
                #[cfg(windows)]
                {
                    if path.is_dir() {
                        std::os::windows::fs::symlink_dir(target, destination)?;
                    } else {
                        std::os::windows::fs::symlink_file(target, destination)?;
                    }
                }
            }
            let entry = Entry {
                kind: "symlink".into(),
                digest: string(target)?.replace('\\', "/"),
                size: 0,
                executable: false,
            };
            linked_target = Some(resolved);
            entry
        } else if metadata.is_dir() {
            if let Some(destination) = &destination {
                fs::create_dir_all(destination)?;
            }
            Entry {
                kind: "directory".into(),
                digest: String::new(),
                size: 0,
                executable: executable(&metadata),
            }
        } else if metadata.is_file() {
            self.bytes = self
                .bytes
                .checked_add(metadata.len())
                .ok_or_else(|| invalid("project size overflow"))?;
            if self.bytes > 32 * 1024 * 1024 * 1024 {
                return Err(invalid("project snapshot exceeds 32 GiB"));
            }
            capture_file(path, destination.as_deref(), self.request)?
        } else {
            return Err(invalid(format!(
                "project snapshot cannot copy a device, socket or FIFO: {}",
                path.display()
            )));
        };
        self.files.insert(name, entry);
        if metadata.is_dir() {
            let mut children = fs::read_dir(path)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<io::Result<Vec<_>>>()?;
            children.sort();
            for child in children {
                self.collect(&child)?;
            }
            if let Some(destination) = destination {
                File::open(destination)?
                    .set_times(fs::FileTimes::new().set_modified(metadata.modified()?))?;
            }
        }
        if let Some(target) = linked_target {
            // A build-root link can reach ignored inputs elsewhere in the
            // repository. Record the link first so directory cycles terminate.
            match fs::symlink_metadata(&target) {
                Ok(_) => self.collect(&target)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

pub(super) struct Snapshot {
    pub root: PathBuf,
    pub build_root: PathBuf,
    pub original_root: PathBuf,
    pub original_build_root: PathBuf,
    pub inputs: Manifest,
    store: PathBuf,
    vcs: bool,
    // Drop owns every copied byte, including local compiler and SDK files.
    pub work: MatchWork,
}

impl Snapshot {
    fn gather(&self, request: &ExecutionRequest, destination: Option<&Path>) -> Result<Manifest> {
        let mut collector = Collector {
            root: &self.original_root,
            scope: &self.original_build_root,
            destination,
            store: &self.store,
            request,
            files: BTreeMap::new(),
            bytes: 0,
        };
        collector.collect(&self.original_build_root)?;
        if self.vcs {
            let names = git_text(
                request,
                &self.original_root,
                &["ls-files", "--cached", "-z"],
            )?;
            for name in names.split('\0').filter(|name| !name.is_empty()) {
                let path = self.original_root.join(name);
                match fs::symlink_metadata(&path) {
                    Ok(_) => collector.collect(&path)?,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let head = git(
                request,
                &self.original_root,
                &["symbolic-ref", "-q", "HEAD"],
            )?;
            let head_arguments = if head.status.success() {
                vec!["symbolic-ref", "-q", "HEAD"]
            } else {
                vec!["rev-parse", "HEAD"]
            };
            for (name, arguments) in [
                ("\0vcs/head", head_arguments),
                (
                    "\0vcs/refs",
                    vec!["for-each-ref", "--format=%(refname) %(objectname)"],
                ),
            ] {
                let value = git_text(request, &self.original_root, &arguments)?;
                if let Some(destination) = destination {
                    if git_text(request, destination, &arguments)? != value {
                        return Err(invalid("Git identity changed during snapshot preparation"));
                    }
                }
                collector.files.insert(
                    name.into(),
                    Entry {
                        kind: "vcs".into(),
                        digest: crate::sha256::hex(crate::sha256::digest(value.as_bytes())),
                        size: 0,
                        executable: false,
                    },
                );
            }
            let index = git_text(
                request,
                &self.original_root,
                &["rev-parse", "--path-format=absolute", "--git-path", "index"],
            )?;
            let index = Path::new(index.trim());
            if index.is_file() {
                let output = destination.map(|root| root.join(".git/index"));
                collector.files.insert(
                    "\0vcs/index".into(),
                    capture_file(index, output.as_deref(), request)?,
                );
                if let Some(parent) = index.parent() {
                    for file in fs::read_dir(parent)? {
                        let file = file?;
                        if file
                            .file_name()
                            .to_string_lossy()
                            .starts_with("sharedindex.")
                        {
                            let output =
                                destination.map(|root| root.join(".git").join(file.file_name()));
                            collector.files.insert(
                                format!("\0vcs/{}", file.file_name().to_string_lossy()),
                                capture_file(&file.path(), output.as_deref(), request)?,
                            );
                        }
                    }
                }
            }
            let common = git_text(
                request,
                &self.original_root,
                &["rev-parse", "--path-format=absolute", "--git-common-dir"],
            )?;
            let worktree = git_text(
                request,
                &self.original_root,
                &[
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-path",
                    "config.worktree",
                ],
            )?;
            for (name, source) in [
                ("config", Path::new(common.trim()).join("config")),
                ("config.worktree", PathBuf::from(worktree.trim())),
            ] {
                if source.is_file() {
                    let output = destination.map(|root| root.join(".git").join(name));
                    collector.files.insert(
                        format!("\0vcs/{name}"),
                        capture_file(&source, output.as_deref(), request)?,
                    );
                }
            }
        }
        Ok(collector.files)
    }

    pub fn create(core: &Core, request: &ExecutionRequest, build_root: &Path) -> Result<Self> {
        let original_build_root = build_root.canonicalize()?;
        let vcs = original_build_root
            .ancestors()
            .any(|path| fs::symlink_metadata(path.join(".git")).is_ok());
        let original_root = if vcs {
            PathBuf::from(
                git_text(
                    request,
                    &original_build_root,
                    &["rev-parse", "--show-toplevel"],
                )?
                .trim(),
            )
            .canonicalize()?
        } else {
            original_build_root.clone()
        };
        // Large SDK/ROM trees belong on the project filesystem, not a capped
        // /tmp tmpfs. Colocation also permits copy-on-write filesystem clones.
        let work = MatchWork::create(core.db_path())?;
        let root = work.0.join("project");
        fs::create_dir(&root)?;
        let build_root = root.join(
            original_build_root
                .strip_prefix(&original_root)
                .map_err(|error| invalid(error.to_string()))?,
        );
        let mut snapshot = Self {
            root,
            build_root,
            original_root,
            original_build_root,
            inputs: BTreeMap::new(),
            store: core.db_path().canonicalize()?,
            vcs,
            work,
        };
        if vcs {
            let destination = snapshot.root.join(".git");
            git_text(
                request,
                &snapshot.original_root,
                &[
                    "clone",
                    "--mirror",
                    "--no-hardlinks",
                    "--dissociate",
                    "--",
                    string(&snapshot.original_root)?,
                    string(&destination)?,
                ],
            )?;
            git_text(
                request,
                &snapshot.root,
                &[
                    "--git-dir",
                    string(&destination)?,
                    "config",
                    "core.bare",
                    "false",
                ],
            )?;
        }
        snapshot.inputs = snapshot.gather(request, Some(&snapshot.root))?;
        if vcs {
            for name in ["config", "config.worktree"] {
                let config = snapshot.root.join(".git").join(name);
                if config.is_file() {
                    for (key, value) in [
                        ("core.bare", "false"),
                        ("core.worktree", string(&snapshot.original_root)?),
                        ("core.fsmonitor", "false"),
                    ] {
                        git_text(
                            request,
                            &snapshot.root,
                            &["config", "--file", string(&config)?, key, value],
                        )?;
                    }
                }
            }
        }
        Ok(snapshot)
    }

    pub fn original_unchanged(&self, request: &ExecutionRequest) -> Result<bool> {
        Ok(self.inputs == self.gather(request, None)?)
    }

    pub fn scan(&self, request: &ExecutionRequest) -> Result<Manifest> {
        let mut collector = Collector {
            root: &self.root,
            scope: &self.build_root,
            destination: None,
            store: &self.store,
            request,
            files: BTreeMap::new(),
            bytes: 0,
        };
        collector.collect(&self.root)?;
        Ok(collector.files)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn internal_links_capture_ignored_sibling_inputs_without_aliasing_or_cycles() {
        let work = MatchWork::create(&std::env::temp_dir()).unwrap();
        let root = work.0.join("original");
        let scope = root.join("build");
        let destination = work.0.join("private");
        let store = work.0.join("store");
        fs::create_dir_all(&scope).unwrap();
        fs::create_dir(root.join("orig")).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(root.join("orig/input.bin"), b"original bytes").unwrap();
        std::os::unix::fs::symlink("../orig", scope.join("orig")).unwrap();
        std::os::unix::fs::symlink("../build", root.join("orig/cycle")).unwrap();
        let request = ExecutionRequest {
            binary: PathBuf::new(),
            artifact_digest: String::new(),
            input: romwright_model::ProgramInput {
                source_path: String::new(),
                binary_digest: String::new(),
                image_selector: String::new(),
                map_digest: None,
                raw: None,
                keys_digest: None,
            },
            config: crate::session::RuntimeConfig::from_env(),
            program: String::new(),
            language: String::new(),
            base: 0,
            revision: 0,
            project_dir: store.clone(),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
            cancel: crate::exec::CancelToken::default(),
        };
        let mut collector = Collector {
            root: &root,
            scope: &scope,
            destination: Some(&destination),
            store: &store,
            request: &request,
            files: BTreeMap::new(),
            bytes: 0,
        };
        collector.collect(&scope).unwrap();
        let copied = destination.join("build/orig/input.bin");
        assert_eq!(fs::read(&copied).unwrap(), b"original bytes");
        assert_eq!(
            fs::read(destination.join("build/orig/cycle/orig/input.bin")).unwrap(),
            b"original bytes"
        );
        assert_eq!(
            fs::metadata(destination.join("orig"))
                .unwrap()
                .modified()
                .unwrap(),
            fs::metadata(root.join("orig")).unwrap().modified().unwrap()
        );
        fs::write(copied, b"private build bytes").unwrap();
        assert_eq!(
            fs::read(root.join("orig/input.bin")).unwrap(),
            b"original bytes"
        );
    }
}
