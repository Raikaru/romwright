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

/// Files at least this large are memory-mapped instead of read onto the heap:
/// a disc image is hundreds of times larger than the few kilobytes of it any
/// loader looks at, and a mapping costs resident memory only for the pages
/// something touches. Smaller files are read; a mapping of a small file saves
/// nothing and keeps a descriptor-less window onto a file that could change.
const MAP_MIN: usize = 16 << 20;

/// Bytes a loader, a worker or a matcher reads: a heap buffer or a read-only
/// mapping of an immutable artifact. Clones share the one backing.
#[derive(Clone)]
pub struct SharedBytes(Backing);

#[derive(Clone)]
enum Backing {
    Heap(Arc<[u8]>),
    Mapped(Arc<Mapped>),
}

impl SharedBytes {
    /// Whether both handles share one backing.
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        match (&left.0, &right.0) {
            (Backing::Heap(left), Backing::Heap(right)) => Arc::ptr_eq(left, right),
            (Backing::Mapped(left), Backing::Mapped(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    /// Whether the bytes are a file mapping rather than a heap buffer.
    pub fn is_mapped(&self) -> bool {
        matches!(self.0, Backing::Mapped(_))
    }

    fn downgrade(&self) -> WeakBytes {
        match &self.0 {
            Backing::Heap(bytes) => WeakBytes::Heap(Arc::downgrade(bytes)),
            Backing::Mapped(mapped) => WeakBytes::Mapped(Arc::downgrade(mapped)),
        }
    }
}

impl std::ops::Deref for SharedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.0 {
            Backing::Heap(bytes) => bytes,
            Backing::Mapped(mapped) => mapped.as_slice(),
        }
    }
}

impl AsRef<[u8]> for SharedBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl From<Arc<[u8]>> for SharedBytes {
    fn from(bytes: Arc<[u8]>) -> Self {
        Self(Backing::Heap(bytes))
    }
}

impl From<Vec<u8>> for SharedBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Backing::Heap(bytes.into()))
    }
}

impl std::fmt::Debug for SharedBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "SharedBytes({} bytes, {})",
            self.len(),
            if self.is_mapped() { "mapped" } else { "heap" }
        )
    }
}

enum WeakBytes {
    Heap(std::sync::Weak<[u8]>),
    Mapped(std::sync::Weak<Mapped>),
}

impl WeakBytes {
    fn upgrade(&self) -> Option<SharedBytes> {
        match self {
            Self::Heap(weak) => weak.upgrade().map(|bytes| SharedBytes(Backing::Heap(bytes))),
            Self::Mapped(weak) => weak.upgrade().map(|mapped| SharedBytes(Backing::Mapped(mapped))),
        }
    }

    fn alive(&self) -> bool {
        match self {
            Self::Heap(weak) => weak.strong_count() > 0,
            Self::Mapped(weak) => weak.strong_count() > 0,
        }
    }
}

/// A read-only, private mapping of a whole file.
///
/// Soundness rests on the file being immutable while mapped: artifacts are
/// published read-only, named by the digest of their bytes and never updated
/// in place, and every mapping here is of a published artifact (an input is
/// copied into the store before it is mapped, never mapped where the caller
/// can still write it).
struct Mapped {
    pointer: *const u8,
    length: usize,
}

// SAFETY: the mapping is read-only for its whole life and owns no thread-affine state.
unsafe impl Send for Mapped {}
unsafe impl Sync for Mapped {}

impl Mapped {
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `pointer` maps `length` readable bytes until `drop`.
        unsafe { std::slice::from_raw_parts(self.pointer, self.length) }
    }
}

#[cfg(unix)]
impl Mapped {
    fn map(file: &std::fs::File, length: usize) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        // SAFETY: a fresh read-only private mapping of `length` bytes of an open file.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            pointer: pointer.cast(),
            length,
        })
    }
}

#[cfg(unix)]
impl Drop for Mapped {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the range `map` returned.
        unsafe {
            libc::munmap(self.pointer.cast_mut().cast(), self.length);
        }
    }
}

/// Buffers of artifacts this process still holds, by content digest. An
/// artifact is immutable and named by the digest of its bytes, so a second
/// `open` of one that is still alive shares the buffer instead of reading the
/// file again: a multi-gigabyte disc image is held once, not once per reader.
static LIVE: std::sync::Mutex<Vec<(String, WeakBytes)>> = std::sync::Mutex::new(Vec::new());

fn live_register(digest: &str, bytes: &SharedBytes) {
    let mut live = LIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    live.retain(|(_, weak)| weak.alive());
    if !live.iter().any(|(held, _)| held == digest) {
        live.push((digest.to_string(), bytes.downgrade()));
    }
}

fn live_lookup(digest: &str) -> Option<SharedBytes> {
    let live = LIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    live.iter()
        .find(|(held, _)| held == digest)
        .and_then(|(_, weak)| weak.upgrade())
}

/// Reads a file straight into its shared buffer. `fs::read(..).into()` holds
/// the file twice while the `Vec` is copied into the `Arc`, which on a
/// multi-gigabyte disc image is the difference between fitting and an OOM kill.
pub(crate) fn read_shared(path: &Path) -> std::io::Result<Arc<[u8]>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let len = usize::try_from(file.metadata()?.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "file too large"))?;
    let buffer = Arc::<[u8]>::new_zeroed_slice(len);
    // SAFETY: the allocation is zero-filled, and every bit pattern is a valid `u8`.
    let mut buffer = unsafe { buffer.assume_init() };
    let target = Arc::get_mut(&mut buffer).expect("a new Arc has one owner");
    file.read_exact(target)?;
    // A file that grew while it was read is not the file that was measured.
    if file.read(&mut [0u8])? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file changed while it was read",
        ));
    }
    Ok(buffer)
}

fn changed_while_read() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "file changed while it was read")
}

/// An open artifact file's bytes: mapped from `map_min` bytes up, read below.
/// The caller has already established that the file is the artifact it means.
fn bytes_of(file: std::fs::File, path: &Path, map_min: usize) -> std::io::Result<SharedBytes> {
    let length = usize::try_from(file.metadata()?.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "file too large"))?;
    #[cfg(unix)]
    if length >= map_min.max(1) {
        return Ok(SharedBytes(Backing::Mapped(Arc::new(Mapped::map(&file, length)?))));
    }
    let _ = (&file, map_min);
    Ok(read_shared(path)?.into())
}

/// Lowercase hex SHA-256 of everything `reader` yields, in bounded memory.
fn digest_stream(reader: impl std::io::Read) -> std::io::Result<String> {
    Ok(crate::sha256::hex(crate::sha256::digest_reader(reader)?))
}

fn store_root(project: &Path) -> std::io::Result<PathBuf> {
    let root = project.join("artifacts");
    std::fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(root)
}

/// Publishes whatever `fill` writes as an immutable artifact and returns its
/// digest, holding at most one write buffer: the bytes are hashed as they are
/// written to a private staging file, which is then hard-linked under their
/// digest (atomic, and never over a snapshot another process published first).
pub(crate) fn publish_with(
    project: &Path,
    fill: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    struct Hashing<W> {
        inner: W,
        hash: Sha256,
    }
    impl<W: Write> Write for Hashing<W> {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            let count = self.inner.write(buffer)?;
            self.hash.update(&buffer[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
    let root = store_root(project)?;
    let staging = root.join(format!(
        ".capture-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let outcome = (|| -> std::io::Result<String> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&staging)?;
        let mut writer = Hashing {
            inner: std::io::BufWriter::with_capacity(1 << 20, file),
            hash: Sha256::new(),
        };
        fill(&mut writer)?;
        let Hashing { inner, hash } = writer;
        let file = inner.into_inner().map_err(|error| error.into_error())?;
        let digest = crate::sha256::hex(hash.finalize().into());
        file.sync_all()?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)?;
        let length = file.metadata()?.len();
        drop(file);
        let path = root.join(&digest);
        match std::fs::hard_link(&staging, &path) {
            Ok(()) => Ok(digest),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // The name is the digest of the bytes: the published file is
                // those bytes unless it was damaged after publication.
                let published = std::fs::File::open(&path)?;
                if published.metadata()?.len() == length
                    && digest_stream(&published)? == digest
                {
                    Ok(digest)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("corrupt immutable artifact {}", path.display()),
                    ))
                }
            }
            Err(error) => Err(error),
        }
    })();
    let _ = std::fs::remove_file(&staging);
    outcome
}

#[derive(Clone, Debug)]
pub struct Artifact {
    pub digest: String,
    pub bytes: SharedBytes,
    pub path: PathBuf,
}

impl Artifact {
    /// Snapshots `source` into the project's artifact store. A large source is
    /// streamed into the store (hashed as it goes) and the stored copy is
    /// mapped, so the input is never held in memory; the caller's file, which
    /// can change under us, is never the one mapped.
    pub fn capture(project: &Path, source: &Path) -> crate::Result<Self> {
        Self::capture_with(project, source, MAP_MIN)
    }

    fn capture_with(project: &Path, source: &Path, map_min: usize) -> crate::Result<Self> {
        let length = std::fs::metadata(source)?.len();
        if usize::try_from(length).is_ok_and(|length| length < map_min.max(1)) {
            return Self::from_bytes(project, read_shared(source)?);
        }
        let digest = publish_with(project, |out| {
            use std::io::Read;
            let mut file = std::fs::File::open(source)?;
            let measured = file.metadata()?.len();
            let mut buffer = vec![0u8; 1 << 20];
            let mut copied = 0u64;
            loop {
                let count = match file.read(&mut buffer) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if count == 0 {
                    break;
                }
                out.write_all(&buffer[..count])?;
                copied += count as u64;
            }
            // A file that grew or shrank while it was read is not the file that was measured.
            if copied != measured {
                return Err(changed_while_read());
            }
            Ok(())
        })?;
        let path = project.join("artifacts").join(&digest);
        let bytes = bytes_of(std::fs::File::open(&path)?, &path, map_min)?;
        live_register(&digest, &bytes);
        Ok(Self {
            digest,
            bytes,
            path: path.canonicalize()?,
        })
    }

    pub fn open(project: &Path, digest: &str) -> crate::Result<Self> {
        Self::open_with(project, digest, MAP_MIN)
    }

    fn open_with(project: &Path, digest: &str, map_min: usize) -> crate::Result<Self> {
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
        if let Some(bytes) = live_lookup(digest) {
            return Ok(Self {
                digest: digest.into(),
                bytes,
                path: path.canonicalize()?,
            });
        }
        // One descriptor verifies and maps: the bytes checked are the bytes used.
        let file = std::fs::File::open(&path)?;
        if digest_stream(&file)? != digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact digest mismatch",
            )
            .into());
        }
        let bytes = bytes_of(file, &path, map_min)?;
        live_register(digest, &bytes);
        Ok(Self {
            digest: digest.into(),
            bytes,
            path: path.canonicalize()?,
        })
    }

    pub fn from_bytes(project: &Path, bytes: Arc<[u8]>) -> crate::Result<Self> {
        let bytes = SharedBytes::from(bytes);
        let digest = crate::import_cache::digest_bytes(&bytes);
        let root = store_root(project)?;
        let path = root.join(&digest);
        match std::fs::read(&path) {
            Ok(existing) => {
                if existing.as_slice() != &*bytes {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("corrupt immutable artifact {}", path.display()),
                    )
                    .into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let published = publish_with(project, |out| out.write_all(&bytes))?;
                if published != digest {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "artifact digest changed while it was published",
                    )
                    .into());
                }
            }
            Err(error) => return Err(error.into()),
        }
        live_register(&digest, &bytes);
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

    #[test]
    fn a_live_artifact_is_shared_not_read_again() {
        let root = std::env::temp_dir().join(format!(
            "romwright-artifact-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("input");
        std::fs::write(&source, b"shared bytes").unwrap();
        let held = Artifact::capture(&root, &source).unwrap();
        let again = Artifact::open(&root, &held.digest).unwrap();
        assert!(SharedBytes::ptr_eq(&held.bytes, &again.bytes));
        let digest = held.digest.clone();
        drop((held, again));
        // Once nothing holds it, the next open reads and verifies the file.
        let reread = Artifact::open(&root, &digest).unwrap();
        assert_eq!(&*reread.bytes, b"shared bytes");
    }

    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "romwright-artifact-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn a_large_input_is_streamed_into_the_store_and_mapped() {
        let root = scratch("mapped");
        let source = root.join("input");
        let content: Vec<u8> = (0..(3 << 20) + 17).map(|index| (index * 31 % 251) as u8).collect();
        std::fs::write(&source, &content).unwrap();
        let captured = Artifact::capture_with(&root, &source, 1 << 20).unwrap();
        assert!(captured.bytes.is_mapped());
        assert_eq!(&*captured.bytes, content.as_slice());
        assert_eq!(captured.digest, crate::import_cache::digest_bytes(&content));
        assert_eq!(std::fs::read(&captured.path).unwrap(), content);
        // The caller's file is not the mapped one: replacing it changes nothing.
        std::fs::write(&source, b"replaced").unwrap();
        assert_eq!(&*captured.bytes, content.as_slice());
        // A second capture of the same bytes finds the published file and verifies it.
        std::fs::write(&source, &content).unwrap();
        let again = Artifact::capture_with(&root, &source, 1 << 20).unwrap();
        assert_eq!(again.digest, captured.digest);
        // A live artifact is shared; a dropped one is opened, verified and mapped again.
        let opened = Artifact::open_with(&root, &captured.digest, 1 << 20).unwrap();
        assert!(SharedBytes::ptr_eq(&captured.bytes, &opened.bytes));
        let digest = captured.digest.clone();
        let path = captured.path.clone();
        drop((captured, again, opened));
        let reopened = Artifact::open_with(&root, &digest, 1 << 20).unwrap();
        assert!(reopened.bytes.is_mapped());
        assert_eq!(&*reopened.bytes, content.as_slice());
        drop(reopened);
        // Damage after publication is refused, never mapped.
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)] // a scratch file this test just wrote
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).unwrap();
        let mut damaged = content.clone();
        damaged[1 << 20] ^= 1;
        std::fs::write(&path, damaged).unwrap();
        assert!(Artifact::open_with(&root, &digest, 1 << 20).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_small_input_stays_on_the_heap() {
        let root = scratch("heap");
        let source = root.join("input");
        std::fs::write(&source, b"small").unwrap();
        let artifact = Artifact::capture(&root, &source).unwrap();
        assert!(!artifact.bytes.is_mapped());
        assert_eq!(&*artifact.bytes, b"small");
        std::fs::remove_dir_all(root).unwrap();
    }
}
