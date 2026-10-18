//! Sessionful runtime foundation (review Phase 2 / CORE-002 + RuntimeConfig).
//!
//! The clipboard of the ratified review: "the UI must not know storage or
//! launcher details" and "open/map once; share reads across all views and
//! workers". This module replaces the per-read `load_native` pattern with a
//! single read-only memory map per open program, a first-class (immutable)
//! runtime configuration, and a session that carries the image.
//!
//! `RuntimeConfig` is the internal contract going forward: environment
//! variables may seed defaults (the CLI's env surface stays), but services
//! take an explicit value — never call `std::env` themselves.

use crate::artifact::SharedBytes;
use crate::native::NativeImport;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Immutable runtime configuration (built from env defaults or explicit
/// values; services receive one instead of reading process-wide state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Path to the `romwright-worker` binary.
    pub worker_path: PathBuf,
    /// Path to the patched `ghidra_opt` (raw-SLEIGH mode).
    pub decompiler_path: PathBuf,
    /// objdiff executable used by matching runs.
    pub objdiff_path: PathBuf,
    /// Declarations exported from the pinned C library type archive.
    pub library_prototypes: PathBuf,
    /// Spec root directory (pspec/cspec/tspec/coretypes + registers.txt).
    pub spec_root: PathBuf,
    /// Selected Ghidra language id (defaults to x86-64).
    pub language_id: String,
    /// Installed processor directory the in-process SLEIGH lifter reads.
    pub language_dir: PathBuf,
    /// Compiled .sla used by the raw-SLEIGH worker hook.
    pub sla_path: Option<PathBuf>,
    /// Ghidra 12.1.3 install root (SLEIGH language lookup).
    pub ghidra_install: PathBuf,
    /// Peak RSS permitted for one worker process (bytes).
    pub worker_memory_cap: u64,
    /// Maximum concurrent long-running jobs for a service using this Core.
    pub job_workers: usize,
    /// Semantic passes applied to live native SSA before printing C.
    pub ir_passes: Vec<String>,
    /// True when `language_dir` came from an explicit pin; a pinned
    /// directory survives adopting an image's own language.
    pub language_dir_pinned: bool,
    /// Lanes one discovery flow batch is split across (in-process SLEIGH
    /// decoders) and propagation lanes a reference round is split across.
    /// Each lane keeps the mode switches its own decodes committed, so the
    /// count shapes what is found on images that mix instruction sets and
    /// must be the same on every host (`DEFAULT_CONSOLE_SHARDS`).
    pub console_shards: usize,
    /// Recover jump tables by value-set analysis over p-code before asking
    /// the decompiler (m13-001). On: measured against truth on libc -- every
    /// case target must decode and lie inside the branching function's own
    /// extent, taken from the image's symbol table -- the pass plus the
    /// decompiler answers 142 dispatches at 0.9967 soundness, against stock
    /// Ghidra's 132 at 0.9794 and the decompiler alone at 130 at 0.9956. The
    /// pass alone is the soundest of all at 0.9989, and costs under a second.
    pub switch_vsa: bool,
    /// Accept a table whose end no guard states, bounded only by its
    /// targets ceasing to be code. Off by default: measured against stock on
    /// libc these over-run their real end.
    /// Let the decompiler answer the dispatches value-set analysis refused.
    /// On by default; off measures the accelerator alone.
    pub switch_decompiler: bool,
    /// Ask the switch stage about the indirect jumps the reference pass
    /// bounded but could not finish a table for, and the walk's list lacks
    /// (`infer_data_references`). On by default (`ROMWRIGHT_NO_BRANCHIND_CANDIDATES`);
    /// off measures the walk's list alone.
    pub branchind_candidates: bool,
    /// Recover the table of an indirect jump inside the reference flow
    /// (`native_runtime::propagation::jump`). On by default
    /// (`ROMWRIGHT_NO_BRANCHIND_RECOVERY`); it is the value-set pass, so
    /// `switch_vsa` off turns it off too.
    pub branchind_recovery: bool,
    /// Work units one switch decompile may spend before the decompiler
    /// refuses it (`native_runtime::SWITCH_WORK_BUDGET`;
    /// `ROMWRIGHT_SWITCH_WORK_BUDGET` overrides, 0 is unlimited). A count, not
    /// a time, so the same function gets the same answer on every host; it is
    /// part of the import cache's key because it changes what is recovered.
    pub switch_work_budget: u64,
    /// Seconds one switch decompile may run before its worker is killed
    /// (`native_runtime::SWITCH_WALL_GUARD`, `ROMWRIGHT_SWITCH_WALL_SECS`
    /// overrides). A backstop, never what decides a function's answer: one it
    /// kills makes the import degraded.
    pub switch_wall_guard_secs: u64,
    /// Recover parameters passed in registers that no shipped prototype
    /// model claims (m4-001). Off by default: II.1 reserves enabling an M4
    /// pass, so it changes user-visible output only when asked.
    pub register_params: bool,
    /// Merge the p-code type inference into the prototypes the
    /// `infer_prototypes` job persists (`types_infer::prototypes`). On:
    /// measured on the console ROM imports (200 sampled functions per
    /// image, 2026-10-08) DWARF type-slot agreement rose gba 0.258 -> 0.372,
    /// nds 0.493 -> 0.605, ps2-dungeon 0.344 -> 0.426 with arity unchanged.
    /// `ROMWRIGHT_INFERRED_TYPES=0` turns it off for ablation.
    pub inferred_types: bool,
    /// Promote the target of a proven tail call to a function (m5-007).
    /// Stock Ghidra does not create these, so the pass moves output past
    /// the frozen baseline; off by default for the same II.1 reason.
    pub promote_tailcalls: bool,
    /// The compiler id the importer records instead of detecting one
    /// (`romwright-cli import --compiler`, `ROMWRIGHT_COMPILER`). `None`
    /// lets the detectors decide.
    pub compiler: Option<String>,
    /// The file of per-function signatures the struct pass hands one decompile
    /// (`ROMWRIGHT_STRUCT_OVERLAY` for the worker, `struct_pass`); never
    /// stored with the project. Set by the pass on the request it makes.
    pub struct_overlay: Option<PathBuf>,
    /// Environment the decompiler worker gets on top of the process's own, set
    /// per request: the printing variant of the near-miss search
    /// (`match_search::PrintVariant::env`, docs/match.md). Empty by default,
    /// which is today's output byte for byte.
    pub worker_env: Vec<(String, String)>,
}

/// Decoder lanes by default: four, on every host.
///
/// The lane count is part of the answer. Each lane is a decoder with its own
/// context database, into which its decodes commit the mode switches their
/// bytes carry (`globalset`), and which lane decodes an address depends on how
/// a batch is split: the same Vita image imported with one, four and eight
/// lanes holds 62 to 64 rows that differ (function extents, Thumb contexts, a
/// few branch references, all in the import stubs at 0x8167a3fc-0x8167c4d6),
/// and two runs with four lanes hold none. So the count must not follow the
/// host (it used to be one per physical core, capped at eight, and so changed
/// with a core count, a `taskset` or a container's CPU limit), and four is
/// what the reference measurements were taken at. A host with fewer cores
/// time-slices the lanes; one with more leaves cores idle in the decode phases
/// (`ROMWRIGHT_CONSOLE_SHARDS` chooses another count, and then owns the
/// differences).
const DEFAULT_CONSOLE_SHARDS: usize = 4;

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

/// The worker this build drives: an explicit pin, then the worker beside the
/// running executable, then the workspace's release and debug paths.
///
/// The sibling comes before the workspace paths because a release `romwright-cli`
/// driving whatever `cargo build` last left in `target/debug` makes a measured
/// number depend on a build nobody asked for -- which is how a pinned parity
/// count read 25 instead of 30 on an unmodified tree.
fn worker_candidate() -> PathBuf {
    if let Ok(pinned) = std::env::var("ROMWRIGHT_WORKER") {
        return PathBuf::from(pinned);
    }
    let worker = format!("romwright-worker{}", std::env::consts::EXE_SUFFIX);
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(&worker)));
    // The target/ fallbacks resolve against the repository root, not the
    // process cwd — a GUI launched from desktop/.../build must still find
    // target/release/romwright-worker.
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("."));
    let fallbacks = [
        repo_root.join("target/release").join(&worker),
        repo_root.join("target/debug").join(&worker),
        PathBuf::from("target/release").join(&worker),
        PathBuf::from("target/debug").join(&worker),
    ];
    sibling
        .into_iter()
        .chain(fallbacks)
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| repo_root.join("target/debug").join(&worker))
}

/// The worker memory cap in bytes: `ROMWRIGHT_WORKER_MEMORY_CAP` when it names
/// one, 256 MiB otherwise.
///
/// A host with less memory than the one this default was measured on has to
/// bound its workers lower, and a cap below a fresh worker's own footprint
/// would fail every request instead of bounding a long session -- so a value
/// under 16 MiB, or one that is not a number, keeps the default.
fn worker_memory_cap(value: Option<&str>) -> u64 {
    const DEFAULT: u64 = 256 * 1024 * 1024;
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|cap| *cap >= 16 * 1024 * 1024)
        .unwrap_or(DEFAULT)
}

impl RuntimeConfig {
    /// Builds a config from the environment (the CLI's documented surface),
    /// with repo/install-relative defaults.
    pub fn from_env() -> Self {
        let install = crate::native_runtime::ghidra_dir();
        let language_id =
            std::env::var("ROMWRIGHT_LANGUAGE").unwrap_or_else(|_| "x86:LE:64:default".into());
        let pinned_dir = std::env::var("ROMWRIGHT_LANGUAGE_DIR")
            .ok()
            .map(PathBuf::from);
        let language_dir_pinned = pinned_dir.is_some();
        let language_dir = pinned_dir
            .or_else(|| {
                crate::architecture::directory_for_id(&install, &language_id)
                    .ok()
                    .flatten()
            })
            .unwrap_or_else(|| install.join("Ghidra/Processors/x86/data/languages"));
        let worker_path = worker_candidate();
        // Defaults resolve beside the running executable first (a release
        // archive), then inside the source checkout, never against the
        // process cwd -- a GUI launched from desktop/.../build must still
        // find native/build/ghidra_opt and native/specs (`runtime_paths`).
        let layout = crate::runtime_paths::Layout::current();
        let decompiler_path = std::env::var("ROMWRIGHT_GHIDRA_OPT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| layout.decompiler());
        let library_prototypes = std::env::var("ROMWRIGHT_LIBRARY_PROTOTYPES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| layout.library_prototypes());
        let spec_root = std::env::var("ROMWRIGHT_SPECS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| layout.specs());
        let sla_path = std::env::var("ROMWRIGHT_SLA")
            .ok()
            .filter(|p| {
                let pb = PathBuf::from(p);
                pb.is_file()
            })
            .map(PathBuf::from);
        let console_shards = std::env::var("ROMWRIGHT_CONSOLE_SHARDS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|shards| *shards >= 1)
            .unwrap_or(DEFAULT_CONSOLE_SHARDS);
        Self {
            library_prototypes,
            worker_path,
            decompiler_path,
            objdiff_path: std::env::var_os("ROMWRIGHT_OBJDIFF")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("objdiff-cli")),
            spec_root,
            language_id,
            language_dir,
            language_dir_pinned,
            sla_path,
            ghidra_install: install,
            worker_memory_cap: worker_memory_cap(
                std::env::var("ROMWRIGHT_WORKER_MEMORY_CAP").ok().as_deref(),
            ),
            job_workers: std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(2)
                .min(8),
            ir_passes: std::env::var("ROMWRIGHT_IR_PASSES")
                .ok()
                .map(|value| crate::func_ir::parse_pass_names(&value))
                .unwrap_or_else(crate::func_ir::default_pass_names),
            console_shards,
            compiler: std::env::var("ROMWRIGHT_COMPILER").ok().filter(|id| !id.trim().is_empty()),
            struct_overlay: None,
            worker_env: Vec::new(),
            register_params: std::env::var_os("ROMWRIGHT_REGISTER_PARAMS").is_some(),
            inferred_types: std::env::var_os("ROMWRIGHT_INFERRED_TYPES").is_none_or(|value| value != "0"),
            promote_tailcalls: std::env::var_os("ROMWRIGHT_PROMOTE_TAILCALLS").is_some(),
            // Both on unless switched off, so the two switch paths can be
            // measured separately without rebuilding.
            switch_vsa: std::env::var_os("ROMWRIGHT_NO_SWITCH_VSA").is_none(),
            switch_decompiler: std::env::var_os("ROMWRIGHT_NO_SWITCH_DECOMPILER").is_none(),
            branchind_candidates: std::env::var_os("ROMWRIGHT_NO_BRANCHIND_CANDIDATES").is_none(),
            branchind_recovery: std::env::var_os("ROMWRIGHT_NO_BRANCHIND_RECOVERY").is_none(),
            switch_work_budget: std::env::var("ROMWRIGHT_SWITCH_WORK_BUDGET")
                .ok()
                .and_then(|raw| raw.parse().ok())
                .unwrap_or(crate::native_runtime::SWITCH_WORK_BUDGET),
            switch_wall_guard_secs: std::env::var("ROMWRIGHT_SWITCH_WALL_SECS")
                .ok()
                .and_then(|raw| raw.parse().ok())
                .filter(|secs| *secs >= 1)
                .unwrap_or(crate::native_runtime::SWITCH_WALL_GUARD.as_secs()),
        }
    }

    /// Adopts the language a loaded image declares. The SLEIGH language
    /// lookup resolves an id inside one installed processor directory, so the
    /// directory follows the id unless the caller pinned one.
    pub fn adopt_language(&mut self, id: &str) {
        if self.language_id != id {
            // A pinned `.sla` pins the language it was pinned for. Adopting
            // another language has to drop it, or the import believes a pin
            // `language_decompile_config` will refuse at decompile time --
            // which is how a 32-bit image was typed from the 64-bit spec
            // bundle and handed the decompiler a `long` its language has no
            // name for (m4-022).
            self.sla_path = None;
            self.language_id = id.to_string();
        }
        if self.language_dir_pinned {
            return;
        }
        if let Ok(Some(dir)) = crate::architecture::directory_for_id(&self.ghidra_install, id) {
            self.language_dir = dir;
        }
    }
}

/// One mapped file range with its flags (ELF SHF_* / PE section chars).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    pub vaddr: u64,
    /// Virtual size (includes BSS/file-less extent).
    pub size: u64,
    pub file_off: u64,
    /// File-backed bytes (section raw size on disk; may be < `size`).
    pub file_size: u64,
    pub flags: u64,
}

/// Owned program-byte snapshot, region map and sparse patch overlay.
///
/// File-backed reads use immutable shared bytes; BSS reads return zeros and
/// patch bytes take precedence. Replacing or truncating the source file cannot
/// change an existing image or invalidate its backing storage.
#[derive(Debug)]
pub struct ProgramImage {
    path: PathBuf,
    map: SharedBytes,
    regions: Vec<MemoryRegion>,
    relocations: Vec<crate::native::MemoryRelocation>,
    patches: BTreeMap<u64, Patch>,
}

/// Bytes that override what a region reads: owned by the image, or a range of
/// the mapped backing (a snapshot holds each patch once, beside its region).
#[derive(Debug)]
enum Patch {
    Owned(Vec<u8>),
    Backed { start: usize, len: usize },
}

mod snapshot;

impl ProgramImage {
    /// Captures `binary` and derives regions from the existing native loader
    /// without running discovery.
    pub fn open(binary: &Path) -> crate::Result<Self> {
        Self::open_with_raw_base(binary, None)
    }

    /// Native formats use loader addresses; unrecognized raw files may use
    /// an explicit base. A malformed ELF/PE never falls back to raw bytes.
    pub fn open_with_raw_base(binary: &Path, raw_base: Option<u64>) -> crate::Result<Self> {
        Self::open_for_program(binary, None, raw_base)
    }

    /// Selects a container image by the imported program identity, never by
    /// address overlap (different processors can map the same addresses).
    pub fn open_for_program(
        binary: &Path,
        program: Option<&str>,
        raw_base: Option<u64>,
    ) -> crate::Result<Self> {
        // A large 3DS card is read as its program view; anything else straight
        // into the shared buffer (`fs::read(..).into()` would hold it twice).
        let map: SharedBytes = match crate::native::threeds::program_view(binary)? {
            Some(view) => std::sync::Arc::<[u8]>::from(view).into(),
            None => crate::artifact::read_shared(binary)?.into(),
        };
        let images = match crate::native::parse_container(&map) {
            Ok(images) => images,
            Err(_)
                if raw_base.is_some()
                    && !map.starts_with(b"\x7fELF")
                    && !map.starts_with(b"MZ") =>
            {
                crate::native::parse_image_input(
                    &map,
                    raw_base.map(|base| (base, "raw")),
                    &crate::native::keys::KeyStore::empty(),
                )?
            }
            Err(error) => return Err(error.into()),
        };
        let single = images.len() == 1;
        let mut selected = images.into_iter().filter(|(suffix, _)| {
            single
                || (!suffix.is_empty()
                    && program.is_some_and(|name| name.ends_with(&format!(".{suffix}"))))
        });
        let import = match (selected.next(), selected.next()) {
            (Some((_, import)), None) => import,
            _ => {
                return Err(crate::native::ImportError::Bad(
                    "container requires an unambiguous imported program identity".into(),
                )
                .into());
            }
        };
        Ok(Self::from_import(binary.to_path_buf(), map, import))
    }

    pub fn open_input(
        project: &Path,
        input: &romwright_model::ProgramInput,
    ) -> crate::Result<Self> {
        // A worker the importing process started is handed the mapped image
        // its parent already derived, so it neither reads nor re-parses the
        // input (which for a disc is gigabytes) and shares the pages.
        if let Some(digest) = crate::inputs::inherited_snapshot(input) {
            let artifact = crate::artifact::Artifact::open(project, &digest)?;
            return Self::from_snapshot(artifact.path, artifact.bytes);
        }
        let (artifact, import) = crate::inputs::parse(project, input)?;
        Ok(Self::from_import(artifact.path, artifact.bytes, import))
    }

    /// Whether a mapping's bytes differ from the file at its offset:
    /// decompressed or loader-synthesized bytes override file contents.
    fn is_patch(map: &[u8], mapping: &crate::native::Mapping) -> bool {
        let stored = usize::try_from(mapping.file_off)
            .ok()
            .and_then(|offset| map.get(offset..offset.checked_add(mapping.bytes.len())?));
        stored != Some(mapping.bytes.as_slice())
    }

    fn from_import(path: PathBuf, map: SharedBytes, import: crate::native::NativeImport) -> Self {
        let mut patches = BTreeMap::new();
        let regions = import
            .mappings
            .into_iter()
            .map(|mapping| {
                let file_size = mapping.bytes.len() as u64;
                if Self::is_patch(&map, &mapping) {
                    patches.insert(mapping.vaddr, Patch::Owned(mapping.bytes));
                }
                MemoryRegion {
                    vaddr: mapping.vaddr,
                    size: mapping.size,
                    file_off: mapping.file_off,
                    file_size,
                    flags: mapping.flags,
                }
            })
            .collect();
        Self {
            path,
            map,
            regions,
            relocations: import.relocations,
            patches,
        }
    }

    /// The mapped file path (diagnostics).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// All derived regions (ascending vaddr).
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Applies a sparse patch (offset -> bytes) over the mapped image.
    pub fn patch(&mut self, vaddr: u64, bytes: Vec<u8>) {
        self.patches.insert(vaddr, Patch::Owned(bytes));
    }

    /// Reads `size` bytes at `vaddr`. Within a region: file-backed bytes
    /// where the region has them, zeros for the rest (BSS). Patches
    /// override region reads. Returns `None` when the range crosses a
    /// region boundary or is unmapped.
    pub fn read(&self, vaddr: u64, size: u64) -> Option<Vec<u8>> {
        let region = self.region_for(vaddr, size)?;
        let mut out = vec![0u8; usize::try_from(size).ok()?];
        self.read_region(region, vaddr, &mut out)?;
        Some(out)
    }

    /// Strict mapped read into an existing buffer; no allocation.
    pub fn read_into(&self, vaddr: u64, out: &mut [u8]) -> Option<()> {
        let region = self.region_for(vaddr, out.len() as u64)?;
        self.read_region(region, vaddr, out)
    }

    fn region_for(&self, vaddr: u64, size: u64) -> Option<&MemoryRegion> {
        let end = vaddr.checked_add(size)?;
        self.regions
            .iter()
            .find(|r| vaddr >= r.vaddr && end <= r.vaddr + r.size)
    }

    fn read_region(&self, region: &MemoryRegion, vaddr: u64, out: &mut [u8]) -> Option<()> {
        let size = out.len() as u64;
        let local = vaddr - region.vaddr;
        let file_bytes = region.file_off.checked_add(local)?;
        // Zero-fill by default (BSS); copy file-backed bytes where the
        // mapping covers them. `Mmap` derefs to `&[u8]` — no unsafe here.
        for (i, b) in out.iter_mut().enumerate() {
            let at = file_bytes + i as u64;
            if at < region.file_off + region.file_size {
                *b = self.map.get(at as usize).copied().unwrap_or(0);
            } else {
                *b = 0;
            }
        }
        let first = self
            .relocations
            .partition_point(|r| r.address < vaddr.saturating_sub(7));
        for relocation in self.relocations[first..]
            .iter()
            .take_while(|r| r.address < vaddr + size)
        {
            let start = vaddr.max(relocation.address);
            let end = (vaddr + size).min(relocation.address + relocation.width as u64);
            if start < end {
                let src = (start - relocation.address) as usize;
                let dst = (start - vaddr) as usize;
                out[dst..dst + (end - start) as usize]
                    .copy_from_slice(&relocation.bytes[src..src + (end - start) as usize]);
            }
        }
        for (p, patch) in &self.patches {
            let bytes = match patch {
                Patch::Owned(bytes) => bytes.as_slice(),
                Patch::Backed { start, len } => self.map.get(*start..*start + *len)?,
            };
            let pend = p + bytes.len() as u64;
            let ostart = vaddr.max(*p);
            let oend = (vaddr + size).min(pend);
            if ostart < oend {
                let src = (ostart - *p) as usize;
                let dst = (ostart - vaddr) as usize;
                out[dst..dst + (oend - ostart) as usize]
                    .copy_from_slice(&bytes[src..src + (oend - ostart) as usize]);
            }
        }
        Some(())
    }
}

/// An open program: identity + shared image + provenance metadata.
#[derive(Debug, Clone)]
pub struct ProgramSession {
    /// Program name in the project store.
    pub program: String,
    /// Shared, read-only binary image (views and workers share it).
    pub image: Arc<ProgramImage>,
    /// Import provenance and format facts the UI needs to display.
    pub metadata: SessionMetadata,
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    /// Ghidra-compatible language id selected by the importer.
    pub language: String,
    /// `ELF` / `PE`
    pub format: String,
    /// Lowest loaded mapping address, rounded down to a page boundary.
    pub image_base: u64,
}

impl SessionMetadata {
    /// Derives metadata from a loaded import (the session's one parse).
    pub fn from_import(imp: &NativeImport) -> Self {
        let image_base = imp.mappings.iter().map(|m| m.vaddr).min().unwrap_or(0) & !0xfff;
        Self {
            language: imp.language.clone(),
            format: imp.format.clone(),
            image_base,
        }
    }
}

/// Session configuration error.
#[derive(Debug, thiserror::Error)]
#[error("session: {0}")]
pub struct SessionError(pub String);

pub type Result<T> = std::result::Result<T, SessionError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> ProgramImage {
        // File-backed bytes at 0x400000 (file off 0, 0x100 bytes) and a
        // BSS region at 0x400100 (file off 0x100, 0x200 bytes, file only
        // covers 0x40).
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("romwright-session-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("img.bin");
        let data: Vec<u8> = (0..0x1000u64).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let map: SharedBytes = data.into();
        let mut img = ProgramImage {
            path,
            map,
            regions: vec![
                MemoryRegion {
                    vaddr: 0x400000,
                    size: 0x100,
                    file_off: 0,
                    file_size: 0x100,
                    flags: 0x6,
                },
                MemoryRegion {
                    vaddr: 0x400100,
                    size: 0x200,
                    file_off: 0x100,
                    file_size: 0x40,
                    flags: 0x2,
                },
            ],
            relocations: Vec::new(),
            patches: BTreeMap::new(),
        };
        img.patch(0x400010, vec![0xde, 0xad]);
        img
    }

    #[test]
    fn region_read_copies_file_bytes() {
        let image = image();
        let r = image.read(0x400000, 8).unwrap();
        assert_eq!(r, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn bss_zero_fills_beyond_file_range() {
        let image = image();
        // 0x400100 + 0x40 covers the file range; past that: zeros.
        let r = image.read(0x400140, 8).unwrap();
        assert_eq!(r, vec![0; 8]);
        let r = image.read(0x400100, 4).unwrap();
        let want: Vec<u8> = (0x100..0x104).map(|i| (i % 251) as u8).collect();
        assert_eq!(r, want);
    }

    #[test]
    fn patch_overrides_region_read() {
        let image = image();
        let r = image.read(0x400010, 2).unwrap();
        assert_eq!(r, vec![0xde, 0xad]);
    }

    #[test]
    fn unmapped_or_crossing_read_is_none() {
        let image = image();
        assert!(image.read(0x500000, 4).is_none());
        // Spanning two regions (0x4000ff..0x400103) -> None.
        assert!(image.read(0x4000ff, 4).is_none());
    }

    #[test]
    fn source_truncation_does_not_change_open_image() {
        let image = image();
        let before = image.read(0x400000, 8).unwrap();
        std::fs::write(image.path(), []).unwrap();
        assert_eq!(image.read(0x400000, 8).unwrap(), before);
        std::fs::remove_dir_all(image.path().parent().unwrap()).unwrap();
    }

    #[test]
    fn program_image_opens_real_fixture() {
        // Exercises ProgramImage::open's real path: mmap + loader-derived
        // regions; add's entry bytes at 0x400466 must read back from the map.
        let path = Path::new("../../tests/fixtures-src/tiny_bin");
        if !path.is_file() {
            return; // not present in a published crate test context
        }
        let img = ProgramImage::open(path).unwrap();
        assert!(!img.regions().is_empty());
        // add: 55 48 89 e5 (push rbp; mov rbp,rsp)
        let r = img.read(0x400466, 4).unwrap();
        assert_eq!(r, vec![0x55, 0x48, 0x89, 0xe5]);
    }

    #[test]
    fn runtime_config_builds_from_env_defaults() {
        let cfg = RuntimeConfig::from_env();
        assert_eq!(cfg.worker_memory_cap, 256 * 1024 * 1024);
        assert!(cfg.spec_root.ends_with("native/specs"));
    }

    /// The cap is a knob because a host with less memory than this one has to
    /// bound its workers lower, and a session gate has to be able to reach the
    /// recycle path on purpose. A value under a fresh worker's own footprint
    /// would fail every request instead of bounding a long one, so it is
    /// refused in favour of the default.
    #[test]
    fn worker_memory_cap_reads_a_value_and_refuses_one_under_the_floor() {
        for (value, expected) in [
            (Some("134217728"), 128 * 1024 * 1024),
            (Some(" 67108864 "), 64 * 1024 * 1024),
            (Some("1024"), 256 * 1024 * 1024),
            (Some("not-a-number"), 256 * 1024 * 1024),
            (None, 256 * 1024 * 1024),
        ] {
            assert_eq!(worker_memory_cap(value), expected, "value={value:?}");
        }
    }
}
