//! In-process SLEIGH p-code lifting.
//!
//! The SLEIGH runtime is Kuna's `kuna-sleigh` (Apache-2.0,
//! <https://github.com/noelo-Lab/kuna>, rev `c4f735f9`), a Rust port of the
//! pinned Ghidra 12.1.3 `Sleigh` translator. Around it, this module
//! reproduces what Ghidra's SLEIGH console set up for a loaded image (the
//! console this lifter replaced), so a lift here answers what it answered:
//!
//! * the language is resolved the way `SleighArchitecture` resolves it
//!   (`sleigh_arch.cc`): the spec search path is the scanned Ghidra install
//!   (`scanForSleighDirectories`) followed by the session's language
//!   directory (`-s`), every `.ldefs` on it is read in directory order, and
//!   the first `<language>` whose id matches wins; its `.sla`, processor
//!   spec and compiler spec are the first files of those names on the path;
//! * address-space truncations from the `.ldefs`, then the `<context_data>`
//!   of the processor spec and then of the compiler spec, initialise the
//!   context database (`Architecture::restoreFromSpec`);
//! * the load image holds the bytes the console's loader held:
//!   `LoadImageXml` over the mapped chunks (with its redundant-chunk removal
//!   and 512-byte zero padding), `RawLoadImage` for `load file <language>`,
//!   or the PE sections BFD presents for `load file pei-*`;
//! * context values arrive as the console's `context` command sets them, and
//!   each lifted instruction commits its own `globalset`s, as the console's
//!   `oneInstruction` did;
//! * a decoded PowerPC `bclr` with BO\[2\]=0, BH=0 and LK=0 reports its LR
//!   `BRANCHIND` as `RETURN` (the same rewrite as
//!   `native/romwright_ppc_return.hh` `PowerPcReturnEmit` in `ghidra_opt`);
//! * a constructor walk past the console's 75 parser states is bad data;
//! * `UnimplError` is `UNIMPL`, every other decode failure `BAD`.
//!
//! One console behaviour is deliberately not reproduced: its
//! `DisassemblyCache` hands back an address's earlier parse even after a
//! `globalset` commit changed the context there. A lift here always decodes
//! under the context the database holds now, as a fresh console does.
use super::{NativeRuntimeError, PcodeInstruction, PcodeOp, PcodeVarnode, Result};
use crate::native::{NativeContext, NativeImport};
use crate::session::RuntimeConfig;
use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::{IdRegistry, XmlDecode};
use kuna_base::space::AddrSpace;
use kuna_base::xml::{Element, xml_tree};
use kuna_num::opcodes::{OpCode, get_opname};
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::globalcontext::{ContextInternal, register_globalcontext_ids};
use kuna_sleigh::loadimage::LoadImage;
use kuna_sleigh::slaimage::SlaImage;
use kuna_sleigh::sleigh::Sleigh;
use kuna_sleigh::translate::{PcodeEmit, Translate};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, LazyLock, Mutex};

/// The inflated `.sla` files in use, shared by every decoder of a language
/// (`SlaImage`: the constructor templates stay in the image and each decoder
/// decodes the ones it uses). Held weakly: an image lives while a decoder
/// of its language does, in the pool or out.
static SLA_IMAGES: Mutex<Vec<(PathBuf, u64, Option<std::time::SystemTime>, std::sync::Weak<SlaImage>)>> = Mutex::new(Vec::new());

fn sla_image(path: &Path) -> Result<Arc<SlaImage>> {
    let failed = |e: &dyn std::fmt::Display| NativeRuntimeError(format!("{}: {e}", path.display()));
    let meta = std::fs::metadata(path).map_err(|e| failed(&e))?;
    let (length, modified) = (meta.len(), meta.modified().ok());
    // One parse at a time: decoders of a language start together, and all but
    // the first take the image the first made.
    let mut images = SLA_IMAGES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    images.retain(|entry| entry.3.strong_count() > 0);
    if let Some(found) = images
        .iter()
        .find(|entry| entry.0 == path && entry.1 == length && entry.2 == modified)
        .and_then(|entry| entry.3.upgrade())
    {
        return Ok(found);
    }
    let started = std::time::Instant::now();
    let bytes = std::fs::read(path).map_err(|e| failed(&e))?;
    let image = Arc::new(SlaImage::parse(&bytes).map_err(kuna)?);
    crate::native::tally::add("sla-parse", started);
    images.push((path.to_path_buf(), length, modified, Arc::downgrade(&image)));
    Ok(image)
}

fn kuna(error: KunaError) -> NativeRuntimeError {
    NativeRuntimeError(format!("SLEIGH: {error}"))
}

/// A SLEIGH translator over one loaded image, with its context state.
///
/// A lifter built through `mapped_pooled` is handed back to a process-wide
/// pool when it drops, and the next `mapped_pooled` for the same language
/// takes it, puts its context database back as the spec left it and gives it
/// the new image: decoding an image's own bytes is cheap, but decoding the
/// language's `.sla` costs more than a small image's whole analysis, and an
/// import of hundreds of programs built it thousands of times.
pub struct SleighLifter {
    core: std::mem::ManuallyDrop<LifterCore>,
    pooled: Option<Pooled>,
}

/// What a pooled lifter needs to be reused.
struct Pooled {
    key: PoolKey,
    /// The context database as it was when the spec had been applied and no
    /// image or context had been: what every use starts from.
    pristine: Box<dyn kuna_sleigh::globalcontext::ContextDatabase>,
}

/// Lifters idle between uses: bounded, so what the pool holds is a constant
/// fraction of what a run can have in flight (one decoded `.sla` each).
const POOL_CAP: usize = 16;
static POOL: Mutex<Vec<SleighLifter>> = Mutex::new(Vec::new());

/// Whether the import being analysed holds one program, so that nothing else
/// competes for the decoders idle in the pool and what a decoder keeps for a
/// next round (its parsed specs) is held for no one else.
static SINGLE_PROGRAM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn set_single_program(single: bool) {
    SINGLE_PROGRAM.store(single, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn single_program() -> bool {
    SINGLE_PROGRAM.load(std::sync::atomic::Ordering::Relaxed)
}

/// Drops every decoder idle in the pool. For an import that has finished
/// with its decoders (the last program of a container), or a small one about
/// to spend its memory elsewhere: an idle decoder holds the language's
/// tables, megabytes that the allocator would otherwise keep from whatever
/// runs next.
pub(crate) fn release_idle_decoders() {
    let idle = std::mem::take(&mut *POOL.lock().unwrap_or_else(|poisoned| poisoned.into_inner()));
    for mut lifter in idle {
        // Not back into the pool: it is being emptied.
        lifter.pooled = None;
        drop(lifter);
    }
}

impl Drop for SleighLifter {
    fn drop(&mut self) {
        // SAFETY: `core` is taken here and nowhere else, and `self` is not used again.
        let mut core = unsafe { std::mem::ManuallyDrop::take(&mut self.core) };
        let Some(pooled) = self.pooled.take() else { return };
        // Back to what the spec left, with no image and no context of its own.
        core.sleigh.set_loader(Box::new(NoImage));
        core.sleigh.reset_for_reuse(pooled.pristine.clone_for_speculation());
        let mut idle = POOL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if idle.len() < POOL_CAP {
            idle.push(SleighLifter { core: std::mem::ManuallyDrop::new(core), pooled: Some(pooled) });
        }
    }
}

/// Lifters are interchangeable when they decode the same language from the
/// same specs. (A flow decoder and a plain lifter are the same decoder in two
/// modes: `TemplateArena::set_marked`, so either takes the other's place.)
#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    specs: String,
}

/// The lifter's own state, `SleighLifter` less its pool bookkeeping.
pub struct LifterCore {
    pub(super) sleigh: Sleigh,
    pub(super) code_space: Rc<AddrSpace>,
    /// `LR` on a PowerPC language: the register the conditional-LR return
    /// rewrite compares a `BRANCHIND` target against.
    pub(super) powerpc_lr: Option<VarnodeData>,
    big_endian: bool,
    /// `unaffected`.
    unaffected: Vec<(u64, u32)>,
    /// The resolved language's `.ldefs` id and the id of the compiler tag
    /// the console used for it (`SleighArchitecture`'s `LanguageDescription`
    /// and `getCompiler`): what the Ghidra pattern constraints select by.
    pub(super) language_id: String,
    pub(super) compiler_id: String,
    /// The Ghidra install the pattern files are read from (`SLEIGHHOME`).
    pub(super) ghidra_root: PathBuf,
    /// What linkage evidence reads off the language.
    pub(super) linkage: Rc<super::linkage::LinkageEnv>,
    /// The resolved language's processor and compiler specs: where they are,
    /// and the parsed trees once something asks. The decoder's own build reads
    /// them and lets go; the reference propagation reads its calling-convention
    /// model off them, and only the decoders that propagate keep the trees.
    spec_paths: (PathBuf, PathBuf),
    pspec: std::cell::OnceCell<Rc<Element>>,
    cspec: std::cell::OnceCell<Rc<Element>>,
}

impl LifterCore {
    /// Lets go of the parsed specs (they are read again when something asks).
    pub(super) fn release_specs(&mut self) {
        self.pspec.take();
        self.cspec.take();
    }

    /// The processor spec, parsed on first use.
    pub(super) fn pspec(&self) -> Result<&Rc<Element>> {
        if let Some(spec) = self.pspec.get() {
            return Ok(spec);
        }
        let spec = read_spec(&self.spec_paths.0, "processor_spec")?;
        Ok(self.pspec.get_or_init(|| spec))
    }

    /// The compiler spec, parsed on first use.
    pub(super) fn cspec(&self) -> Result<&Rc<Element>> {
        if let Some(spec) = self.cspec.get() {
            return Ok(spec);
        }
        let spec = read_spec(&self.spec_paths.1, "compiler_spec")?;
        Ok(self.cspec.get_or_init(|| spec))
    }
}

// SAFETY: every `Rc` and `RefCell` reachable from a lifter belongs to the
// lifter's own object graph (the translator, its spaces, its load image and
// context database); none is cloned out or shared with another value, and the
// lifter is not `Sync`. Moving the whole graph to another thread therefore
// never leaves a reference count touched from two threads. Kuna's one
// thread-local (`kuna_base::space`'s fspec registry) belongs to the
// decompiler and is never reached by decoding.
unsafe impl Send for SleighLifter {}

impl std::ops::Deref for SleighLifter {
    type Target = LifterCore;
    fn deref(&self) -> &LifterCore {
        &self.core
    }
}

impl std::ops::DerefMut for SleighLifter {
    fn deref_mut(&mut self) -> &mut LifterCore {
        &mut self.core
    }
}

impl SleighLifter {
    /// The lifter for a mapped image: `LoadImageXml`'s byte view of the
    /// image's chunks, under the image's
    /// `language:compiler`, with the image's own mode contexts set.
    pub fn mapped(cfg: &RuntimeConfig, import: &NativeImport) -> Result<Self> {
        let archid = Self::archid(import);
        let mut lifter = Self::build(cfg, &archid, Self::mapped_image(import))?;
        lifter.set_contexts(&import.contexts)?;
        Ok(lifter)
    }

    fn archid(import: &NativeImport) -> String {
        format!("{}:{}", import.language, import.compiler.as_deref().unwrap_or("default"))
    }

    /// The load image of a mapped import, built against the translator's spaces.
    fn mapped_image(import: &NativeImport) -> impl FnOnce(&Sleigh) -> Result<Box<dyn LoadImage>> + '_ {
        move |sleigh| {
            let ram = sleigh
                .base()
                .manager()
                .get_space_by_name("ram")
                .cloned()
                .ok_or_else(|| NativeRuntimeError("mapped image: no ram space".into()))?;
            Ok(Box::new(XmlImage::new(ram, super::image::chunks(import))))
        }
    }

    /// `mapped` with the whole `.sla` decoded into this lifter's own tables.
    #[cfg(test)]
    fn mapped_eager(cfg: &RuntimeConfig, import: &NativeImport) -> Result<Self> {
        let archid = Self::archid(import);
        let mut lifter = Self::build_untimed(cfg, &archid, Self::mapped_image(import), true)?;
        lifter.set_contexts(&import.contexts)?;
        Ok(lifter)
    }

    /// `mapped`, from the pool when a lifter of this language is idle in it,
    /// and returned to it when dropped. (A flow decoder and a plain lifter are
    /// one decoder in two modes, so the pool's flow decoder serves a plain
    /// lifter and the other way round: `TemplateArena::set_marked`.)
    ///
    /// The pool moves a lifter between threads, which is sound only when
    /// nothing outside the lifter still holds a reference count into its
    /// object graph when it drops (see the `Send` note above). Callers hold
    /// that: the decoder wrappers drop what they cloned out of the lifter
    /// (`SleighFlow::emit`, the propagation lane's spaces and templates)
    /// before the lifter itself.
    pub fn mapped_pooled(cfg: &RuntimeConfig, import: &NativeImport) -> Result<Self> {
        let lifter = Self::acquire(cfg, import)?;
        // The pool may hand back a flow decoder: read the language's own
        // templates.
        lifter.sleigh.base().set_marked_templates(false);
        Ok(lifter)
    }

    /// A decoder of the image's language, from the pool when one is idle, in
    /// whatever mode it was left (the caller sets it).
    pub(super) fn acquire(cfg: &RuntimeConfig, import: &NativeImport) -> Result<Self> {
        // `ROMWRIGHT_NO_DECODER_POOL`: every decoder built from its `.sla`, as
        // before the pool (the switch the pooled path is measured against).
        if std::env::var_os("ROMWRIGHT_NO_DECODER_POOL").is_some() {
            return Self::mapped(cfg, import);
        }
        let archid = Self::archid(import);
        let key = PoolKey { specs: format!("{:?}|{archid}", spec_paths(cfg)) };
        let reused = {
            let mut idle = POOL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let at = idle.iter().rposition(|lifter| lifter.pooled.as_ref().is_some_and(|pooled| pooled.key == key));
            at.map(|at| idle.swap_remove(at))
        };
        if let Some(mut lifter) = reused {
            crate::native::tally::add_value("decoder-reuses", 1.0);
            let image = Self::mapped_image(import)(&lifter.sleigh)?;
            lifter.sleigh.set_loader(image);
            lifter.set_contexts(&import.contexts)?;
            return Ok(lifter);
        }
        let mut lifter = Self::build(cfg, &archid, Self::mapped_image(import))?;
        let pristine = lifter.sleigh.with_context_db_mut(|db| db.clone_for_speculation());
        lifter.pooled = Some(Pooled { key, pristine });
        lifter.set_contexts(&import.contexts)?;
        Ok(lifter)
    }

    /// The lifter for the image at `binary`:
    /// an ELF or DOL through its mapped import, a PE through BFD's view of
    /// its sections, anything else as a raw image under the configured
    /// language at `base` (an x86 language gets no `adjust vma`).
    pub fn file(cfg: &RuntimeConfig, binary: &Path, base: u64) -> Result<Self> {
        if let Some(import) = super::image::parse_binary(cfg, binary)? {
            // The image names its own language, and an installed language
            // the Ghidra scan does not reach (the vendored Gekko, Xenon and
            // PSX definitions) lives in the directory that id belongs to.
            let mut configured = cfg.clone();
            configured.language_id = import.language.clone();
            if let Ok(Some(directory)) =
                crate::architecture::directory_for_id(&cfg.ghidra_install, &import.language)
            {
                configured.language_dir = directory;
            }
            return Self::mapped(&configured, &import);
        }
        let target = super::bfd_target_for(&cfg.language_id, binary)?;
        let target = target.as_str();
        let adjust = if cfg.language_id.starts_with("x86:") { 0 } else { base };
        let bytes = std::fs::read(binary)
            .map_err(|e| NativeRuntimeError(format!("lift image read: {e}")))?;
        if let Some(archid) = bfd_archid(target) {
            let sections = pe_sections(&bytes, target == "pei-x86-64")?;
            return Self::build(cfg, archid, |sleigh| {
                let mut image = BfdImage::new(bytes, sections);
                image.adjust(AddrSpace::address_to_byte(
                    adjust,
                    default_code_space(sleigh)?.get_word_size(),
                ));
                Ok(Box::new(image))
            });
        }
        Self::build(cfg, target, |sleigh| {
            let vma = AddrSpace::address_to_byte(adjust, default_code_space(sleigh)?.get_word_size());
            Ok(Box::new(RawImage { bytes, vma }))
        })
    }

    fn build(
        cfg: &RuntimeConfig,
        archid: &str,
        image: impl FnOnce(&Sleigh) -> Result<Box<dyn LoadImage>>,
    ) -> Result<Self> {
        let started = std::time::Instant::now();
        let built = Self::build_untimed(cfg, archid, image, std::env::var_os("ROMWRIGHT_EAGER_SLA").is_some());
        crate::native::tally::add("decoder-build", started);
        crate::native::tally::add_value("decoder-builds", 1.0);
        built
    }

    /// `eager`: decode the whole `.sla` into this lifter's own tables, as
    /// before the shared image (`ROMWRIGHT_EAGER_SLA`; what the lazy decode
    /// is tested against).
    fn build_untimed(
        cfg: &RuntimeConfig,
        archid: &str,
        image: impl FnOnce(&Sleigh) -> Result<Box<dyn LoadImage>>,
        eager: bool,
    ) -> Result<Self> {
        let language = resolve_language(cfg, archid)?;
        let sla = if eager { None } else { Some(sla_image(&language.sla)?) };
        let pspec = read_spec(&language.pspec, "processor_spec")?;
        let cspec = read_spec(&language.cspec, "compiler_spec")?;
        let mut sleigh = Sleigh::new(Box::new(NoImage), Box::new(ContextInternal::new()));
        let sla_started = std::time::Instant::now();
        match sla {
            Some(image) => sleigh.initialize_from_image(image).map_err(kuna)?,
            None => {
                let bytes = std::fs::read(&language.sla)
                    .map_err(|e| NativeRuntimeError(format!("{}: {e}", language.sla.display())))?;
                sleigh.initialize_from_sla(&bytes).map_err(kuna)?;
            }
        }
        crate::native::tally::add("decoder-sla-init", sla_started);
        for (space, size) in &language.truncations {
            sleigh
                .base()
                .manager()
                .truncate_space(space, *size)
                .map_err(kuna)?;
        }
        // `<tracked_set>` rows name registers.
        sleigh.install_register_lookup().map_err(kuna)?;
        let mut registry = IdRegistry::with_base_ids();
        register_globalcontext_ids(&mut registry);
        for spec in [&pspec, &cspec] {
            for data in spec
                .get_children()
                .iter()
                .filter(|child| child.get_name() == "context_data")
            {
                let mut decoder =
                    XmlDecode::new_with_root(sleigh.base().manager(), &registry, data, 0);
                sleigh
                    .with_context_db_mut(|db| db.decode_from_spec(&mut decoder))
                    .map_err(kuna)?;
            }
        }
        let loader = image(&sleigh)?;
        sleigh.set_loader(loader);
        let code_space = default_code_space(&sleigh)?;
        let powerpc_lr = if language.processor == "PowerPC" {
            Some(sleigh.get_register_varnode(b"LR").map_err(kuna)?)
        } else {
            None
        };
        let big_endian = sleigh.translate_base().is_big_endian();
        let unaffected = unaffected_registers(&sleigh, &cspec);
        let data_space = pspec_data_space(&sleigh, &pspec, &code_space);
        let linkage = Rc::new(super::linkage::LinkageEnv::new(&mut sleigh, Rc::clone(&code_space), data_space));
        Ok(Self {
            core: std::mem::ManuallyDrop::new(LifterCore {
                sleigh,
                code_space,
                powerpc_lr,
                big_endian,
                unaffected,
                language_id: language.id,
                compiler_id: language.compiler,
                ghidra_root: cfg.ghidra_install.clone(),
                linkage,
                spec_paths: (language.pspec, language.cspec),
                pspec: std::cell::OnceCell::new(),
                cspec: std::cell::OnceCell::new(),
            }),
            pooled: None,
        })
    }

    /// The registers a call leaves as it found them, as `(register-space
    /// offset, size)`: the compiler spec's default prototype's
    /// `<unaffected>` list (r4-r11 and sp on ARM, r1/r2/r13-r31 on PowerPC,
    /// s0-s8/sp/gp on MIPS). Ghidra's decompiler reads the same list.
    pub fn unaffected(&self) -> &[(u64, u32)] {
        &self.unaffected
    }

    /// Sets context variables from their addresses on, as the console's
    /// `context <name> <address> <value>` does (`ContextDatabase::setVariable`).
    pub fn set_contexts(&mut self, contexts: &[NativeContext]) -> Result<()> {
        for context in contexts {
            let address = self.address(context.address);
            self.sleigh
                .with_context_db_mut(|db| {
                    // `(uintm)value`: the console truncates to a context word.
                    db.set_variable(context.name.as_bytes(), &address, context.value as u32)
                })
                .map_err(kuna)?;
        }
        Ok(())
    }

    /// The names of the language's user-defined p-code operations, indexed as
    /// the first input of a `CALLOTHER`.
    pub fn user_op_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        self.sleigh.get_user_op_names(&mut names);
        names
    }

    /// The p-code of the instruction at each address, in order, as SLEIGH
    /// emits it.
    pub fn lift(&mut self, addresses: &[u64]) -> Vec<PcodeInstruction> {
        let mut emit = Collect { ops: Vec::new() };
        addresses
            .iter()
            .map(|&address| {
                let at = self.address(address);
                emit.ops.clear();
                let decoded = if self.exhausts_parser_states(&at) {
                    Err(KunaError::bad_data("Parser state exhausted"))
                } else {
                    self.sleigh.one_instruction(&mut emit, &at)
                };
                let address = at.get_offset();
                match decoded {
                    Ok(length) => {
                        let mut ops = std::mem::take(&mut emit.ops);
                        if length == 4 && self.conditional_lr_return(&at) {
                            let lr = self.powerpc_lr.as_ref().expect("PowerPC LR");
                            for op in &mut ops {
                                if op.opcode == "BRANCHIND"
                                    && op.inputs.len() == 1
                                    && op.inputs[0].offset == lr.offset
                                    && op.inputs[0].size == lr.size
                                    && lr.space.as_ref().is_some_and(|space| {
                                        space.get_name() == op.inputs[0].space
                                    })
                                {
                                    op.opcode = "RETURN".into();
                                }
                            }
                        }
                        PcodeInstruction {
                            address,
                            length: u8::try_from(length).unwrap_or(1),
                            ops,
                            error: None,
                        }
                    }
                    Err(error) => PcodeInstruction {
                        address,
                        length: 1,
                        ops: Vec::new(),
                        error: Some(
                            match error {
                                KunaError::Unimpl { .. } => "UNIMPL",
                                _ => "BAD",
                            }
                            .into(),
                        ),
                    },
                }
            })
            .collect()
    }

    /// The console's parser holds 75 constructor states, the base and 74
    /// operands (`DisassemblyCache`, sleigh.cc:457), and a walk needing more
    /// is bad data (`ParserContext::allocateOperand` in
    /// `native/ghidra-opt-sleigh.patch`); Kuna grows its arena instead. Its
    /// operand views are one per allocated operand state. Checked before
    /// decoding, as the console fails before any context commit, and after
    /// the alignment check `oneInstruction` makes before it parses (an
    /// unaligned address is `UNIMPL` however many states its bytes need).
    pub(super) fn exhausts_parser_states(&self, at: &Address) -> bool {
        const OPERAND_STATES: usize = 74;
        let alignment = self.sleigh.translate_base().get_alignment();
        if alignment > 1 && at.get_offset() % alignment as u64 != 0 {
            return false;
        }
        self.sleigh
            .instruction_mask(at)
            .is_ok_and(|mask| mask.operands.len() > OPERAND_STATES)
    }

    /// A console address: an offset in the default code space, scaled to
    /// bytes as `parse_machaddr` scales it.
    pub(super) fn address(&self, address: u64) -> Address {
        Address::new(
            Rc::clone(&self.code_space),
            AddrSpace::address_to_byte(address, self.code_space.get_word_size()),
        )
    }

    /// A PowerPC `bclr` whose BO\[2\] is clear (it decrements CTR) with BH=0
    /// and LK=0: stock SLEIGH emits its LR exit as `BRANCHIND`.
    pub(super) fn conditional_lr_return(&self, at: &Address) -> bool {
        if self.powerpc_lr.is_none() {
            return false;
        }
        let mut bytes = [0u8; 4];
        if self.sleigh.loader_rc().borrow_mut().load_fill(&mut bytes, at).is_err() {
            return false;
        }
        let word = if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };
        word & 0xfc80_ffff == 0x4c00_0020
    }
}

/// The default data space: the processor spec's `<data_space space=..>`
/// (`Architecture::parseProcessorConfig`), else the code space
/// (`AddrSpaceManager::setDefaultCodeSpace`).
fn pspec_data_space(sleigh: &Sleigh, pspec: &Element, code_space: &Rc<AddrSpace>) -> Rc<AddrSpace> {
    pspec
        .get_children()
        .iter()
        .filter(|child| child.get_name() == "data_space")
        .filter_map(|child| child.get_attribute_value("space").ok())
        .filter_map(|name| {
            sleigh
                .base()
                .manager()
                .get_space_by_name(&String::from_utf8_lossy(name))
                .cloned()
        })
        .last()
        .unwrap_or_else(|| Rc::clone(code_space))
}

fn default_code_space(sleigh: &Sleigh) -> Result<Rc<AddrSpace>> {
    sleigh
        .base()
        .manager()
        .get_default_code_space()
        .cloned()
        .ok_or_else(|| NativeRuntimeError("SLEIGH: no default code space".into()))
}

/// Collects one instruction's operations as the console's `PcodePrinter`
/// wrote them: the space by name, opcodes by the translator's names.
struct Collect {
    ops: Vec<PcodeOp>,
}

impl PcodeEmit for Collect {
    fn dump(
        &mut self,
        _addr: &Address,
        opc: OpCode,
        outvar: Option<&VarnodeData>,
        vars: &[VarnodeData],
    ) {
        self.ops.push(PcodeOp {
            opcode: opcode_name(opc).into(),
            output: outvar.map(varnode),
            inputs: vars.iter().map(varnode).collect(),
        });
    }
}

fn varnode(data: &VarnodeData) -> PcodeVarnode {
    PcodeVarnode {
        space: data
            .space
            .as_ref()
            .map(|space| space.get_name().to_string())
            .unwrap_or_default(),
        offset: data.offset,
        size: data.size,
    }
}

/// Ghidra's `get_opname`: Kuna renamed slot 71 (`EXTRACT`), which SLEIGH
/// semantics cannot emit, to its own `ZPULL`.
pub(super) fn opcode_name(opc: OpCode) -> &'static str {
    match opc {
        OpCode::CPUI_ZPULL => "EXTRACT",
        other => get_opname(other),
    }
}

/// Stands in until the image is built against the translator's spaces.
struct NoImage;

impl LoadImage for NoImage {
    fn get_file_name(&self) -> &str {
        ""
    }
    fn load_fill(&mut self, _ptr: &mut [u8], _addr: &Address) -> KunaResult<()> {
        Err(KunaError::data_unavail("no load image"))
    }
    fn get_arch_type(&self) -> Vec<u8> {
        Vec::new()
    }
    fn adjust_vma(&mut self, _adjust: i64) {}
}

/// `LoadImageXml` (loadimage_xml.cc): chunks keyed by their `ram` address,
/// a later chunk at the same address replacing an earlier one, then
/// `pad()`.
struct XmlImage {
    ram: Rc<AddrSpace>,
    chunks: BTreeMap<u64, Vec<u8>>,
}

impl XmlImage {
    fn new<'a>(ram: Rc<AddrSpace>, chunks: impl Iterator<Item = (u64, &'a [u8])>) -> Self {
        let mut image = Self {
            ram,
            chunks: BTreeMap::new(),
        };
        for (offset, bytes) in chunks {
            image.chunks.insert(offset, bytes.to_vec());
        }
        image.pad();
        image
    }

    /// `LoadImageXml::pad`: drop chunks a previous one fully covers, then
    /// follow each chunk with up to 512 zero bytes, stopping at the next
    /// chunk and the end of the space.
    fn pad(&mut self) {
        let mut last: Option<u64> = None;
        let keys: Vec<u64> = self.chunks.keys().copied().collect();
        for key in keys {
            if let Some(previous) = last {
                let end1 = previous
                    .wrapping_add(self.chunks[&previous].len() as u64)
                    .wrapping_sub(1);
                let end2 = key
                    .wrapping_add(self.chunks[&key].len() as u64)
                    .wrapping_sub(1);
                if end1 >= end2 {
                    self.chunks.remove(&key);
                    continue;
                }
            }
            last = Some(key);
        }
        let highest = self.ram.get_highest();
        let mut padding = Vec::new();
        let mut entries = self.chunks.iter().peekable();
        while let Some((&first, bytes)) = entries.next() {
            let end = self.ram.wrap_offset(first.wrapping_add(bytes.len() as u64));
            if end < first {
                continue; // All the way to the end of the space.
            }
            let mut size = 512u64.min(highest.wrapping_sub(end).wrapping_add(1));
            if let Some(&(&next, _)) = entries.peek() {
                if end >= next {
                    continue;
                }
                size = size.min(next - end);
            }
            padding.push((end, size));
        }
        for (end, size) in padding {
            self.chunks
                .entry(end)
                .or_default()
                .resize(usize::try_from(size).unwrap_or(512), 0);
        }
    }
}

impl LoadImage for XmlImage {
    fn get_file_name(&self) -> &str {
        ""
    }

    /// `LoadImageXml::loadFill`: contiguous chunks from the one at or before
    /// the address; any byte no chunk holds fails the whole read.
    fn load_fill(&mut self, ptr: &mut [u8], addr: &Address) -> KunaResult<()> {
        let unmapped = || KunaError::data_unavail(format!("Bytes at {:#x} are not mapped", addr.get_offset()));
        if !addr
            .get_space()
            .is_some_and(|space| Rc::ptr_eq(space, &self.ram))
        {
            return Err(unmapped());
        }
        let mut current = addr.get_offset();
        let start = self
            .chunks
            .range(..=current)
            .next_back()
            .map(|(&key, _)| key)
            .or_else(|| self.chunks.keys().next().copied());
        let Some(start) = start else {
            return Err(unmapped());
        };
        let mut filled = 0;
        for (&key, chunk) in self.chunks.range(start..) {
            if filled == ptr.len() {
                break;
            }
            let over = self.ram.wrap_offset(current.wrapping_sub(key));
            if over >= chunk.len() as u64 {
                return Err(unmapped());
            }
            let over = over as usize;
            let take = (chunk.len() - over).min(ptr.len() - filled);
            ptr[filled..filled + take].copy_from_slice(&chunk[over..over + take]);
            filled += take;
            current = self.ram.wrap_offset(current.wrapping_add(take as u64));
        }
        if filled < ptr.len() {
            return Err(unmapped());
        }
        Ok(())
    }

    fn get_arch_type(&self) -> Vec<u8> {
        Vec::new()
    }

    fn adjust_vma(&mut self, _adjust: i64) {}
}

/// `RawLoadImage` (loadimage.cc): the file at `vma`; a read that starts in
/// the file zero-fills past its end, one that starts outside fails.
struct RawImage {
    bytes: Vec<u8>,
    vma: u64,
}

impl LoadImage for RawImage {
    fn get_file_name(&self) -> &str {
        ""
    }

    fn load_fill(&mut self, ptr: &mut [u8], addr: &Address) -> KunaResult<()> {
        let size = self.bytes.len() as u64;
        let current = addr.get_offset().wrapping_sub(self.vma);
        if current >= size {
            return Err(KunaError::data_unavail(format!(
                "Unable to load {} bytes at {:#x}",
                ptr.len(),
                addr.get_offset()
            )));
        }
        let start = current as usize;
        let take = (self.bytes.len() - start).min(ptr.len());
        ptr[..take].copy_from_slice(&self.bytes[start..start + take]);
        ptr[take..].fill(0);
        Ok(())
    }

    fn get_arch_type(&self) -> Vec<u8> {
        Vec::new()
    }

    fn adjust_vma(&mut self, _adjust: i64) {}
}

/// The language a `load file <target>` names through BFD
/// (`BfdArchitecture::resolveArchitecture`): only PE images reach BFD.
fn bfd_archid(target: &str) -> Option<&'static str> {
    match target {
        "pei-i386" => Some("x86:LE:32:default:windows"),
        "pei-x86-64" => Some("x86:LE:64:default:windows"),
        _ => None,
    }
}

/// One BFD section of a PE image.
struct BfdSection {
    vma: u64,
    size: u64,
    /// File offset of the contents; `None` reads as zeros.
    file: Option<u64>,
}

/// The sections BFD's PE reader makes (`coff_swap_scnhdr_in`): the section
/// table in order, `ImageBase` added to every non-zero `VirtualAddress`, and
/// the size cut to `VirtualSize` where the raw data is padded past it or an
/// uninitialized section has none.
fn pe_sections(bytes: &[u8], sixty_four: bool) -> Result<Vec<BfdSection>> {
    use object::LittleEndian as LE;
    use object::Object as _;
    use object::read::pe::{ImageNtHeaders, PeFile32, PeFile64};
    fn sections<H: ImageNtHeaders>(file: &object::read::pe::PeFile<'_, H>) -> Vec<BfdSection> {
        let base = file.relative_address_base();
        file.section_table()
            .iter()
            .map(|header| {
                let virtual_address = u64::from(header.virtual_address.get(LE));
                let virtual_size = u64::from(header.virtual_size.get(LE));
                let raw_size = u64::from(header.size_of_raw_data.get(LE));
                let uninitialized = header.characteristics.get(LE)
                    & object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
                    != 0;
                let size = if virtual_size > 0
                    && ((uninitialized && raw_size == 0) || raw_size > virtual_size)
                {
                    virtual_size
                } else {
                    raw_size
                };
                let pointer = u64::from(header.pointer_to_raw_data.get(LE));
                BfdSection {
                    vma: if virtual_address == 0 {
                        0
                    } else {
                        base.wrapping_add(virtual_address)
                    },
                    size,
                    file: (pointer != 0 && raw_size != 0).then_some(pointer),
                }
            })
            .collect()
    }
    let error = |e: object::read::Error| NativeRuntimeError(format!("PE image: {e}"));
    match object::FileKind::parse(bytes).map_err(error)? {
        object::FileKind::Pe32 if !sixty_four => Ok(sections(&PeFile32::parse(bytes).map_err(error)?)),
        object::FileKind::Pe64 if sixty_four => Ok(sections(&PeFile64::parse(bytes).map_err(error)?)),
        _ => Err(NativeRuntimeError("BFD PE target on a non-PE image".into())),
    }
}

/// `LoadImageBfd` (loadimage_bfd.cc) over PE sections: a read must start
/// inside a section; past it, other sections' bytes follow and every
/// unmapped byte reads as zero.
///
/// The console reads through a 512-byte buffer it does not invalidate on a
/// failed read, so there a read near an earlier unmapped one returns whatever
/// the buffer last held; that depends on every decode before it and is not
/// reproduced. A read that does not reuse the buffer answers exactly this.
struct BfdImage {
    bytes: Vec<u8>,
    sections: Vec<BfdSection>,
}

impl BfdImage {
    fn new(bytes: Vec<u8>, sections: Vec<BfdSection>) -> Self {
        Self { bytes, sections }
    }

    /// `LoadImageBfd::adjustVma`: every section moves.
    fn adjust(&mut self, adjust: u64) {
        for section in &mut self.sections {
            section.vma = section.vma.wrapping_add(adjust);
        }
    }

    /// `findSection`: the first section holding `offset`, else the lowest
    /// one above it.
    fn find_section(&self, offset: u64) -> Option<&BfdSection> {
        self.sections
            .iter()
            .find(|section| offset >= section.vma && offset < section.vma.wrapping_add(section.size))
            .or_else(|| {
                self.sections
                    .iter()
                    .filter(|section| section.vma > offset)
                    .fold(None, |champion: Option<&BfdSection>, section| match champion {
                        Some(best) if best.vma <= section.vma => Some(best),
                        _ => Some(section),
                    })
            })
    }
}

impl LoadImage for BfdImage {
    fn get_file_name(&self) -> &str {
        ""
    }

    fn load_fill(&mut self, ptr: &mut [u8], addr: &Address) -> KunaResult<()> {
        let mut current = addr.get_offset();
        let mut offset = 0usize;
        while offset < ptr.len() {
            let remaining = ptr.len() - offset;
            let Some(section) = self.find_section(current) else {
                if offset == 0 {
                    break;
                }
                ptr[offset..].fill(0);
                return Ok(());
            };
            let read = if section.vma > current {
                if offset == 0 {
                    break;
                }
                let read = (section.vma - current).min(remaining as u64) as usize;
                ptr[offset..offset + read].fill(0);
                read
            } else {
                let end = section.vma.wrapping_add(section.size);
                let read = (remaining as u64).min(end - current) as usize;
                let within = current - section.vma;
                let source = section.file.and_then(|file| {
                    let start = usize::try_from(file.checked_add(within)?).ok()?;
                    self.bytes.get(start..start.checked_add(read)?)
                });
                match source {
                    Some(source) => ptr[offset..offset + read].copy_from_slice(source),
                    None => ptr[offset..offset + read].fill(0),
                }
                read
            };
            offset += read;
            current = current.wrapping_add(read as u64);
        }
        if offset < ptr.len() {
            return Err(KunaError::data_unavail(format!(
                "Unable to load {} bytes at {:#x}",
                ptr.len() - offset,
                addr.get_offset()
            )));
        }
        Ok(())
    }

    fn get_arch_type(&self) -> Vec<u8> {
        Vec::new()
    }

    fn adjust_vma(&mut self, _adjust: i64) {}
}

/// One `<language>` of an `.ldefs` file (`LanguageDescription`).
struct LanguageDescription {
    id: String,
    processor: String,
    slafile: String,
    processorspec: String,
    /// `(id, spec)` per `<compiler>`.
    compilers: Vec<(String, String)>,
    /// `(space, size)` per `<truncate_space>`.
    truncations: Vec<(String, u32)>,
}

/// The files and facts one resolved language decodes with.
struct Language {
    id: String,
    compiler: String,
    processor: String,
    sla: PathBuf,
    pspec: PathBuf,
    cspec: PathBuf,
    truncations: Vec<(String, u32)>,
}

fn attribute(element: &Element, name: &str) -> Result<String> {
    element
        .get_attribute_value(name)
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .map_err(kuna)
}

/// `LanguageDescription::decode` over every `<language>` of one `.ldefs`.
fn language_descriptions(ldefs: &Path, out: &mut Vec<LanguageDescription>) -> Result<()> {
    let Ok(bytes) = std::fs::read(ldefs) else {
        return Ok(());
    };
    // An unparsable file is a warning to the console, not a failure.
    let Ok(document) = xml_tree(&bytes) else {
        return Ok(());
    };
    for language in document
        .get_root()
        .get_children()
        .iter()
        .filter(|child| child.get_name() == "language")
    {
        let mut description = LanguageDescription {
            id: attribute(language, "id")?,
            processor: attribute(language, "processor")?,
            slafile: attribute(language, "slafile")?,
            processorspec: attribute(language, "processorspec")?,
            compilers: Vec::new(),
            truncations: Vec::new(),
        };
        for child in language.get_children().iter() {
            match child.get_name() {
                "compiler" => description
                    .compilers
                    .push((attribute(child, "id")?, attribute(child, "spec")?)),
                "truncate_space" => {
                    let size = attribute(child, "size")?;
                    let size = parse_c_integer(&size).ok_or_else(|| {
                        NativeRuntimeError(format!("{}: bad truncate_space size", ldefs.display()))
                    })?;
                    description
                        .truncations
                        .push((attribute(child, "space")?, size as u32));
                }
                _ => {}
            }
        }
        out.push(description);
    }
    Ok(())
}

/// An integer as `strtoul(.., 0)` reads one: hex after `0x`, octal after a
/// leading `0`, decimal otherwise.
fn parse_c_integer(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if text.len() > 1 && text.starts_with('0') {
        u64::from_str_radix(&text[1..], 8).ok()
    } else {
        text.parse().ok()
    }
}

/// Every description on one search path, read once per process as the
/// console reads them once (`collectSpecFiles`).
fn descriptions(paths: &[PathBuf]) -> Result<Arc<Vec<LanguageDescription>>> {
    type Cache = Mutex<HashMap<Vec<PathBuf>, Arc<Vec<LanguageDescription>>>>;
    static CACHE: LazyLock<Cache> = LazyLock::new(Default::default);
    let cache = &*CACHE;
    if let Some(found) = cache
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(paths)
    {
        return Ok(Arc::clone(found));
    }
    let mut found = Vec::new();
    for path in paths {
        for ldefs in match_list_dir(path, ".ldefs") {
            language_descriptions(&ldefs, &mut found)?;
        }
    }
    let found = Arc::new(found);
    cache
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(paths.to_vec(), Arc::clone(&found));
    Ok(found)
}

/// `SleighArchitecture::resolveArchitecture` + `buildSpecFile` for the
/// language an architecture id names.
fn resolve_language(cfg: &RuntimeConfig, archid: &str) -> Result<Language> {
    let paths = spec_paths(cfg);
    let archid = archid
        .strip_prefix("binary-")
        .or_else(|| archid.strip_prefix("default-"))
        .unwrap_or(archid);
    let archid = normalize_architecture(archid)?;
    let (baseid, compiler) = archid.rsplit_once(':').expect("normalized id has fields");
    let all = descriptions(&paths)?;
    let language = all
        .iter()
        .find(|language| language.id == baseid)
        .ok_or_else(|| NativeRuntimeError(format!("No sleigh specification for {baseid}")))?;
    let (compiler_id, spec) = language
        .compilers
        .iter()
        .find(|(id, _)| id == compiler)
        .or_else(|| language.compilers.iter().find(|(id, _)| id == "default"))
        .or_else(|| language.compilers.first())
        .map(|(id, spec)| (id.as_str(), spec.as_str()))
        .ok_or_else(|| NativeRuntimeError(format!("{baseid} declares no compiler")))?;
    let find = |name: &str| {
        find_file(&paths, name)
            .ok_or_else(|| NativeRuntimeError(format!("Could not find {name} for {archid}")))
    };
    Ok(Language {
        id: language.id.clone(),
        compiler: compiler_id.to_owned(),
        processor: language.processor.clone(),
        sla: find(&language.slafile)?,
        pspec: find(&language.processorspec)?,
        cspec: find(spec)?,
        truncations: language.truncations.clone(),
    })
}

/// `SleighArchitecture::normalizeArchitecture`.
fn normalize_architecture(name: &str) -> Result<String> {
    let colons: Vec<usize> = name
        .char_indices()
        .skip(1)
        .filter(|&(_, c)| c == ':')
        .map(|(index, _)| index)
        .take(4)
        .collect();
    if colons.len() != 3 && colons.len() != 4 {
        return Err(NativeRuntimeError(format!(
            "Architecture string does not look like sleigh id: {name}"
        )));
    }
    let processor = &name[..colons[0]];
    let endian = &name[colons[0] + 1..colons[1]];
    let size = &name[colons[1] + 1..colons[2]];
    let (variant, compiler) = if colons.len() == 4 {
        (&name[colons[2] + 1..colons[3]], &name[colons[3] + 1..])
    } else {
        (&name[colons[2] + 1..], "default")
    };
    let processor = if processor.contains("386") { "x86" } else { processor };
    let endian = if endian.contains("big") {
        "BE"
    } else if endian.contains("little") {
        "LE"
    } else {
        endian
    };
    let mut size = size.to_string();
    if let Some(at) = size.find("bit") {
        size.replace_range(at..at + 3, "");
    }
    if let Some(at) = size.find('-') {
        size.remove(at);
    }
    Ok(format!("{processor}:{endian}:{size}:{variant}:{compiler}"))
}

/// The spec search path of `SleighArchitecture`: the scanned Ghidra install
/// (`SLEIGHHOME`, here `RuntimeConfig::ghidra_install`), then the language
/// directory (`-s`).
fn spec_paths(cfg: &RuntimeConfig) -> Vec<PathBuf> {
    let mut paths = scan_for_sleigh_directories(&cfg.ghidra_install);
    paths.push(cfg.language_dir.clone());
    paths
}

/// `FileManage::findFile`.
fn find_file(paths: &[PathBuf], name: &str) -> Option<PathBuf> {
    let readable = |path: &Path| std::fs::File::open(path).is_ok();
    if name.starts_with('/') {
        let path = PathBuf::from(name);
        return readable(&path).then_some(path);
    }
    paths
        .iter()
        .map(|path| path.join(name))
        .find(|path| readable(path))
}

/// `FileManage::matchListDir`: entries ending in `suffix`, no dot files, in
/// directory order.
fn match_list_dir(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.ends_with(suffix) && !name.starts_with('.')
        })
        .map(|entry| entry.path())
        .collect()
}

/// `FileManage::directoryList`: subdirectories (symlinks followed), no dot
/// directories, in directory order.
fn directory_list(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let directory = match entry.file_type() {
                Ok(kind) if kind.is_dir() => true,
                Ok(kind) if kind.is_symlink() => entry.path().is_dir(),
                Ok(_) => false,
                Err(_) => entry.path().is_dir(),
            };
            directory && !entry.file_name().to_string_lossy().starts_with('.')
        })
        .map(|entry| entry.path())
        .collect()
}

/// `FileManage::scanDirectoryRecursive`.
pub(super) fn scan_directory_recursive(out: &mut Vec<PathBuf>, name: &str, root: &Path, depth: u32) {
    if depth == 0 {
        return;
    }
    for path in directory_list(root) {
        if path.file_name().is_some_and(|base| base == name) {
            out.push(path);
        } else {
            scan_directory_recursive(out, name, &path, depth - 1);
        }
    }
}

/// `SleighArchitecture::scanForSleighDirectories`.
fn scan_for_sleigh_directories(root: &Path) -> Vec<PathBuf> {
    let mut ghidra = Vec::new();
    scan_directory_recursive(&mut ghidra, "Ghidra", root, 2);
    let mut processors = Vec::new();
    for dir in &ghidra {
        scan_directory_recursive(&mut processors, "Processors", dir, 1);
        scan_directory_recursive(&mut processors, "contrib", dir, 1);
    }
    let mut languages = Vec::new();
    if !processors.is_empty() {
        let modules: Vec<PathBuf> = processors.iter().flat_map(|dir| directory_list(dir)).collect();
        let mut data = Vec::new();
        for module in &modules {
            scan_directory_recursive(&mut data, "data", module, 1);
        }
        let mut found = Vec::new();
        for dir in &data {
            scan_directory_recursive(&mut found, "languages", dir, 1);
        }
        languages.extend(found.iter().cloned());
        for dir in &found {
            languages.extend(directory_list(dir));
        }
    }
    if languages.is_empty() {
        languages.push(root.to_path_buf());
    }
    languages
}

/// A spec file's root element, as `DocumentStorage::openDocument` reads it.
fn read_spec(path: &Path, root: &str) -> Result<Rc<Element>> {
    let bytes = std::fs::read(path)
        .map_err(|e| NativeRuntimeError(format!("{}: {e}", path.display())))?;
    let document = xml_tree(&bytes).map_err(kuna)?;
    let element = Rc::clone(document.get_root());
    if element.get_name() != root {
        return Err(NativeRuntimeError(format!(
            "{}: no <{root}> tag",
            path.display()
        )));
    }
    Ok(element)
}

/// `SleighLifter::unaffected`: the `<register name=..>` rows of the
/// `<unaffected>` list in the compiler spec's `<default_proto>`. A name the
/// language does not define is skipped, which only forgets more.
fn unaffected_registers(sleigh: &Sleigh, cspec: &Element) -> Vec<(u64, u32)> {
    let children = |element: &Element, name: &str| -> Vec<Rc<Element>> {
        element
            .get_children()
            .iter()
            .filter(|child| child.get_name() == name)
            .cloned()
            .collect()
    };
    let mut registers = Vec::new();
    for proto in children(cspec, "default_proto") {
        for prototype in children(&proto, "prototype") {
            for list in children(&prototype, "unaffected") {
                for register in children(&list, "register") {
                    let Ok(name) = register.get_attribute_value("name") else {
                        continue;
                    };
                    if let Ok(varnode) = sleigh.get_register_varnode(name) {
                        let in_registers = varnode
                            .space
                            .as_ref()
                            .is_some_and(|space| space.get_name() == "register");
                        if in_registers {
                            registers.push((varnode.offset, varnode.size));
                        }
                    }
                }
            }
        }
    }
    registers
}

#[cfg(test)]
mod tests {
    use super::SleighLifter;
    use crate::native::{Mapping, NativeImport};
    use crate::session::RuntimeConfig;

    /// The configuration and an import of `words` at 0x1000, or `None`
    /// without a Ghidra install.
    fn image(language: &str, words: &[(u64, u32)], big_endian: bool) -> Option<(RuntimeConfig, NativeImport)> {
        let mut cfg = RuntimeConfig::from_env();
        if !cfg.ghidra_install.join("Ghidra").is_dir() {
            eprintln!("SKIP: no Ghidra install");
            return None;
        }
        cfg.adopt_language(language);
        let end = words.iter().map(|&(address, _)| address + 4).max().unwrap_or(0x1000);
        let mut bytes = vec![0u8; (end - 0x1000) as usize];
        for &(address, word) in words {
            let at = (address - 0x1000) as usize;
            let word = if big_endian { word.to_be_bytes() } else { word.to_le_bytes() };
            bytes[at..at + 4].copy_from_slice(&word);
        }
        let import = NativeImport {
            language: language.into(),
            mappings: vec![Mapping { vaddr: 0x1000, size: bytes.len() as u64, file_off: 0, flags: 6, bytes }],
            ..Default::default()
        };
        Some((cfg, import))
    }

    /// A lifter over `words` at 0x1000, or `None` without a Ghidra install.
    fn lifter(language: &str, words: &[(u64, u32)], big_endian: bool) -> Option<SleighLifter> {
        let (cfg, import) = image(language, words, big_endian)?;
        Some(SleighLifter::mapped(&cfg, &import).unwrap())
    }

    /// The lazily decoded `.sla` (constructors, decision trees and templates
    /// decoded when an instruction reaches them, from the shared image) lifts
    /// every instruction of random bytes exactly as the eagerly decoded one,
    /// and the flow decoder's marked templates match too.
    #[test]
    fn a_lazily_decoded_language_lifts_what_the_eager_decode_does() {
        for (language, step, big_endian) in [
            ("x86:LE:64:default", 1usize, false),
            ("x86:LE:32:default", 1, false),
            ("PowerPC:BE:32:default", 4, true),
            ("ARM:LE:32:v5t", 4, false),
            ("AARCH64:LE:64:v8A", 4, false),
            ("MIPS:LE:32:default", 4, false),
        ] {
            let Some((cfg, mut import)) = image(language, &[(0x1ffc, 0)], big_endian) else { return };
            let mut state = 0x2545_f491_4f6c_dd1du64;
            let bytes: Vec<u8> = (0..0x1800)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 24) as u8
                })
                .collect();
            import.mappings[0].size = bytes.len() as u64;
            import.mappings[0].bytes = bytes;
            let mut lazy = SleighLifter::mapped(&cfg, &import).unwrap();
            let mut eager = SleighLifter::mapped_eager(&cfg, &import).unwrap();
            let addresses: Vec<u64> = (0..0x1700).step_by(step).map(|at| 0x1000 + at as u64).collect();
            let (lazy_ops, eager_ops) = (lazy.lift(&addresses), eager.lift(&addresses));
            assert_eq!(lazy_ops.len(), eager_ops.len());
            let mut decoded = 0;
            for (a, b) in lazy_ops.iter().zip(&eager_ops) {
                assert_eq!(format!("{a:?}"), format!("{b:?}"), "{language} at {:#x}", a.address);
                decoded += usize::from(a.error.is_none());
            }
            assert!(decoded > addresses.len() / 4, "{language}: only {decoded} of {} decoded", addresses.len());
        }
    }

    /// A lifter that went back to the pool decodes the next image under that
    /// image's bytes and the spec's context, not under what its last image
    /// committed: `blx` made 0x2000 Thumb in the first image, and 0x2000 is
    /// ARM in the second, as a lifter built fresh reads it.
    #[test]
    fn a_pooled_lifter_starts_over_with_the_new_image() {
        let words = |blx: bool| {
            [(0x1004u64, if blx { 0xfa00_03fdu32 } else { 0xe1a0_0000 }), (0x2000, 0xe3a0_0001)]
        };
        let Some((cfg, first)) = image("ARM:LE:32:v5t", &words(true), false) else {
            return;
        };
        let (_, second) = image("ARM:LE:32:v5t", &words(false), false).unwrap();
        let mut used = SleighLifter::mapped_pooled(&cfg, &first).unwrap();
        assert!(used.lift(&[0x1004])[0].error.is_none());
        assert_eq!(used.lift(&[0x2000])[0].length, 2, "blx committed Thumb at its target");
        drop(used);
        let mut reused = SleighLifter::mapped_pooled(&cfg, &second).unwrap();
        let mut fresh = SleighLifter::mapped(&cfg, &second).unwrap();
        for address in [0x2000, 0x1004] {
            let (reused, fresh) = (&reused.lift(&[address])[0], &fresh.lift(&[address])[0]);
            assert_eq!(reused.length, fresh.length);
            assert_eq!(reused.error, fresh.error);
            assert_eq!(reused.ops.len(), fresh.ops.len());
        }
        assert_eq!(reused.lift(&[0x2000])[0].length, 4);
    }

    /// The console's parse cache answered 0x2000 in ARM mode after `blx`
    /// committed Thumb there (one NDS instruction in the differential run);
    /// a lift decodes under the context the database now holds.
    #[test]
    fn globalset_commit_applies_to_a_later_lift() {
        let Some(mut lifter) = lifter(
            "ARM:LE:32:v5t",
            &[(0x1004, 0xfa00_03fd), (0x2000, 0xe3a0_0001)], // blx 0x2000; mov r0,#1
            false,
        ) else {
            return;
        };
        assert_eq!(lifter.lift(&[0x2000])[0].length, 4);
        assert!(lifter.lift(&[0x1004])[0].error.is_none());
        let thumb = &lifter.lift(&[0x2000])[0];
        assert_eq!((thumb.length, thumb.error.as_deref()), (2, None));
    }

    /// `vpush` with imm8=0xf0 walks past the console's 74 operand states.
    #[test]
    fn walks_past_the_console_parser_states_are_bad() {
        let Some(mut lifter) = lifter(
            "ARM:LE:32:v8",
            &[(0x1000, 0xed2d_4bf0), (0x1004, 0xed2d_8b10)], // vpush {d4..}; vpush {d8-d15}
            false,
        ) else {
            return;
        };
        let lifted = lifter.lift(&[0x1000, 0x1004]);
        assert_eq!(lifted[0].error.as_deref(), Some("BAD"));
        assert_eq!(lifted[1].error, None);
        assert_eq!(lifted[1].ops.iter().filter(|op| op.opcode == "STORE").count(), 8);
    }

    /// Conditional LR exits are returns; `bctr` stays an indirect branch.
    #[test]
    fn powerpc_conditional_lr_exits_return() {
        let Some(mut lifter) = lifter(
            "PowerPC:BE:32:default",
            &[(0x1000, 0x4e40_0020), (0x1004, 0x4e40_0021), (0x1008, 0x4e80_0420)],
            true,
        ) else {
            return;
        };
        let lifted = lifter.lift(&[0x1000, 0x1004, 0x1008]);
        let has = |index: usize, opcode: &str| lifted[index].ops.iter().any(|op| op.opcode == opcode);
        assert!(has(0, "RETURN") && !has(0, "BRANCHIND"));
        assert!(!has(1, "RETURN"));
        assert!(has(2, "BRANCHIND") && !has(2, "RETURN"));
    }

    /// BFD's section view and the raw file under the same language read
    /// the same instruction bytes.
    #[test]
    fn pe_through_bfd_matches_the_raw_file() {
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures-src/tiny_pe.exe");
        let mut cfg = RuntimeConfig::from_env();
        if !cfg.ghidra_install.join("Ghidra").is_dir() || !binary.is_file() {
            eprintln!("SKIP: no Ghidra install or fixture");
            return;
        }
        cfg.adopt_language("x86:LE:64:default");
        // `.text` is file offset 0x600 at 0x140001000.
        let bfd = SleighLifter::file(&cfg, &binary, 0).unwrap().lift(&[0x1_4000_1000]);
        let mut raw = super::SleighLifter::build(&cfg, "x86:LE:64:default", |_| {
            Ok(Box::new(super::RawImage {
                bytes: std::fs::read(&binary).unwrap(),
                vma: 0x1_4000_1000 - 0x600,
            }))
        })
        .unwrap();
        assert_eq!(bfd, raw.lift(&[0x1_4000_1000]));
        assert!(bfd[0].error.is_none() && !bfd[0].ops.is_empty());
    }
}
