//! Native (no-JVM) runtime services: the in-process SLEIGH lifter, flow and
//! reference passes, and the decompiler worker.
//!
//! These were CLI-local until the review that tightened the facade contract
//! (a GUI — the intended consumer — could not reuse `decompile` /
//! `disasm` without copying `Command::new` spawn logic out of
//! romwright-cli/main.rs). They now live behind the Core facade so every consumer
//! (CLI, GUI, agents) speaks only Core API methods.
//!
//! The runtime contract is `RuntimeConfig` (crate::session): services take
//! an explicit value — never read process-wide env vars. The environment is
//! consulted only when the config is BUILT (`RuntimeConfig::from_env`), so
//! the CLI's env surface is preserved while everything below it is honest
//! about its inputs.

#[cfg(test)]
use crate::native::NativeImport;
use crate::session::RuntimeConfig;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
mod disasm;
mod flow;
mod image;
mod lift;
mod linkage;
#[cfg(test)]
mod oracle;
mod patterns;
mod propagation;
mod reference_pass;
pub use disasm::{disasm_native, listing_native};
pub use flow::SleighFlow;
pub(crate) use lift::{release_idle_decoders, set_single_program, single_program};
pub use lift::SleighLifter;
pub(crate) use reference_pass::{DemandReferences, ReferenceContext, open_lanes as open_reference_lanes};
pub(crate) use patterns::FunctionPatterns;
pub(crate) use propagation::{JumpShape, Refusal};

/// Facade error for the native runtime (string-typed: these are setup and
/// child-process failures, reported verbatim to the caller).
#[derive(Debug)]
pub struct NativeRuntimeError(pub String);

impl std::fmt::Display for NativeRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NativeRuntimeError {}

pub type Result<T, E = NativeRuntimeError> = std::result::Result<T, E>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(NativeRuntimeError(msg.into()))
}

/// The pinned Ghidra install root: `ROMWRIGHT_GHIDRA`, then the language data
/// shipped beside the executable (`<exe dir>/../share/romwright/ghidra`), the
/// checkout's `build/ghidra` (where `setup.py` extracts it), and last
/// `ghidra_12.1.3_PUBLIC` in the user's home directory (`$HOME`, or
/// `%USERPROFILE%` on Windows); see `runtime_paths`.
pub fn ghidra_dir() -> PathBuf {
    std::env::var("ROMWRIGHT_GHIDRA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate::runtime_paths::Layout::current().ghidra())
}

/// The register the spec bundle aliases as `ISAModeSwitch`, when the
/// language has one: Ghidra's ARM analyzer reads the register of that name
/// at every computed flow to learn the target's instruction set
/// (`ArmAnalyzer.flowArmThumb`), and the pinned pspecs spell the alias as
/// `<register name="TB" alias="ISAModeSwitch"/>`. The decompiler's own
/// pspec reader keeps no aliases, so the name travels to the console by
/// option. A language that declares the register under that name itself
/// needs no alias and gets none.
fn mode_register_alias(spec_root: &std::path::Path, language: &str) -> Option<String> {
    let bundle = spec_root.join(language.replace(':', "-")).join("pspec.xml");
    let text = std::fs::read_to_string(bundle).ok()?;
    for element in text
        .split('<')
        .filter(|element| element.starts_with("register "))
    {
        let attribute = |name: &str| {
            let key = format!("{name}=\"");
            let start = element.find(&key)? + key.len();
            let end = element[start..].find('"')? + start;
            Some(element[start..end].to_string())
        };
        if attribute("alias").as_deref() == Some("ISAModeSwitch") {
            return attribute("name");
        }
    }
    None
}

/// Resolves the decompile inputs for a program language id: the compiled
/// SLA (from the install's .ldefs), the language dir, and the vendored
/// spec bundle (native/specs/<lang>, generated once via `dump-specs`).
/// Falls back to the configured x86 defaults when the language is the
/// default x86-64 or the env explicitly set the pieces.
pub fn language_decompile_config(
    cfg: &RuntimeConfig,
    language: &str,
) -> Result<(
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    String,
)> {
    // An explicit pin wins only for the language it pins. A pinned x86-64
    // `.sla` applied to an ARM or MIPS program decompiles that program with
    // the wrong decoder and yields plausible-looking nonsense, so a
    // mismatched pin is ignored in favour of the program's own language.
    if let Some(sla) = cfg
        .sla_path
        .as_ref()
        .filter(|_| language == cfg.language_id)
    {
        return Ok((
            sla.clone(),
            cfg.spec_root.clone(),
            cfg.language_dir.clone(),
            cfg.language_id.clone(),
        ));
    }
    // Default x86-64: keep the vendored x86 bundle.
    if language == "x86:LE:64:default" {
        return Ok((
            cfg.ghidra_install
                .join("Ghidra/Processors/x86/data/languages/x86-64.sla"),
            cfg.spec_root.clone(),
            cfg.language_dir.clone(),
            cfg.language_id.clone(),
        ));
    }
    // Other languages: resolve the sla from the install ldefs and the
    // vendored spec bundle keyed by the language id.
    let specs = crate::architecture::discover(&cfg.ghidra_install)
        .map_err(|e| NativeRuntimeError(e.to_string()))?;
    let spec = specs.iter().find(|s| s.id == language).ok_or_else(|| {
        NativeRuntimeError(format!(
            "language {language} not found in the Ghidra install"
        ))
    })?;
    let lang_dir = std::path::PathBuf::from(&spec.language_dir);
    let slafile = crate::architecture::slafile_for_id(&lang_dir, language)
        .map_err(|e| NativeRuntimeError(e.to_string()))?
        .ok_or_else(|| {
            NativeRuntimeError(format!("no .sla listed for {language} in its .ldefs"))
        })?;
    let sla = lang_dir.join(slafile);
    let bundle = cfg.spec_root.join(language.replace(':', "-"));
    if !bundle.join("tspec.xml").is_file() {
        return err(format!(
            "spec bundle missing for {language}: {} — generate it once with \
             `romwright-cli dump-specs <program> --out {}` (JVM bridge)",
            bundle.display(),
            bundle.display()
        ));
    }
    Ok((sla, bundle, lang_dir, language.to_string()))
}

/// Performant `decompile`: one address decompiled by the patched
/// `ghidra_opt` through `romwright-worker` (raw-SLEIGH, no JVM).
fn worker_command(
    request: &crate::exec::ExecutionRequest,
    addresses: &[String],
    structured: bool,
) -> Result<Command> {
    let cfg = &request.config;
    let (sla, specs, lang_dir, language_id) = language_decompile_config(cfg, &request.language)?;
    if !sla.is_file() {
        return err(format!(
            "configured SLA does not exist: {} — the Ghidra language data is missing; run \
             `python setup.py` in the source checkout, use a release archive, or point \
             ROMWRIGHT_GHIDRA at a Ghidra 12.1.3 install",
            sla.display()
        ));
    }
    if !cfg.decompiler_path.is_file() {
        return err(format!(
            "native decompiler missing: {} — run `python setup.py` in the source checkout \
             (builds native/build/ghidra_opt) or use a release archive; ROMWRIGHT_GHIDRA_OPT pins another",
            cfg.decompiler_path.display()
        ));
    }
    if !specs.join("tspec.xml").is_file() {
        return err(format!("spec dir incomplete: {}", specs.display()));
    }
    let input = serde_json::to_string(&request.input)
        .map_err(|error| NativeRuntimeError(format!("encode captured input: {error}")))?;
    // The worker maps the image this process derived, so its memory does not
    // grow with the input or with the number of workers.
    let image = crate::inputs::snapshot_binding(&request.project_dir, &request.input)
        .map_err(|error| NativeRuntimeError(format!("program image snapshot: {error}")))?;
    let remaining = request
        .deadline
        .saturating_duration_since(std::time::Instant::now());
    let mut command = Command::new(&cfg.worker_path);
    command
        .arg(&cfg.decompiler_path)
        .arg(specs)
        .arg(&request.program)
        .args(addresses)
        .arg("--project")
        .arg(&request.project_dir)
        .env("ROMWRIGHT_LANGUAGE", language_id)
        .env("ROMWRIGHT_LANGUAGE_DIR", lang_dir)
        .env("ROMWRIGHT_SLA", sla)
        .env("ROMWRIGHT_PROGRAM_INPUT", input)
        .env(crate::inputs::SNAPSHOT_ENV, image)
        .env("ROMWRIGHT_IR_PASSES", cfg.ir_passes.join(","))
        .env("WORKER_ACTION", "decompile")
        .env(
            "WORKER_DECOMPILE_TIMEOUT_SECS",
            remaining.as_secs().saturating_add(1).to_string(),
        )
        .env_remove("WORKER_STRUCTURED")
        .env_remove("ROMWRIGHT_STRUCT_OVERLAY");
    if structured {
        command.env("WORKER_STRUCTURED", "1");
    }
    if let Some(overlay) = &cfg.struct_overlay {
        command.env("ROMWRIGHT_STRUCT_OVERLAY", overlay);
    }
    command.envs(cfg.worker_env.iter().map(|(key, value)| (key, value)));
    Ok(command)
}

fn run_decompiler(
    request: &crate::exec::ExecutionRequest,
    addresses: &[String],
    structured: bool,
) -> Result<Vec<u8>> {
    let mut command = worker_command(request, addresses, structured)?;
    let limit = usize::try_from(request.config.worker_memory_cap).unwrap_or(usize::MAX);
    let out = crate::exec::run_command(&mut command, request, None, limit)
        .map_err(|error| NativeRuntimeError(error.to_string()))?;
    if !out.status.success() {
        return err(format!(
            "worker failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Structures control-flow graphs through the decompiler's own
/// `structureGraph` command, one JSON request per graph, answered in order.
///
/// Nothing is decompiled: the command runs `structureLoops`,
/// `calcForwardDominator` and `CollapseStructure` over the graph given, which
/// is what lets our own structuring be scored on identical input.
pub fn structure_native(
    request: &crate::exec::ExecutionRequest,
    requests: &[String],
) -> Result<Vec<String>> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let mut command = worker_command(request, &[], false)?;
    command.arg("--structure");
    let payload: String = requests
        .iter()
        .map(|request| format!("{request}\n"))
        .collect();
    let limit = usize::try_from(request.config.worker_memory_cap).unwrap_or(usize::MAX);
    let out = crate::exec::run_command(&mut command, request, Some(payload.as_bytes()), limit)
        .map_err(|error| NativeRuntimeError(error.to_string()))?;
    if !out.status.success() {
        return err(format!(
            "structuring worker failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .map(str::to_string)
        .collect())
}

/// Perform `decompile`: one address decompiled by the patched
/// `ghidra_opt` through `romwright-worker` (raw-SLEIGH, no JVM).
pub fn decompile_native(request: &crate::exec::ExecutionRequest, address: &str) -> Result<String> {
    let stdout = run_decompiler(request, &[address.to_string()], false)?;
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Decompiles several addresses from one worker launch. The decompiler loads
/// its language once per launch, so a batch is what makes comparing a
/// hundreds-of-functions image affordable (m4-022). Answers are keyed by the
/// eight-digit address the caller asked for.
pub fn decompile_native_batch(
    request: &crate::exec::ExecutionRequest,
    addresses: &[String],
) -> Result<std::collections::BTreeMap<String, String>> {
    if addresses.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    if addresses.len() == 1 {
        let text = decompile_native(request, &addresses[0])?;
        let key = u64::from_str_radix(addresses[0].trim_start_matches("0x"), 16)
            .map_err(|e| NativeRuntimeError(format!("address {}: {e}", addresses[0])))?;
        return Ok([(format!("{key:08x}"), text)].into_iter().collect());
    }
    let stdout = run_decompiler(request, addresses, false)?;
    let text = String::from_utf8(stdout)
        .map_err(|e| NativeRuntimeError(format!("worker batch is not UTF-8: {e}")))?;
    serde_json::from_str(text.trim())
        .map_err(|e| NativeRuntimeError(format!("invalid worker batch: {e}")))
}

/// Structured documents for several addresses from one worker launch, keyed
/// like `decompile_native_batch`. A single address still goes through the
/// batch protocol so the answer shape is one.
pub fn decompile_native_docs(
    request: &crate::exec::ExecutionRequest,
    addresses: &[String],
) -> Result<std::collections::BTreeMap<String, romwright_model::DecompDoc>> {
    if addresses.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    if addresses.len() == 1 {
        let doc = decompile_native_doc(request, &addresses[0])?;
        return Ok([(format!("{:08x}", doc.address.offset), doc)]
            .into_iter()
            .collect());
    }
    let stdout = run_decompiler(request, addresses, true)?;
    let text = String::from_utf8(stdout)
        .map_err(|e| NativeRuntimeError(format!("worker batch is not UTF-8: {e}")))?;
    serde_json::from_str(text.trim())
        .map_err(|e| NativeRuntimeError(format!("invalid structured worker batch: {e}")))
}

/// The decompiler's own count of the work one switch decompile may do
/// (`romwright_budget.hh`: an action run, an op a rule pool visits, a rule
/// tried, and the loops that dominate the big functions, one unit each; about
/// 5 to 10 million units a second). The limit decides on what the function
/// costs, never on how long the host took to do it, so a function is finished
/// or refused the same way on every run.
///
/// Calibrated on the dispatchers the corpus asks about (`ROMWRIGHT_WORK_TRACE`,
/// STATUS.md 2026-10-10). Of 482 owners on psv the median costs 86 thousand
/// units and the 99th percentile 29 million; the heaviest of psv, AW and capcom
/// then cost, in millions, 1513, 778, 740, 237 (AW 0x8273d480), 226 (psv
/// 0x8130ffc0), 193, 182 (capcom 0x1ab430), 158, 117, 114, 102 and 102, and
/// below them 56 (psv) and 12 (AW, capcom). The limit sits in the empty stretch
/// between 56 and 102 million: everything above it is refused on every run, on
/// every host, and names itself in the import's notes. Each of those was
/// refused or not by the 60 s wall-clock limit this replaces according to the
/// host's load (20 to 40 s on an idle one, 59 s and a timeout on a busy one),
/// which is the nondeterminism. Which side of the limit capcom's two near 102
/// million fall on is visible in the reference score: answered, their tables
/// turn five functions the truth names into case blocks and recall reads
/// 0.9412; refused, 0.9418 (m21-001 at limits of 110 and 60 million).
pub(crate) const SWITCH_WORK_BUDGET: u64 = 75_000_000;

/// How long one switch decompile may run on the wall clock before its
/// worker is killed. Only a backstop for a decompile that stopped charging
/// work (a hang): the work budget is what ends a runaway one, long before
/// this. A function the guard kills is reported apart from a refusal
/// (`SwitchRecovery::wall_clock`), because the answer then depends on the
/// host and the import must not be kept.
pub(crate) const SWITCH_WALL_GUARD: Duration = Duration::from_secs(900);

/// The exception type the decompiler raises when a decompile passes its work
/// budget (`WorkBudgetExceeded`, ghidra_process.cc).
const WORK_BUDGET_EXCEEDED: &str = "WorkBudgetExceeded";

/// One line of the worker's `--switches` answer.
#[derive(serde::Deserialize)]
struct SwitchResponse {
    address: u64,
    result: std::result::Result<Vec<romwright_model::JumpTable>, String>,
    /// The failure was the wall-clock guard.
    #[serde(default)]
    wall_clock: bool,
}

#[derive(Default)]
pub(crate) struct SwitchRecovery {
    pub tables: Vec<romwright_model::JumpTable>,
    pub completed: usize,
    pub failures: Vec<String>,
    /// Functions the decompiler refused for passing the work budget: the same
    /// answer on every host, so the import stays reproducible.
    pub over_budget: Vec<String>,
    /// Functions whose worker the wall-clock guard killed. Whether one of
    /// these finished depended on the load of the host.
    pub wall_clock: Vec<String>,
}

impl SwitchRecovery {
    /// Files one function's answer: its tables, or why it has none. A refusal
    /// for the work budget and a kill by the wall-clock guard are told apart
    /// from the decompiler's own errors, because only the first is the same
    /// answer on every host.
    fn record(&mut self, response: SwitchResponse) {
        match response.result {
            Ok(tables) => {
                self.completed += 1;
                self.tables.extend(tables);
            }
            Err(error) => {
                let failure = format!("{:#x}: {error}", response.address);
                if response.wall_clock {
                    self.wall_clock.push(failure);
                } else if error.contains(WORK_BUDGET_EXCEEDED) {
                    self.over_budget.push(failure);
                } else {
                    self.failures.push(failure);
                }
            }
        }
    }
}

/// Compact, independently bounded function results. A child failure retains
/// completed records; cancellation, the outer deadline and snapshot checks
/// still invalidate the operation.
pub(crate) fn recover_native_switches(
    request: &crate::exec::ExecutionRequest,
    addresses: &[String],
) -> Result<SwitchRecovery> {
    let mut pending = addresses
        .iter()
        .map(|address| {
            u64::from_str_radix(address.trim_start_matches("0x"), 16)
                .map_err(|error| NativeRuntimeError(format!("address {address}: {error}")))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    let mut recovery = SwitchRecovery::default();
    if pending.is_empty() {
        return Ok(recovery);
    }
    let command_started = std::time::Instant::now();
    let mut command = worker_command(request, addresses, false)?;
    crate::native::tally::add("switch-command", command_started);
    command
        .arg("--switches")
        .env("WORKER_DECOMPILE_TIMEOUT_SECS", request.config.switch_wall_guard_secs.to_string())
        .env("ROMWRIGHT_WORK_BUDGET", request.config.switch_work_budget.to_string());
    let limit = usize::try_from(request.config.worker_memory_cap).unwrap_or(usize::MAX);
    let run_started = std::time::Instant::now();
    let out = crate::exec::run_command(&mut command, request, None, limit)
        .map_err(|error| NativeRuntimeError(error.to_string()))?;
    crate::native::tally::add("switch-worker", run_started);
    for line in out
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let response: SwitchResponse = match serde_json::from_slice(line) {
            Ok(response) => response,
            Err(error) => {
                recovery
                    .failures
                    .push(format!("invalid switch response: {error}"));
                break;
            }
        };
        if !pending.remove(&response.address) {
            recovery.failures.push(format!(
                "unexpected switch response: {:#x}",
                response.address
            ));
            break;
        }
        recovery.record(response);
    }
    if !out.status.success() {
        recovery.failures.push(format!(
            "switch worker failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
        ));
    }
    if !pending.is_empty() {
        recovery.failures.push(format!(
            "{} functions have no switch response",
            pending.len()
        ));
    }
    Ok(recovery)
}

/// Performs the same native decompile but returns the packed document as
/// structured model data. The worker stamped revision is zero; the Core
/// facade replaces it with the current durable program revision.
pub fn decompile_native_doc(
    request: &crate::exec::ExecutionRequest,
    address: &str,
) -> Result<romwright_model::DecompDoc> {
    let stdout = run_decompiler(request, &[address.to_string()], true)?;
    let text = String::from_utf8(stdout)
        .map_err(|e| NativeRuntimeError(format!("worker document is not UTF-8: {e}")))?;
    serde_json::from_str(text.trim())
        .map_err(|e| NativeRuntimeError(format!("invalid structured worker document: {e}")))
}

/// The lowest address the store records for `program`, when the program is
/// already imported. A platform image has no header to read a base from.
pub(crate) fn program_image_base(program: &str, project_dir: &Path) -> Option<u64> {
    let db = crate::ProjectDb::open(&project_dir.join("project.sqlite")).ok()?;
    let id = db.program_id(program).ok()?;
    db.memory_regions(id)
        .ok()?
        .iter()
        // Only regions the image actually backs: a platform's declared RAM
        // and IO windows carry no bytes and would name the wrong base.
        .filter(|region| region.source == "native-import")
        .map(|region| region.start.offset)
        .min()
}

/// Maps the configured Ghidra language id + binary format to the BFD target
/// name the console's `load file` command expects. The console's BFD loader
/// derives the SLEIGH language from the image header itself, so the target
/// must be a BFD name, never a Ghidra language id.
fn bfd_target_for(language_id: &str, binary: &Path) -> Result<String> {
    use std::io::Read as _;
    let mut magic = [0u8; 4];
    let mut file = std::fs::File::open(binary)
        .map_err(|e| NativeRuntimeError(format!("bfd target probe: {e}")))?;
    let got = file
        .read(&mut magic)
        .map_err(|e| NativeRuntimeError(format!("bfd target probe: {e}")))?;
    if got >= 2 && &magic[..2] == b"MZ" {
        let sixty_four = language_id.contains(":64:");
        return Ok(if sixty_four {
            "pei-x86-64".into()
        } else {
            "pei-i386".into()
        });
    }
    // A colon-bearing "target" is the language id, which the console's patched
    // loader takes as a raw architecture instead of asking BFD to recognise the
    // file. That is the only workable answer for a machine BFD's x86 targets
    // refuse: handed `elf32-i386`, a MIPS image answers `not in recognized
    // object file format` and then `Could not create architecture`, which is
    // how one hung an import for fourteen minutes (m11-002).
    if !language_id.starts_with("x86:") {
        return Ok(language_id.to_string());
    }
    let sixty_four = language_id.contains(":64:");
    Ok(if sixty_four {
        "elf64-x86-64".into()
    } else {
        "elf32-i386".into()
    })
}

/// A pointer-sized constant observed at a p-code assignment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConstantFact {
    pub pc: u64,
    pub varnode: ConstantVarnode,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConstantVarnode {
    pub space: String,
    pub offset: u64,
    pub size: u32,
}

/// One p-code varnode, its space named as the translator names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcodeVarnode {
    pub space: String,
    pub offset: u64,
    pub size: u32,
}

impl PcodeVarnode {
    pub fn is_const(&self) -> bool {
        self.space == "const"
    }
    /// True for a varnode that holds machine state between instructions --
    /// a register or a stack slot -- as opposed to a within-instruction
    /// temporary or a constant.
    pub fn is_persistent(&self) -> bool {
        self.space == "register" || self.space == "stack"
    }
}

/// One p-code operation, opcode named as the translator names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcodeOp {
    pub opcode: String,
    pub output: Option<PcodeVarnode>,
    pub inputs: Vec<PcodeVarnode>,
}

/// The p-code of one machine instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcodeInstruction {
    pub address: u64,
    pub length: u8,
    pub ops: Vec<PcodeOp>,
    /// `BAD` or `UNIMPL` when SLEIGH could not decode the address.
    pub error: Option<String>,
}

/// An inferred mapped-memory reference at its instruction address.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReferenceFact {
    pub from: u64,
    pub to: u64,
    pub kind: ReferenceKind,
    /// Bytes the access touches, from the p-code that performs it. Zero when
    /// the address is only taken, which proves no width.
    #[serde(default)]
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferenceKind {
    Read,
    Write,
    ReadWrite,
    Data,
    /// A call through a register whose value the propagation resolved; the
    /// target is reported as held, low bit included.
    ComputedCall,
    /// A branch through a register whose value the propagation resolved.
    ComputedJump,
    /// A load or store through the stack pointer: `to` is the offset from the
    /// entry stack pointer in the pointer's width, two's complement, and
    /// `size` the access width.
    Stack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FlowKind {
    Branch,
    CBranch,
    BranchInd,
    Call,
    CallInd,
    Return,
    Fallthrough,
    Bad,
    Unimpl,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FlowResult {
    pub address: u64,
    pub length: u8,
    pub fallthrough: Option<u64>,
    pub targets: Vec<u64>,
    pub kind: FlowKind,
    /// True only for a single, side-effect-free direct SLEIGH branch operation.
    #[serde(default)]
    pub pure_jump: bool,
    /// True only when SLEIGH successfully decodes an instruction with no p-code.
    #[serde(default)]
    pub no_op: bool,
    /// Instruction flow classification, including conditional terminal paths.
    pub terminal: bool,
    pub conditional: bool,
    /// Actual RETURN p-code, distinct from a terminal instruction such as a loop.
    pub return_op: bool,
    /// Length of each delay-slot instruction; `length` includes these bytes.
    pub delay_slots: Vec<u8>,
    /// The instruction set the address was decoded in, on a language that
    /// carries one in its `LowBitCodeMode` context field (ARM's Thumb bit,
    /// MIPS's ISA mode); absent on every other language.
    #[serde(default)]
    pub mode: Option<u64>,
    /// Branch and call targets whose instruction set, as it flows from this
    /// instruction, differs from what the console currently holds there:
    /// `(target, mode)`. Ghidra's disassembler carries context along flow
    /// (`DisassemblerContextImpl`); the native console only paints explicit
    /// change points, so a caller sets these before decoding the target.
    #[serde(default)]
    pub target_modes: Vec<(u64, u64)>,
}

/// Bounded SLEIGH evidence for an indirect transfer through a pointer slot.
/// A slot alone is not an imported function: the loader must establish its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkageResult {
    pub address: u64,
    /// Proven linkage-shape extent, even when its slot needs caller context.
    pub length: u32,
    pub slot: Option<u64>,
    /// A possible local linkage shape, not proof of an imported function.
    pub needs_context: bool,
}

#[derive(Debug)]
pub(crate) struct LinkageContext {
    pub origin: u64,
    pub branch: u64,
    pub target: u64,
}

/// Pointer-sized constants of one range under the strict policy (no
/// reference-inference heuristics): what tests that pin that policy ask.
#[cfg(test)]
pub(crate) fn strict_constants(
    cfg: &RuntimeConfig,
    import: &NativeImport,
    start: u64,
    end: u64,
) -> Result<Vec<ConstantFact>> {
    let mut lane = propagation::Propagator::mapped(cfg, import)?;
    let (functions, tables) = Default::default();
    let query = propagation::Query {
        start,
        end,
        trust_writable: false,
        seeds: &[],
        tracked: None,
        mode_register: None,
        externals: &[],
        functions: &functions,
        tables: &tables,
        recover: false,
    };
    lane.constants(&query)?
        .ok_or_else(|| NativeRuntimeError(format!("constants at {start:#x} are undecodable")))
}

/// The reference facts of one range as the reference pass asks for them
/// (writable initial values trusted); `None` is a range with no decodable
/// flow.
#[cfg(test)]
pub(crate) fn range_references(
    cfg: &RuntimeConfig,
    import: &NativeImport,
    start: u64,
    end: u64,
) -> Result<Option<Vec<ReferenceFact>>> {
    let mut lane = propagation::Propagator::mapped(cfg, import)?;
    let (functions, tables) = Default::default();
    let query = propagation::Query {
        start,
        end,
        trust_writable: true,
        seeds: &[],
        tracked: None,
        mode_register: None,
        externals: &[],
        functions: &functions,
        tables: &tables,
        recover: true,
    };
    Ok(lane.references(&query)?.map(|answer| answer.references))
}

#[cfg(test)]
mod tests {
    /// The reference facts as (instruction, target, kind): what a test about
    /// *which* references exist is asserting. Access widths have their own
    /// test, `reference_facts_carry_the_access_width`.
    fn triples(facts: &[super::ReferenceFact]) -> Vec<(u64, u64, super::ReferenceKind)> {
        facts
            .iter()
            .map(|fact| (fact.from, fact.to, fact.kind))
            .collect()
    }

    use super::*;

    /// The in-process propagation over one mapped image, asked the way the
    /// reference pass asks it but with no call context: what the tests about
    /// *which* facts exist assert on.
    struct Lane {
        config: RuntimeConfig,
        lane: Option<propagation::Propagator>,
    }

    impl Lane {
        fn new(cfg: &RuntimeConfig) -> Result<Self> {
            Ok(Self { config: cfg.clone(), lane: None })
        }

        fn load_mapped(&mut self, import: &NativeImport) -> Result<()> {
            self.lane = Some(propagation::Propagator::mapped(&self.config, import)?);
            Ok(())
        }

        fn query<'a>(
            start: u64,
            end: u64,
            trust_writable: bool,
            functions: &'a std::collections::HashMap<u64, usize>,
            tables: &'a std::collections::HashMap<u64, Vec<u64>>,
        ) -> propagation::Query<'a> {
            propagation::Query {
                start,
                end,
                trust_writable,
                seeds: &[],
                tracked: None,
                mode_register: None,
                externals: &[],
                functions,
                tables,
                recover: true,
            }
        }

        fn references(
            &mut self,
            start: u64,
            end: u64,
            _mappings: &[crate::native::Mapping],
            trust_writable: bool,
        ) -> Result<Vec<ReferenceFact>> {
            let (functions, tables) = Default::default();
            let query = Self::query(start, end, trust_writable, &functions, &tables);
            self.lane
                .as_mut()
                .expect("an image is loaded")
                .references(&query)?
                .map(|answer| answer.references)
                .ok_or_else(|| NativeRuntimeError(format!("references at {start:#x} are undecodable")))
        }

        fn constants(
            &mut self,
            start: u64,
            end: u64,
            _mappings: &[crate::native::Mapping],
            trust_writable: bool,
        ) -> Result<Vec<ConstantFact>> {
            let (functions, tables) = Default::default();
            let query = Self::query(start, end, trust_writable, &functions, &tables);
            self.lane
                .as_mut()
                .expect("an image is loaded")
                .constants(&query)?
                .ok_or_else(|| NativeRuntimeError(format!("constants at {start:#x} are undecodable")))
        }
    }

    /// An ARM or Thumb image at 0x1000 from `(address, value)` pairs; `None`
    /// without a Ghidra install. `thumb` words are halfwords and the whole
    /// image decodes as Thumb.
    fn jump_image(thumb: bool, words: &[(u64, u32)], size: u64) -> Option<(RuntimeConfig, NativeImport)> {
        let mut cfg = RuntimeConfig::from_env();
        cfg.adopt_language("ARM:LE:32:v5t");
        if !cfg.ghidra_install.join("Ghidra").is_dir() {
            eprintln!("SKIP: no Ghidra install");
            return None;
        }
        let mut bytes = vec![0u8; size as usize];
        for &(address, value) in words {
            let at = (address - 0x1000) as usize;
            if thumb && value <= 0xffff {
                bytes[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
            } else {
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        let contexts = if thumb {
            vec![crate::native::NativeContext { name: "LowBitCodeMode".into(), address: 0x1000, value: 1 }]
        } else {
            Vec::new()
        };
        let import = NativeImport {
            language: "ARM:LE:32:v5t".into(),
            contexts,
            mappings: vec![crate::native::Mapping { vaddr: 0x1000, size, file_off: 0, flags: 5, bytes }],
            ..Default::default()
        };
        Some((cfg, import))
    }

    /// Four cases that each read one literal and leave for 0x1040, after the
    /// dispatch the caller supplies below 0x1020: the case bodies sit at
    /// 0x1020, 0x1028, 0x1030 and 0x1038 and read 0x1060, 0x1064, 0x1068 and
    /// 0x106c, so a read of one is evidence the flow reached that case.
    const ARM_CASES: [(u64, u32); 17] = [
        (0x101c, 0xe12f_ff1e), // bx lr
        (0x1020, 0xe59f_2038), // case 0: ldr r2,[pc,#0x38] (0x1060)
        (0x1024, 0xea00_0005), // b 0x1040
        (0x1028, 0xe59f_2034), // case 1: ldr r2,[0x1064]
        (0x102c, 0xea00_0003),
        (0x1030, 0xe59f_2030), // case 2: ldr r2,[0x1068]
        (0x1034, 0xea00_0001),
        (0x1038, 0xe59f_202c), // case 3: ldr r2,[0x106c]
        (0x103c, 0xeaff_ffff), // b 0x1040
        (0x1040, 0xe12f_ff1e), // bx lr
        (0x1060, 0x1111_1111),
        (0x1064, 0x2222_2222),
        (0x1068, 0x3333_3333),
        (0x106c, 0x4444_4444),
        (0x1044, 0),
        (0x1048, 0),
        (0x104c, 0),
    ];

    /// The reads the four cases of `ARM_CASES` make, as (instruction, literal).
    const CASE_READS: [(u64, u64); 4] = [(0x1020, 0x1060), (0x1028, 0x1064), (0x1030, 0x1068), (0x1038, 0x106c)];

    impl Lane {
        /// The whole answer for one range, with the recovery of indirect
        /// jumps that have no stored table on or off.
        fn answer(&mut self, start: u64, end: u64, recover: bool) -> propagation::Answer {
            let (functions, tables) = Default::default();
            let mut query = Self::query(start, end, true, &functions, &tables);
            query.recover = recover;
            self.lane
                .as_mut()
                .expect("an image is loaded")
                .references(&query)
                .unwrap()
                .expect("the range decodes")
        }
    }

    fn read_from(answer: &propagation::Answer, from: u64, to: u64) -> bool {
        answer.references.iter().any(|fact| fact.from == from && fact.to == to && fact.kind == ReferenceKind::Read)
    }

    /// `cmp r0,#3; addls pc,pc,r0,lsl #2` over four `b case`: the targets of
    /// the jump are the slots after the default branch (the add reads pc as
    /// the instruction plus 8), and the flow reaches every case through them.
    #[test]
    fn an_arm_branch_island_is_followed_into_its_cases() {
        let mut words = vec![
            (0x1000, 0xe350_0003), // cmp r0,#3
            (0x1004, 0x908f_f100), // addls pc,pc,r0,lsl #2
            (0x1008, 0xea00_000c), // b 0x1040 (default)
            (0x100c, 0xea00_0003), // b 0x1020
            (0x1010, 0xea00_0004), // b 0x1028
            (0x1014, 0xea00_0005), // b 0x1030
            (0x1018, 0xea00_0006), // b 0x1038
        ];
        words.extend(ARM_CASES);
        let Some((cfg, import)) = jump_image(false, &words, 0x70) else { return };
        let mut lane = Lane::new(&cfg).unwrap();
        lane.load_mapped(&import).unwrap();
        let answer = lane.answer(0x1000, 0x1044, true);
        assert_eq!(
            answer.recovered_jumps,
            vec![(0x1004, propagation::JumpShape::Island, vec![0x100c, 0x1010, 0x1014, 0x1018])]
        );
        for (from, to) in CASE_READS {
            assert!(read_from(&answer, from, to), "the flow did not reach the case at {from:#x}: {:?}", answer.references);
        }
        // Before the recovery the jump was a call and its cases were lost.
        let before = lane.answer(0x1000, 0x1044, false);
        assert!(before.recovered_jumps.is_empty());
        assert_eq!(before.truncated_jumps, vec![(0x1004, propagation::JumpShape::Island)]);
        assert!(CASE_READS.iter().all(|&(from, to)| !read_from(&before, from, to)), "{:?}", before.references);
    }

    /// `cmp r0,#3; ldrls pc,[pc,r0,lsl #2]` over four words: a guarded read of
    /// a table, whose entries are the cases.
    #[test]
    fn a_guarded_arm_table_read_is_followed_into_its_cases() {
        let mut words = vec![
            (0x1000, 0xe350_0003), // cmp r0,#3
            (0x1004, 0x979f_f100), // ldrls pc,[pc,r0,lsl #2]
            (0x1008, 0xea00_000c), // b 0x1040 (default)
            (0x100c, 0x1020),
            (0x1010, 0x1028),
            (0x1014, 0x1030),
            (0x1018, 0x1038),
        ];
        words.extend(ARM_CASES);
        let Some((cfg, import)) = jump_image(false, &words, 0x70) else { return };
        let mut lane = Lane::new(&cfg).unwrap();
        lane.load_mapped(&import).unwrap();
        let answer = lane.answer(0x1000, 0x1044, true);
        assert_eq!(
            answer.recovered_jumps,
            vec![(0x1004, propagation::JumpShape::TableLoad, vec![0x1020, 0x1028, 0x1030, 0x1038])]
        );
        for (from, to) in CASE_READS {
            assert!(read_from(&answer, from, to), "the flow did not reach the case at {from:#x}: {:?}", answer.references);
        }
        // A case outside the range being traced is not followed: the flow of
        // this range cannot place it, so the jump stays a call.
        let narrow = lane.answer(0x1000, 0x1030, true);
        assert!(narrow.recovered_jumps.is_empty());
        assert_eq!(narrow.refused_jumps, vec![(0x1004, propagation::JumpShape::TableLoad, propagation::Refusal::Outside)]);
    }

    /// The same table read with nothing that bounds the index: the table's
    /// end is not known, so no case is claimed.
    #[test]
    fn an_unguarded_arm_table_read_is_not_a_table() {
        let mut words = vec![
            (0x1000, 0xe1a0_0000), // mov r0,r0
            (0x1004, 0xe79f_f100), // ldr pc,[pc,r0,lsl #2]
            (0x1008, 0xea00_000c),
            (0x100c, 0x1020),
            (0x1010, 0x1028),
            (0x1014, 0x1030),
            (0x1018, 0x1038),
        ];
        words.extend(ARM_CASES);
        let Some((cfg, import)) = jump_image(false, &words, 0x70) else { return };
        let mut lane = Lane::new(&cfg).unwrap();
        lane.load_mapped(&import).unwrap();
        let answer = lane.answer(0x1000, 0x1044, true);
        assert!(answer.recovered_jumps.is_empty(), "{:?}", answer.recovered_jumps);
        assert_eq!(answer.refused_jumps, vec![(0x1004, propagation::JumpShape::TableLoad, propagation::Refusal::NoGuard)]);
        assert!(CASE_READS.iter().all(|&(from, to)| !read_from(&answer, from, to)), "{:?}", answer.references);
    }

    /// `bx r3` is handed a pointer: a call, not a dispatch. The recovery is
    /// not asked, so it cannot answer.
    #[test]
    fn a_branch_through_a_register_is_a_call_not_a_dispatch() {
        let Some((cfg, import)) = jump_image(false, &[(0x1000, 0xe3a0_0001), (0x1004, 0xe12f_ff13)], 0x10) else { return };
        let mut lane = Lane::new(&cfg).unwrap();
        lane.load_mapped(&import).unwrap();
        let answer = lane.answer(0x1000, 0x1008, true);
        assert!(answer.recovered_jumps.is_empty() && answer.refused_jumps.is_empty());
        assert_eq!(answer.truncated_jumps, vec![(0x1004, propagation::JumpShape::Pointer)]);
    }

    /// `pop {r0}; bx r0` is the Thumb return of agbcc code: the target is a
    /// stack slot, not an entry of a table, so the recovery is not asked even
    /// with a conditional branch ahead of it (it was 2,400 asks on pokeemerald).
    #[test]
    fn a_thumb_pop_return_is_a_pointer_not_a_dispatch() {
        let words: [(u64, u32); 5] = [
            (0x1000, 0x2900), // cmp r1,#0
            (0x1002, 0xd000), // beq 0x1006
            (0x1004, 0x46c0), // nop
            (0x1006, 0xbc01), // pop {r0}
            (0x1008, 0x4700), // bx r0
        ];
        let Some((cfg, import)) = jump_image(true, &words, 0x10) else { return };
        let mut lane = Lane::new(&cfg).unwrap();
        lane.load_mapped(&import).unwrap();
        let answer = lane.answer(0x1000, 0x100a, true);
        assert!(answer.recovered_jumps.is_empty() && answer.refused_jumps.is_empty(), "{:?}", answer.refused_jumps);
        assert_eq!(answer.truncated_jumps, vec![(0x1008, propagation::JumpShape::Pointer)]);
    }

    /// Two ways into the dispatch set the index to 1 and 0, so the first
    /// answer is the two slots they reach; the first case sets it to 2 and
    /// loops back, a way in nothing had traced yet. Asked again over the
    /// whole flow the table is a different one, so the first answer is struck
    /// and the jump stays a call rather than keep a table that missed a case.
    #[test]
    fn a_table_a_looping_case_invalidates_is_struck_not_kept() {
        let words: [(u64, u32); 18] = [
            (0x1000, 0xe351_0000), // cmp r1,#0
            (0x1004, 0x0a00_0001), // beq 0x1010
            (0x1008, 0xe3a0_0001), // mov r0,#1
            (0x100c, 0xea00_0000), // b 0x1014
            (0x1010, 0xe3a0_0000), // mov r0,#0
            (0x1014, 0xe350_0003), // cmp r0,#3 (the dispatch's head)
            (0x1018, 0x908f_f100), // addls pc,pc,r0,lsl #2
            (0x101c, 0xe12f_ff1e), // bx lr (default)
            (0x1020, 0xea00_0002), // b 0x1030
            (0x1024, 0xea00_0003), // b 0x1038
            (0x1028, 0xea00_0003), // b 0x103c
            (0x102c, 0xea00_0003), // b 0x1040
            (0x1030, 0xe3a0_0002), // case 0: mov r0,#2
            (0x1034, 0xeaff_fff6), // b 0x1014
            (0x1038, 0xe12f_ff1e), // case 1: bx lr
            (0x103c, 0xe12f_ff1e),
            (0x1040, 0xe12f_ff1e),
            (0x1044, 0),
        ];
        let Some((cfg, import)) = jump_image(false, &words, 0x48) else { return };
        let mut lane = Lane::new(&cfg).unwrap();
        lane.load_mapped(&import).unwrap();
        let answer = lane.answer(0x1000, 0x1044, true);
        assert!(answer.recovered_jumps.is_empty(), "{:?}", answer.recovered_jumps);
        assert_eq!(answer.refused_jumps, vec![(0x1018, propagation::JumpShape::Island, propagation::Refusal::Unstable)]);
    }

    /// Thumb `lsls r0,r0,#1; add pc,r0` reads the pc as the instruction plus
    /// 4, so slot 0 is two halfwords past the add, not one.
    #[test]
    fn a_thumb_branch_island_is_followed_into_its_cases() {
        let words: [(u64, u32); 33] = [
            (0x1000, 0x2803), // cmp r0,#3
            (0x1002, 0xd80f), // bhi 0x1024 (default)
            (0x1004, 0x0040), // lsls r0,r0,#1
            (0x1006, 0x4487), // add pc,r0
            (0x1008, 0x46c0), // nop
            (0x100a, 0xe003), // b 0x1014
            (0x100c, 0xe004), // b 0x1018
            (0x100e, 0xe005), // b 0x101c
            (0x1010, 0xe006), // b 0x1020
            (0x1012, 0x46c0),
            (0x1014, 0x4a04), // case 0: ldr r2,[pc,#16] (0x1028)
            (0x1016, 0xe005), // b 0x1024
            (0x1018, 0x4a04), // case 1: (0x102c)
            (0x101a, 0xe003),
            (0x101c, 0x4a04), // case 2: (0x1030)
            (0x101e, 0xe001),
            (0x1020, 0x4a04), // case 3: (0x1034)
            (0x1022, 0xe7ff),
            (0x1024, 0x4770), // bx lr
            (0x1026, 0x46c0),
            (0x1028, 0x1111_1111),
            (0x102c, 0x2222_2222),
            (0x1030, 0x3333_3333),
            (0x1034, 0x4444_4444),
            (0x1038, 0),
            (0x103a, 0),
            (0x103c, 0),
            (0x103e, 0),
            (0x1040, 0),
            (0x1042, 0),
            (0x1044, 0),
            (0x1046, 0),
            (0x1048, 0),
        ];
        let Some((cfg, import)) = jump_image(true, &words, 0x50) else { return };
        let mut lane = Lane::new(&cfg).unwrap();
        lane.load_mapped(&import).unwrap();
        let answer = lane.answer(0x1000, 0x1026, true);
        assert_eq!(
            answer.recovered_jumps,
            vec![(0x1006, propagation::JumpShape::Island, vec![0x100a, 0x100c, 0x100e, 0x1010])]
        );
        for (from, to) in [(0x1014, 0x1028), (0x1018, 0x102c), (0x101c, 0x1030), (0x1020, 0x1034)] {
            assert!(read_from(&answer, from, to), "the flow did not reach the case at {from:#x}: {:?}", answer.references);
        }
    }

    #[test]
    #[ignore = "requires arm-none-eabi GNU binutils"]
    fn file_queries_preserve_thumb_and_arm_symbol_contexts() {
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = std::env::temp_dir().join(format!(
            "romwright-file-context-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = Fixture(root);
        let source = root.0.join("mixed.s");
        let object = root.0.join("mixed.o");
        let binary = root.0.join("mixed.elf");
        std::fs::write(
            &source,
            ".syntax unified\n.text\n.thumb\n.global thumb_leaf\n.type thumb_leaf,%function\n\
             .thumb_func\nthumb_leaf:\nmovs r0,#7\nbx lr\n.size thumb_leaf,.-thumb_leaf\n\
             .balign 4\n.arm\n.global arm_leaf\n.type arm_leaf,%function\n\
             arm_leaf:\nmov r0,#9\nbx lr\n.size arm_leaf,.-arm_leaf\n",
        )
        .unwrap();
        let run = |command: &mut Command| {
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{command:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(Command::new("arm-none-eabi-as")
            .arg("-mcpu=arm7tdmi")
            .arg("-o").arg(&object).arg(&source));
        run(Command::new("arm-none-eabi-ld")
            .args(["-Ttext=0x08000000", "--entry=thumb_leaf"])
            .arg("-o").arg(&binary).arg(&object));
        let cfg = RuntimeConfig::from_env();
        let core = crate::Core::open(&root.0.join("project")).unwrap();
        for (entry, instruction_length, expected_bytes) in [
            (0x08000000, 2, ["0720", "7047"]),
            (0x08000004, 4, ["0900a0e3", "1eff2fe1"]),
        ] {
            let address = format!("{entry:#x}");
            for listing in [
                disasm_native(&cfg, &binary, &address, 2).unwrap(),
                listing_native(&cfg, &binary, &address, 2).unwrap(),
            ] {
                let addresses: Vec<_> = listing.lines()
                    .filter(|line| line.starts_with("0x") && !line.starts_with("Bytes"))
                    .map(|line| {
                        let (address, _) = line.trim().split_once(':').unwrap();
                        u64::from_str_radix(address.trim_start_matches("0x"), 16).unwrap()
                    })
                    .collect();
                assert_eq!(addresses, [entry, entry + instruction_length]);
            }
            let window = core
                .listing_window(&binary, &romwright_model::Address::ram(entry), 16, 0.0)
                .unwrap();
            let bytes: Vec<_> = window.rows.iter()
                .filter(|row| row.kind == romwright_model::ListingRowKind::Instruction)
                .take(2)
                .map(|row| row.bytes.as_str())
                .collect();
            assert_eq!(bytes, expected_bytes);
            let import = image::parse_binary(&cfg, &binary).unwrap().expect("an ELF image");
            let returned = SleighFlow::mapped(&cfg, &import).unwrap()
                .flow(&[entry + instruction_length]).remove(0);
            assert_eq!(returned.kind, FlowKind::Return);
            assert_eq!(u64::from(returned.length), instruction_length);
        }
        let mut arm_cfg = cfg.clone();
        arm_cfg.language_id = "ARM:LE:32:v8".into();
        arm_cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/ARM/data/languages");
        let import = image::parse_binary(&arm_cfg, &binary).unwrap().expect("an ELF image");
        let mut flow = SleighFlow::mapped(&arm_cfg, &import).unwrap();
        assert_eq!(flow.flow(&[0x08000002])[0].kind, FlowKind::Return);
    }

    #[test]
    fn test_pcode_flow_x86_and_ppc() {
        let cfg = RuntimeConfig::from_env();
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        let flow_of = |cfg: &RuntimeConfig, binary: &Path, address: u64| {
            let import = image::parse_binary(cfg, binary).unwrap().expect("an ELF image");
            SleighFlow::mapped(cfg, &import).unwrap().flow(&[address]).remove(0)
        };
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let x86_bin = manifest_dir.join("../../tests/fixtures-src/tiny_bin");
        if !x86_bin.is_file() {
            eprintln!("SKIP: tiny_bin not present");
            return;
        }
        let flow_ret = flow_of(&cfg, &x86_bin, 0x400479);
        assert_eq!(flow_ret.kind, FlowKind::Return);
        assert_eq!(flow_ret.fallthrough, None);
        assert_eq!(flow_ret.length, 1);

        let flow_fall = flow_of(&cfg, &x86_bin, 0x400466);
        assert_eq!(flow_fall.kind, FlowKind::Fallthrough);
        assert_eq!(flow_fall.fallthrough, Some(0x400467));

        let ppc_bin =
            Path::new("/home/raikaru/Projects/agent-under-fire/orig/GQFE78/files/base.elf");
        if ppc_bin.is_file() {
            let mut ppc_cfg = cfg.clone();
            ppc_cfg.language_id = "PowerPC:BE:32:default".into();
            ppc_cfg.language_dir = ppc_cfg
                .ghidra_install
                .join("Ghidra/Processors/PowerPC/data/languages");
            let flow_fall = flow_of(&ppc_cfg, ppc_bin, 0x80680000);
            assert_eq!(flow_fall.length, 4);
            assert_eq!(flow_fall.kind, FlowKind::Fallthrough);
            assert_eq!(flow_fall.fallthrough, Some(0x80680004));

            let flow_cbranch = flow_of(&ppc_cfg, ppc_bin, 0x8068001c);
            assert_eq!(flow_cbranch.length, 4);
            assert_eq!(flow_cbranch.kind, FlowKind::CBranch);
            assert_eq!(flow_cbranch.fallthrough, Some(0x80680020));
            assert_eq!(flow_cbranch.targets, vec![0x80680030]);
        }
    }

    #[test]
    fn powerpc_conditional_lr_returns_preserve_calls_and_branch_hints() {
        let cfg = RuntimeConfig::from_env();
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        // bdzlr, bdnzlr, bdnzflr lt, bdzlrl, bdzlr with BH=1, bctr.
        let words = [0x4e400020u32, 0x4e000020, 0x4c000020, 0x4e400021, 0x4e400820, 0x4e800420];
        for endian in ["BE", "LE"] {
            let mut cfg = cfg.clone();
            cfg.language_id = format!("PowerPC:{endian}:32:default");
            cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/PowerPC/data/languages");
            let code: Vec<_> = words.iter().flat_map(|word| {
                if endian == "BE" { word.to_be_bytes() } else { word.to_le_bytes() }
            }).collect();
            let import = NativeImport {
                language: cfg.language_id.clone(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000, size: code.len() as u64, file_off: 0, flags: 6, bytes: code,
                }],
                ..Default::default()
            };
            let mut session = SleighFlow::mapped(&cfg, &import).unwrap();
            let mut flow_at = |address| session.flow(&[address]).remove(0);
            for address in [0x1000, 0x1004, 0x1008] {
                let flow = flow_at(address);
                assert_eq!(flow.kind, FlowKind::Return, "{endian} at {address:#x}");
                assert!(flow.conditional && flow.terminal && flow.return_op);
                assert_eq!(flow.fallthrough, Some(address + 4));
            }
            let call = flow_at(0x100c);
            assert!(!call.return_op && !call.terminal);
            assert!(call.conditional);
            assert_eq!(call.fallthrough, Some(0x1010));
            let hinted = flow_at(0x1010);
            assert!(!hinted.return_op && !hinted.terminal);
            assert!(hinted.conditional);
            let ctr = flow_at(0x1014);
            assert!(!ctr.return_op && !ctr.terminal && !ctr.conditional);
            assert_eq!(ctr.fallthrough, None);
        }
    }

    #[test]
    fn constant_propagation_reports_mapped_globals() {
        let cfg = RuntimeConfig::from_env();
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        // llvm-mc: materialize 0x3000, load its pointer, advance one pointer,
        // load an unmapped pointer, return. The loaded 0x5000 targets BSS.
        let cases: &[(&str, &str, usize, bool, &[u8], u64, u64)] = &[
            (
                "x86",
                "x86:LE:64:default",
                8,
                false,
                &[
                    0x48, 0xb8, 0, 0x30, 0, 0, 0, 0, 0, 0, 0x48, 0x8b, 8, 0x48, 0x83, 0xc0, 8,
                    0x48, 0x8b, 0x10, 0xc3,
                ],
                0x100a,
                0x100d,
            ),
            (
                "PowerPC",
                "PowerPC:BE:32:default",
                4,
                true,
                &[
                    0x3c, 0x60, 0, 0, 0x60, 0x63, 0x30, 0, 0x80, 0x83, 0, 0, 0x38, 0x63, 0, 4,
                    0x80, 0xa3, 0, 0, 0x4e, 0x80, 0, 0x20,
                ],
                0x1008,
                0x100c,
            ),
        ];
        for &(processor, language, pointer_size, big_endian, code, load_pc, add_pc) in cases {
            let mut cfg = cfg.clone();
            cfg.language_id = language.into();
            cfg.language_dir = cfg
                .ghidra_install
                .join(format!("Ghidra/Processors/{processor}/data/languages"));
            let mut data = Vec::new();
            for pointer in [0x5000u64, 0x4000] {
                if big_endian {
                    data.extend_from_slice(&pointer.to_be_bytes()[8 - pointer_size..]);
                } else {
                    data.extend_from_slice(&pointer.to_le_bytes()[..pointer_size]);
                }
            }
            let code_end = 0x1000 + code.len() as u64;
            let import = NativeImport {
                language: language.into(),
                mappings: vec![
                    crate::native::Mapping {
                        vaddr: 0x1000,
                        size: code.len() as u64,
                        file_off: 0,
                        flags: 6,
                        bytes: code.to_vec(),
                    },
                    crate::native::Mapping {
                        vaddr: 0x3000,
                        size: data.len() as u64,
                        file_off: 0,
                        flags: 2,
                        bytes: data,
                    },
                    crate::native::Mapping {
                        vaddr: 0x5000,
                        size: 16,
                        file_off: 0,
                        flags: 3,
                        bytes: Vec::new(),
                    },
                ],
                ..Default::default()
            };
            let mut session = Lane::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let facts = session
                .constants(0x1000, code_end, &import.mappings, false)
                .unwrap();
            assert!(
                facts.iter().any(|fact| {
                    fact.pc == load_pc
                        && fact.value == 0x5000
                        && fact.varnode.space == "register"
                        && fact.varnode.size == pointer_size as u32
                }),
                "{language}: readonly global pointer into BSS"
            );
            assert!(
                facts.iter().any(|fact| {
                    fact.pc == add_pc && fact.value == 0x3000 + pointer_size as u64
                }),
                "{language}: propagated pointer arithmetic"
            );
            assert!(
                facts.iter().all(|fact| fact.value != 0x4000),
                "{language}: unmapped values are not pointer facts"
            );
        }
    }

    #[test]
    fn constant_propagation_respects_call_stack_semantics() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        // GNU as: retain rsp-8 in r12, call a separate RET, store a pointer
        // through the restored rsp, then read through r12. The slots differ.
        // The second case captures PC with CALL-to-next / POP, not a callee.
        // A recursive call must remain a call, with a reachable continuation.
        let cases: &[(&[u8], u64, Option<u64>)] = &[
            (
                &[
                    0x4c, 0x8d, 0x64, 0x24, 0xf8, 0xe8, 0x13, 0, 0, 0, 0x48, 0xb8, 0, 0x50, 0, 0,
                    0, 0, 0, 0, 0x48, 0x89, 0x04, 0x24, 0x49, 0x8b, 0x0c, 0x24, 0xc3, 0xc3,
                ],
                0x100a,
                Some(0x1018),
            ),
            (
                &[0xe8, 0, 0, 0, 0, 0x58, 0x48, 0x05, 0xfb, 0x3f, 0, 0, 0xc3],
                0x1006,
                None,
            ),
            (
                &[
                    0x41, 0x54, 0x49, 0xbc, 0, 0x50, 0, 0, 0, 0, 0, 0, 0x85, 0xff, 0x74, 0x0a,
                    0xff, 0xcf, 0xe8, 0xe9, 0xff, 0xff, 0xff, 0x4c, 0x89, 0xe0, 0x41, 0x5c, 0xc3,
                ],
                0x1017,
                None,
            ),
        ];
        for &(code, known_pc, distinct_slot_pc) in cases {
            let end = 0x1000 + code.len() as u64;
            let import = NativeImport {
                language: cfg.language_id.clone(),
                mappings: vec![
                    crate::native::Mapping {
                        vaddr: 0x1000,
                        size: code.len() as u64,
                        file_off: 0,
                        flags: 6,
                        bytes: code.to_vec(),
                    },
                    crate::native::Mapping {
                        vaddr: 0x5000,
                        size: 16,
                        file_off: 0,
                        flags: 3,
                        bytes: Vec::new(),
                    },
                ],
                ..Default::default()
            };
            let mut session = Lane::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let facts = session
                .constants(0x1000, end, &import.mappings, false)
                .unwrap();
            assert!(facts.iter().any(|fact| {
                fact.pc == known_pc && fact.value == 0x5000 && fact.varnode.space == "register"
            }));
            if let Some(pc) = distinct_slot_pc {
                assert!(
                    facts
                        .iter()
                        .all(|fact| fact.pc != pc || fact.value != 0x5000),
                    "callee return must restore rsp before subsequent memory accesses: {facts:?}"
                );
            }
        }
    }

    #[test]
    fn data_references_report_access_kinds() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        // Direct accesses and pointers; indirect jump slots are DATA, calls READ.
        let code = vec![
            0x8b, 0x05, 0xfa, 0x1f, 0, 0, 0x83, 0x05, 0xf3, 0x1f, 0, 0, 1, 0x48, 0x8d, 0x3d, 0xec,
            0x2f, 0, 0, 0x48, 0x89, 0x3d, 0xed, 0x1f, 0, 0, 0xff, 0x15, 0xe7, 0x1f, 0,
            0, // call [0x3008]
            // Conditional bounded exit, otherwise jump through a memory slot.
            0x85, 0xf6, 0x0f, 0x85, 0xd7, 0x0f, 0, 0, 0xff, 0x25, 0xd1, 0x1f, 0,
            0, // jmp [0x3000]
        ];
        let import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x1000,
                    size: code.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes: code,
                },
                crate::native::Mapping {
                    vaddr: 0x2000,
                    size: 25,
                    file_off: 0,
                    flags: 6,
                    bytes: vec![
                        0x31, 0xc0, 0x75, 0x01, 0xc3, // xor eax,eax; jne path; ret
                        0x8b, 0x05, 0xf5, 0x0f, 0, 0, // path: read [0x3000]
                        0x48, 0x8d, 0x05, 0xee, 0x1f, 0, 0, // lea rax,[0x4000]
                        0x48, 0x3d, 0, 0x40, 0, 0, 0xc3, // cmp rax,0x4000; ret
                    ],
                },
                crate::native::Mapping {
                    vaddr: 0x3000,
                    size: 16,
                    file_off: 0,
                    flags: 3,
                    bytes: vec![1; 16],
                },
                crate::native::Mapping {
                    vaddr: 0x4000,
                    size: 16,
                    file_off: 0,
                    flags: 0x32, // Readable ELF mergeable-string section.
                    bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x102f, &import.mappings, false)
            .unwrap();
        for (from, to, kind) in [
            (0x1000, 0x3000, ReferenceKind::Read),
            (0x1006, 0x3000, ReferenceKind::ReadWrite),
            (0x100d, 0x4000, ReferenceKind::Data),
            (0x1014, 0x3008, ReferenceKind::Write),
            (0x101b, 0x3008, ReferenceKind::Read),
            (0x1029, 0x3000, ReferenceKind::Data),
        ] {
            assert!(
                refs.iter().any(|reference| reference.from == from
                    && reference.to == to
                    && reference.kind == kind),
                "missing {kind:?} {from:#x} -> {to:#x}: {refs:?}"
            );
        }
        assert!(
            refs.iter()
                .all(|reference| matches!(reference.to, 0x3000 | 0x3008 | 0x4000)),
            "{refs:?}"
        );
        assert!(
            refs.iter()
                .all(|reference| (0x1000..0x102f).contains(&reference.from)),
            "reference inference escaped the function bounds: {refs:?}"
        );
        // References describe decoded operands even on provably untaken paths.
        // Constant-value queries must retain their stricter reachable-flow rule.
        let constants = session
            .constants(0x2000, 0x2019, &import.mappings, false)
            .unwrap();
        assert!(
            constants.iter().all(|fact| fact.value != 0x4000),
            "{constants:?}"
        );
        let refs = session
            .references(0x2000, 0x2019, &import.mappings, false)
            .unwrap();
        for (from, to, kind) in [
            (0x2005, 0x3000, ReferenceKind::Read),
            (0x200b, 0x4000, ReferenceKind::Data),
            (0x2012, 0x4000, ReferenceKind::Data),
        ] {
            assert!(
                refs.iter().any(|reference| reference.from == from
                    && reference.to == to
                    && reference.kind == kind),
                "{refs:?}"
            );
        }
    }

    #[test]
    fn computed_references_require_pointer_use() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        // The first addition transiently equals a mapped address. Only the
        // second result escapes as the return value; neither is a literal.
        let code = vec![
            0x48, 0xc7, 0xc0, 0xff, 0x3f, 0, 0, // mov rax,0x3fff
            0x48, 0x83, 0xc0, 1, // add rax,1
            0x48, 0x83, 0xc0, 1, // add rax,1
            0xc3,
        ];
        let mut import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x1000,
                    size: code.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes: code,
                },
                crate::native::Mapping {
                    vaddr: 0x4000,
                    size: 16,
                    file_off: 0,
                    flags: 3,
                    bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x1010, &import.mappings, false)
            .unwrap();
        assert_eq!(
            triples(&refs),
            vec![(0x100bu64, 0x4001u64, ReferenceKind::Data)],
            "computed intermediates are not references; the return references its last setter"
        );
        // Equal pointer values at a join retain both possible setter origins.
        import.mappings[0].bytes = vec![
            0x48, 0xc7, 0xc0, 0xff, 0x3f, 0, 0, 0x85, 0xff, 0x74,
            6, // test edi,edi; je alternative
            0x48, 0x83, 0xc0, 2, 0xeb, 4, 0x48, 0x83, 0xc0, 2, 0xc3,
        ];
        import.mappings[0].size = import.mappings[0].bytes.len() as u64;
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x1016, &import.mappings, false)
            .unwrap();
        assert_eq!(
            triples(&refs),
            vec![
                (0x100bu64, 0x4001u64, ReferenceKind::Data),
                (0x1011u64, 0x4001u64, ReferenceKind::Data),
            ],
            "a joined value must not lose either reaching setter"
        );
        // A computed argument must be observed before CALL clobbers its
        // register, and attributed to the setter rather than the call.
        cfg.language_id = "AARCH64:LE:64:v8A".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/AARCH64/data/languages");
        import.language = cfg.language_id.clone();
        import.mappings[0].bytes = vec![
            0xe0, 0xff, 0x87, 0xd2, // mov x0,#0x3fff
            0x00, 0x04, 0x00, 0x91, // add x0,x0,#1
            0x00, 0x04, 0x00, 0x91, // add x0,x0,#1
            0x05, 0x00, 0x00, 0x94, // bl 0x1020
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ];
        import.mappings[0].size = import.mappings[0].bytes.len() as u64;
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x1014, &import.mappings, false)
            .unwrap();
        assert_eq!(
            triples(&refs),
            vec![(0x1008u64, 0x4001u64, ReferenceKind::Data),],
            "computed arguments need source attribution before call effects"
        );
        // The e500 ABI uses an unnamed 32-bit slice of a 64-bit register.
        // Without a named-register setter, the return is the reference source.
        cfg.language_id = "PowerPC:BE:32:e500".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/PowerPC/data/languages");
        import.language = cfg.language_id.clone();
        import.mappings[0].bytes = vec![
            0x38, 0x60, 0x3f, 0xff, // li r3,0x3fff
            0x38, 0x63, 0x00, 0x01, // addi r3,r3,1
            0x38, 0x63, 0x00, 0x01, // addi r3,r3,1
            0x4e, 0x80, 0x00, 0x20, // blr
        ];
        import.mappings[0].size = import.mappings[0].bytes.len() as u64;
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x1010, &import.mappings, false)
            .unwrap();
        assert_eq!(
            triples(&refs),
            vec![(0x100cu64, 0x4001u64, ReferenceKind::Data),],
            "unnamed register slices must not invent a named-register setter"
        );
    }

    #[test]
    fn reference_queries_use_selected_compiler_abi() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        let code = vec![
            0x48, 0xc7, 0xc7, 0xff, 0x3f, 0, 0, // mov rdi,0x3fff
            0x48, 0x83, 0xc7, 2, // add rdi,2
            0x48, 0xc7, 0xc1, 0xff, 0x3f, 0, 0, // mov rcx,0x3fff
            0x48, 0x83, 0xc1, 3, // add rcx,3
            0xe8, 0x25, 0, 0, 0, // call 0x1040
            0x31, 0xc0, 0xc3,
        ];
        let mut import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x1000,
                    size: code.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes: code,
                },
                crate::native::Mapping {
                    vaddr: 0x4000,
                    size: 16,
                    file_off: 0,
                    flags: 3,
                    bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        for compiler in ["gcc", "default"] {
            import.compiler = Some(compiler.to_string());
            let mut session = Lane::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let refs = session
                .references(0x1000, 0x101e, &import.mappings, false)
                .unwrap();
            let mut expected = vec![(0x1012u64, 0x4002u64, ReferenceKind::Data)];
            if compiler == "gcc" {
                expected.insert(0, (0x1007u64, 0x4001u64, ReferenceKind::Data));
            }
            assert_eq!(
                triples(&refs),
                expected,
                "RDI is a SysV argument but not a Windows x64 argument ({compiler})"
            );
        }
    }

    #[test]
    fn data_references_do_not_promote_fallthrough() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        let mut import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![crate::native::Mapping {
                vaddr: 0x1000,
                size: 16,
                file_off: 0,
                flags: 6,
                // The following function's entry is also the saved return PC.
                bytes: vec![0xe8, 0x0b, 0, 0, 0, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            }],
            ..Default::default()
        };
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x1005, &import.mappings, false)
            .unwrap();
        assert!(
            refs.is_empty(),
            "saving a return PC is not a data reference: {refs:?}"
        );
        import.mappings[0].bytes[..6].copy_from_slice(&[0x8b, 0x05, 0, 0, 0, 0]);
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x1006, &import.mappings, false)
            .unwrap();
        assert_eq!(
            triples(&refs),
            vec![(0x1000u64, 0x1006u64, ReferenceKind::Read),],
            "a real access to following data must not be suppressed"
        );
    }

    #[test]
    fn reference_facts_carry_the_access_width() {
        // `mov eax,[rip+0]` reads four bytes; `mov rax,[rip+0]` reads eight.
        // The width is the access's, not the pointer's, and an address that is
        // only computed proves none.
        let cfg = RuntimeConfig::from_env();
        if !crate::architecture::language_installed(&cfg.ghidra_install, &cfg.language_id) {
            return;
        }
        for (bytes, expected) in [
            (vec![0x8b, 0x05, 0, 0, 0, 0, 0xc3], 4u32),
            (vec![0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xc3], 8u32),
        ] {
            let end = 0x1000 + bytes.len() as u64;
            let mut padded = bytes.clone();
            padded.resize(16, 0);
            let import = crate::native::NativeImport {
                binary: std::path::PathBuf::new(),
                language: cfg.language_id.clone(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000,
                    size: 16,
                    file_off: 0,
                    flags: 6,
                    bytes: padded,
                }],
                ..Default::default()
            };
            let mut session = Lane::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let refs = session
                .references(0x1000, end, &import.mappings, false)
                .unwrap();
            let read = refs
                .iter()
                .find(|fact| fact.kind == ReferenceKind::Read)
                .unwrap_or_else(|| panic!("no read reference in {refs:?}"));
            assert_eq!(read.size, expected, "{refs:?}");
        }
        // `lea rax,[rip+0]` takes an address without touching it.
        let import = crate::native::NativeImport {
            binary: std::path::PathBuf::new(),
            language: cfg.language_id.clone(),
            mappings: vec![crate::native::Mapping {
                vaddr: 0x1000,
                size: 16,
                file_off: 0,
                flags: 6,
                bytes: vec![
                    0x48, 0x8d, 0x05, 0xf9, 0x2f, 0, 0, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            }],
            ..Default::default()
        };
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x1008, &import.mappings, false)
            .unwrap();
        for fact in &refs {
            if fact.kind == ReferenceKind::Data {
                assert_eq!(fact.size, 0, "a taken address proves no width: {refs:?}");
            }
        }
    }

    #[test]
    fn scalar_reference_eligibility_respects_instruction_alignment() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "AARCH64:LE:64:v8A".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/AARCH64/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        let mut import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x1000,
                    size: 8,
                    file_off: 0,
                    flags: 6,
                    bytes: vec![0x01, 0x80, 0x01, 0x10, 0xc0, 0x03, 0x5f, 0xd6], // adr x1,0x4000; ret
                },
                crate::native::Mapping {
                    vaddr: 0x4000,
                    size: 16,
                    file_off: 0,
                    flags: 3,
                    bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x1008, &import.mappings, false)
            .unwrap();
        assert!(
            refs.is_empty(),
            "unused ADR is not a scalar reference: {refs:?}"
        );
        import.mappings[0].bytes[0] = 0; // adr x0,0x4000; ret
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x1008, &import.mappings, false)
            .unwrap();
        assert_eq!(
            triples(&refs),
            vec![(0x1000u64, 0x4000u64, ReferenceKind::Data),],
            "returned addresses remain eligible for computed reference inference"
        );
    }

    #[test]
    fn x86_computed_address_operands_create_references() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:32:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        let mut import = NativeImport {
            language: cfg.language_id.clone(),
            compiler: Some("gcc".into()),
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x1000,
                    size: 11,
                    file_off: 0,
                    flags: 6,
                    bytes: vec![
                        0xbb, 0xff, 0x3f, 0, 0, // mov ebx,0x3fff
                        0x8d, 0x43, 1, // lea eax,[ebx+1]
                        0x31, 0xc0, 0xc3, // discard result; ret
                    ],
                },
                crate::native::Mapping {
                    vaddr: 0x4000,
                    size: 16,
                    file_off: 0,
                    flags: 3,
                    bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x100b, &import.mappings, false)
            .unwrap();
        assert_eq!(
            triples(&refs),
            vec![(0x1005u64, 0x4000u64, ReferenceKind::Data),],
            "computed address operands are references even when not returned"
        );
        import.mappings[0].bytes[5..8].copy_from_slice(&[0x83, 0xc3, 1]); // add ebx,1
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session
            .references(0x1000, 0x100b, &import.mappings, false)
            .unwrap();
        assert!(
            refs.is_empty(),
            "unused arithmetic is not address formation: {refs:?}"
        );
    }

    #[test]
    fn repeated_instruction_flow_does_not_escape_into_pcode_labels() {
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        let mut session = SleighFlow::mapped(
            &cfg,
            &NativeImport {
                language: cfg.language_id.clone(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000,
                    size: 3,
                    file_off: 0,
                    flags: 6,
                    bytes: vec![0xf3, 0xa4, 0xc3], // REP MOVSB; RET
                }],
                ..Default::default()
            },
        )
        .unwrap();
        let flows = session.flow(&[0x1000]);
        assert_eq!(flows[0].kind, FlowKind::Fallthrough);
        assert_eq!(flows[0].fallthrough, Some(0x1002));
        assert!(
            flows[0].targets.is_empty(),
            "instruction-local repeat branches are not machine flow references"
        );
    }

    #[test]
    fn non_stack_symbolic_offsets_are_data_references() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        for (setup, transfer, expected) in [
            // rax = unknown rdi; jmp [rax+offset]: a data slot
            (
                [0x48, 0x89, 0xf8],
                0x60,
                vec![(0x1009, 0x10048, ReferenceKind::Data)],
            ),
            // rax = stack alias; jmp [rax+offset]: a frame slot, never data
            (
                [0x48, 0x89, 0xe0],
                0x60,
                vec![(0x1009, 0x10048, ReferenceKind::Stack)],
            ),
            ([0x48, 0x89, 0xf8], 0x50, Vec::new()), // original call [rax+offset]
        ] {
            let mut code = setup.to_vec();
            code.extend_from_slice(&[0x48, 0x05, 0, 0, 1, 0]); // add rax,0x10000
            code.extend_from_slice(&[0xff, transfer, 0x48, 0xc3]);
            let end = 0x1000 + code.len() as u64;
            let import = NativeImport {
                language: cfg.language_id.clone(),
                mappings: vec![
                    crate::native::Mapping {
                        vaddr: 0x1000,
                        size: code.len() as u64,
                        file_off: 0,
                        flags: 6,
                        bytes: code,
                    },
                    crate::native::Mapping {
                        vaddr: 0x10048,
                        size: 8,
                        file_off: 0,
                        flags: 2,
                        bytes: vec![0; 8],
                    },
                ],
                ..Default::default()
            };
            let mut session = Lane::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let facts = session
                .references(0x1000, end, &import.mappings, false)
                .unwrap();
            let triples: Vec<_> = facts
                .iter()
                .map(|fact| (fact.from, fact.to, fact.kind))
                .collect();
            assert_eq!(triples, expected, "setup={setup:x?}, transfer={transfer:x}");
            assert!(
                session
                    .constants(0x1000, end, &import.mappings, false)
                    .unwrap()
                    .is_empty(),
                "a symbolic offset is not a proven constant pointer"
            );
        }
    }

    /// A MIPS call whose pointer argument is finished in the delay slot: the
    /// delay slot's p-code carries the call's address, so the reference is
    /// the call's (paired with the in-process propagation in test builds).
    #[test]
    fn mips_delay_slot_arguments_are_referenced_at_the_call() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "MIPS:LE:32:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/MIPS/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        let words: [u32; 6] = [
            0x3c04_8017,                                  // lui a0,0x8017
            0x0c00_0000 | ((0x8010_0020u32 >> 2) & 0x03ff_ffff), // jal 0x80100020
            0x2484_0200,                                  // addiu a0,a0,0x200 (delay slot)
            0x03e0_0008,                                  // jr ra
            0,                                            // nop
            0,
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x8010_0000,
                    size: code.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes: code,
                },
                crate::native::Mapping {
                    vaddr: 0x8017_0000,
                    size: 0x1000,
                    file_off: 0,
                    flags: 3,
                    bytes: vec![0; 0x1000],
                },
            ],
            ..Default::default()
        };
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x8010_0000, 0x8010_0018, &import.mappings, false).unwrap();
        assert_eq!(
            triples(&refs),
            vec![(0x8010_0004, 0x8017_0200, ReferenceKind::Data)],
            "the delay slot finishes the argument: {refs:?}"
        );
    }

    /// A pointer left in the return register and returned: the reference is
    /// attributed where the setter search ends, as the decompiler's
    /// propagation does.
    #[test]
    fn mips_returned_pointers_are_referenced_at_the_return() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "MIPS:LE:32:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/MIPS/data/languages");
        if !cfg.language_dir.is_dir() {
            eprintln!("SKIP: SLEIGH language not available");
            return;
        }
        const LUI_V0: u32 = 0x3c02_8017; // lui v0,0x8017
        const ADDIU_V0: u32 = 0x2442_0200; // addiu v0,v0,0x200
        const ADDIU_SP_DOWN: u32 = 0x27bd_ffe8; // addiu sp,sp,-0x18
        const ADDIU_SP_UP: u32 = 0x27bd_0018; // addiu sp,sp,0x18
        const LW_RA: u32 = 0x8fbf_0014; // lw ra,0x14(sp)
        const SW_RA: u32 = 0xafbf_0014; // sw ra,0x14(sp)
        const JR_RA: u32 = 0x03e0_0008;
        let jal = 0x0c00_0000 | ((0x8010_1000u32 >> 2) & 0x03ff_ffff);
        let variants: [&[u32]; 7] = [
            &[LUI_V0, ADDIU_V0, JR_RA, 0],
            &[LUI_V0, ADDIU_V0, LW_RA, JR_RA, 0],
            &[ADDIU_SP_DOWN, LUI_V0, ADDIU_V0, ADDIU_SP_UP, JR_RA, 0],
            &[ADDIU_SP_DOWN, SW_RA, jal, 0, LUI_V0, ADDIU_V0, LW_RA, ADDIU_SP_UP, JR_RA, 0],
            &[ADDIU_SP_DOWN, SW_RA, LW_RA, LUI_V0, ADDIU_V0, LW_RA, ADDIU_SP_UP, JR_RA, 0],
            &[LUI_V0, ADDIU_V0, 0xac82_0000, JR_RA, 0], // sw v0,0(a0)
            &[SW_RA, LUI_V0, ADDIU_V0, JR_RA, 0],
        ];
        let mut code = vec![0u8; 0x2000];
        let mut ends = Vec::new();
        for (index, words) in variants.iter().enumerate() {
            let base = index * 0x100;
            for (slot, word) in words.iter().enumerate() {
                code[base + slot * 4..base + slot * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            ends.push((0x8010_0000 + base as u64, 0x8010_0000 + (base + words.len() * 4) as u64));
        }
        let import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x8010_0000,
                    size: code.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes: code,
                },
                crate::native::Mapping {
                    vaddr: 0x8017_0000,
                    size: 0x1000,
                    file_off: 0,
                    flags: 3,
                    bytes: vec![0; 0x1000],
                },
            ],
            ..Default::default()
        };
        let mut session = Lane::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        // A pointer left in v0 is referenced where the injected `v0 = v0` of
        // `setISAMode` writes it, which is the return's own address.
        for (start, end) in ends {
            let refs = session.references(start, end, &import.mappings, false).unwrap();
            assert!(
                refs.iter().any(|fact| fact.kind == ReferenceKind::Data && fact.to == 0x8017_0200),
                "{start:#x}: {refs:?}"
            );
        }
    }

    /// The worker's answer for one function is filed by what decided it: the
    /// wall-clock guard (the host's load did), the work budget (the function
    /// did, on every host), or the decompiler's own error.
    #[test]
    fn a_switch_answer_is_filed_by_what_decided_it() {
        let lines = [
            r#"{"address":4096,"result":{"Err":"decompiler timed out after 59s"},"wall_clock":true}"#,
            r#"{"address":4112,"result":{"Err":"decompiler exception: WorkBudgetExceeded: decompiler work budget of 5 units exceeded"},"wall_clock":false}"#,
            r#"{"address":4128,"result":{"Err":"decompiler exception: Low-level Error: Flow exceeded maximum allowable instructions"}}"#,
            r#"{"address":4144,"result":{"Ok":[]},"wall_clock":false}"#,
        ];
        let mut recovery = SwitchRecovery::default();
        for line in lines {
            recovery.record(serde_json::from_str(line).expect("a worker answer parses"));
        }
        assert_eq!(recovery.wall_clock.len(), 1, "{:?}", recovery.wall_clock);
        assert!(recovery.wall_clock[0].starts_with("0x1000: "));
        assert_eq!(recovery.over_budget.len(), 1, "{:?}", recovery.over_budget);
        assert!(recovery.over_budget[0].starts_with("0x1010: "));
        assert_eq!(recovery.failures.len(), 1, "{:?}", recovery.failures);
        assert!(recovery.failures[0].contains("Flow exceeded"));
        assert_eq!(recovery.completed, 1);
    }
}
