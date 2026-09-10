//! Native (no-JVM) runtime services: SLEIGH console + the decompiler worker.
//!
//! These were CLI-local until the review that tightened the facade contract
//! (a GUI — the intended consumer — could not reuse `decompile` /
//! `disasm` without copying `Command::new` spawn logic out of
//! lre-cli/main.rs). They now live behind the Core facade so every consumer
//! (CLI, GUI, agents) speaks only Core API methods.
//!
//! The runtime contract is `RuntimeConfig` (crate::session): services take
//! an explicit value — never read process-wide env vars. The environment is
//! consulted only when the config is BUILT (`RuntimeConfig::from_env`), so
//! the CLI's env surface is preserved while everything below it is honest
//! about its inputs.

use crate::native::{NativeImport, elf_image_base, pe_image_base};
use crate::session::RuntimeConfig;
use std::path::{Path, PathBuf};
use std::process::Command;
mod image;
use image::MappedImage;

/// Exact refusal from `Propagation::run` in `native/ventris_constants.hh`:
/// the range has no decodable flow, so it carries no propagation facts.
const UNDECODABLE: &str = "Constant propagation requires decodable function flow";

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

pub type Result<T> = std::result::Result<T, NativeRuntimeError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(NativeRuntimeError(msg.into()))
}

/// The pinned Ghidra install root (env override, then the default path).
pub fn ghidra_dir() -> PathBuf {
    std::env::var("VENTRIS_GHIDRA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(format!(
                "{}/ghidra_12.1.3_PUBLIC",
                std::env::var("HOME").unwrap_or_default()
            ))
        })
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
    for element in text.split('<').filter(|element| element.starts_with("register ")) {
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

pub fn find_console(cfg: &RuntimeConfig) -> Result<PathBuf> {
    if let Some(ref p) = cfg.console_path {
        if p.is_file() {
            return Ok(p.clone());
        }
    }
    if let Ok(val) = std::env::var("VENTRIS_CONSOLE") {
        let p = PathBuf::from(val);
        if p.is_file() {
            return Ok(p);
        }
    }
    for candidate in [
        PathBuf::from("native/build/decomp_native"),
        PathBuf::from("../../native/build/decomp_native"),
        PathBuf::from("../native/build/decomp_native"),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    err(
        "SLEIGH console missing: build native/build_console.sh (needs binutils-devel) or configure console_path",
    )
}

fn console_output(cfg: &RuntimeConfig, binary: &Path, address: &str) -> Result<String> {
    let console = find_console(cfg)?;
    let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
    let langs = cfg.language_dir.to_string_lossy().into_owned();
    let hex_addr = if address.starts_with("0x") {
        address.to_string()
    } else {
        format!("0x{address}")
    };
    let mapped = MappedImage::for_elf_or_dol(cfg, binary)?;
    let bfd_target = bfd_target_for(&cfg.language_id, binary)?;
    let load_script = if let Some(image) = &mapped {
        image.command()
    } else if cfg.language_id.starts_with("x86:") {
        format!(
            "load file {} {}\nadjust vma 0x400000\n",
            bfd_target,
            binary.display()
        )
    } else {
        format!("load file {} {}\n", bfd_target, binary.display())
    };
    let script =
        format!("{load_script}map function {hex_addr} func\nload function func\ndisassemble\n",);
    let mut child = Command::new(&console)
        .arg("-s")
        .arg(&langs)
        .env("SLEIGHHOME", &ghroot)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| NativeRuntimeError(format!("console spawn: {e}")))?;
    use std::io::Write as _;
    child
        .stdin
        .take()
        .ok_or_else(|| NativeRuntimeError("console stdin".into()))?
        .write_all(script.as_bytes())
        .map_err(|e| NativeRuntimeError(format!("console write: {e}")))?;
    let out = child
        .wait_with_output()
        .map_err(|e| NativeRuntimeError(format!("console wait: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn instruction_line(line: &str) -> bool {
    let Some((address, _)) = line.trim().split_once(':') else {
        return false;
    };
    let address = address.trim().trim_start_matches("0x");
    !address.is_empty() && u64::from_str_radix(address, 16).is_ok()
}

fn structural_line(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("Function ")
        || line.starts_with("Block ")
        || line.starts_with("Label ")
        || line.starts_with("Data ")
}

fn filtered_listing(output: &str, count: u32, include_structural: bool) -> Vec<String> {
    let mut instructions = 0u32;
    let mut lines = Vec::new();
    for line in output.lines() {
        let is_instruction = instruction_line(line);
        let is_structural = include_structural && structural_line(line);
        if !is_instruction && !is_structural {
            continue;
        }
        if is_instruction {
            if instructions >= count {
                break;
            }
            instructions += 1;
        }
        lines.push(line.to_string());
    }
    lines
}

/// Performs `disasm`: one function mapped + disassembled by the
/// SLEIGH console, returning only address-prefixed instruction lines.
pub fn disasm_native(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    count: u32,
) -> Result<String> {
    let output = console_output(cfg, binary, address)?;
    let lines = filtered_listing(&output, count, false);
    if lines.is_empty() {
        return err("console produced no listing");
    }
    Ok(lines.join("\n"))
}

/// Runs the same console request as `disasm_native`, preserving structural
/// marker lines for the Core listing parser.
pub fn listing_native(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    count: u32,
) -> Result<String> {
    let output = console_output(cfg, binary, address)?;
    let lines = filtered_listing(&output, count, true);
    if !lines.iter().any(|line| instruction_line(line)) {
        return err("console produced no listing");
    }
    Ok(lines.join("\n"))
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
    if let Some(sla) = cfg.sla_path.as_ref().filter(|_| language == cfg.language_id) {
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
             `lre-cli dump-specs <program> --out {}` (JVM bridge)",
            bundle.display(),
            bundle.display()
        ));
    }
    Ok((sla, bundle, lang_dir, language.to_string()))
}

/// Performant `decompile`: one address decompiled by the patched
/// `ghidra_opt` through `lre-worker` (raw-SLEIGH, no JVM).
fn run_decompiler(
    cfg: &RuntimeConfig,
    binary: &Path,
    addresses: &[String],
    program: &str,
    project_dir: &Path,
    base: Option<u64>,
    structured: bool,
) -> Result<Vec<u8>> {
    let opt = &cfg.decompiler_path;
    let worker = &cfg.worker_path;
    // The patched ghidra_opt self-disassembles only when a compiled .sla is
    // configured (see native/build_ghidra_opt.sh). The program language
    // drives the SLA + spec bundle; explicit env overrides win.
    let language = crate::session::program_language(cfg, program, project_dir)
        .unwrap_or_else(|_| cfg.language_id.clone());
    let (sla, specs, lang_dir, language_id) = language_decompile_config(cfg, &language)?;
    if !sla.is_file() {
        return err(format!(
            "configured SLA does not exist: {} — the decompiler silently fails \
             (\"no architecture registered\") without a readable .sla",
            sla.display()
        ));
    }
    if !opt.is_file() {
        return err(format!(
            "native decompiler missing: {} — build it via native/build_ghidra_opt.sh",
            opt.display()
        ));
    }
    if !specs.join("tspec.xml").is_file() {
        return err(format!(
            "spec dir incomplete: {} (needs tspec.xml; use native/specs)",
            specs.display()
        ));
    }
    let base = match base {
        Some(b) => b,
        None => {
            let data = std::fs::read(binary)
                .map_err(|e| NativeRuntimeError(format!("{}: {e}", binary.display())))?;
            // A container header names the base; a raw platform image does
            // not, so the program's own stored regions are asked first --
            // a cartridge with two processors has two bases, and only the
            // store knows which program this request is for.
            program_image_base(program, project_dir)
                .or_else(|| pe_image_base(&data))
                .or_else(|| elf_image_base(&data))
                .or_else(|| {
                    crate::native::parse_native(&data)
                        .ok()
                        .and_then(|import| {
                            import.mappings.iter().map(|mapping| mapping.vaddr).min()
                        })
                })
                .unwrap_or(0x400000)
        }
    };
    let mut command = Command::new(worker);
    command
        .arg(opt)
        .arg(specs)
        .arg(binary)
        .arg(program)
        .args(addresses)
        .arg("--project")
        .arg(project_dir)
        .arg("--base")
        .arg(format!("{base:#x}"))
        .env("VENTRIS_LANGUAGE", &language_id)
        .env("VENTRIS_LANGUAGE_DIR", &lang_dir)
        .env("VENTRIS_SLA", &sla);
    if structured {
        command.env("WORKER_STRUCTURED", "1");
    }
    let out = command
        .output()
        .map_err(|e| NativeRuntimeError(format!("worker spawn: {e}")))?;
    if !out.status.success() {
        return err(format!(
            "worker failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Perform `decompile`: one address decompiled by the patched
/// `ghidra_opt` through `lre-worker` (raw-SLEIGH, no JVM).
pub fn decompile_native(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    program: &str,
    project_dir: &Path,
    base: Option<u64>,
) -> Result<String> {
    let stdout = run_decompiler(
        cfg, binary, std::slice::from_ref(&address.to_string()), program, project_dir,
        base, false,
    )?;
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Decompiles several addresses from one worker launch. The decompiler loads
/// its language once per launch, so a batch is what makes comparing a
/// hundreds-of-functions image affordable (m4-022). Answers are keyed by the
/// eight-digit address the caller asked for.
pub fn decompile_native_batch(
    cfg: &RuntimeConfig,
    binary: &Path,
    addresses: &[String],
    program: &str,
    project_dir: &Path,
    base: Option<u64>,
) -> Result<std::collections::BTreeMap<String, String>> {
    if addresses.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    if addresses.len() == 1 {
        let text = decompile_native(cfg, binary, &addresses[0], program, project_dir, base)?;
        let key = u64::from_str_radix(addresses[0].trim_start_matches("0x"), 16)
            .map_err(|e| NativeRuntimeError(format!("address {}: {e}", addresses[0])))?;
        return Ok([(format!("{key:08x}"), text)].into_iter().collect());
    }
    let stdout = run_decompiler(cfg, binary, addresses, program, project_dir, base, false)?;
    let text = String::from_utf8(stdout)
        .map_err(|e| NativeRuntimeError(format!("worker batch is not UTF-8: {e}")))?;
    serde_json::from_str(text.trim())
        .map_err(|e| NativeRuntimeError(format!("invalid worker batch: {e}")))
}

/// Structured documents for several addresses from one worker launch, keyed
/// like `decompile_native_batch`. A single address still goes through the
/// batch protocol so the answer shape is one.
pub fn decompile_native_docs(
    cfg: &RuntimeConfig,
    binary: &Path,
    addresses: &[String],
    program: &str,
    project_dir: &Path,
    base: Option<u64>,
) -> Result<std::collections::BTreeMap<String, lre_model::DecompDoc>> {
    if addresses.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    if addresses.len() == 1 {
        let doc = decompile_native_doc(cfg, binary, &addresses[0], program, project_dir, base)?;
        return Ok([(format!("{:08x}", doc.address.offset), doc)].into_iter().collect());
    }
    let stdout = run_decompiler(cfg, binary, addresses, program, project_dir, base, true)?;
    let text = String::from_utf8(stdout)
        .map_err(|e| NativeRuntimeError(format!("worker batch is not UTF-8: {e}")))?;
    serde_json::from_str(text.trim())
        .map_err(|e| NativeRuntimeError(format!("invalid structured worker batch: {e}")))
}

/// Performs the same native decompile but returns the packed document as
/// structured model data. The worker stamped revision is zero; the Core
/// facade replaces it with the current durable program revision.
pub fn decompile_native_doc(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    program: &str,
    project_dir: &Path,
    base: Option<u64>,
) -> Result<lre_model::DecompDoc> {
    let stdout = run_decompiler(
        cfg, binary, std::slice::from_ref(&address.to_string()), program, project_dir,
        base, true,
    )?;
    let text = String::from_utf8(stdout)
        .map_err(|e| NativeRuntimeError(format!("worker document is not UTF-8: {e}")))?;
    serde_json::from_str(text.trim())
        .map_err(|e| NativeRuntimeError(format!("invalid structured worker document: {e}")))
}

/// The lowest address the store records for `program`, when the program is
/// already imported. A platform image has no header to read a base from.
fn program_image_base(program: &str, project_dir: &Path) -> Option<u64> {
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

/// Reads console output until the interactive prompt "[decomp]> " is seen.
/// The prompt carries no trailing newline, so `read_line` deadlocks; the
/// console also buffers, so the read must be byte-wise.
/// One console output line, or the prompt that means the console has said all
/// it intends to.
///
/// The prompt carries no newline, so a reader that waits for one waits for
/// ever: a MIPS image whose BFD target the console refused answered
/// `Execution error: No architecture loaded` and then the prompt, and an
/// import that expected one `FLOW` line per address hung on the second read
/// for fourteen minutes before this existed.
enum ConsoleOutput {
    Line(String),
    Prompt(String),
}

fn read_line_or_prompt(
    reader: &mut std::io::BufReader<std::process::ChildStdout>,
) -> Result<ConsoleOutput> {
    use std::io::Read as _;
    const PROMPT: &[u8] = b"[decomp]> ";
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let read = reader
            .read(&mut byte)
            .map_err(|e| NativeRuntimeError(format!("console read: {e}")))?;
        if read == 0 {
            return err("console closed before answering");
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(ConsoleOutput::Line(
                String::from_utf8_lossy(&buf).into_owned(),
            ));
        }
        if buf.ends_with(PROMPT) {
            return Ok(ConsoleOutput::Prompt(
                String::from_utf8_lossy(&buf).into_owned(),
            ));
        }
    }
}

fn read_until_prompt(reader: &mut std::io::BufReader<std::process::ChildStdout>) -> Result<String> {
    use std::io::Read as _;
    const PROMPT: &[u8] = b"[decomp]> ";
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader
            .read(&mut byte)
            .map_err(|e| NativeRuntimeError(format!("console read: {e}")))?;
        if n == 0 {
            return err("console closed before prompt");
        }
        buf.push(byte[0]);
        if buf.ends_with(PROMPT) {
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
    }
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


/// One p-code varnode as the console prints it: `<space>:<offset>:<size>`.
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
    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.rsplitn(3, ':');
        let size = parts.next()?.parse().ok()?;
        let offset = u64::from_str_radix(parts.next()?.trim_start_matches("0x"), 16).ok()?;
        let space = parts.next()?.to_string();
        Some(Self {
            space,
            offset,
            size,
        })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
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

#[derive(Debug, serde::Deserialize)]
pub(crate) struct FunctionPatterns {
    pub alignment: u64,
    pub rules: Vec<FunctionPatternRule>,
    pub matches: Vec<FunctionPatternMatch>,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct FunctionPatternRule {
    pub file: String,
    pub actions: Vec<FunctionPatternAction>,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct FunctionPatternAction {
    pub kind: String,
    pub attributes: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct FunctionPatternMatch {
    pub address: u64,
    pub rule: usize,
}

pub fn console_flow(cfg: &RuntimeConfig, binary: &Path, address: u64) -> Result<FlowResult> {
    let console = find_console(cfg)?;
    let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
    let langs = cfg.language_dir.to_string_lossy().into_owned();

    let mapped = MappedImage::for_elf_or_dol(cfg, binary)?;
    let target = bfd_target_for(&cfg.language_id, binary)?;
    let mappings = crate::native::load_native_mappings(binary).unwrap_or_default();
    let adjust_vma = mappings
        .iter()
        .find(|m| address >= m.vaddr && address < m.vaddr + m.size)
        .or_else(|| mappings.first())
        .map(|m| m.vaddr.wrapping_sub(m.file_off))
        .unwrap_or(0);

    let script = if let Some(image) = &mapped {
        format!("{}flow 0x{address:x}\nquit\n", image.command())
    } else if cfg.language_id.starts_with("x86:") {
        format!(
            "load file {} {}\nflow 0x{:x}\nquit\n",
            target,
            binary.display(),
            address
        )
    } else {
        format!(
            "load file {} {}\nadjust vma 0x{:x}\nflow 0x{:x}\nquit\n",
            target,
            binary.display(),
            adjust_vma,
            address
        )
    };
    let mut child = Command::new(&console)
        .arg("-s")
        .arg(&langs)
        .env("SLEIGHHOME", &ghroot)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| NativeRuntimeError(format!("console spawn: {e}")))?;

    use std::io::Write as _;
    child
        .stdin
        .take()
        .ok_or_else(|| NativeRuntimeError("console stdin".into()))?
        .write_all(script.as_bytes())
        .map_err(|e| NativeRuntimeError(format!("console write: {e}")))?;

    let out = child
        .wait_with_output()
        .map_err(|e| NativeRuntimeError(format!("console wait: {e}")))?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_flow_output(&stdout, address)
}

fn parse_address_token(text: &str) -> Option<u64> {
    let clean = text
        .trim()
        .trim_start_matches(|c: char| c.is_alphabetic() || c == ':');
    let hex = clean.trim_start_matches("0x");
    (!hex.is_empty())
        .then(|| u64::from_str_radix(hex, 16).ok())
        .flatten()
}

fn parse_flow_output(stdout: &str, expected_addr: u64) -> Result<FlowResult> {
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("FLOW ") {
            let mut addr = expected_addr;
            let mut length = 1u8;
            let mut fallthrough = None;
            let mut kind = FlowKind::Fallthrough;
            let mut targets = Vec::new();
            let mut pure_jump = false;
            let mut no_op = false;
            let mut terminal = false;
            let mut conditional = false;
            let mut return_op = false;
            let mut delay_slots = Vec::new();
            let mut mode = None;
            let mut target_modes = Vec::new();
            let mut metadata = 0u8;

            for part in rest.split_whitespace() {
                if let Some(val) = part.strip_prefix("len=") {
                    length = val.parse().unwrap_or(1);
                } else if let Some(val) = part.strip_prefix("fall=") {
                    if val != "none" {
                        fallthrough = parse_address_token(val);
                    }
                } else if let Some(val) = part.strip_prefix("kind=") {
                    kind = match val {
                        "BRANCH" => FlowKind::Branch,
                        "CBRANCH" => FlowKind::CBranch,
                        "BRANCHIND" => FlowKind::BranchInd,
                        "CALL" => FlowKind::Call,
                        "CALLIND" => FlowKind::CallInd,
                        "RETURN" => FlowKind::Return,
                        "BAD" => FlowKind::Bad,
                        "UNIMPL" => FlowKind::Unimpl,
                        _ => FlowKind::Fallthrough,
                    };
                } else if let Some(val) = part.strip_prefix("pure_jump=") {
                    pure_jump = val == "1";
                } else if let Some(val) = part.strip_prefix("no_op=") {
                    no_op = val == "1";
                } else if let Some(val) = part.strip_prefix("terminal=") {
                    terminal = val == "1";
                    metadata |= 1;
                } else if let Some(val) = part.strip_prefix("conditional=") {
                    conditional = val == "1";
                    metadata |= 2;
                } else if let Some(val) = part.strip_prefix("mode=") {
                    mode = val.parse::<u64>().ok();
                } else if let Some(val) = part.strip_prefix("flow_modes=") {
                    for item in val.split(',').filter(|item| !item.is_empty()) {
                        let (target, value) = item.split_once(':').ok_or_else(|| {
                            NativeRuntimeError("invalid flow_modes entry".into())
                        })?;
                        let target = parse_address_token(target)
                            .ok_or_else(|| NativeRuntimeError("invalid flow_modes target".into()))?;
                        let value = value
                            .parse::<u64>()
                            .map_err(|_| NativeRuntimeError("invalid flow_modes value".into()))?;
                        target_modes.push((target, value));
                    }
                } else if let Some(val) = part.strip_prefix("return_op=") {
                    return_op = val == "1";
                    metadata |= 4;
                } else if let Some(val) = part.strip_prefix("delays=") {
                    metadata |= 8;
                    if !val.is_empty() {
                        for item in val.split(',') {
                            let length: u8 = item.parse().map_err(|_| {
                                NativeRuntimeError("invalid delay-slot length".into())
                            })?;
                            if length == 0 {
                                return err("zero delay-slot length");
                            }
                            delay_slots.push(length);
                        }
                    }
                } else if let Some(val) = part.strip_prefix("targets=") {
                    for t in val.split(',') {
                        if let Some(target_addr) = parse_address_token(t) {
                            targets.push(target_addr);
                        }
                    }
                } else if let Some(a) = parse_address_token(part) {
                    addr = a;
                }
            }
            if metadata != 15 {
                return err("console lacks instruction flow metadata; rebuild the native console");
            }
            if delay_slots.iter().map(|&size| size as usize).sum::<usize>() >= length as usize {
                return err("delay slots exceed the instruction extent");
            }
            return Ok(FlowResult {
                terminal,
                conditional,
                return_op,
                delay_slots,
                mode,
                target_modes,
                no_op,
                pure_jump,
                address: addr,
                length,
                fallthrough,
                targets,
                kind,
            });
        }
    }
    err(format!("console produced no FLOW line: {stdout}"))
}
/// Persistent SLEIGH console session (m1-003-b).
///
/// Spawns `decomp_native` once and reuses the process for many `flow`
/// requests, avoiding the per-instruction spawn cost that makes the
/// one-shot `console_flow` unsuitable for whole-binary discovery.
pub struct ConsoleSession {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: std::io::BufReader<std::process::ChildStdout>,
    language_id: String,
    /// The install a mapped ELF image's language is selected from.
    install: std::path::PathBuf,
    reference_labels: Option<Vec<(u64, String)>>,
    reference_registers: Vec<crate::native::NativeRegisterContext>,
    active_reference_registers: usize,
    reference_call_register: Option<&'static str>,
    /// Import slots the loaded image names, sorted: a read of one answers
    /// the external, as `VarnodeContext.getValue` does (:540-544).
    external_slots: Vec<u64>,
    /// The register an interworking branch writes the target's instruction
    /// set into, under the name Ghidra's analyzers use for it: the spec
    /// bundle's `<register name="TB" alias="ISAModeSwitch"/>` names ARM's;
    /// MIPS declares a register of that name outright.
    reference_mode_register: Option<String>,
    new_reference_targets: Vec<u64>,
    /// Commands written to this console. Batching is a claim about this
    /// number against the instructions decoded, not about wall time.
    requests: u64,
}

/// One session's reference context as plain data (see
/// `ConsoleSession::reference_shard_spec`).
pub(crate) struct ReferenceShardSpec {
    labels: Option<Vec<(u64, String)>>,
    registers: Vec<crate::native::NativeRegisterContext>,
    active: usize,
    call_register: Option<&'static str>,
    mode_register: Option<String>,
    external_slots: Vec<u64>,
}

impl ConsoleSession {
    /// Spawn the console and wait for the first interactive prompt.
    pub fn new(cfg: &RuntimeConfig) -> Result<Self> {
        let console = find_console(cfg)?;
        let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
        let langs = cfg.language_dir.to_string_lossy().into_owned();

        let mut child = Command::new(&console)
            .arg("-s")
            .arg(&langs)
            .env("SLEIGHHOME", &ghroot)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NativeRuntimeError(format!("console spawn: {e}")))?;

        let stdin = child.stdin.take().expect("console stdin");
        let stdout = child.stdout.take().expect("console stdout");
        let mut reader = std::io::BufReader::with_capacity(128 * 1024, stdout);

        // The console prints an initial "[decomp]> " prompt.
        let _ = read_until_prompt(&mut reader)?;

        Ok(Self {
            child,
            stdin,
            reader,
            language_id: cfg.language_id.clone(),
            install: cfg.ghidra_install.clone(),
            reference_labels: None,
            reference_registers: Vec::new(),
            active_reference_registers: 0,
            reference_call_register: None,
            external_slots: Vec::new(),
            reference_mode_register: None,
            new_reference_targets: Vec::new(),
            requests: 0,
        })
    }

    /// Load ELF/DOL through the native mapped image. Other formats retain
    /// their BFD/raw address-base handling.
    pub fn load(&mut self, binary: &Path, base: u64) -> Result<()> {
        self.reference_labels = None;
        self.reference_registers.clear();
        self.active_reference_registers = 0;
        self.reference_call_register = None;
        self.new_reference_targets.clear();
        let selection = RuntimeConfig {
            ghidra_install: self.install.clone(),
            ..RuntimeConfig::from_env()
        };
        if let Some(image) = MappedImage::for_elf_or_dol(&selection, binary)? {
            return self.load_xml(&image);
        }
        let target = bfd_target_for(&self.language_id, binary)?;
        let script = if self.language_id.starts_with("x86:") {
            format!("load file {} {}\n", target, binary.display())
        } else {
            format!(
                "load file {} {}\nadjust vma 0x{:x}\n",
                target,
                binary.display(),
                base
            )
        };
        self.send(&script)?;

        // One prompt per command written (load + optional adjust).
        let prompts = if self.language_id.starts_with("x86:") {
            1
        } else {
            2
        };
        for _ in 0..prompts {
            let _ = read_until_prompt(&mut self.reader)?;
        }
        Ok(())
    }

    /// Load existing native mappings without flattening sparse virtual addresses.
    pub fn load_mapped(&mut self, import: &NativeImport) -> Result<()> {
        let image = MappedImage::new(import)?;
        self.load_xml(&image)?;
        // The image's own mode declarations, before anything decodes.
        self.set_contexts(&import.contexts)
    }

    fn load_xml(&mut self, image: &MappedImage) -> Result<()> {
        self.reference_labels = None;
        self.reference_registers.clear();
        self.active_reference_registers = 0;
        self.reference_call_register = None;
        self.new_reference_targets.clear();
        self.send(&image.command())?;
        let response = read_until_prompt(&mut self.reader)?;
        if !response.contains("successfully loaded:") {
            return err(format!("mapped image load failed: {response}"));
        }
        Ok(())
    }

    /// Propagate a function over `[start, end)` without changing the loaded image.
    ///
    /// Facts contain only pointer-sized constants targeting a supplied mapping.
    /// Writable initial memory is untrusted unless explicitly enabled; unknown
    /// calls still invalidate it. Unsupported or failed requests return errors,
    /// not an empty successful analysis.
    pub fn constants(
        &mut self,
        start: u64,
        end: u64,
        mappings: &[crate::native::Mapping],
        trust_writable: bool,
    ) -> Result<Vec<ConstantFact>> {
        self.propagation_query("constants", "CONSTANTS ", start, end, mappings, trust_writable)?
            .ok_or_else(|| NativeRuntimeError(format!("constants at {start:#x} are undecodable")))
    }

    /// Infer read/write/data references without mutating the loaded image.
    /// `None` means the console refused this range as undecodable.
    pub fn optional_references(
        &mut self,
        start: u64,
        end: u64,
        mappings: &[crate::native::Mapping],
        trust_writable: bool,
    ) -> Result<Option<Vec<ReferenceFact>>> {
        self.propagation_query("references", "REFERENCES ", start, end, mappings, trust_writable)
    }

    /// Facts for a range the caller already knows decodes.
    pub fn references(
        &mut self,
        start: u64,
        end: u64,
        mappings: &[crate::native::Mapping],
        trust_writable: bool,
    ) -> Result<Vec<ReferenceFact>> {
        self.optional_references(start, end, mappings, trust_writable)?
            .ok_or_else(|| NativeRuntimeError(format!("references at {start:#x} are undecodable")))
    }

    /// Names the pinned patterns attached to the starts they proved. The
    /// console already consumes these to install call fixups; the store wants
    /// the same names on its functions.
    pub(crate) fn pattern_labels(&self) -> &[(u64, String)] {
        self.reference_labels.as_deref().unwrap_or(&[])
    }

    pub(crate) fn prepare_reference_context(&mut self, import: &NativeImport) -> Result<()> {
        self.reference_registers.clone_from(&import.register_contexts);
        self.active_reference_registers = self.reference_registers.len();
        self.reference_call_register = import.reference_call_register;
        self.external_slots = import
            .externals
            .iter()
            .map(|(slot, _)| *slot)
            .filter(|slot| *slot != 0)
            .collect();
        self.external_slots.sort_unstable();
        self.external_slots.dedup();
        self.reference_mode_register = mode_register_alias(&import.cfg.spec_root, &import.language);
        self.new_reference_targets.clear();
        if self.reference_labels.is_none() {
            // Only byte-backed ranges are searchable: a section's virtual
            // extent can outrun its contents, and the load image raises
            // DataUnavailError for the rest.
            let ranges = crate::native::code_ranges(import);
            self.function_patterns(&ranges)?;
        }
        self.send_reference_fixups(import)
    }

    /// Applies context register values before anything decodes. A context is
    /// only honoured for an address the console has not parsed yet: the
    /// disassembly cache keys parsed instructions by address
    /// (`DisassemblyCache`, sleigh.hh:107-122), so the caller sends these
    /// immediately after the image loads.
    pub(crate) fn set_contexts(&mut self, contexts: &[crate::native::NativeContext]) -> Result<()> {
        use std::fmt::Write as _;
        if contexts.is_empty() {
            return Ok(());
        }
        // Written in batches: one write of every command would fill the
        // console's stdout pipe while it waits for the rest of its input, and
        // both sides would block. An image can declare thousands of these.
        for batch in contexts.chunks(128) {
            let mut script = String::new();
            for context in batch {
                if context.name.is_empty()
                    || context
                        .name
                        .chars()
                        .any(|c| !c.is_ascii_alphanumeric() && c != '_')
                {
                    return err(format!("invalid context register name: {}", context.name));
                }
                let _ = writeln!(
                    script,
                    "context {} 0x{:x} {}",
                    context.name, context.address, context.value
                );
            }
            self.send(&script)?;
            for _ in 0..batch.len() {
                let response = read_until_prompt(&mut self.reader)?;
                if !response.contains("CONTEXT ") {
                    return err(format!("context command failed: {}", response.trim()));
                }
            }
        }
        Ok(())
    }

    /// Names the pattern-proven function starts inside this console, so a
    /// propagated call lands on a real function instead of raw bytes.
    fn send_reference_fixups(&mut self, import: &NativeImport) -> Result<()> {
        use std::fmt::Write as _;
        let mut script = String::new();
        let mut count = 0;
        let Some(labels) = self.reference_labels.as_ref() else {
            return err("reference fixups need function patterns");
        };
        for (address, label) in labels {
            if !import.functions.iter().any(|function| function.entry == *address && function.size > 1) {
                continue;
            }
            if label.is_empty() || label.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return err("invalid function-pattern label");
            }
            let _ = writeln!(script, "referencefixup 0x{address:x} {label}");
            count += 1;
        }
        if count != 0 {
            // Batched for the same reason as `set_contexts`: one write of
            // every command would deadlock against the console's own output.
            let mut pending = 0usize;
            let mut chunk = String::new();
            for line in script.lines() {
                chunk.push_str(line);
                chunk.push('\n');
                pending += 1;
                if pending == 128 {
                    self.flush_fixups(&chunk, pending)?;
                    chunk.clear();
                    pending = 0;
                }
            }
            if pending != 0 {
                self.flush_fixups(&chunk, pending)?;
            }
        }
        Ok(())
    }

    /// Writes one batch of `referencefixup` commands and reads its answers.
    fn flush_fixups(&mut self, script: &str, count: usize) -> Result<()> {
        self.send(script)?;
        for _ in 0..count {
            let response = read_until_prompt(&mut self.reader)?;
            if !response.lines().any(|line| matches!(line, "FIXUP 0" | "FIXUP 1")) {
                return err(format!("reference context failed: {response}"));
            }
        }
        Ok(())
    }

    /// Commands written to this console so far.
    pub(crate) fn requests(&self) -> u64 {
        self.requests
    }

    /// Everything a shard needs to reach this session's exact reference
    /// context. Plain data, so shards can be opened concurrently: console
    /// startup is serial work otherwise, and it dominates a short round.
    pub(crate) fn reference_shard_spec(&self) -> ReferenceShardSpec {
        ReferenceShardSpec {
            labels: self.reference_labels.clone(),
            registers: self.reference_registers.clone(),
            active: self.active_reference_registers,
            call_register: self.reference_call_register,
            mode_register: self.reference_mode_register.clone(),
            external_slots: self.external_slots.clone(),
        }
    }

    /// Opens `count` more consoles on the same image, concurrently: console
    /// startup is serial work that would otherwise dominate a short round.
    /// A shard is an optimization, so one that fails to open is dropped.
    pub(crate) fn open_image_shards(import: &NativeImport, count: usize) -> Vec<Self> {
        if count == 0 {
            return Vec::new();
        }
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..count)
                .map(|_| {
                    scope.spawn(|| {
                        let mut shard = Self::new(&import.cfg)?;
                        shard.load_mapped(import)?;
                        Ok::<Self, NativeRuntimeError>(shard)
                    })
                })
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| handle.join().ok().and_then(|shard| shard.ok()))
                .collect()
        })
    }

    /// Gives this console `spec`'s reference context. One round of the
    /// reference pass never reads a context discovered inside that round, so
    /// shards observe identical inputs and produce the same facts as a
    /// single session would.
    pub(crate) fn prepare_as_reference_shard(
        &mut self,
        spec: &ReferenceShardSpec,
        import: &NativeImport,
    ) -> Result<()> {
        self.reference_labels.clone_from(&spec.labels);
        self.reference_registers.clone_from(&spec.registers);
        self.active_reference_registers = spec.active;
        self.reference_call_register = spec.call_register;
        self.reference_mode_register = spec.mode_register.clone();
        self.external_slots.clone_from(&spec.external_slots);
        self.new_reference_targets.clear();
        self.send_reference_fixups(import)
    }

    /// Replaces this session's register context before a round; the whole
    /// context is active, matching `take_reference_context_targets`.
    pub(crate) fn sync_reference_context(&mut self, contexts: &[crate::native::NativeRegisterContext]) {
        self.reference_registers = contexts.to_vec();
        self.active_reference_registers = contexts.len();
        self.new_reference_targets.clear();
    }

    /// The register context this session queries with.
    pub(crate) fn reference_contexts(&self) -> &[crate::native::NativeRegisterContext] {
        &self.reference_registers
    }

    /// Removes and returns the contexts this session discovered past `keep`.
    pub(crate) fn drain_discovered_contexts(
        &mut self,
        keep: usize,
    ) -> Vec<crate::native::NativeRegisterContext> {
        self.new_reference_targets.clear();
        if self.reference_registers.len() <= keep {
            return Vec::new();
        }
        self.reference_registers.split_off(keep)
    }

    /// Adds `contexts` that are not already covered, returning their targets.
    pub(crate) fn adopt_reference_contexts(
        &mut self,
        contexts: Vec<crate::native::NativeRegisterContext>,
    ) -> Vec<u64> {
        let mut targets = Vec::new();
        for context in contexts {
            if self.reference_registers.iter().any(|existing| {
                existing.register == context.register
                    && existing.start <= context.start
                    && context.start < existing.end
            }) {
                continue;
            }
            targets.push(context.start);
            self.reference_registers.push(context);
        }
        self.active_reference_registers = self.reference_registers.len();
        targets
    }



    fn propagation_query<T: serde::de::DeserializeOwned>(
        &mut self,
        command: &str,
        prefix: &str,
        start: u64,
        end: u64,
        mappings: &[crate::native::Mapping],
        trust_writable: bool,
    ) -> Result<Option<Vec<T>>> {
        use std::fmt::Write as _;
        let mut script = String::with_capacity(64 + mappings.len() * 48);
        let _ = write!(
            script,
            "{command} 0x{start:x} 0x{end:x} {}",
            u8::from(trust_writable)
        );
        for mapping in mappings.iter().filter(|mapping| mapping.size != 0) {
            let mapping_end = mapping.vaddr.checked_add(mapping.size).ok_or_else(|| {
                NativeRuntimeError("constant-propagation mapping range overflows".into())
            })?;
            let _ = write!(
                script,
                " 0x{:x} 0x{mapping_end:x} {}",
                mapping.vaddr, mapping.flags & 7
            );
        }
        for slot in &self.external_slots {
            let _ = write!(script, " --external 0x{slot:x}");
        }
        if command == "references" {
            if let Some(register) = self.reference_call_register {
                if register.is_empty() || register.chars().any(|c| c.is_whitespace() || c.is_control()) {
                    return err("invalid call-context register");
                }
                let _ = write!(script, " --track-register {register}");
            }
            if let Some(register) = self.reference_mode_register.as_deref() {
                if register.is_empty() || register.chars().any(|c| c.is_whitespace() || c.is_control()) {
                    return err("invalid mode register");
                }
                let _ = write!(script, " --mode-register {register}");
            }
            for context in self.reference_registers.iter().take(self.active_reference_registers) {
                if context.start <= start && start < context.end {
                    if context.register.is_empty()
                        || context.register.chars().any(|c| c.is_whitespace() || c.is_control()) {
                        return err("invalid reference context register");
                    }
                    let _ = write!(script, " --register {} 0x{:x}", context.register, context.value);
                }
            }
        }
        script.push('\n');
        self.send(&script)?;
        let response = read_until_prompt(&mut self.reader)?;
        let payload = match response.lines().find_map(|line| line.trim().strip_prefix(prefix)) {
            Some(payload) => payload,
            // The console refuses one undecodable range without ending the
            // session; unknown flow yields no facts and aborts nothing. Any
            // other failure still stops the caller.
            None if response.contains(UNDECODABLE) => return Ok(None),
            None => return Err(NativeRuntimeError(format!("{command} query failed: {response}"))),
        };
        let facts = serde_json::from_str(payload)
            .map_err(|error| NativeRuntimeError(format!("invalid {command} facts: {error}")))?;
        if command == "references" {
            if let Some(register) = self.reference_call_register {
                #[derive(serde::Deserialize)]
                struct CallRegister { target: u64, value: u64 }
                let payload = response.lines().find_map(|line| line.strip_prefix("CALL_REGISTERS "))
                    .ok_or_else(|| NativeRuntimeError(format!("missing call-context facts: {response}")))?;
                let contexts: Vec<CallRegister> = serde_json::from_str(payload)
                    .map_err(|error| NativeRuntimeError(format!("invalid call-context facts: {error}")))?;
                for context in contexts {
                    if self.reference_registers.iter().any(|existing| {
                        existing.register == register &&
                            existing.start <= context.target && context.target < existing.end
                    }) { continue; }
                    let end = context.target.checked_add(1)
                        .ok_or_else(|| NativeRuntimeError("call-context address overflow".into()))?;
                    self.reference_registers.push(crate::native::NativeRegisterContext {
                        start: context.target, end, register: register.into(), value: context.value,
                    });
                    self.new_reference_targets.push(context.target);
                }
            }
        }
        Ok(Some(facts))
    }

    /// Ask the console for the control-flow of one instruction.
    pub fn flow(&mut self, address: u64) -> Result<FlowResult> {
        let script = format!("flow 0x{:x}\n", address);
        self.send(&script)?;

        use std::io::{BufRead as _, Read as _};
        // The console echoes the command; read and discard it.
        let mut echo = String::new();
        if self
            .reader
            .read_line(&mut echo)
            .map_err(|e| NativeRuntimeError(format!("console read: {e}")))?
            == 0
        {
            return err("console closed before flow output");
        }

        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| NativeRuntimeError(format!("console read: {e}")))?;
        if n == 0 {
            return err("console closed before flow output");
        }

        // Every command is followed by the prompt "[decomp]> " (no newline).
        let mut prompt = [0u8; 10];
        self.reader
            .read_exact(&mut prompt)
            .map_err(|e| NativeRuntimeError(format!("console prompt: {e}")))?;

        // Bad addresses produce a "Low-level ERROR" line and no FLOW.
        if line.contains("Low-level ERROR") {
            return Ok(FlowResult {
                terminal: false,
                conditional: false,
                return_op: false,
                delay_slots: Vec::new(), mode: None, target_modes: Vec::new(),
                no_op: false,
                pure_jump: false,
                address,
                length: 1,
                fallthrough: Some(address + 1),
                targets: Vec::new(),
                kind: FlowKind::Bad,
            });
        }

        parse_flow_output(&line, address)
    }

    /// Same as `flow` but never fails: unparseable/missing output becomes a
    /// length-1 `Bad` result so a walk can continue.
    pub fn try_flow(&mut self, address: u64) -> FlowResult {
        self.flow(address).unwrap_or(FlowResult {
            terminal: false,
            conditional: false,
            return_op: false,
            delay_slots: Vec::new(), mode: None, target_modes: Vec::new(),
            no_op: false,
            pure_jump: false,
            address,
            length: 1,
            fallthrough: Some(address + 1),
            targets: Vec::new(),
            kind: FlowKind::Bad,
        })
    }
    /// Queries control-flow for multiple addresses in a single batch request.
    pub fn flow_batch(&mut self, addresses: &[u64]) -> Result<Vec<FlowResult>> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        use std::fmt::Write as _;
        let mut script = String::with_capacity(addresses.len() * 12 + 8);
        script.push_str("flow");
        for addr in addresses {
            let _ = write!(script, " 0x{:x}", addr);
        }
        script.push('\n');
        self.send(&script)?;

        // The echo of the command itself.
        let echo = match read_line_or_prompt(&mut self.reader)? {
            ConsoleOutput::Line(line) => line,
            ConsoleOutput::Prompt(text) => {
                return err(format!("console answered no flow output: {}", text.trim()));
            }
        };
        let _ = echo;

        let mut results = Vec::with_capacity(addresses.len());
        for (index, &addr) in addresses.iter().enumerate() {
            let line = match read_line_or_prompt(&mut self.reader)? {
                ConsoleOutput::Line(line) => line,
                // The prompt before the last result: the console refused the
                // request (an unloaded image, a parse error) and said so once
                // instead of once per address.
                ConsoleOutput::Prompt(text) => {
                    return err(format!(
                        "console answered {index} of {} flow results (first unanswered 0x{:x}): {}",
                        addresses.len(),
                        addr,
                        text.trim()
                    ));
                }
            };
            if line.contains("Execution error") || line.contains("Command parsing error") {
                return err(format!("console refused the flow request: {}", line.trim()));
            }
            if line.contains("Low-level ERROR") {
                results.push(FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(), mode: None, target_modes: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: addr,
                    length: 1,
                    fallthrough: Some(addr + 1),
                    targets: Vec::new(),
                    kind: FlowKind::Bad,
                });
            } else {
                results.push(parse_flow_output(&line, addr).unwrap_or(FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(), mode: None, target_modes: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: addr,
                    length: 1,
                    fallthrough: Some(addr + 1),
                    targets: Vec::new(),
                    kind: FlowKind::Bad,
                }));
            }
        }

        // The trailing prompt, which every answered request ends with.
        match read_line_or_prompt(&mut self.reader)? {
            ConsoleOutput::Prompt(_) => Ok(results),
            ConsoleOutput::Line(line) => err(format!(
                "console said more than it was asked for: {}",
                line.trim()
            )),
        }
    }

    /// Reads the p-code of each address in one batch request.
    ///
    /// This is the console's `pcode` command: SLEIGH's own operations for the
    /// instruction, in emission order, with no analysis applied. The reasoning
    /// over them happens in Rust (`native::vsa`).
    pub fn pcode_batch(&mut self, addresses: &[u64]) -> Result<Vec<PcodeInstruction>> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        use std::fmt::Write as _;
        let mut script = String::with_capacity(addresses.len() * 12 + 8);
        script.push_str("pcode");
        for addr in addresses {
            let _ = write!(script, " 0x{addr:x}");
        }
        script.push('\n');
        self.send(&script)?;
        // The echo of the command itself.
        match read_line_or_prompt(&mut self.reader)? {
            ConsoleOutput::Line(_) => {}
            ConsoleOutput::Prompt(text) => {
                return err(format!("console answered no p-code: {}", text.trim()));
            }
        }
        let mut out: Vec<PcodeInstruction> = Vec::with_capacity(addresses.len());
        loop {
            let line = match read_line_or_prompt(&mut self.reader)? {
                ConsoleOutput::Line(line) => line,
                ConsoleOutput::Prompt(text) => {
                    return err(format!(
                        "console stopped after {} of {} p-code answers: {}",
                        out.len(),
                        addresses.len(),
                        text.trim()
                    ));
                }
            };
            let line = line.trim();
            if line == "PCODE end" {
                break;
            }
            if line.contains("Execution error") || line.contains("Command parsing error") {
                return err(format!("console refused the p-code request: {line}"));
            }
            if let Some(rest) = line.strip_prefix("PCODE ") {
                let mut fields = rest.split_whitespace();
                let address = fields
                    .next()
                    .and_then(|text| {
                        u64::from_str_radix(
                            text.trim_start_matches(|c: char| !c.is_ascii_hexdigit())
                                .trim_start_matches("0x"),
                            16,
                        )
                        .ok()
                    })
                    .unwrap_or(0);
                let mut length = 1u8;
                let mut error = None;
                for field in fields {
                    if let Some(value) = field.strip_prefix("len=") {
                        length = value.parse().unwrap_or(1);
                    } else if let Some(value) = field.strip_prefix("error=") {
                        error = Some(value.to_string());
                    }
                }
                out.push(PcodeInstruction {
                    address,
                    length,
                    ops: Vec::new(),
                    error,
                });
                continue;
            }
            if let Some(rest) = line.strip_prefix("OP ") {
                let Some(instruction) = out.last_mut() else {
                    continue;
                };
                let mut fields = rest.split_whitespace();
                let _index = fields.next();
                let Some(opcode) = fields.next() else { continue };
                let mut op = PcodeOp {
                    opcode: opcode.to_string(),
                    output: None,
                    inputs: Vec::new(),
                };
                for field in fields {
                    let Some((label, value)) = field.split_once('=') else {
                        continue;
                    };
                    let Some(varnode) = PcodeVarnode::parse(value) else {
                        continue;
                    };
                    if label == "out" {
                        op.output = Some(varnode);
                    } else {
                        op.inputs.push(varnode);
                    }
                }
                instruction.ops.push(op);
            }
        }
        // The trailing prompt every answered request ends with.
        match read_line_or_prompt(&mut self.reader)? {
            ConsoleOutput::Prompt(_) => Ok(out),
            ConsoleOutput::Line(line) => err(format!(
                "console said more than it was asked for: {}",
                line.trim()
            )),
        }
    }

    /// Same as `flow_batch` but never errors, returning fallback results on failure.
    pub fn try_flow_batch(&mut self, addresses: &[u64]) -> Vec<FlowResult> {
        self.flow_batch(addresses).unwrap_or_else(|_| {
            addresses
                .iter()
                .map(|&addr| FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(), mode: None, target_modes: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: addr,
                    length: 1,
                    fallthrough: Some(addr + 1),
                    targets: Vec::new(),
                    kind: FlowKind::Bad,
                })
                .collect()
        })
    }

    /// Identify linkage stubs without reading or fabricating imported pointer values.
    pub fn linkage_batch(&mut self, addresses: &[u64]) -> Result<Vec<LinkageResult>> {
        self.query_linkages(addresses, "linkage")
    }

    /// PLT metadata establishes entry boundaries; register setup need not be pure.
    pub(crate) fn plt_linkage_batch(&mut self, addresses: &[u64]) -> Result<Vec<LinkageResult>> {
        self.query_linkages(addresses, "linkage --table")
    }

    pub(crate) fn context_linkage_batch(
        &mut self,
        contexts: &[LinkageContext],
    ) -> Result<Vec<LinkageResult>> {
        use std::fmt::Write as _;
        if contexts.is_empty() {
            return Ok(Vec::new());
        }
        let mut command = String::with_capacity(contexts.len() * 57 + 15);
        command.push_str("linkage --from");
        for context in contexts {
            let _ = write!(
                command,
                " 0x{:x} 0x{:x} 0x{:x}",
                context.origin, context.branch, context.target
            );
        }
        command.push('\n');
        self.send(&command)?;
        self.read_linkages(contexts.iter().map(|context| context.target))
    }

    fn query_linkages(&mut self, addresses: &[u64], prefix: &str) -> Result<Vec<LinkageResult>> {
        use std::fmt::Write as _;
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        let mut command = String::with_capacity(addresses.len() * 19 + prefix.len() + 1);
        command.push_str(prefix);
        for address in addresses {
            let _ = write!(command, " 0x{address:x}");
        }
        command.push('\n');
        self.send(&command)?;
        self.read_linkages(addresses.iter().copied())
    }

    fn read_linkages(
        &mut self,
        expected: impl ExactSizeIterator<Item = u64>,
    ) -> Result<Vec<LinkageResult>> {
        let response = read_until_prompt(&mut self.reader)?;
        let results: Vec<LinkageResult> = response
            .lines()
            .filter_map(|line| line.strip_prefix("LINKAGE "))
            .map(|line| {
                serde_json::from_str(line).map_err(|error| {
                    NativeRuntimeError(format!("invalid linkage response: {error}"))
                })
            })
            .collect::<Result<_>>()?;
        if results.len() != expected.len()
            || results.iter().zip(expected).any(|(result, address)| {
                result.address != address
                    || (result.length != 0) != (result.slot.is_some() || result.needs_context)
                    || (result.needs_context && result.slot.is_some())
            })
        {
            return err("incomplete or mismatched linkage response");
        }
        Ok(results)
    }

    pub(crate) fn function_patterns(&mut self, ranges: &[(u64, u64)]) -> Result<FunctionPatterns> {
        use std::fmt::Write as _;
        let mut command = String::from("functionstarts");
        for &(start, end) in ranges {
            if start >= end {
                return err("invalid function-pattern search range");
            }
            let _ = write!(command, " 0x{start:x} 0x{end:x}");
        }
        command.push('\n');
        self.send(&command)?;
        let response = read_until_prompt(&mut self.reader)?;
        let mut lines = response
            .lines()
            .filter_map(|line| line.strip_prefix("PATTERNS "));
        let patterns: FunctionPatterns = serde_json::from_str(
            lines
                .next()
                .ok_or_else(|| NativeRuntimeError("missing function-pattern response".into()))?,
        )
        .map_err(|error| {
            NativeRuntimeError(format!("invalid function-pattern response: {error}"))
        })?;
        if lines.next().is_some()
            || patterns.alignment == 0
            || patterns.matches.iter().any(|hit| {
                hit.rule >= patterns.rules.len()
                    || !ranges
                        .iter()
                        .any(|&(start, end)| start <= hit.address && hit.address < end)
            })
        {
            return err("mismatched function-pattern response");
        }
        // Retain only annotation evidence needed after discovery; avoid rescanning
        // the image when the reference pass reuses this loaded console.
        let labels = self.reference_labels.get_or_insert_with(Vec::new);
        for hit in &patterns.matches {
            for action in &patterns.rules[hit.rule].actions {
                if action.kind != "funcstart"
                    || !action.attributes.get("validcode")
                        .is_some_and(|value| value.eq_ignore_ascii_case("function")) {
                    continue;
                }
                if let Some(label) = action.attributes.get("label") {
                    if !labels.iter().any(|(address, name)| *address == hit.address && name == label) {
                        labels.push((hit.address, label.clone()));
                    }
                }
            }
        }
        Ok(patterns)
    }

    /// Close stdin and wait for the child to exit.
    pub fn quit(mut self) -> Result<()> {
        let _ = self.send("quit\n");
        let _ = self.child.wait();
        Ok(())
    }

    fn send(&mut self, s: &str) -> Result<()> {
        use std::io::Write as _;
        self.requests += 1;
        self.stdin
            .write_all(s.as_bytes())
            .and_then(|_| self.stdin.flush())
            .map_err(|e| {
                // A write fails because the console is gone. Say how it went:
                // a silent exit is otherwise indistinguishable from a bug on
                // this side of the pipe.
                let fate = match self.child.try_wait() {
                    Ok(Some(status)) => format!(" (console exited: {status})"),
                    Ok(None) => String::new(),
                    Err(error) => format!(" (console status unknown: {error})"),
                };
                NativeRuntimeError(format!("console write: {e}{fate}"))
            })
    }
}
impl Drop for ConsoleSession {
    fn drop(&mut self) {
        use std::io::Write as _;
        let _ = self.stdin.write_all(b"quit\n");
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    /// The reference facts as (instruction, target, kind): what a test about
    /// *which* references exist is asserting. Access widths have their own
    /// test, `reference_facts_carry_the_access_width`.
    fn triples(facts: &[super::ReferenceFact]) -> Vec<(u64, u64, super::ReferenceKind)> {
        facts.iter().map(|fact| (fact.from, fact.to, fact.kind)).collect()
    }

    use super::*;

    #[test]
    fn test_pcode_flow_x86_and_ppc() {
        let cfg = RuntimeConfig::from_env();
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let x86_bin = manifest_dir.join("../../tests/fixtures-src/tiny_bin");
        if !x86_bin.is_file() {
            eprintln!("SKIP: tiny_bin not present");
            return;
        }
        let flow_ret = console_flow(&cfg, &x86_bin, 0x400479).expect("x86 ret flow");
        assert_eq!(flow_ret.kind, FlowKind::Return);
        assert_eq!(flow_ret.fallthrough, None);
        assert_eq!(flow_ret.length, 1);

        let flow_fall = console_flow(&cfg, &x86_bin, 0x400466).expect("x86 add flow");
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
            let flow_fall =
                console_flow(&ppc_cfg, ppc_bin, 0x80680000).expect("ppc fallthrough flow");
            assert_eq!(flow_fall.length, 4);
            assert_eq!(flow_fall.kind, FlowKind::Fallthrough);
            assert_eq!(flow_fall.fallthrough, Some(0x80680004));

            let flow_cbranch =
                console_flow(&ppc_cfg, ppc_bin, 0x8068001c).expect("ppc cbranch flow");
            assert_eq!(flow_cbranch.length, 4);
            assert_eq!(flow_cbranch.kind, FlowKind::CBranch);
            assert_eq!(flow_cbranch.fallthrough, Some(0x80680020));
            assert_eq!(flow_cbranch.targets, vec![0x80680030]);
        }
    }

    #[test]
    fn console_session_persists_multiple_flows() {
        let cfg = RuntimeConfig::from_env();
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let x86_bin = manifest_dir.join("../../tests/fixtures-src/tiny_bin");
        if !x86_bin.is_file() {
            eprintln!("SKIP: tiny_bin not present");
            return;
        }
        let mut session = ConsoleSession::new(&cfg).expect("console session");
        let mappings = crate::native::load_native_mappings(&x86_bin).unwrap_or_default();
        let base = mappings
            .first()
            .map(|m| m.vaddr.wrapping_sub(m.file_off))
            .unwrap_or(0);
        session.load(&x86_bin, base).expect("load tiny_bin");

        let flow_ret = session.flow(0x400479).expect("x86 ret flow");
        assert_eq!(flow_ret.kind, FlowKind::Return);
        assert_eq!(flow_ret.length, 1);

        let flow_fall = session.flow(0x400466).expect("x86 fall flow");
        assert_eq!(flow_fall.kind, FlowKind::Fallthrough);
        assert_eq!(flow_fall.length, 1);
        assert_eq!(flow_fall.fallthrough, Some(0x400467));

        session.quit().unwrap();
    }

    #[test]
    fn constant_propagation_reports_mapped_globals() {
        let cfg = RuntimeConfig::from_env();
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
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
            let mut session = ConsoleSession::new(&cfg).unwrap();
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
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
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
            let mut session = ConsoleSession::new(&cfg).unwrap();
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
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        // Direct accesses and pointers; indirect jump slots are DATA, calls READ.
        let code = vec![
            0x8b, 0x05, 0xfa, 0x1f, 0, 0, 0x83, 0x05, 0xf3, 0x1f, 0, 0, 1, 0x48, 0x8d, 0x3d, 0xec,
            0x2f, 0, 0, 0x48, 0x89, 0x3d, 0xed, 0x1f, 0, 0,
            0xff, 0x15, 0xe7, 0x1f, 0, 0, // call [0x3008]
            // Conditional bounded exit, otherwise jump through a memory slot.
            0x85, 0xf6, 0x0f, 0x85, 0xd7, 0x0f, 0, 0,
            0xff, 0x25, 0xd1, 0x1f, 0, 0, // jmp [0x3000]
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
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x102f, &import.mappings, false).unwrap();
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
            refs.iter().all(|reference| matches!(
                reference.to,
                0x3000 | 0x3008 | 0x4000
            )),
            "{refs:?}"
        );
        assert!(refs.iter().all(|reference| (0x1000..0x102f).contains(&reference.from)),
                "reference inference escaped the function bounds: {refs:?}");
        // References describe decoded operands even on provably untaken paths.
        // Constant-value queries must retain their stricter reachable-flow rule.
        let constants = session.constants(0x2000, 0x2019, &import.mappings, false).unwrap();
        assert!(constants.iter().all(|fact| fact.value != 0x4000), "{constants:?}");
        let refs = session.references(0x2000, 0x2019, &import.mappings, false).unwrap();
        for (from, to, kind) in [
            (0x2005, 0x3000, ReferenceKind::Read),
            (0x200b, 0x4000, ReferenceKind::Data),
            (0x2012, 0x4000, ReferenceKind::Data),
        ] {
            assert!(refs.iter().any(|reference| reference.from == from
                && reference.to == to && reference.kind == kind), "{refs:?}");
        }
    }

    #[test]
    fn computed_references_require_pointer_use() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
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
                    vaddr: 0x1000, size: code.len() as u64, file_off: 0,
                    flags: 6, bytes: code,
                },
                crate::native::Mapping {
                    vaddr: 0x4000, size: 16, file_off: 0, flags: 3,
                    bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x1010, &import.mappings, false).unwrap();
        assert_eq!(triples(&refs), vec![(0x100bu64, 0x4001u64, ReferenceKind::Data)], "computed intermediates are not references; the return references its last setter");
        // Equal pointer values at a join retain both possible setter origins.
        import.mappings[0].bytes = vec![
            0x48, 0xc7, 0xc0, 0xff, 0x3f, 0, 0,
            0x85, 0xff, 0x74, 6, // test edi,edi; je alternative
            0x48, 0x83, 0xc0, 2, 0xeb, 4,
            0x48, 0x83, 0xc0, 2, 0xc3,
        ];
        import.mappings[0].size = import.mappings[0].bytes.len() as u64;
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x1016, &import.mappings, false).unwrap();
        assert_eq!(triples(&refs), vec![
            (0x100bu64, 0x4001u64, ReferenceKind::Data),
            (0x1011u64, 0x4001u64, ReferenceKind::Data),
        ], "a joined value must not lose either reaching setter");
        // A computed argument must be observed before CALL clobbers its
        // register, and attributed to the setter rather than the call.
        cfg.language_id = "AARCH64:LE:64:v8A".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/AARCH64/data/languages");
        import.language = cfg.language_id.clone();
        import.mappings[0].bytes = vec![
            0xe0, 0xff, 0x87, 0xd2, // mov x0,#0x3fff
            0x00, 0x04, 0x00, 0x91, // add x0,x0,#1
            0x00, 0x04, 0x00, 0x91, // add x0,x0,#1
            0x05, 0x00, 0x00, 0x94, // bl 0x1020
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ];
        import.mappings[0].size = import.mappings[0].bytes.len() as u64;
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x1014, &import.mappings, false).unwrap();
        assert_eq!(triples(&refs), vec![
            (0x1008u64, 0x4001u64, ReferenceKind::Data),
        ], "computed arguments need source attribution before call effects");
        // The e500 ABI uses an unnamed 32-bit slice of a 64-bit register.
        // Without a named-register setter, the return is the reference source.
        cfg.language_id = "PowerPC:BE:32:e500".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/PowerPC/data/languages");
        import.language = cfg.language_id.clone();
        import.mappings[0].bytes = vec![
            0x38, 0x60, 0x3f, 0xff, // li r3,0x3fff
            0x38, 0x63, 0x00, 0x01, // addi r3,r3,1
            0x38, 0x63, 0x00, 0x01, // addi r3,r3,1
            0x4e, 0x80, 0x00, 0x20, // blr
        ];
        import.mappings[0].size = import.mappings[0].bytes.len() as u64;
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x1010, &import.mappings, false).unwrap();
        assert_eq!(triples(&refs), vec![
            (0x100cu64, 0x4001u64, ReferenceKind::Data),
        ], "unnamed register slices must not invent a named-register setter");
    }

    #[test]
    fn reference_queries_use_selected_compiler_abi() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
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
                    vaddr: 0x1000, size: code.len() as u64, file_off: 0,
                    flags: 6, bytes: code,
                },
                crate::native::Mapping {
                    vaddr: 0x4000, size: 16, file_off: 0, flags: 3, bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        for compiler in ["gcc", "default"] {
            import.compiler = Some(compiler.to_string());
            let mut session = ConsoleSession::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let refs = session.references(0x1000, 0x101e, &import.mappings, false).unwrap();
            let mut expected = vec![
                (0x1012u64, 0x4002u64, ReferenceKind::Data),
            ];
            if compiler == "gcc" {
                expected.insert(0,
                    (0x1007u64, 0x4001u64, ReferenceKind::Data));
            }
            assert_eq!(triples(&refs), expected,
                "RDI is a SysV argument but not a Windows x64 argument ({compiler})");
        }
    }

    #[test]
    fn data_references_do_not_promote_fallthrough() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let mut import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![crate::native::Mapping {
                vaddr: 0x1000, size: 16, file_off: 0, flags: 6,
                // The following function's entry is also the saved return PC.
                bytes: vec![0xe8, 0x0b, 0, 0, 0, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            }],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x1005, &import.mappings, false).unwrap();
        assert!(refs.is_empty(), "saving a return PC is not a data reference: {refs:?}");
        import.mappings[0].bytes[..6].copy_from_slice(&[0x8b, 0x05, 0, 0, 0, 0]);
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x1006, &import.mappings, false).unwrap();
        assert_eq!(triples(&refs), vec![
            (0x1000u64, 0x1006u64, ReferenceKind::Read),
        ], "a real access to following data must not be suppressed");
    }

    #[test]
    fn reference_facts_carry_the_access_width() {
        // `mov eax,[rip+0]` reads four bytes; `mov rax,[rip+0]` reads eight.
        // The width is the access's, not the pointer's, and an address that is
        // only computed proves none.
        let cfg = RuntimeConfig::from_env();
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
                    vaddr: 0x1000, size: 16, file_off: 0, flags: 6, bytes: padded,
                }],
                ..Default::default()
            };
            let mut session = ConsoleSession::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let refs = session.references(0x1000, end, &import.mappings, false).unwrap();
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
                vaddr: 0x1000, size: 16, file_off: 0, flags: 6,
                bytes: vec![0x48, 0x8d, 0x05, 0xf9, 0x2f, 0, 0, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0],
            }],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x1008, &import.mappings, false).unwrap();
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
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/AARCH64/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let mut import = NativeImport {
            language: cfg.language_id.clone(),
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x1000, size: 8, file_off: 0, flags: 6,
                    bytes: vec![0x01, 0x80, 0x01, 0x10, 0xc0, 0x03, 0x5f, 0xd6], // adr x1,0x4000; ret
                },
                crate::native::Mapping {
                    vaddr: 0x4000, size: 16, file_off: 0, flags: 3, bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x1008, &import.mappings, false).unwrap();
        assert!(refs.is_empty(), "unused ADR is not a scalar reference: {refs:?}");
        import.mappings[0].bytes[0] = 0; // adr x0,0x4000; ret
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x1008, &import.mappings, false).unwrap();
        assert_eq!(triples(&refs), vec![
            (0x1000u64, 0x4000u64, ReferenceKind::Data),
        ], "returned addresses remain eligible for computed reference inference");
    }

    #[test]
    fn x86_computed_address_operands_create_references() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:32:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let mut import = NativeImport {
            language: cfg.language_id.clone(),
            compiler: Some("gcc".into()),
            mappings: vec![
                crate::native::Mapping {
                    vaddr: 0x1000, size: 11, file_off: 0, flags: 6,
                    bytes: vec![
                        0xbb, 0xff, 0x3f, 0, 0, // mov ebx,0x3fff
                        0x8d, 0x43, 1, // lea eax,[ebx+1]
                        0x31, 0xc0, 0xc3, // discard result; ret
                    ],
                },
                crate::native::Mapping {
                    vaddr: 0x4000, size: 16, file_off: 0, flags: 3, bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x100b, &import.mappings, false).unwrap();
        assert_eq!(triples(&refs), vec![
            (0x1005u64, 0x4000u64, ReferenceKind::Data),
        ], "computed address operands are references even when not returned");
        import.mappings[0].bytes[5..8].copy_from_slice(&[0x83, 0xc3, 1]); // add ebx,1
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let refs = session.references(0x1000, 0x100b, &import.mappings, false).unwrap();
        assert!(refs.is_empty(), "unused arithmetic is not address formation: {refs:?}");
    }

    #[test]
    fn linkage_queries_require_bounded_side_effect_free_slot_flow() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        // LLVM llvm-mc encodings; every positive computes the slot at 0x3008.
        let cases: &[(&str, &str, &[u8], &[u8], &[u8])] = &[
            (
                "x86",
                "x86:LE:64:default",
                &[0xff, 0x25, 0x02, 0x20, 0, 0],
                &[0xff, 0xe0],
                &[0xb8, 1, 0, 0, 0],
            ),
            (
                "x86",
                "x86:LE:32:default",
                &[0xff, 0x25, 0x08, 0x30, 0, 0],
                &[0xff, 0xe0],
                &[0xb8, 1, 0, 0, 0],
            ),
            (
                "AARCH64",
                "AARCH64:LE:64:v8A",
                &[0x10, 0, 0, 0xd0, 0x11, 6, 0x40, 0xf9, 0x20, 2, 0x1f, 0xd6],
                &[0x20, 2, 0x1f, 0xd6],
                &[0x20, 0, 0x80, 0xd2],
            ),
            (
                "PowerPC",
                "PowerPC:BE:32:default",
                &[
                    0x3d, 0x60, 0, 0, 0x81, 0x6b, 0x30, 8, 0x7d, 0x69, 3, 0xa6, 0x4e, 0x80, 4, 0x20,
                ],
                &[0x4e, 0x80, 4, 0x20],
                &[0x38, 0x60, 0, 1],
            ),
        ];
        for &(processor, language, code, unknown, extra_write) in cases {
            let mut cfg = cfg.clone();
            cfg.language_id = language.into();
            cfg.language_dir = cfg
                .ghidra_install
                .join(format!("Ghidra/Processors/{processor}/data/languages"));
            let mut bytes = vec![0; 0x300];
            bytes[..code.len()].copy_from_slice(code);
            bytes[0x100..0x100 + unknown.len()].copy_from_slice(unknown);
            bytes[0x200..0x200 + extra_write.len()].copy_from_slice(extra_write);
            bytes[0x200 + extra_write.len()..0x200 + extra_write.len() + code.len()]
                .copy_from_slice(code);
            let import = NativeImport {
                language: language.into(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000,
                    size: bytes.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes,
                }],
                ..Default::default()
            };
            let mut session = ConsoleSession::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let rows = session.linkage_batch(&[0x1000, 0x1100, 0x1200]).unwrap();
            assert_eq!(rows[0].slot, Some(0x3008), "{language}");
            assert_eq!(rows[0].length as usize, code.len(), "{language}");
            assert!(
                rows[1].slot.is_none(),
                "{language}: unknown incoming register"
            );
            assert!(rows[2].slot.is_none(), "{language}: unused register write");
            // A rejected query must not poison the following console request.
            assert_eq!(session.flow(0x1000).unwrap().address, 0x1000);
        }
        let mut session = ConsoleSession::new(&cfg).unwrap();
        let mut bytes = vec![0; 0x300];
        // A store to a constant address, followed by a valid indirect transfer.
        bytes[..13].copy_from_slice(&[0xc6, 5, 0, 0, 0, 0, 1, 0xff, 0x25, 0xfb, 0x1f, 0, 0]);
        // One load, seven self-copies, one jump: exceeds the eight-instruction bound.
        bytes[0x100..0x107].copy_from_slice(&[0x48, 0x8b, 5, 1, 0x1f, 0, 0]);
        for i in 0..7 {
            bytes[0x107 + i * 3..0x10a + i * 3].copy_from_slice(&[0x48, 0x89, 0xc0]);
        }
        bytes[0x11c..0x11e].copy_from_slice(&[0xff, 0xe0]);
        session
            .load_mapped(&NativeImport {
                language: cfg.language_id.clone(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000,
                    size: bytes.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes,
                }],
                ..Default::default()
            })
            .unwrap();
        let rows = session.linkage_batch(&[0x1000, 0x1100]).unwrap();
        assert!(
            rows.iter().all(|row| row.slot.is_none()),
            "stores and unbounded chains are not thunks"
        );
    }

    #[test]
    fn repeated_instruction_flow_does_not_escape_into_pcode_labels() {
        let mut cfg = crate::session::RuntimeConfig::from_env();
        let Ok(console) = find_console(&cfg) else {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        };
        cfg.console_path = Some(console);
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session
            .load_mapped(&NativeImport {
                language: cfg.language_id.clone(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000,
                    size: 3,
                    file_off: 0,
                    flags: 6,
                    bytes: vec![0xf3, 0xa4, 0xc3], // REP MOVSB; RET
                }],
                ..Default::default()
            })
            .unwrap();
        let flows = session.flow_batch(&[0x1000]).unwrap();
        assert_eq!(flows[0].kind, FlowKind::Fallthrough);
        assert_eq!(flows[0].fallthrough, Some(0x1002));
        assert!(
            flows[0].targets.is_empty(),
            "instruction-local repeat branches are not machine flow references"
        );
    }

    #[test]
    fn elf_pattern_selection_uses_loader_compiler() {
        let mut cfg = crate::session::RuntimeConfig::from_env();
        let Ok(console) = find_console(&cfg) else {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        };
        cfg.console_path = Some(console);
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        // ELF64 with one allocated code section: ret; push rbp; mov rbp,rsp; ret.
        // The pinned GCC patterns recognize the entry after ret; Windows does not.
        let mut elf = vec![0u8; 0x200];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (offset, value) in [(16, 2u16), (18, 62), (58, 64), (60, 2)] {
            elf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        elf[40..48].copy_from_slice(&0x80u64.to_le_bytes());
        elf[0xc4..0xc8].copy_from_slice(&1u32.to_le_bytes());
        for (offset, value) in [(0xc8, 6u64), (0xd0, 0x1000), (0xd8, 0x180), (0xe0, 6)] {
            elf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        elf[0x180..0x186].copy_from_slice(&[0xc3, 0x55, 0x48, 0x89, 0xe5, 0xc3]);
        let mut import = crate::native::import_elf(&elf).unwrap();
        crate::native::select_language(&mut import, &cfg).unwrap();
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        session.send("functionstarts 0x1000 0x1006\n").unwrap();
        let response = read_until_prompt(&mut session.reader).unwrap();
        let payload = response
            .lines()
            .find_map(|line| line.strip_prefix("PATTERNS "))
            .unwrap_or_else(|| panic!("missing pattern response: {response}"));
        let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert!(
            parsed["matches"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["address"] == 0x1001),
            "ELF compiler selection must recognize the GCC entry: {response}"
        );
    }

    #[test]
    fn function_pattern_queries_preserve_prefix_marks_and_range_bounds() {
        let mut cfg = crate::session::RuntimeConfig::from_env();
        let Ok(console) = find_console(&cfg) else {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        };
        cfg.console_path = Some(console);
        cfg.language_id = "AARCH64:LE:64:v8A".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/AARCH64/data/languages");
        let query = |session: &mut ConsoleSession, end: u64| {
            session
                .send(&format!("functionstarts 0x1000 0x{end:x}\n"))
                .unwrap();
            let response = read_until_prompt(&mut session.reader).unwrap();
            let payload = response
                .lines()
                .find_map(|line| line.strip_prefix("PATTERNS "))
                .unwrap_or_else(|| panic!("missing pattern response: {response}"));
            let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
            let mut addresses: Vec<_> = parsed["matches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["address"].as_u64().unwrap())
                .collect();
            addresses.sort_unstable();
            addresses.dedup();
            addresses
        };
        let cases: &[(&[u32], &[u64])] = &[
            // ret; nop; stp x29,x30,[sp,#-32]!; mov x29,sp; ret.
            // Both the wildcard prefix and the pair's post-pattern mark match.
            (
                &[0xd65f03c0, 0xd503201f, 0xa9be7bfd, 0x910003fd, 0xd65f03c0],
                &[0x1004, 0x1008],
            ),
            // ret; sub sp,sp,#16; add sp,sp,#16; ret: pair-only match.
            (&[0xd65f03c0, 0xd10043ff, 0x910043ff, 0xd65f03c0], &[0x1004]),
        ];
        for &(words, expected) in cases {
            let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let end = 0x1000 + bytes.len() as u64;
            let mut session = ConsoleSession::new(&cfg).unwrap();
            session
                .load_mapped(&NativeImport {
                    language: cfg.language_id.clone(),
                    mappings: vec![crate::native::Mapping {
                        vaddr: 0x1000,
                        size: bytes.len() as u64,
                        file_off: 0,
                        flags: 6,
                        bytes,
                    }],
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(query(&mut session, end).as_slice(), expected);
            assert!(
                query(&mut session, 0x1007).is_empty(),
                "a pattern must not read past the requested mapped range"
            );
        }

        // A private pattern root exercises DSL boundaries without modifying the SDK.
        struct PatternRoot(PathBuf);
        impl Drop for PatternRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root =
            std::env::temp_dir().join(format!("ventris-pattern-grammar-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let root = PatternRoot(root);
        let patterns = root.0.join("Ghidra/Processors/Fixture/data/patterns");
        std::fs::create_dir_all(&patterns).unwrap();
        std::fs::write(
            patterns.join("patternconstraints.xml"),
            r#"
<patternconstraints><language id="AARCH64:*:64:*">
  <patternfile>grammar.xml</patternfile>
  <compiler id="not-the-selected-compiler"><patternfile>missing.xml</patternfile></compiler>
</language></patternconstraints>"#,
        )
        .unwrap();
        std::fs::write(
            patterns.join("grammar.xml"),
            r#"
<patternlist>
  <pattern mark="0"><data>0xa. * 1011....</data>
    <align mark="0x100000001" bits="2"/><possiblefuncstart/>
  </pattern>
  <patternpairs totalbits="9" postbits="4">
    <prepatterns><data>0xc.</data></prepatterns>
    <postpatterns><data>0xd.</data><funcstart/></postpatterns>
  </patternpairs>
  <patternpairs totalbits="8" postbits="5">
    <prepatterns><data>0xe.</data></prepatterns>
    <postpatterns><data>0xf.</data><funcstart/></postpatterns>
  </patternpairs>
</patternlist>"#,
        )
        .unwrap();
        cfg.ghidra_install = root.0.clone();
        let mut bytes = vec![0; 0x10002];
        bytes[3..5].copy_from_slice(&[0xa1, 0xb2]);
        bytes[0xffff..0x10001].copy_from_slice(&[0xa3, 0xb4]);
        bytes[0x13..0x15].copy_from_slice(&[0xc1, 0xd2]);
        bytes[0x17..0x19].copy_from_slice(&[0xe3, 0xf4]);
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session
            .load_mapped(&NativeImport {
                language: cfg.language_id.clone(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000,
                    size: bytes.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes,
                }],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            query(&mut session, 0x11002),
            vec![0x1004, 0x11000],
            "marks override attributes; alignment uses the raw start; fixed-bit thresholds apply"
        );
        assert_eq!(
            query(&mut session, 0x11000),
            vec![0x1004],
            "a match across a scan-buffer boundary still needs its complete byte sequence"
        );
    }

    #[test]
    fn non_stack_symbolic_offsets_are_data_references() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        for (setup, transfer, expected) in [
            // rax = unknown rdi; jmp [rax+offset]: a data slot
            ([0x48, 0x89, 0xf8], 0x60, vec![(0x1009, 0x10048, ReferenceKind::Data)]),
            // rax = stack alias; jmp [rax+offset]: a frame slot, never data
            ([0x48, 0x89, 0xe0], 0x60, vec![(0x1009, 0x10048, ReferenceKind::Stack)]),
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
                        vaddr: 0x1000, size: code.len() as u64, file_off: 0,
                        flags: 6, bytes: code,
                    },
                    crate::native::Mapping {
                        vaddr: 0x10048, size: 8, file_off: 0, flags: 2, bytes: vec![0; 8],
                    },
                ],
                ..Default::default()
            };
            let mut session = ConsoleSession::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let facts = session.references(0x1000, end, &import.mappings, false).unwrap();
            let triples: Vec<_> = facts.iter().map(|fact| (fact.from, fact.to, fact.kind)).collect();
            assert_eq!(triples, expected, "setup={setup:x?}, transfer={transfer:x}");
            assert!(session.constants(0x1000, end, &import.mappings, false).unwrap().is_empty(),
                "a symbolic offset is not a proven constant pointer");
        }
    }
}
