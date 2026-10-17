//! The near-miss search inside a `new-project` repository: the project's
//! pinned compiler and flags (`config/project.json`, `config/toolchain.json`,
//! `build/tools/`, resolved the way `configure.py` resolves them), the retail
//! bytes of the function from `orig/`, the function's printings from the
//! project's own store (`.romwright`), and where `configure.py swap` picks the
//! chosen C up.

use super::object::{self, ElfObject};
use super::plan::PrintVariant;
use super::{Evaluator, Score};
use crate::Core;
use crate::emit_m2c::M2cOptions;
use crate::new_project::elf::Elf32;
use crate::new_project::manifest::Manifest;
use romwright_model::FunctionRow;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The include `configure.py swap` puts in front of a unit's C.
pub const UNIT_PRELUDE: &str = "#include \"romwright_types.h\"\n\n";

const COMPILE_TIMEOUT: Duration = Duration::from_secs(120);

pub struct MatchProject {
    pub root: PathBuf,
    pub name: String,
    pub image_name: String,
    pub orig: PathBuf,
    /// The program name in the project store (`new-project` sanitizes the project name).
    pub program: String,
    /// `mwcc-ps2`, `ee-gcc`, or for the MIPS splat projects `ido`, `gcc-mips`, `psyq`, `psp-gcc`, `mwcc-psp`.
    pub kind: String,
    pub compiler_id: String,
    pub cflags: Vec<String>,
    /// Compiler argv prefix: launcher (wibo) and the compiler.
    cc: Vec<String>,
    launcher: Vec<String>,
    given: std::collections::BTreeMap<String, String>,
    template: Option<Vec<String>>,
    env: Vec<(String, String)>,
    pub objdiff: Option<PathBuf>,
    layout: Vec<(u64, u64, u64)>,
    yaml: PathBuf,
    /// Big-endian objects (N64, GameCube/Wii).
    pub big: bool,
    /// The dtk files of a GameCube/Wii project: `(symbols.txt, splits.txt, objects.json)`.
    dtk: Option<(PathBuf, PathBuf, PathBuf)>,
    /// ARM projects: whether the function being scored is Thumb (mwccarm objects do not say), set by `ProjectEvaluator`.
    pub thumb_hint: std::cell::Cell<Option<bool>>,
    /// Windows PE projects (`kind` is `pe`): the compiler is Visual C++ (`cl.exe` through wibo), whose C has no `long long`.
    pub msvc: bool,
}

fn program_name(stem: &str) -> String {
    stem.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

fn strings(value: &serde_json::Value) -> Vec<String> {
    value.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

impl MatchProject {
    /// Opens the repository at `root`; the tools must already be in `build/tools/` (`python3 configure.py`).
    pub fn open(root: &Path) -> Result<MatchProject, String> {
        let root = std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
        let read = |relative: &str| -> Result<String, String> {
            std::fs::read_to_string(root.join(relative)).map_err(|e| format!("{}: {e} (is this a `romwright-cli new-project` repository?)", root.join(relative).display()))
        };
        let project: serde_json::Value = serde_json::from_str(&read("config/project.json")?).map_err(|e| format!("config/project.json: {e}"))?;
        if project["romwright"]["kind"].as_str() == Some("pe-per-function") {
            return Self::open_pe(root, &project);
        }
        let name = project["name"].as_str().ok_or("config/project.json has no name")?.to_string();
        let image_name = project["image"]["file"].as_str().ok_or("config/project.json has no image")?.to_string();
        let kind = project["compiler"]["kind"].as_str().unwrap_or("ee-gcc").to_string();
        let compiler_id = project["tools"]["compiler"].as_str().ok_or("config/project.json names no compiler")?.to_string();
        let cflags = strings(&project["compiler"]["cflags"]);
        let yaml = root.join(project["splat"]["yaml"].as_str().unwrap_or(""));
        let dtk = (kind == "mwcc-gc").then(|| {
            let path = |key: &str| root.join(project["dtk"][key].as_str().unwrap_or(""));
            (path("symbols"), path("splits"), path("objects"))
        });
        let big = project["compiler"]["endian"].as_str() == Some("big") || dtk.is_some();
        // N64 names its main store program `<name>.main`; the project records the one it imported.
        let program = project["image"]["program"].as_str().map(str::to_string).unwrap_or_else(|| program_name(&name));
        let layout = project["layout"]
            .as_array()
            .map(|rows| rows.iter().filter_map(|r| Some((r["vaddr"].as_u64()?, r["offset"].as_u64()?, r["size"].as_u64()?))).collect())
            .unwrap_or_default();
        let manifest = Manifest::parse(&read("config/toolchain.json")?).map_err(|e| format!("config/toolchain.json: {e}"))?;
        let tool = manifest.tool(&compiler_id).ok_or_else(|| format!("config/toolchain.json has no tool {compiler_id}"))?;

        // The profile (`config/toolchain.local.json`) replaces tools one by one, as `configure.py` reads it.
        let profile: serde_json::Value = match std::fs::read_to_string(root.join("config/toolchain.local.json")) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| format!("config/toolchain.local.json: {e}"))?,
            Err(_) => serde_json::Value::Null,
        };
        let given: std::collections::BTreeMap<String, String> = profile["tools"]
            .as_object()
            .map(|tools| tools.iter().filter_map(|(k, v)| Some((k.clone(), v["path"].as_str()?.to_string()))).collect())
            .unwrap_or_default();
        let recipe = &profile["recipe"];
        let env: Vec<(String, String)> = recipe["environment"]
            .as_object()
            .map(|e| e.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
            .unwrap_or_default();
        let template = profile["compile_arguments"].as_array().map(|_| strings(&profile["compile_arguments"]));

        let tools = root.join("build/tools");
        let installed = |id: &str| -> PathBuf { tools.join(id) };
        let windows_exe = match given.get("compiler") {
            Some(path) => path.to_ascii_lowercase().ends_with(".exe"),
            None => tool.runtime.as_deref() == Some("wibo"),
        };
        let launcher: Vec<String> = if let Some(program) = recipe["compiler"].as_str() {
            std::iter::once(program.to_string()).chain(strings(&recipe["arguments"])).collect()
        } else if windows_exe {
            vec![given.get("wibo").cloned().unwrap_or_else(|| installed("wibo").join("wibo").display().to_string())]
        } else {
            Vec::new()
        };
        let compiler = match given.get("compiler") {
            Some(path) => path.clone(),
            // The compilers bundle holds one directory per version (`GC/2.6/mwcceppc.exe`).
            // The mwccarm archive holds `mwccarm/<1.2|2.0|dsi>/<build>/mwccarm.exe`.
            None if kind == "mwcc-arm" => installed(&compiler_id)
                .join("mwccarm")
                .join(project["compiler"]["mw_version"].as_str().unwrap_or("2.0/sp2p3"))
                .join(tool.entry.as_deref().unwrap_or(""))
                .display()
                .to_string(),
            None => match project["compiler"]["mw_version"].as_str().filter(|_| kind == "mwcc-gc") {
                Some(version) => installed(&compiler_id).join(version).join(tool.entry.as_deref().unwrap_or("")).display().to_string(),
                None => installed(&compiler_id).join(tool.entry.as_deref().unwrap_or("")).display().to_string(),
            },
        };
        if !given.contains_key("compiler") && !Path::new(&compiler).exists() {
            return Err(format!("{compiler} is missing: run `python3 configure.py` in {} first (it installs the pinned tools into build/tools/)", root.display()));
        }
        if let Some(wibo) = launcher.first().filter(|_| windows_exe && recipe["compiler"].is_null())
            && !Path::new(wibo).exists() {
                return Err(format!("{wibo} is missing: run `python3 configure.py` in {} first", root.display()));
            }
        let mut cc = launcher.clone();
        cc.push(compiler);
        let objdiff = given
            .get("objdiff-cli")
            .map(PathBuf::from)
            .or_else(|| project["tools"]["report"].as_str().map(|id| installed(id).join("objdiff-cli")))
            .filter(|p| p.exists());
        Ok(MatchProject {
            orig: root.join(project["image"]["orig"].as_str().unwrap_or("")),
            program,
            root,
            name,
            image_name,
            kind,
            compiler_id,
            cflags,
            cc,
            launcher,
            given,
            template,
            env,
            objdiff,
            layout,
            yaml,
            big,
            dtk,
            thumb_hint: Default::default(),
            msvc: false,
        })
    }

    /// A Windows PE repository (`config/project.json` kind `pe-per-function`): the compiler and the tools are what
    /// `configure.py` resolved into `build/config.json`.
    fn open_pe(root: PathBuf, project: &serde_json::Value) -> Result<MatchProject, String> {
        let name = project["name"].as_str().ok_or("config/project.json has no name")?.to_string();
        let image_name = project["image"]["file"].as_str().ok_or("config/project.json has no image")?.to_string();
        let config_path = root.join("build/config.json");
        let config: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&config_path).map_err(|e| {
            format!("{}: {e}: run `python3 configure.py` in {} first (it installs the pinned compiler and writes build/config.json)", config_path.display(), root.display())
        })?)
        .map_err(|e| format!("build/config.json: {e}"))?;
        let family = config["family"].as_str().unwrap_or("msvc").to_string();
        let tool = config["tool"].as_str().ok_or("build/config.json names no compiler")?.to_string();
        let winpath = |p: &str| format!("Z:{}", p.replace('/', "\\"));
        let (cc, env) = if family == "msvc" {
            let (wibo, cl) = (config["wibo"].as_str().ok_or("build/config.json has no wibo")?, config["cl"].as_str().ok_or("build/config.json has no cl")?);
            for tool in [wibo, cl] {
                if !Path::new(tool).exists() {
                    return Err(format!("{tool} is missing: run `python3 configure.py` in {} first", root.display()));
                }
            }
            let include: Vec<String> = strings(&config["include"]);
            (vec![wibo.to_string(), cl.to_string()], vec![("INCLUDE".to_string(), include.iter().map(|d| winpath(d)).collect::<Vec<_>>().join(";"))])
        } else {
            let clang = config["clang"].as_str().map(str::to_string).or_else(|| std::env::var("CLANG").ok()).ok_or("build/config.json names no clang (set $CLANG or config/toolchain.local.json)")?;
            (vec![clang, "--target=i686-pc-windows-msvc".to_string()], Vec::new())
        };
        let objdiff = config["objdiff"].as_str().map(PathBuf::from).filter(|p| p.exists());
        Ok(MatchProject {
            orig: root.join(project["image"]["orig"].as_str().unwrap_or("")),
            program: program_name(&name),
            root,
            name,
            image_name,
            kind: "pe".into(),
            compiler_id: tool,
            cflags: strings(&config["flags"]),
            cc: cc.clone(),
            launcher: Vec::new(),
            given: Default::default(),
            template: None,
            env,
            objdiff,
            layout: Vec::new(),
            yaml: PathBuf::new(),
            big: false,
            dtk: None,
            thumb_hint: Default::default(),
            msvc: family == "msvc",
        })
    }

    /// The compile command for `source` -> `output`, as `configure.py`'s `cc_command` builds it.
    fn compile_argv(&self, source: &Path, output: &Path) -> Vec<String> {
        let (src, out) = (source.display().to_string(), output.display().to_string());
        // A Windows PE project: `cl.exe` through wibo (paths in Windows spelling), or clang for a Windows target.
        if self.kind == "pe" {
            let mut argv = self.cc.clone();
            if self.msvc {
                let winpath = |p: &str| format!("Z:{}", p.replace('/', "\\"));
                argv.extend(["/nologo".to_string(), "/c".to_string()]);
                argv.extend(self.cflags.iter().cloned());
                argv.extend(["/I".to_string(), winpath(&self.root.join("include").display().to_string())]);
                argv.extend([format!("/Fo{}", winpath(&out)), winpath(&src)]);
            } else {
                argv.extend(self.cflags.iter().cloned());
                argv.extend(["-I".to_string(), self.root.join("include").display().to_string(), "-c".to_string(), src, "-o".to_string(), out]);
            }
            return argv;
        }
        // The MIPS splat projects compile through tools/cc.py, which `ninja` uses too.
        if matches!(self.kind.as_str(), "ido" | "gcc-mips" | "psyq" | "psp-gcc" | "mwcc-psp") {
            return vec!["python3".into(), "tools/cc.py".into(), src, out];
        }
        // GBA: cpp | agbcc | as through tools/cc.py (`OUT SRC`), which `ninja` uses too.
        if matches!(self.kind.as_str(), "agbcc" | "mwcc-arm") {
            return vec!["python3".into(), "tools/cc.py".into(), out, src];
        }
        if let Some(template) = self.template.as_ref().filter(|t| t.iter().any(|a| a.contains("{source}"))) {
            let mut argv = self.launcher.clone();
            for arg in template {
                if let Some(tool) = arg.strip_prefix("{tool:").and_then(|a| a.strip_suffix('}')) {
                    argv.push(self.given.get(tool).cloned().unwrap_or_default());
                } else {
                    argv.push(arg.replace("{root}", &self.root.display().to_string()).replace("{source}", &src).replace("{output}", &out));
                }
            }
            return argv;
        }
        let mut argv = self.cc.clone();
        if self.kind == "mwcc-gc" {
            // dtk-template's flags, one entry per option (`-proc gekko` is two words).
            argv.extend(self.cflags.iter().flat_map(|flag| flag.split_whitespace().map(str::to_string)));
            argv.extend(["-c".into(), src, "-o".into(), out]);
        } else if self.kind == "mwcc-ps2" {
            argv.extend(self.cflags.iter().cloned());
            argv.extend(["-Iinclude".into(), "-c".into(), src, "-o".into(), out]);
        } else {
            argv.push("-c".into());
            argv.extend(self.cflags.iter().cloned());
            argv.extend(["-Iinclude".into(), "-o".into(), out, src]);
        }
        argv
    }

    /// Compiles C text with the project's compiler and flags in a scratch directory; returns the object's bytes.
    pub fn compile(&self, text: &str, scratch: &Path, tag: &str) -> Result<Vec<u8>, String> {
        let directory = scratch.join(tag);
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).map_err(|e| format!("{}: {e}", directory.display()))?;
        let (source, output) = (directory.join("unit.c"), directory.join("unit.o"));
        std::fs::write(&source, text).map_err(|e| e.to_string())?;
        let argv = self.compile_argv(&source, &output);
        let tmp = self.root.join("build/tmp");
        let _ = std::fs::create_dir_all(&tmp);
        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]).current_dir(&self.root).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for key in ["TMPDIR", "TMP", "TEMP"] {
            command.env(key, &tmp);
        }
        command.envs(self.env.iter().map(|(k, v)| (k, v)));
        let mut child = command.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound && !Path::new("/lib/ld-linux.so.2").exists() && self.cc.len() == 1 {
                format!("cannot run {}: {e}; the ee-gcc builds are 32-bit Linux programs and need /lib/ld-linux.so.2 (libc6-i386 / glibc.i686)", argv[0])
            } else {
                format!("cannot run {}: {e}", argv[0])
            }
        })?;
        let (mut stdout, mut stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let out_reader = std::thread::spawn(move || {
            let mut text = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stdout, &mut text);
            text
        });
        let err_reader = std::thread::spawn(move || {
            let mut text = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stderr, &mut text);
            text
        });
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if started.elapsed() > COMPILE_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err("the compiler timed out".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let log = String::from_utf8_lossy(&out_reader.join().unwrap_or_default()).into_owned()
            + &String::from_utf8_lossy(&err_reader.join().unwrap_or_default());
        let object = std::fs::read(&output).ok().filter(|_| status.success());
        let _ = std::fs::remove_dir_all(&directory);
        object.ok_or_else(|| {
            let line = log.lines().find(|l| l.contains("error") || l.contains("Error")).or_else(|| log.lines().last()).unwrap_or("no output");
            format!("compile failed ({status}): {}", line.trim())
        })
    }

    /// The retail bytes of `[address, address + size)` from the project's image.
    pub fn retail_bytes(&self, address: u64, size: u64) -> Result<Vec<u8>, String> {
        if self.kind == "mwcc-arm" {
            return self.nds_retail_bytes(address, size);
        }
        let data = std::fs::read(&self.orig).map_err(|e| format!("{}: {e}", self.orig.display()))?;
        if self.kind == "pe" {
            return super::pe::retail_bytes(&data, address, size);
        }
        if !data.starts_with(b"\x7fELF") {
            // A ROM or PS-X EXE: the project's `layout` rows are the file-backed code ranges.
            for &(vaddr, offset, filesz) in &self.layout {
                if vaddr <= address && address + size <= vaddr + filesz {
                    let at = (offset + address - vaddr) as usize;
                    return data.get(at..at + size as usize).map(<[u8]>::to_vec).ok_or_else(|| format!("{address:#x} is past the end of {}", self.image_name));
                }
            }
            return Err(format!("{address:#x}+{size:#x} is not inside a raw code range of {} (compressed or overlay code is not part of the project)", self.image_name));
        }
        let elf = Elf32::parse(&data)?;
        for load in elf.loads() {
            let (start, end) = (u64::from(load.vaddr), u64::from(load.vaddr) + u64::from(load.memsz));
            if start <= address && address + size <= end {
                let at = u64::from(load.offset) + (address - start);
                let filesz_end = u64::from(load.offset) + u64::from(load.filesz);
                let have = filesz_end.saturating_sub(at).min(size) as usize;
                let mut bytes = data[at as usize..at as usize + have].to_vec();
                bytes.resize(size as usize, 0);
                return Ok(bytes);
            }
        }
        Err(format!("{address:#x}+{size:#x} is not inside a loadable segment of {}", self.image_name))
    }

    /// Where `configure.py swap` will find C for the function at `address`: `(unit, already a C unit)`.
    pub fn unit_of(&self, address: u64) -> Result<(String, bool), String> {
        if self.kind == "pe" {
            return self.pe_unit_row(address).map(|(cname, _)| (cname, true));
        }
        if let Some(files) = &self.dtk {
            return gc_unit_of(files, address).map(|(unit, source)| (unit, source.is_some()));
        }
        if self.kind == "agbcc" {
            let row = self.units_row(address)?;
            return Ok((row["name"].as_str().unwrap_or("").to_string(), row["kind"].as_str() == Some("c")));
        }
        let offset = self
            .layout
            .iter()
            .find(|(vaddr, _, size)| *vaddr <= address && address < vaddr + size)
            .map(|(vaddr, offset, _)| offset + address - vaddr)
            .ok_or_else(|| format!("{address:#x} is in none of the image's file segments"))?;
        let text = std::fs::read_to_string(&self.yaml).map_err(|e| format!("{}: {e}", self.yaml.display()))?;
        unit_in_yaml(&text, offset).ok_or_else(|| format!("no function unit starts at file offset {offset:#x} in {}", self.yaml.display()))
    }

    /// Puts `text` where `configure.py swap` picks it up and returns the file:
    /// `src/<unit>.c` when the function is already a C unit, else
    /// `decompiled/<unit name>.c` (the file `swap` copies in).
    pub fn write_best(&self, address: u64, text: &str) -> Result<PathBuf, String> {
        if self.kind == "pe" {
            // A PE unit is one function per file: the file `new-project` wrote, kept `NON_MATCHING` (build.py report says
            // whether the new print matches) with its `// FUNCTION:` annotation.
            let (_, source) = self.pe_unit_row(address)?;
            let path = self.root.join(source);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let text = if self.msvc { crate::new_project::pe::msvc_dialect(text) } else { text.to_string() };
            let annotation = std::fs::read_to_string(&path)
                .ok()
                .and_then(|old| old.lines().find(|l| l.starts_with("// FUNCTION:")).map(str::to_string))
                .unwrap_or_else(|| format!("// FUNCTION: {} {address:#010x}", self.name.to_ascii_uppercase()));
            let body = format!("/* NON_MATCHING: written by `romwright-cli match --write`. */\n{annotation}\n#include \"romwright_types.h\"\n\n{}\n", text.trim_end());
            std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
            return Ok(path);
        }
        if let Some(files) = &self.dtk {
            // dtk project: the unit's own source when it has one, else the file `swap` copies in.
            let (unit, source) = gc_unit_of(files, address)?;
            let path = match source {
                Some(source) => self.root.join(source),
                None => {
                    let name = gc_function_name(files, address)?;
                    self.root.join("decompiled").join(format!("{name}.c"))
                }
            };
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let _ = unit;
            let body = if text.starts_with("#include") { text.to_string() } else { format!("{UNIT_PRELUDE}{text}") };
            std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
            return Ok(path);
        }
        if self.kind == "mwcc-arm" {
            // NDS: a function replaced by C has its source in config/swaps.json; else the file `swap` copies in.
            let name = self.nds_function_name(address)?;
            let swapped = std::fs::read_to_string(self.root.join("config/swaps.json"))
                .ok()
                .and_then(|text| serde_json::from_str::<Vec<serde_json::Value>>(&text).ok())
                .and_then(|rows| rows.into_iter().find(|r| r["name"].as_str() == Some(name.as_str())))
                .and_then(|r| r["source"].as_str().map(str::to_string));
            let path = match swapped {
                Some(source) => self.root.join(source),
                None => self.root.join("decompiled").join(format!("{name}.c")),
            };
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let body = if text.starts_with("#include") { text.to_string() } else { format!("{UNIT_PRELUDE}{text}") };
            std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
            return Ok(path);
        }
        if self.kind == "agbcc" {
            // GBA: the unit table names the source of a C unit; an assembly unit's C goes where `swap` reads it.
            let row = self.units_row(address)?;
            let name = row["name"].as_str().unwrap_or("").to_string();
            let path = match (row["kind"].as_str(), row["source"].as_str()) {
                (Some("c"), Some(source)) => self.root.join(source),
                _ => self.root.join("decompiled").join(format!("{name}.c")),
            };
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let body = if text.starts_with("#include") { text.to_string() } else { format!("{UNIT_PRELUDE}{text}") };
            std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
            return Ok(path);
        }
        let (unit, is_c) = self.unit_of(address)?;
        let path = if is_c {
            self.root.join("src").join(format!("{unit}.c"))
        } else {
            let stem = Path::new(&unit).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or(unit.clone());
            self.root.join("decompiled").join(format!("{stem}.c"))
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let body = if is_c && !text.starts_with("#include") { format!("{UNIT_PRELUDE}{text}") } else { text.to_string() };
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(path)
    }
}

impl MatchProject {
    /// `(function name, source path)` of the unit at `address`, from `config/functions.tsv` of a Windows PE project.
    fn pe_unit_row(&self, address: u64) -> Result<(String, String), String> {
        let path = self.root.join("config/functions.tsv");
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 6 && u64::from_str_radix(cols[0].trim_start_matches("0x"), 16).ok() == Some(address) {
                return Ok((cols[3].to_string(), cols[5].to_string()));
            }
        }
        Err(format!("no unit at {address:#x} in {}", path.display()))
    }

    /// The retail bytes of an ARM9 function of a Nintendo DS project: the decompressed `extract/arm9/arm9.bin`
    /// (or an autoload's binary) at the address its `base_address` says. Overlays share addresses and are not served.
    fn nds_retail_bytes(&self, address: u64, size: u64) -> Result<Vec<u8>, String> {
        let base_of = |yaml: &Path| -> Option<u64> {
            let text = std::fs::read_to_string(yaml).ok()?;
            text.lines().find_map(|l| l.strip_prefix("base_address:")).and_then(|v| v.trim().parse::<u64>().ok())
        };
        let extract = self.root.join("extract/arm9");
        for (bin, yaml) in [("arm9.bin", "arm9.yaml"), ("itcm.bin", "itcm.yaml"), ("dtcm.bin", "dtcm.yaml")] {
            let Some(base) = base_of(&extract.join(yaml)) else { continue };
            let Ok(data) = std::fs::read(extract.join(bin)) else { continue };
            if address >= base && address + size <= base + data.len() as u64 {
                let at = (address - base) as usize;
                return Ok(data[at..at + size as usize].to_vec());
            }
        }
        Err(format!("{address:#x}+{size:#x} is not inside the ARM9 program or an autoload of the extracted ROM (overlay functions are not served)"))
    }

    /// The dsd function row at `address` in the main module: `(name, Thumb)`.
    fn nds_function_row(&self, address: u64) -> Option<(String, bool)> {
        let text = std::fs::read_to_string(self.root.join("config/dsd/arm9/symbols.txt")).ok()?;
        let key = format!(" addr:{address:#010x}");
        text.lines().find(|l| l.contains(" kind:function(") && l.contains(&key)).map(|l| {
            let name = l.split_whitespace().next().unwrap_or("").to_string();
            (name, l.contains("kind:function(thumb"))
        })
    }

    fn nds_function_name(&self, address: u64) -> Result<String, String> {
        self.nds_function_row(address).map(|r| r.0).ok_or_else(|| format!("no function at {address:#x} in config/dsd/arm9/symbols.txt"))
    }

    /// Whether the function at `address` is Thumb, from the project's own tables (GBA units, dsd symbols).
    pub fn thumb_at(&self, address: u64) -> Option<bool> {
        match self.kind.as_str() {
            "agbcc" => self.units_row(address).ok().map(|row| row["mode"].as_str() == Some("thumb")),
            "mwcc-arm" => self.nds_function_row(address).map(|r| r.1),
            _ => None,
        }
    }

    /// The `config/units.json` row (GBA projects) of the function unit that starts at `address`.
    fn units_row(&self, address: u64) -> Result<serde_json::Value, String> {
        let path = self.root.join("config/units.json");
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let rows: Vec<serde_json::Value> = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        rows.into_iter()
            .find(|row| row["start"].as_u64() == Some(address) && matches!(row["kind"].as_str(), Some("asm" | "c")))
            .ok_or_else(|| format!("no function unit starts at {address:#x} in config/units.json"))
    }
}

/// The name of the function row of `symbols.txt` at `address`.
fn gc_function_name(files: &(PathBuf, PathBuf, PathBuf), address: u64) -> Result<String, String> {
    let text = std::fs::read_to_string(&files.0).map_err(|e| format!("{}: {e}", files.0.display()))?;
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(" = ") else { continue };
        let Some((place, attributes)) = rest.split_once(';') else { continue };
        let Some(hex) = place.split(":0x").nth(1) else { continue };
        if attributes.contains("type:function") && u64::from_str_radix(hex.trim(), 16).ok() == Some(address) {
            return Ok(name.trim().to_string());
        }
    }
    Err(format!("no function row at {address:#x} in {}", files.0.display()))
}

/// `(unit, source)` for the function at `address` of a dtk project: the `splits.txt` unit whose
/// `.text` range holds it (else `main/<name>.c`, which `configure.py swap` creates) and the
/// source file `objects.json` gives that unit, when it has one.
fn gc_unit_of(files: &(PathBuf, PathBuf, PathBuf), address: u64) -> Result<(String, Option<String>), String> {
    let splits = std::fs::read_to_string(&files.1).map_err(|e| format!("{}: {e}", files.1.display()))?;
    let mut found = None;
    let mut unit = "";
    for line in splits.lines() {
        if !line.starts_with(char::is_whitespace) && line.trim_end().ends_with(':') && !line.starts_with("Sections") {
            unit = line.trim_end().trim_end_matches(':');
        } else if let Some(range) = line.trim().strip_prefix(".text") {
            let hex = |key: &str| -> Option<u64> {
                let at = range.find(key)? + key.len();
                let digits: String = range[at..].trim_start_matches("0x").chars().take_while(char::is_ascii_hexdigit).collect();
                u64::from_str_radix(&digits, 16).ok()
            };
            if let (Some(start), Some(end)) = (hex("start:"), hex("end:"))
                && start <= address && address < end && !unit.is_empty() {
                    found = Some(unit.to_string());
                }
        }
    }
    let unit = match found {
        Some(unit) => unit,
        None => format!("main/{}.c", gc_function_name(files, address)?),
    };
    let objects: serde_json::Value = std::fs::read_to_string(&files.2)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(serde_json::Value::Null);
    let source = objects["objects"][&unit]["source"].as_str().map(str::to_string);
    Ok((unit, source))
}

/// The `(unit, is C)` of the splat entry `- [0xOFFSET, asm|c, unit]` that starts at file offset `offset`.
fn unit_in_yaml(text: &str, offset: u64) -> Option<(String, bool)> {
    for line in text.lines() {
        let Some(body) = line.trim_start().strip_prefix("- [").and_then(|l| l.trim_end().strip_suffix(']')) else { continue };
        let parts: Vec<&str> = body.splitn(3, ", ").collect();
        let [start, kind, unit] = parts[..] else { continue };
        let Some(start) = start.strip_prefix("0x").and_then(|h| u64::from_str_radix(h, 16).ok()) else { continue };
        if start == offset && (kind == "asm" || kind == "c") {
            return Some((unit.to_string(), kind == "c"));
        }
    }
    None
}

/// The function a `match` argument names: a symbol name, `0xADDR`, a bare hex address or `func_ADDR`.
pub fn resolve_function(core: &Core, program: &str, query: &str) -> Result<FunctionRow, String> {
    let functions = core.functions(program).map_err(|e| e.to_string())?;
    if let Some(function) = functions.iter().find(|f| f.name == query) {
        return Ok(function.clone());
    }
    let hex = query.strip_prefix("func_").or_else(|| query.strip_prefix("0x")).unwrap_or(query);
    if let Ok(address) = u64::from_str_radix(hex, 16)
        && let Some(function) = functions.iter().find(|f| f.entry.offset == address) {
            return Ok(function.clone());
        }
    Err(format!("no function {query} in {program} ({} functions)", functions.len()))
}

/// Share of equal instruction words under the relocation mask: what the score falls back to without `objdiff-cli`.
fn word_percent(body: &[u8], mask: &[u8], retail: &[u8]) -> f64 {
    let words = body.len().max(retail.len()).div_ceil(4);
    if words == 0 {
        return 100.0;
    }
    let equal = (0..words)
        .filter(|w| {
            (0..4).all(|b| {
                let i = w * 4 + b;
                i < body.len() && i < retail.len() && (body[i] ^ retail[i]) & mask[i] == 0
            })
        })
        .count();
    equal as f64 * 100.0 / words as f64
}

/// objdiff's match percent of one function (`functionRelocDiffs=none`), the lane harness's measure.
// The target is described by independent flags the objdiff call site forwards unchanged.
#[allow(clippy::too_many_arguments)]
fn objdiff_percent(objdiff: &Path, name: &str, retail: &[u8], function: &object::Function, e_flags: u32, big: bool, ppc: bool, arm_thumb: Option<bool>, x86: bool, scratch: &Path) -> Result<f64, String> {
    let target = scratch.join("target.o");
    let base = scratch.join("base.o");
    let record = scratch.join("objdiff.json");
    if x86 {
        // As for PowerPC: both sides carry the compiled function's relocations, the retail bytes cleared under them.
        let mask = object::field_mask(function.body.len(), &function.relocations, false);
        let masked: Vec<u8> = (0..function.body.len()).map(|i| retail.get(i).copied().unwrap_or(0) & mask[i]).collect();
        let cleared: Vec<u8> = function.body.iter().zip(&mask).map(|(byte, keep)| byte & keep).collect();
        std::fs::write(&target, object::object_for_objdiff_x86(&masked, &function.relocations, name)).map_err(|e| e.to_string())?;
        std::fs::write(&base, object::object_for_objdiff_x86(&cleared, &function.relocations, name)).map_err(|e| e.to_string())?;
    } else if ppc {
        // The retail object has no relocation records, so its instructions hold final addresses where the
        // compiled ones hold zeros plus a relocation. Both sides get the compiled function's relocations,
        // with the retail bytes cleared under them: the relocated fields compare equal and the rest is the code.
        let mask = object::field_mask(function.body.len(), &function.relocations, true);
        let masked: Vec<u8> = (0..function.body.len()).map(|i| retail.get(i).copied().unwrap_or(0) & mask[i]).collect();
        let cleared: Vec<u8> = function.body.iter().zip(&mask).map(|(byte, keep)| byte & keep).collect();
        std::fs::write(&target, object::object_for_objdiff_ppc(&masked, &function.relocations, name, e_flags)).map_err(|e| e.to_string())?;
        std::fs::write(&base, object::object_for_objdiff_ppc(&cleared, &function.relocations, name, e_flags)).map_err(|e| e.to_string())?;
    } else if let Some(thumb) = arm_thumb {
        // As for PowerPC: both sides carry the compiled function's relocations, the retail bytes cleared under them.
        let mask = object::field_mask(function.body.len(), &function.relocations, false);
        let masked: Vec<u8> = (0..function.body.len()).map(|i| retail.get(i).copied().unwrap_or(0) & mask[i]).collect();
        let cleared: Vec<u8> = function.body.iter().zip(&mask).map(|(byte, keep)| byte & keep).collect();
        std::fs::write(&target, object::object_for_objdiff_arm(&masked, &function.relocations, name, e_flags, thumb)).map_err(|e| e.to_string())?;
        std::fs::write(&base, object::object_for_objdiff_arm(&cleared, &function.relocations, name, e_flags, thumb)).map_err(|e| e.to_string())?;
    } else {
        std::fs::write(&target, object::object_for_objdiff(retail, &[], name, e_flags, big)).map_err(|e| e.to_string())?;
        std::fs::write(&base, object::object_for_objdiff(&function.body, &function.relocations, name, e_flags, big)).map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_file(&record);
    let output = Command::new(objdiff)
        .args(["diff", "-1"])
        .arg(&target)
        .arg("-2")
        .arg(&base)
        .arg(name)
        .args(["--format", "json", "-o"])
        .arg(&record)
        .args(["-c", "functionRelocDiffs=none"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("objdiff-cli: {e}"))?;
    if !output.status.success() {
        return Err(format!("objdiff-cli failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&record).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    json["left"]["symbols"]
        .as_array()
        .and_then(|symbols| symbols.iter().find(|s| s["name"].as_str() == Some(name)))
        .map(|s| s["match_percent"].as_f64().unwrap_or(0.0))
        .ok_or_else(|| "objdiff-cli reported no such symbol".to_string())
}

/// Scores one C text against the retail bytes of a function.
pub fn score_text(project: &MatchProject, text: &str, name: &str, retail: &[u8], scratch: &Path, tag: &str) -> Score {
    let mut score = Score::default();
    let text = if project.msvc { crate::new_project::pe::msvc_dialect(text) } else { text.to_string() };
    let source = format!("{UNIT_PRELUDE}{text}");
    let object_bytes = match project.compile(&source, scratch, tag) {
        Ok(bytes) => bytes,
        Err(error) => {
            score.error = Some(error);
            return score;
        }
    };
    let pe = project.kind == "pe";
    let object = if pe {
        super::pe::CoffObject::parse(&object_bytes).and_then(|o| o.function(name)).map(|f| (0, false, false, None, f))
    } else {
        ElfObject::parse(&object_bytes).and_then(|o| o.function(name).map(|f| (o.e_flags, o.is_big(), o.is_ppc(), o.is_arm().then_some(f.thumb || project.thumb_hint.get() == Some(true)), f)))
    };
    let (e_flags, big, ppc, arm_thumb, mut function) = match object {
        Ok(found) => found,
        Err(error) => {
            score.error = Some(error);
            return score;
        }
    };
    if pe && function.body.len() > retail.len() {
        // A jump table (relocated words) and the alignment after the function are not part of its retail size: they are
        // cut when nothing but relocation fields and padding follows the function's own bytes.
        let mask = object::field_mask(function.body.len(), &function.relocations, false);
        if (retail.len()..function.body.len()).all(|i| mask[i] == 0 || matches!(function.body[i], 0x90 | 0xCC | 0)) {
            function.body.truncate(retail.len());
            function.relocations.retain(|r| r.offset + 4 <= retail.len());
        }
    }
    score.compiled = true;
    score.size = Some(function.body.len());
    let differences = object::compare(&function.body, &function.relocations, retail, big);
    score.byte_diffs = (function.body.len() == retail.len()).then_some(differences);
    score.exact = function.body.len() == retail.len() && differences == 0;
    let mask = object::field_mask(function.body.len(), &function.relocations, big);
    let measure = tag.to_string() + "-objdiff";
    let objdiff_dir = scratch.join(&measure);
    let _ = std::fs::create_dir_all(&objdiff_dir);
    let measured = match &project.objdiff {
        Some(objdiff) => objdiff_percent(objdiff, name, retail, &function, e_flags, big, ppc, arm_thumb, pe, &objdiff_dir),
        None => Err("objdiff-cli not installed (python3 configure.py installs it): percent is the share of equal instruction words".to_string()),
    };
    let _ = std::fs::remove_dir_all(&objdiff_dir);
    match measured {
        Ok(percent) => score.percent = percent,
        Err(note) => {
            score.percent = word_percent(&function.body, &mask, retail);
            score.error = Some(note);
        }
    }
    if score.exact {
        score.percent = 100.0;
    }
    score
}

/// Prints and scores one function of a project.
pub struct ProjectEvaluator<'a> {
    pub core: &'a Core,
    pub project: &'a MatchProject,
    pub function: FunctionRow,
    pub retail: Vec<u8>,
    pub scratch: PathBuf,
    counter: usize,
}

impl<'a> ProjectEvaluator<'a> {
    pub fn new(core: &'a Core, project: &'a MatchProject, function: FunctionRow, scratch: PathBuf) -> Result<Self, String> {
        let retail = project.retail_bytes(function.entry.offset, function.size)?;
        project.thumb_hint.set(project.thumb_at(function.entry.offset));
        std::fs::create_dir_all(&scratch).map_err(|e| format!("{}: {e}", scratch.display()))?;
        Ok(ProjectEvaluator { core, project, function, retail, scratch, counter: 0 })
    }
}

impl Evaluator for ProjectEvaluator<'_> {
    /// The function's C exactly as `new-project --decompile` writes it, under the variant's printing switches.
    fn print(&mut self, variant: &PrintVariant) -> Result<String, String> {
        self.counter += 1;
        let outdir = self.scratch.join(format!("print{}", self.counter));
        let _ = std::fs::remove_dir_all(&outdir);
        let options = M2cOptions { worker_env: variant.env(), ..M2cOptions::default() };
        let result = self
            .core
            .export_m2c(&self.project.orig, &self.project.program, &outdir, None, Some(self.function.entry.offset), &options)
            .map_err(|e| e.to_string());
        let text = result.and_then(|_| {
            let mut files: Vec<PathBuf> = std::fs::read_dir(&outdir)
                .map_err(|e| e.to_string())?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "c"))
                .collect();
            files.sort();
            match files.as_slice() {
                [one] => std::fs::read_to_string(one).map_err(|e| e.to_string()),
                _ => Err(format!("the export wrote {} C files for one function", files.len())),
            }
        });
        let _ = std::fs::remove_dir_all(&outdir);
        text
    }

    fn score(&mut self, text: &str) -> Score {
        self.counter += 1;
        let tag = format!("score{}", self.counter);
        score_text(self.project, text, &self.function.name, &self.retail, &self.scratch, &tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splat_entries_are_found_by_file_offset() {
        let yaml = "segments:\n  - [0x1000, databin, header]\n  - [0xf2c78, asm, main/0145/FUN_001f1c78]\n  - [0xf2cc4, c, main/0145_2/FUN_001f1cc4]\n";
        assert_eq!(unit_in_yaml(yaml, 0xf2c78), Some(("main/0145/FUN_001f1c78".to_string(), false)));
        assert_eq!(unit_in_yaml(yaml, 0xf2cc4), Some(("main/0145_2/FUN_001f1cc4".to_string(), true)));
        assert_eq!(unit_in_yaml(yaml, 0x1000), None);
    }

    #[test]
    fn dtk_units_come_from_splits_and_sources_from_objects_json() {
        let dir = std::env::temp_dir().join(format!("romwright-gc-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let files = (dir.join("symbols.txt"), dir.join("splits.txt"), dir.join("objects.json"));
        std::fs::write(&files.0, "FUN_80003154 = .text:0x80003154; // type:function size:0x20 scope:global\nFUN_80003200 = .text:0x80003200; // type:function size:0x10\n").unwrap();
        std::fs::write(
            &files.1,
            "Sections:\n\t.text       type:code align:4\n\nmain/FUN_80003200.c:\n\t.text       start:0x80003200 end:0x80003210\n\t.data       start:0x80400000 end:0x80400010\n",
        )
        .unwrap();
        std::fs::write(&files.2, "{\"objects\": {\"main/FUN_80003200.c\": {\"source\": \"src/main/FUN_80003200.c\", \"matching\": false}}}").unwrap();
        // A function with no unit yet is named after itself (the file `configure.py swap` creates).
        assert_eq!(gc_unit_of(&files, 0x8000_3154).unwrap(), ("main/FUN_80003154.c".to_string(), None));
        // A unit that holds it, with its source from objects.json.
        assert_eq!(
            gc_unit_of(&files, 0x8000_3200).unwrap(),
            ("main/FUN_80003200.c".to_string(), Some("src/main/FUN_80003200.c".to_string()))
        );
        assert_eq!(gc_function_name(&files, 0x8000_3154).unwrap(), "FUN_80003154");
        assert!(gc_function_name(&files, 0x8000_3999).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn word_percent_counts_equal_instruction_words() {
        let retail = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let body = [1u8, 2, 3, 4, 9, 9, 9, 9];
        assert_eq!(word_percent(&body, &[0xFF; 8], &retail), 50.0);
        // The second word differs only inside a masked field.
        assert_eq!(word_percent(&body, &[0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0], &retail), 100.0);
        assert_eq!(word_percent(&[], &[], &[]), 100.0);
    }
}
