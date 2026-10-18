//! Non-matching scaffold for the platforms with no byte-matching ecosystem:
//! Nintendo 3DS, Switch, PlayStation 3, PlayStation 4, PS Vita and Xbox 360.
//!
//! There is no build that reproduces the retail bytes, so the scaffold holds
//! what romwright knows and a way to look at it: symbol files, the segment and
//! section map with load addresses and image hashes, recovered prototypes and
//! types, romwright's decompiled C one function per file (marked
//! `NON_MATCHING`), a build that only proves the C compiles (pinned clang; it
//! has a backend for all six CPUs), and, for the CPUs objdiff understands, an
//! `objdiff.json` pairing each function's retail bytes (wrapped as a target
//! object, `scaffold_obj`) with the project's compiled C. PowerPC has no
//! objdiff backend: its target objects are written for `export-scratch` and
//! romwright's matching workspaces instead.
//!
//! Like the PS2 plugin this is a pure function from facts to files; the CLI
//! gathers the facts (`Core::scaffold_facts`), decompiles, and writes the files.
//! Keys never appear here: the container loaders take the user's keys on the
//! command line and the scaffold records image hashes only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

use serde_json::json;

use super::manifest::Manifest;
use super::scaffold_obj::{self, Arch, Transfer};
use super::GeneratedFile;
use crate::export::ExportFacts;
use crate::{Core, Result};

/// The pinned compiler every scaffold compiles with unless a retail compiler
/// is chosen (`toolchains.json`).
pub const CLANG_ID: &str = "clang-22.1.8";
const OBJDIFF_ID: &str = "objdiff-cli";
const WIBO_ID: &str = "wibo";
const MAX_FUNCTION_BYTES: u64 = 1 << 20;
/// Every armcc unit's flags: decomp.me's n3ds command line (ARM11 MPCore,
/// fast VFP, ARM/Thumb interworking) and C99 for the decompiler's C.
const ARMCC_BASE_FLAGS: &[&str] = &["--cpu=MPCore", "--fpmode=fast", "--apcs=/interwork", "--c99"];
/// armcc's own optimisation defaults, written out so `config/project.json` says them.
const ARMCC_DEFAULT_OPT: &[&str] = &["-O2", "-Ospace"];

/// One platform's build target.
pub struct Target {
    pub id: &'static str,
    pub name: &'static str,
    pub arch: Arch,
    /// clang `--target=`.
    pub triple: &'static str,
    pub cflags: &'static [&'static str],
    /// Ghidra language prefixes of the programs this platform builds from;
    /// others in the same container (PS3 SPU images) keep config only.
    pub languages: &'static [&'static str],
    pub data_model: &'static str,
    /// objdiff has a backend for the CPU.
    pub objdiff: bool,
    /// Why not, when it has none (shown in the README and `--list-platforms`).
    pub no_objdiff: &'static str,
    pub why_not_matching: &'static str,
    pub notes: &'static str,
    pub keys: &'static str,
    /// ARM build attributes the target objects carry (`Tag_CPU_name`,
    /// `Tag_CPU_arch`, `Tag_FP_arch`), so a disassembler decodes the retail
    /// bytes for the same architecture as the compiler's objects.
    pub arm_cpu: Option<(&'static str, u8, u8)>,
}

macro_rules! cflags {
    ($($extra:literal),*) => {
        &[
            "-std=gnu17", "-ffreestanding", "-nostdlibinc", "-fno-builtin", "-fno-pic", "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables", "-O2", "-w", "-Wno-implicit-function-declaration", "-Wno-int-conversion",
            "-Wno-incompatible-pointer-types", $($extra),*
        ]
    };
}

pub const TARGETS: &[Target] = &[
    Target {
        id: "3ds",
        name: "Nintendo 3DS",
        arch: Arch::Arm32,
        triple: "armv6k-none-eabi",
        cflags: cflags!["-marm", "-mfloat-abi=hard", "-mfpu=vfpv2"],
        languages: &["ARM:"],
        data_model: "ILP32 (ARM11 MPCore, ARMv6K, VFPv2)",
        objdiff: true,
        no_objdiff: "",
        why_not_matching: "no linker or C runtime ships with the public armcc builds, so no build relinks the retail `.code`",
        notes: "romwright reads NCCH, NCSD and CIA containers (cleartext, or a title whose NCCH uses the documented all-zero fixed key). \
A flat ExeFS `.code` is imported with `--raw 0x100000 --language ARM:LE:32:v6`, which carries no section table: the scaffold then has one region. \
Code mixes ARM and Thumb: every function carries `mode:arm` or `mode:thumb` in the symbol file (the mode the analysis decoded it in), its target object has the matching mapping symbol, and `build.py` compiles its unit in that mode (`--arm`/`--thumb` with armcc, `-marm`/`-mthumb` with clang). \
Nintendo's retail compiler is ARM's armcc (RVCT 4.0/4.1, ARM Compiler 5): `romwright-cli new-project --compiler armcc-4.1-b713` (any `armcc-*` build in romwright's tool manifest) builds every unit with it, and `--cflags \"-O3 -Otime\"` replaces its optimisation flags. Without `--compiler` the units only get clang's compile check.",
        keys: "A retail title encrypted with console-provisioned keys (bootrom slots, the CIA common key, ticket title keys) has to be decrypted by you first, or its keys passed to `romwright-cli new-project --keys FILE`; they are used in memory and never written into this repository.",
        arm_cpu: Some(("MPCore", 9, 2)),
    },
    Target {
        id: "switch",
        name: "Nintendo Switch",
        arch: Arch::Aarch64,
        triple: "aarch64-none-elf",
        cflags: cflags!["-mcpu=cortex-a57"],
        languages: &["AARCH64:"],
        data_model: "LP64 (AArch64)",
        objdiff: true,
        no_objdiff: "",
        why_not_matching: "retail NSOs are built with Nintendo's clang fork and link-time optimisation, which no public build reproduces",
        notes: "A container of several NSOs (`main`, `subsdk0`, `rtld`, ...) becomes one module each: its own `config/<module>/symbols.txt`, its own section map and load address, and, where the file is an NSO, its build id in `config/modules.json`. \
An NSO is an in-memory image whose module name and symbols come from its own `MOD0` dynamic table.",
        keys: "NCA and XCI content is decrypted with the user's `prod.keys` (`romwright-cli new-project --keys prod.keys`); keys are used in memory and never written into this repository.",
        arm_cpu: None,
    },
    Target {
        id: "ps3",
        name: "PlayStation 3",
        arch: Arch::Ppc64,
        triple: "powerpc-unknown-none-eabi",
        cflags: cflags!["-maltivec", "-mcpu=970"],
        languages: &["PowerPC:"],
        data_model: "ILP32 pointers with 64-bit registers (PPU)",
        objdiff: false,
        no_objdiff: "objdiff has no PowerPC64 backend",
        why_not_matching: "SNC/GCC PPU output in SELF containers has no public matching toolchain, and objdiff has no PowerPC64 backend",
        notes: "The PPU image is the module. The compile check uses clang's 32-bit PowerPC target because the PS3 ABI is a 64-bit ELF with a 32-bit data model: it checks the C, not the PS3 ABI. \
Target objects are written to `orig/target/` for `romwright-cli export-scratch --target-object` and romwright's matching workspaces; there is no objdiff.json. \
SPU images in the same container are listed in `config/modules.json` with their symbols and section map but have no C (the decompiler's SPU output is not part of this scaffold).",
        keys: "An encrypted SELF/EBOOT.BIN is decrypted with the user's RAP/klic (`--keys FILE`) or by an external tool first; keys are used in memory and never written into this repository.",
        arm_cpu: None,
    },
    Target {
        id: "ps4",
        name: "PlayStation 4",
        arch: Arch::X86_64,
        triple: "x86_64-unknown-none-elf",
        cflags: cflags!["-march=btver2"],
        languages: &["x86:LE:64"],
        data_model: "LP64 (x86-64 System V)",
        objdiff: true,
        no_objdiff: "",
        why_not_matching: "clang x86-64 output from console SDK builds is not reproducible without the exact SDK and flags",
        notes: "romwright imports the decrypted ELF. Unpacking a SELF needs the console's firmware keys, which are the user's; the scaffold records the image sha256 only. \
Direct `call`/`jmp` rel32 instructions are turned into `R_X86_64_PLT32` relocations in the target objects; RIP-relative data operands are left as retail bytes and show as differences in objdiff.",
        keys: "romwright never decrypts a PS4 SELF and stores no key material.",
        arm_cpu: None,
    },
    Target {
        id: "vita",
        name: "PlayStation Vita",
        arch: Arch::Arm32,
        triple: "armv7a-none-eabi",
        cflags: cflags!["-mthumb", "-mcpu=cortex-a9", "-mfpu=neon", "-mfloat-abi=hard"],
        languages: &["ARM:"],
        data_model: "ILP32 (Cortex-A9, Thumb-2)",
        objdiff: false,
        no_objdiff: "objdiff-cli 3.6.1 rejects ARMv7 objects (`ARM arch ARMv7 not supported`)",
        why_not_matching: "Vita builds (SNC, GCC and clang, depending on the studio) link against Sony's SDK libraries and are not reproducible without them",
        notes: "Import names come from the SELF's module info: NIDs are resolved to library function names where romwright's NID table knows them and listed as `type:import` rows in the symbol file. \
A linker BINMAP, when you have one, is passed to `new-project` with `--map` and names the rest. \
Every function carries `mode:arm` or `mode:thumb` in the symbol file and `build.py` compiles its unit in that mode (`-marm`/`-mthumb`).",
        keys: "An NPDRM SELF needs the title's klic (`--keys FILE`); it is used in memory and never written into this repository.",
        arm_cpu: None,
    },
    Target {
        id: "x360",
        name: "Xbox 360",
        arch: Arch::Ppc32,
        triple: "powerpc-unknown-none-eabi",
        cflags: cflags!["-maltivec", "-mcpu=970"],
        languages: &["PowerPC:"],
        data_model: "ILP32 (Xenon, 32-bit addresses)",
        objdiff: false,
        no_objdiff: "objdiff has no PowerPC64 backend",
        why_not_matching: "MSVC PowerPC output in XEX2 containers has no public matching toolchain, and objdiff has no PowerPC64 backend",
        notes: "romwright imports the PE inside a XEX2 (or a bare PE). Target objects are written to `orig/target/` for `romwright-cli export-scratch --target-object` and romwright's matching workspaces; there is no objdiff.json. \
VMX128 instructions are not expressed as intrinsics: the C that uses them says so with `irregular` comments.",
        keys: "XEX2 decryption and decompression use the user's keys (`--keys FILE`) or an already extracted PE; keys are used in memory and never written into this repository.",
        arm_cpu: None,
    },
];

pub fn target(id: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|t| t.id == id)
}

/// The compiler a scaffold builds its units with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldCompiler {
    /// Manifest id.
    pub tool: String,
    /// `clang` (a compile check only) or `armcc` (the retail compiler: every
    /// unit compares with its function byte for byte).
    pub family: &'static str,
    /// Every flag but the per-unit mode and the paths.
    pub flags: Vec<String>,
}

impl ScaffoldCompiler {
    /// Whether the units are built with the retail compiler.
    pub fn retail(&self) -> bool {
        self.family == "armcc"
    }
}

/// The compiler of a scaffold: `--compiler` (an armcc build of the target's
/// platform from the manifest) with `--cflags` as its optimisation flags, or
/// the clang compile check with the target's fixed flags.
pub fn compiler_for(
    target: &Target,
    requested: Option<&str>,
    opt: Option<Vec<String>>,
    manifest: &Manifest,
) -> std::result::Result<ScaffoldCompiler, String> {
    let retail: Vec<&str> = manifest
        .tools
        .iter()
        .filter(|t| t.family.as_deref() == Some("armcc") && t.platform == target.id)
        .map(|t| t.id.as_str())
        .collect();
    let Some(id) = requested.filter(|id| *id != CLANG_ID) else {
        if opt.is_some() {
            return Err(format!(
                "--cflags sets a retail compiler's optimisation flags; {CLANG_ID}'s are fixed (pick one with --compiler: {})",
                if retail.is_empty() { "none for this platform".to_string() } else { retail.join(", ") }
            ));
        }
        return Ok(ScaffoldCompiler {
            tool: CLANG_ID.to_string(),
            family: "clang",
            flags: target.cflags.iter().map(|f| f.to_string()).collect(),
        });
    };
    if !retail.contains(&id) {
        return Err(format!(
            "--compiler {id}: the {} scaffold builds with {CLANG_ID} or one of its retail compilers ({})",
            target.name,
            if retail.is_empty() { "none pinned".to_string() } else { retail.join(", ") }
        ));
    }
    let mut flags: Vec<String> = ARMCC_BASE_FLAGS.iter().map(|f| f.to_string()).collect();
    flags.extend(opt.unwrap_or_else(|| ARMCC_DEFAULT_OPT.iter().map(|f| f.to_string()).collect()));
    Ok(ScaffoldCompiler { tool: id.to_string(), family: "armcc", flags })
}

/// Recognises the containers romwright imports for these six platforms from
/// their magic and header alone. `None` when the bytes say nothing certain (a
/// raw dump, an ARM ELF that is not a Sony module): pass `--platform`.
pub fn detect_platform(data: &[u8]) -> Option<&'static str> {
    let at = |offset: usize, magic: &[u8]| data.get(offset..offset + magic.len()) == Some(magic);
    if at(0x100, b"NCCH") || at(0x100, b"NCSD") || super::scaffold::is_cia(data) {
        return Some("3ds");
    }
    if at(0, b"NSO0") || at(0x10, b"NRO0") || at(0x200, b"NCA3") || at(0x200, b"NCA2") || at(0x100, b"HEAD") {
        return Some("switch");
    }
    if at(0, b"XEX2") || at(0, b"XEX1") {
        return Some("x360");
    }
    if at(0, b"SCE\0") {
        return Some(if crate::native::vita::is_self(data) { "vita" } else { "ps3" });
    }
    if data.len() > 20 && at(0, b"\x7fELF") && data[5] == 1 {
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        return match u16::from_le_bytes([data[18], data[19]]) {
            183 => Some("switch"),
            62 if data[7] == 9 => Some("ps4"),
            40 if e_type >= 0xFE00 => Some("vita"),
            _ => None,
        };
    }
    if data.len() > 20 && at(0, b"\x7fELF") && data[5] == 2 && u16::from_be_bytes([data[18], data[19]]) == 21 {
        return Some("ps3");
    }
    if at(0, b"MZ") {
        let pe = data.get(0x3c..0x40).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
        // IMAGE_FILE_MACHINE_POWERPCBE: an Xbox 360 executable.
        if let Some(pe) = pe
            && data.get(pe..pe + 4) == Some(b"PE\0\0") && data.get(pe + 4..pe + 6) == Some(&[0xF2, 0x01]) {
                return Some("x360");
            }
    }
    None
}

fn is_cia(data: &[u8]) -> bool {
    data.len() >= 0x10 && data[0..4] == [0x20, 0x20, 0x00, 0x00] && data[4..8] == [0x00, 0x00, 0x01, 0x00]
}

// ---------------------------------------------------------------------------
// Facts the CLI gathers from the store.
// ---------------------------------------------------------------------------

/// Everything the plugin reads from one imported program.
#[derive(Debug, Clone, Default)]
pub struct ScaffoldFacts {
    pub facts: ExportFacts,
    /// `(function address, declaration)` recovered by analysis or a fact pack.
    pub prototypes: Vec<(u64, String)>,
    /// `(instruction address, destination, is a call)` for every direct,
    /// non-computed call and jump the analysis recorded.
    pub transfers: Vec<(u64, u64, bool)>,
    /// Function entries in the alternate ARM instruction set (Thumb): decode
    /// contexts, plus the functions A32 cannot hold (unaligned address or size).
    pub thumb: HashSet<u64>,
}

impl Core {
    /// The store's rows for one program, in the shape the scaffold plugin reads.
    pub fn scaffold_facts(&self, program: &str) -> Result<ScaffoldFacts> {
        let id = self.db.program_id(program)?;
        let facts = self.export_facts(program)?;
        let prototypes = self
            .db
            .prototypes(id)?
            .into_iter()
            .map(|row| (row.function.offset, row.signature))
            .collect();
        let transfers = self
            .db
            .xrefs(id)?
            .into_iter()
            .filter(|x| !x.kind.contains("COMPUTED") && (x.kind.contains("CALL") || x.kind == "UNCONDITIONAL_JUMP"))
            .map(|x| (x.from.offset, x.to.offset, x.kind.contains("CALL")))
            .collect();
        // The analysis records the alternate instruction set as a context row at
        // each code address it decoded in it (`TMode` or `LowBitCodeMode` = 1).
        let alternate: HashSet<u64> = self
            .db
            .decode_contexts(id)?
            .into_iter()
            .filter(|(_, name, value)| (name == "TMode" || name == "LowBitCodeMode") && *value != 0)
            .map(|(address, _, _)| address.offset)
            .collect();
        // A32 instructions are whole aligned words: a function whose address or size
        // is not one is Thumb whatever the context rows say (a linker map names
        // functions the analysis never decoded).
        let arm = facts.language.starts_with("ARM:");
        let thumb = facts
            .functions
            .iter()
            .filter(|f| alternate.contains(&f.entry.offset) || (arm && (f.entry.offset % 4 != 0 || f.size % 4 != 0)))
            .map(|f| f.entry.offset)
            .collect();
        Ok(ScaffoldFacts { facts, prototypes, transfers, thumb })
    }
}

// ---------------------------------------------------------------------------
// Inputs and plan
// ---------------------------------------------------------------------------

/// One module of the image: the whole program, or one NSO of a Switch title.
pub struct ModuleInput<'a> {
    pub id: String,
    pub program: String,
    pub facts: &'a ScaffoldFacts,
    /// Retail bytes at an address, from the program's own mapped image.
    pub code: &'a dyn Fn(u64, usize) -> Option<Vec<u8>>,
    /// Build id (Switch NSO), lowercase hex.
    pub build_id: Option<String>,
    /// sha256 of the mapped image, lowercase hex.
    pub mapped_sha256: String,
}

pub struct ScaffoldInputs<'a> {
    pub target: &'static Target,
    pub image_name: &'a str,
    pub project_name: &'a str,
    pub image_sha256: String,
    pub image_size: u64,
    pub modules: Vec<ModuleInput<'a>>,
    pub manifest: &'a Manifest,
    /// What the units are built with (`compiler_for`).
    pub compiler: ScaffoldCompiler,
    /// A toolchain profile (JSON text) written as `config/toolchain.local.json`.
    pub profile: Option<&'a str>,
    pub romwright_version: &'a str,
}

/// One function that has (or may get) a source file.
#[derive(Debug, Clone)]
pub struct Unit {
    pub module: usize,
    pub address: u64,
    pub name: String,
    pub cname: String,
    pub size: u64,
    /// `<module>/<shard>/<stem>`: below `src/`, `build/obj/`, `orig/target/`.
    pub tu: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScaffoldReport {
    pub platform: String,
    pub image_sha256: String,
    pub triple: String,
    pub modules: usize,
    pub buildable_modules: usize,
    pub functions: usize,
    pub sources: usize,
    pub target_objects: usize,
    pub relocated_calls: usize,
    pub objdiff_units: usize,
    pub symbols: usize,
    pub prototypes_emitted: usize,
    pub prototypes_skipped: usize,
}

const C_KEYWORDS: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float",
    "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return", "short", "signed", "sizeof",
    "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "bool", "true",
    "false", "NULL", "main",
];

const TYPE_NAMES: &[&str] = &[
    "s8", "u8", "s16", "u16", "s32", "u32", "s64", "u64", "f32", "f64", "undefined", "undefined1", "undefined2",
    "undefined3", "undefined4", "undefined5", "undefined6", "undefined7", "undefined8", "byte", "word", "dword",
    "qword", "uchar", "ushort", "uint", "ulong", "longlong", "ulonglong", "code", "pointer", "size_t",
];

/// A C identifier for a symbol name: anything else becomes `_` (a map file
/// holds `sut::wcsstr(const` and `.ARM.Collect$$libshutdown$$00000002`).
pub fn c_ident(name: &str, address: u64) -> String {
    let mut out: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        return format!("sub_{address:x}");
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    if out.len() > 200 {
        out.truncate(200);
    }
    out
}

/// Hands out each name once, case-insensitively (file systems fold case).
#[derive(Default)]
pub(super) struct Names(pub(super) HashSet<String>);

impl Names {
    pub(super) fn claim(&mut self, wanted: String, address: u64) -> String {
        let reserved = C_KEYWORDS.contains(&wanted.as_str()) || TYPE_NAMES.contains(&wanted.as_str());
        let name = if reserved { format!("{wanted}_{address:x}") } else { wanted };
        if self.0.insert(name.to_ascii_lowercase()) {
            return name;
        }
        let renamed = format!("{name}_{address:x}");
        self.0.insert(renamed.to_ascii_lowercase());
        renamed
    }
}

/// A file stem short enough for every file system, still unique.
pub(super) fn file_stem(cname: &str, address: u64) -> String {
    if cname.len() <= 80 {
        cname.to_string()
    } else {
        format!("{}_{address:x}", &cname[..60])
    }
}

fn buildable(target: &Target, language: &str) -> bool {
    target.languages.iter().any(|prefix| language.starts_with(prefix))
}

/// The unit of every function of every buildable module: names, paths.
pub fn layout(inputs: &ScaffoldInputs) -> Vec<Unit> {
    let mut units = Vec::new();
    for (index, module) in inputs.modules.iter().enumerate() {
        if !buildable(inputs.target, &module.facts.facts.language) {
            continue;
        }
        let mut names = Names::default();
        let mut functions: Vec<_> = module.facts.facts.functions.iter().collect();
        functions.sort_by_key(|f| f.entry.offset);
        functions.dedup_by_key(|f| f.entry.offset);
        // Symbol names claim first, so the function table and the symbol file
        // agree on every name (`symbols` below repeats this order).
        for function in functions {
            let address = function.entry.offset;
            let cname = names.claim(c_ident(&function.name, address), address);
            let stem = file_stem(&cname, address);
            units.push(Unit {
                module: index,
                address,
                name: function.name.clone(),
                size: function.size,
                tu: format!("{}/{:04x}/{stem}", module.id, address >> 16),
                cname,
            });
        }
    }
    units
}

fn image_regions(facts: &ExportFacts) -> Vec<&romwright_model::MemoryRegion> {
    let mut regions: Vec<_> = facts.regions.iter().filter(|r| r.source == "native-import" && r.size != 0).collect();
    regions.sort_by_key(|r| r.start.offset);
    regions
}

fn escape(name: &str) -> String {
    name.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `name = section:0xADDR; // type:... size:0x..`: functions, labels, imports.
pub(super) fn symbols_text(module: &ModuleInput, units: &[&Unit], arm: bool) -> (String, usize) {
    let facts = &module.facts.facts;
    let regions = image_regions(facts);
    let section_of = |address: u64| {
        regions
            .iter()
            .find(|r| address >= r.start.offset && address < r.start.offset + r.size)
            .map(|r| r.name.as_str())
    };
    let mut text = String::new();
    let _ = writeln!(
        text,
        "# {} (program {}, language {}): name = section:0xADDRESS; // type:function|label|import size:0xN [mode:thumb|arm] [orig:\"name\"]",
        module.id, module.program, facts.language
    );
    let mut count = 0usize;
    let mut taken: HashSet<u64> = HashSet::new();
    let mut names = Names::default();
    for unit in units {
        names.0.insert(unit.cname.to_ascii_lowercase());
    }
    let place = |address: u64| match section_of(address) {
        Some(section) => format!("{}:{address:#x}", section.replace(char::is_whitespace, "_")),
        None => format!("{address:#x}"),
    };
    for unit in units {
        let mut tags = format!("type:function size:{:#x}", unit.size);
        if arm {
            tags.push_str(if module.facts.thumb.contains(&unit.address) { " mode:thumb" } else { " mode:arm" });
        }
        if unit.cname != unit.name {
            let _ = write!(tags, " orig:\"{}\"", escape(&unit.name));
        }
        let _ = writeln!(text, "{} = {}; // {tags}", unit.cname, place(unit.address));
        taken.insert(unit.address);
        count += 1;
    }
    let linkage = |s: &romwright_model::SymbolRow| {
        s.source != crate::native::DEMANGLE_SOURCE && s.source != crate::qualified_prototypes::mangled::DISPLAY_SOURCE
    };
    for symbol in facts.symbols.iter().filter(|s| linkage(s)) {
        let address = symbol.address.offset;
        if !taken.insert(address) && !symbol.external {
            continue;
        }
        let cname = names.claim(c_ident(&symbol.name, address), address);
        let kind = if symbol.external { "import" } else { "label" };
        let mut tags = format!("type:{kind}");
        if cname != symbol.name {
            let _ = write!(tags, " orig:\"{}\"", escape(&symbol.name));
        }
        let _ = writeln!(text, "{cname} = {}; // {tags}", place(address));
        count += 1;
    }
    (text, count)
}

pub(super) const TYPE_WORDS: &[&str] = &[
    "void", "char", "short", "int", "long", "unsigned", "signed", "float", "double", "const", "volatile", "bool", "s8",
    "u8", "s16", "u16", "s32", "u32", "s64", "u64", "f32", "f64", "undefined", "undefined1", "undefined2", "undefined4",
    "undefined8", "byte", "word", "dword", "qword", "uchar", "ushort", "uint", "ulong", "longlong", "ulonglong",
];

pub(super) fn is_ident(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !token.starts_with(|c: char| c.is_ascii_digit())
}

/// `int *foo(char a, ...)` as tokens, keeping `*` and punctuation.
pub(super) fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            word.push(ch);
        } else {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            if !ch.is_whitespace() {
                out.push(ch.to_string());
            }
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// `["unsigned", "char", "*"]` as `unsigned char *`.
pub(super) fn join_type(tokens: &[String]) -> String {
    let mut text = String::new();
    for t in tokens {
        if !text.is_empty() && !text.ends_with('*') {
            text.push(' ');
        }
        text.push_str(t);
    }
    text
}

/// Rewrites a recovered declaration into a prototype made only of the base
/// types (parameter names kept), the function named `name`. `None` when it
/// mentions anything else.
fn clean_prototype(declaration: &str, name: &str) -> Option<String> {
    let declaration = declaration.trim().trim_end_matches(';').trim();
    let open = declaration.find('(')?;
    let close = declaration.rfind(')')?;
    if close < open || !declaration[close + 1..].trim().is_empty() {
        return None;
    }
    let head = tokens(&declaration[..open]);
    let (func, ret) = head.split_last()?;
    if !is_ident(func) || ret.is_empty() {
        return None;
    }
    let allowed = |t: &str| TYPE_WORDS.contains(&t) || t == "*";
    if !ret.iter().all(|t| allowed(t)) {
        return None;
    }
    let mut params = Vec::new();
    let args = declaration[open + 1..close].trim();
    if !args.is_empty() && args != "void" {
        for arg in args.split(',') {
            let toks = tokens(arg);
            if toks.is_empty() {
                return None;
            }
            if toks == ["."; 3] {
                params.push("...".to_string());
                continue;
            }
            let mut ty: &[String] = &toks;
            let mut pname = None;
            if let Some(last) = toks.last()
                && is_ident(last) && !TYPE_WORDS.contains(&last.as_str()) && toks.len() >= 2 {
                    pname = Some(last.as_str());
                    ty = &toks[..toks.len() - 1];
                }
            if ty.is_empty() || !ty.iter().all(|t| allowed(t)) {
                return None;
            }
            let mut text = join_type(ty);
            if let Some(n) = pname {
                if !text.ends_with('*') {
                    text.push(' ');
                }
                text.push_str(n);
            }
            params.push(text);
        }
    }
    let mut ret_text = join_type(ret);
    if !ret_text.ends_with('*') {
        ret_text.push(' ');
    }
    let params = if params.is_empty() { "void".to_string() } else { params.join(", ") };
    Some(format!("{ret_text}{name}({params});"))
}

const TYPES_H: &str = "\
/* Generated by romwright new-project: base types for decompiled C. The widths of `long` and
   pointers follow the compile target (see config/project.json), as the decompiler's do. */
#ifndef ROMWRIGHT_TYPES_H
#define ROMWRIGHT_TYPES_H

typedef signed char s8;
typedef unsigned char u8;
typedef short s16;
typedef unsigned short u16;
typedef int s32;
typedef unsigned int u32;
typedef long long s64;
typedef unsigned long long u64;
typedef float f32;
typedef double f64;

/* The primitive names the decompiler's output uses. */
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned char undefined3[3];
typedef unsigned int undefined4;
typedef unsigned char undefined5[5];
typedef unsigned char undefined6[6];
typedef unsigned char undefined7[7];
typedef unsigned long long undefined8;
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned long long qword;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef void *pointer;
typedef void code(void);
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
typedef _Bool bool;
#endif

#endif
";

pub(super) fn protos_header(entries: &[(String, String)], skipped: usize, module: &str) -> String {
    let mut h = format!(
        "/* Generated by romwright new-project: prototypes recovered for module {module} (analysis, and the fact pack when one was present).\n   Only declarations made of the base types in romwright_types.h are kept; {skipped} were left out because they name other types. */\n"
    );
    let guard: String = module.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect();
    let _ = write!(h, "#ifndef ROMWRIGHT_PROTOS_{guard}_H\n#define ROMWRIGHT_PROTOS_{guard}_H\n\n#include \"romwright_types.h\"\n\n");
    for (name, proto) in entries {
        let _ = writeln!(h, "/* {name} */ {proto}");
    }
    h.push_str("\n#endif\n");
    h
}

pub(super) fn template(path: &str, text: &str, executable: bool) -> GeneratedFile {
    GeneratedFile { path: path.to_string(), bytes: text.as_bytes().to_vec(), executable }
}

pub(super) fn render(template_text: &str, vars: &[(&str, String)]) -> String {
    let mut text = template_text.to_string();
    for (key, value) in vars {
        text = text.replace(&format!("{{{{{key}}}}}"), value);
    }
    text
}

/// A source file: the NON_MATCHING marker, the shared types, the decompiled body.
fn source_text(inputs: &ScaffoldInputs, unit: &Unit, body: &str) -> String {
    let module = &inputs.modules[unit.module];
    let mut body = body.to_string();
    if unit.cname != unit.name && !unit.name.is_empty() {
        body = body.replace(&unit.name, &unit.cname);
    }
    let check = if inputs.compiler.retail() {
        "build.py compiles it with the retail compiler and objdiff compares it with the retail bytes: remove this marker once it matches."
    } else {
        "It reads the retail function; it does not reproduce its bytes. build.py only checks that it compiles."
    };
    format!(
        "/* NON_MATCHING: romwright {} decompilation of `{}` ({} @ {:#x}, {:#x} bytes) from {}.\n * {check} */\n#include \"romwright_types.h\"\n\n{}\n",
        inputs.romwright_version,
        unit.cname,
        module.id,
        unit.address,
        unit.size,
        inputs.image_name,
        body.trim_end()
    )
}

/// The files of the scaffold. `sources` maps a unit's `tu` to the decompiled
/// C text romwright wrote for it; units without text get no file, no object
/// and no objdiff row.
pub fn plan(
    inputs: &ScaffoldInputs,
    units: &[Unit],
    sources: &HashMap<String, String>,
) -> std::result::Result<(Vec<GeneratedFile>, ScaffoldReport), String> {
    let target = inputs.target;
    let compiler = &inputs.compiler;
    let mut ids = vec![compiler.tool.as_str()];
    if compiler.retail() {
        // armcc is a Windows executable: wibo runs it on the other hosts.
        ids.push(WIBO_ID);
    }
    if target.objdiff {
        ids.push(OBJDIFF_ID);
    }
    let subset = inputs.manifest.subset(&ids)?;
    let arm = target.arch == Arch::Arm32;

    let mut files: Vec<GeneratedFile> = Vec::new();
    let mut module_rows = Vec::new();
    let mut symbol_count = 0usize;
    let (mut protos_ok, mut protos_skipped) = (0usize, 0usize);
    let multi = inputs.modules.len() > 1;
    let mut header_includes = Vec::new();

    for (index, module) in inputs.modules.iter().enumerate() {
        let module_units: Vec<&Unit> = units.iter().filter(|u| u.module == index).collect();
        let (symbols, count) = symbols_text(module, &module_units, arm);
        let path = if multi { format!("config/{}/symbols.txt", module.id) } else { "config/symbols.txt".to_string() };
        files.push(template(&path, &symbols, false));
        symbol_count += count;

        // Prototypes whose types the base header defines.
        let by_address: HashMap<u64, &Unit> = module_units.iter().map(|u| (u.address, *u)).collect();
        let mut entries: BTreeMap<u64, (String, String)> = BTreeMap::new();
        let mut skipped = 0usize;
        for (address, declaration) in &module.facts.prototypes {
            let Some(unit) = by_address.get(address) else { continue };
            match clean_prototype(declaration, &unit.cname) {
                Some(text) => {
                    entries.insert(*address, (unit.cname.clone(), text));
                }
                None => skipped += 1,
            }
        }
        protos_ok += entries.len();
        protos_skipped += skipped;
        let entries: Vec<_> = entries.into_values().collect();
        files.push(template(&format!("include/protos_{}.h", module.id), &protos_header(&entries, skipped, &module.id), false));
        header_includes.push(format!("#include \"protos_{}.h\"", module.id));

        let sections: Vec<_> = image_regions(&module.facts.facts)
            .iter()
            .map(|r| json!({"name": r.name, "start": format!("{:#x}", r.start.offset), "size": format!("{:#x}", r.size), "permissions": r.permissions}))
            .collect();
        module_rows.push(json!({
            "id": module.id,
            "program": module.program,
            "language": module.facts.facts.language,
            "compiler": module.facts.facts.compiler,
            "buildable": buildable(target, &module.facts.facts.language),
            "mapped_sha256": module.mapped_sha256,
            "build_id": module.build_id,
            "functions": module.facts.facts.functions.len(),
            "symbols": if multi { format!("config/{}/symbols.txt", module.id) } else { "config/symbols.txt".to_string() },
            "sections": sections,
        }));
    }
    files.push(template(
        "include/romwright_protos.h",
        &format!(
            "/* Generated by romwright new-project: every module's recovered prototypes. */\n#ifndef ROMWRIGHT_PROTOS_H\n#define ROMWRIGHT_PROTOS_H\n\n{}\n\n#endif\n",
            header_includes.join("\n")
        ),
        false,
    ));
    files.push(template("include/romwright_types.h", TYPES_H, false));

    // Sources, target objects, objdiff rows.
    let mut unit_rows = Vec::new();
    let mut objdiff_rows = Vec::new();
    let mut categories: BTreeMap<String, String> = BTreeMap::new();
    let (mut sources_written, mut targets_written, mut relocated) = (0usize, 0usize, 0usize);
    // Per module: function extents and names for the call relocations, and
    // the non-executable regions a literal-pool address names as data.
    struct Prepared<'a> {
        names: HashMap<u64, &'a str>,
        transfers: Vec<(u64, u64, bool)>,
        data: Vec<(u64, u64)>,
        /// Function entries in address order: where a function's pool must end.
        starts: Vec<u64>,
    }
    let mut prepared: HashMap<usize, Prepared> = HashMap::new();
    for unit in units {
        let Some(body) = sources.get(&unit.tu) else { continue };
        let module = &inputs.modules[unit.module];
        files.push(template(&format!("src/{}.c", unit.tu), &source_text(inputs, unit, body), false));
        sources_written += 1;
        let thumb = arm && module.facts.thumb.contains(&unit.address);
        let mut row = json!({
            "function": unit.cname,
            "module": module.id,
            "address": format!("{:#x}", unit.address),
            "size": unit.size,
            "source": format!("src/{}.c", unit.tu),
            "object": format!("build/obj/{}.o", unit.tu),
        });

        let prepared = prepared.entry(unit.module).or_insert_with(|| {
            let names = units.iter().filter(|u| u.module == unit.module).map(|u| (u.address, u.cname.as_str())).collect();
            let mut transfers = module.facts.transfers.clone();
            transfers.sort_unstable();
            let data = image_regions(&module.facts.facts)
                .into_iter()
                .filter(|r| !r.permissions.contains('x'))
                .map(|r| (r.start.offset, r.start.offset + r.size))
                .collect();
            let mut starts: Vec<u64> = units.iter().filter(|u| u.module == unit.module).map(|u| u.address).collect();
            starts.sort_unstable();
            Prepared { names, transfers, data, starts }
        });
        if unit.size > 0 && unit.size <= MAX_FUNCTION_BYTES
            && let Some(mut bytes) = (module.code)(unit.address, unit.size as usize) {
                let (lo, hi) = (unit.address, unit.address + unit.size);
                let first = prepared.transfers.partition_point(|t| t.0 < lo);
                let mut found: Vec<Transfer> = Vec::new();
                for &(from, to, call) in prepared.transfers[first..].iter().take_while(|t| t.0 < hi) {
                    let Some(name) = prepared.names.get(&to) else { continue };
                    // A branch back to the function's own entry is a loop, not a call.
                    if to == unit.address && !call {
                        continue;
                    }
                    // A jump inside the function is control flow.
                    if !call && to >= lo && to < hi {
                        continue;
                    }
                    found.push(Transfer { from, to, name });
                }
                if arm {
                    // A trailing partial instruction (a size the map file gave to code
                    // plus a pool byte) cannot be disassembled: objdiff panics on it.
                    let word = if thumb { 2 } else { 4 };
                    bytes.truncate(bytes.len() / word * word);
                    if bytes.is_empty() {
                        unit_rows.push(row);
                        continue;
                    }
                }
                let mut relocs = Vec::new();
                let mut pools = scaffold_obj::LiteralPools::default();
                if arm {
                    pools = scaffold_obj::arm_literal_pools(&bytes, thumb);
                    // The analysis sizes a function to its last instruction; the pool
                    // its loads read follows it, and belongs to it in the compiler's
                    // object. Take it in when it ends before the next function.
                    let next = prepared.starts.get(prepared.starts.partition_point(|&s| s <= unit.address)).copied();
                    if pools.end > bytes.len() as u64
                        && next.is_none_or(|next| unit.address + pools.end <= next)
                        && let Some(longer) = (module.code)(unit.address, pools.end as usize)
                    {
                        bytes = longer;
                        pools = scaffold_obj::arm_literal_pools(&bytes, thumb);
                    }
                    // Every direct branch to another known function, recorded or
                    // not: a tail call (`B`) is a relocation in the compiler's
                    // object too.
                    for (from, to) in scaffold_obj::arm_direct_branches(unit.address, &bytes, thumb, &pools) {
                        if (to >= lo && to < hi) || found.iter().any(|t| t.from == from) {
                            continue;
                        }
                        if let Some(name) = prepared.names.get(&to) {
                            found.push(Transfer { from, to, name });
                        }
                    }
                    let resolve = |value: u32| -> Option<String> {
                        let value = value as u64;
                        let function = if value & 1 == 1 && module.facts.thumb.contains(&(value & !1)) { value & !1 } else { value };
                        if let Some(name) = prepared.names.get(&function) {
                            return Some(name.to_string());
                        }
                        prepared.data.iter().any(|&(start, end)| value >= start && value < end).then(|| format!("DAT_{value:08x}"))
                    };
                    relocs = scaffold_obj::relocate_pool_words(&mut bytes, &pools, resolve);
                }
                relocs.extend(scaffold_obj::relocate_transfers(target.arch, unit.address, &mut bytes, thumb, &found));
                relocs.sort_by_key(|r| r.offset);
                relocated += relocs.len();
                let attributes = target.arm_cpu.map(|(cpu, arch, fp)| scaffold_obj::arm_attributes(cpu, arch, fp)).unwrap_or_default();
                let object = scaffold_obj::build_object(target.arch, &unit.cname, &bytes, thumb, &relocs, &pools.ranges, &attributes);
                files.push(GeneratedFile { path: format!("orig/target/{}.o", unit.tu), bytes: object, executable: false });
                targets_written += 1;
                row["target"] = json!(format!("orig/target/{}.o", unit.tu));
                if target.objdiff {
                    categories.entry(module.id.clone()).or_insert_with(|| module.id.clone());
                    objdiff_rows.push(json!({
                        "name": format!("{}/{:04x}/{}", module.id, unit.address >> 16, unit.cname),
                        "target_path": format!("orig/target/{}.o", unit.tu),
                        "base_path": format!("build/obj/{}.o", unit.tu),
                        "metadata": {
                            "complete": false,
                            "auto_generated": false,
                            "source_path": format!("src/{}.c", unit.tu),
                            "progress_categories": [module.id],
                            "functions": [{"name": unit.cname, "vram": format!("{:#x}", unit.address), "size": unit.size}],
                        },
                    }));
                }
            }
        if arm {
            row["thumb"] = json!(thumb);
        }
        unit_rows.push(row);
    }

    let objdiff_units = objdiff_rows.len();
    if target.objdiff && objdiff_units > 0 {
        let document = json!({
            "min_version": "2.0.0-beta.5",
            "custom_make": "python3",
            "custom_args": ["build.py"],
            "build_target": false,
            "build_base": true,
            "watch_patterns": ["src/**/*.c", "include/**/*.h"],
            "units": objdiff_rows,
            "progress_categories": categories.iter().map(|(id, name)| json!({"id": id, "name": name})).collect::<Vec<_>>(),
        });
        files.push(template("objdiff.json", &(serde_json::to_string_pretty(&document).map_err(|e| e.to_string())? + "\n"), false));
    }

    let compiler_json = if compiler.retail() {
        json!({
            "tool": compiler.tool,
            "family": compiler.family,
            "cflags": compiler.flags,
            "modes": {"arm": "--arm", "thumb": "--thumb"},
            "arch": target.arch,
            "data_model": target.data_model,
        })
    } else {
        json!({
            "tool": compiler.tool,
            "family": compiler.family,
            "target": target.triple,
            "cflags": compiler.flags,
            "modes": {"arm": "-marm", "thumb": "-mthumb"},
            "arch": target.arch,
            "data_model": target.data_model,
        })
    };
    let kind = if compiler.retail() { "per-function-matching" } else { "non-matching-scaffold" };
    let project = json!({
        "romwright": {"version": inputs.romwright_version, "schema": 1, "platform": target.id, "kind": kind},
        "name": inputs.project_name,
        "image": {"file": inputs.image_name, "orig": format!("orig/{}", inputs.image_name), "sha256": inputs.image_sha256, "size": inputs.image_size},
        "compiler": compiler_json,
        "objdiff": target.objdiff && objdiff_units > 0,
        "units": unit_rows,
    });
    let modules_json = json!({
        "schema": 1,
        "platform": target.id,
        "image": {"file": inputs.image_name, "sha256": inputs.image_sha256, "size": inputs.image_size},
        "modules": module_rows,
    });
    files.push(template("config/project.json", &(serde_json::to_string_pretty(&project).map_err(|e| e.to_string())? + "\n"), false));
    files.push(template("config/modules.json", &(serde_json::to_string_pretty(&modules_json).map_err(|e| e.to_string())? + "\n"), false));
    files.push(template("config/toolchain.json", &(serde_json::to_string_pretty(&subset).map_err(|e| e.to_string())? + "\n"), false));
    if let Some(profile) = inputs.profile {
        files.push(template("config/toolchain.local.json", profile, false));
    }

    let operands = if arm {
        "Direct calls and branches to other known functions (tail calls included) are rewritten into the relocations a compiler would emit. Literal pools are marked as data, and a pool word that holds an address is an `R_ARM_ABS32` to that function or to `DAT_<address>` (8 lowercase hex digits): declare the global under that name (`extern int DAT_00412345;`) and the operand matches. Other pool words are constants."
    } else {
        "Direct calls and branches to other known functions are rewritten into the relocations a compiler would emit (only when the instruction decodes to exactly the target romwright recorded); data operands are not, so literal-pool and RIP-relative operands show as differences."
    };
    let verdict = if compiler.retail() {
        "The base side is the retail compiler's output, so 100% is reachable: a unit at 100% matches its retail function, and its `NON_MATCHING` marker can go."
    } else {
        "A decompilation this far from the original compiler's output will rarely reach 100%: objdiff is a way to compare, not a pass/fail gate."
    };
    let (objdiff_line, objdiff_quickstart, target_note) = if target.objdiff {
        (
            "* `objdiff.json` and `orig/target/`: each decompiled function's retail bytes as a relocatable target object, paired with `build/obj/` (what `build.py` compiles from `src/`).".to_string(),
            "python3 build.py report     # objdiff-cli report over objdiff.json -> build/report.json\n# or open this directory in the objdiff GUI\n".to_string(),
            format!("**Reading objdiff here.** The retail side of each unit is one function cut out of a linked image. {operands} {verdict}"),
        )
    } else {
        (
            format!("* `orig/target/`: each decompiled function's retail bytes as a relocatable target object. There is no `objdiff.json` ({}); these objects are inputs for `romwright-cli export-scratch --target-object` and romwright's matching workspaces.", target.no_objdiff),
            format!("# No objdiff.json ({}): compare one function at a time, e.g.\n#   romwright-cli export-scratch <program> 0xADDR orig/<image> --compiler ID --c-flags FLAGS --target-object orig/target/<module>/<shard>/<function>.o\n", target.no_objdiff),
            format!("**Verification here.** There is no objdiff.json ({}): compare a function with romwright's matching workspace (`romwright-cli match`, `export-scratch`) using the target object under `orig/target/`. Direct calls and branches to other known functions are already relocations in that object.", target.no_objdiff),
        )
    };
    let flags = compiler.flags.join(" ");
    let tool = &compiler.tool;
    let retail_ids: Vec<&str> = inputs
        .manifest
        .tools
        .iter()
        .filter(|t| t.family.as_deref() == Some("armcc") && t.platform == target.id)
        .map(|t| t.id.as_str())
        .collect();
    let (headline, intro, build_line, fetch_line, build_comment, check, tools_note) = if compiler.retail() {
        (
            "**per-function matching**",
            format!("Every unit is built with the retail compiler (`{tool}`, `{flags}`) and compared with its retail function, so a function is decompiled when its bytes match. There is no whole-image build ({}). What this repository gives you:", target.why_not_matching),
            format!("* `build.py`: compiles every unit with `{tool}`; a unit matches when objdiff says its bytes do."),
            format!("python3 build.py fetch      # download the pinned {tool} (decomp.me's armcc bundle, 73 MB), objdiff-cli, and wibo where Windows executables need it"),
            format!("python3 build.py            # compile src/ with {tool} ({flags}); writes build/compile_report.json"),
            "Units compile as C99 (`--c99`): decompiled C has no headers for its callees, so armcc's implicit-declaration warnings are not errors; every error is reported. A unit that fails (a missing struct definition, say) is listed with its first error in `build/compile_report.json`, and the build exits 0 unless you pass `--strict`. Each unit compiles in the mode its function was decoded in (`--arm`/`--thumb`).".to_string(),
            format!("`{tool}` is proprietary (ARM): `config/toolchain.json` records where the decomp.me compilers project hosts it and its sha256; use it only if you are entitled to. objdiff is Apache-2.0 or MIT, wibo MIT. `$ARMCC`, `--armcc PATH` or a toolchain profile (`config/toolchain.local.json` with `{{\"armcc\": \"/path/to/armcc.exe\"}}`) overrides the download."),
        )
    } else {
        let intro = if retail_ids.is_empty() {
            format!("There is no byte-matching build for this platform ({}). What this repository gives you instead:", target.why_not_matching)
        } else {
            format!("Units are only checked to compile with clang here. The retail compiler is pinned too ({}): regenerate with `romwright-cli new-project --compiler <id> --cflags \"...\"` to compare every unit with its retail function. What this repository gives you instead:", retail_ids.join(", "))
        };
        (
            "**non-matching**",
            intro,
            "* `build.py`: compiles every unit with clang to prove it compiles, nothing more.".to_string(),
            "python3 build.py fetch      # download the pinned clang (about 2 GB), and objdiff-cli where the platform has an objdiff backend; optional if clang is on PATH".to_string(),
            format!("python3 build.py            # compile src/ for {}; writes build/compile_report.json", target.triple),
            "The compile check is a syntax and type check against `include/romwright_types.h`, in lenient C: implicit function declarations and integer/pointer conversions are accepted because decompiled C has no headers for its callees; every other error is reported. A unit that fails (a missing struct definition, say) is listed with its first error in `build/compile_report.json`, and the build exits 0 unless you pass `--strict`.".to_string(),
            "LLVM is Apache-2.0 with LLVM exceptions; objdiff is Apache-2.0. A toolchain profile (`--toolchain`, `config/toolchain.local.json` with `{\"clang\": \"/path/to/clang\"}`) overrides the download.".to_string(),
        )
    };
    let readme = render(
        include_str!("templates/scaffold/README.md.tmpl"),
        &[
            ("NAME", inputs.project_name.to_string()),
            ("HEADLINE", headline.to_string()),
            ("PLATFORM_NAME", target.name.to_string()),
            ("IMAGE", inputs.image_name.to_string()),
            ("SHA256", inputs.image_sha256.clone()),
            ("ROMWRIGHT", inputs.romwright_version.to_string()),
            ("INTRO", intro),
            ("DATA_MODEL", target.data_model.to_string()),
            ("BUILD_LINE", build_line),
            ("OBJDIFF_LINE", objdiff_line),
            ("FETCH_LINE", fetch_line),
            ("BUILD_COMMENT", build_comment),
            ("OBJDIFF_QUICKSTART", objdiff_quickstart),
            ("UNITS", sources_written.to_string()),
            ("SYMBOLS", symbol_count.to_string()),
            ("MODULES", inputs.modules.len().to_string()),
            ("CHECK", check),
            ("PLATFORM_NOTES", target.notes.to_string()),
            ("TARGET_NOTE", target_note),
            ("TOOLS_NOTE", tools_note),
            ("KEYS_NOTE", target.keys.to_string()),
        ],
    );
    files.push(template("README.md", &readme, false));
    files.push(template("build.py", include_str!("templates/scaffold/build.py"), true));
    files.push(template("tools/download_tool.py", include_str!("templates/ps2/tools/download_tool.py"), true));
    files.push(template(".gitignore", include_str!("templates/scaffold/gitignore"), false));
    if sources_written == 0 {
        files.push(template("src/.gitkeep", "", false));
    }

    let report = ScaffoldReport {
        platform: target.id.to_string(),
        image_sha256: inputs.image_sha256.clone(),
        triple: target.triple.to_string(),
        modules: inputs.modules.len(),
        buildable_modules: inputs.modules.iter().filter(|m| buildable(target, &m.facts.facts.language)).count(),
        functions: units.len(),
        sources: sources_written,
        target_objects: targets_written,
        relocated_calls: relocated,
        objdiff_units,
        symbols: symbol_count,
        prototypes_emitted: protos_ok,
        prototypes_skipped: protos_skipped,
    };
    Ok((files, report))
}

/// Switch build id of an NSO0 file (`ModuleId`, offset 0x40, 32 bytes), as hex.
pub fn nso_build_id(file: &[u8]) -> Option<String> {
    if file.get(..4) != Some(b"NSO0") {
        return None;
    }
    let id = file.get(0x40..0x60)?;
    Some(id.iter().map(|b| format!("{b:02x}")).collect())
}

/// sha256 as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    crate::sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Where a unit's decompiled C was exported to, below `dir` (the file
/// `export_m2c` writes for unit `tu`).
pub fn exported_source(dir: &Path, unit: &Unit) -> std::path::PathBuf {
    dir.join(format!("{}.c", unit.tu))
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{Address, FunctionRow, MemoryRegion, SymbolRow};

    fn function(address: u64, name: &str, size: u64) -> FunctionRow {
        FunctionRow {
            entry: Address::ram(address),
            name: name.to_string(),
            size,
            signature: None,
            traced: false,
            calling_convention: None,
        }
    }

    /// Two AArch64 functions: `a` calls `b` and returns; `b` returns.
    fn facts() -> ScaffoldFacts {
        ScaffoldFacts {
            facts: ExportFacts {
                program: "game".into(),
                language: "AARCH64:LE:64:v8A".into(),
                functions: vec![function(0x7100_0000_0000, "a::run(int", 8), function(0x7100_0000_0008, "b", 4)],
                symbols: vec![SymbolRow {
                    name: "sceKernelFoo".into(),
                    address: Address::ram(0x7100_0000_0100),
                    external: true,
                    source: "IMPORTED".into(),
                }],
                regions: vec![MemoryRegion {
                    name: ".text".into(),
                    start: Address::ram(0x7100_0000_0000),
                    size: 0x1000,
                    permissions: "r-x".into(),
                    source: "native-import".into(),
                }],
                ..Default::default()
            },
            prototypes: vec![(0x7100_0000_0008, "int b(int x, struct S *s)".into()), (0x7100_0000_0000, "void FUN_a(char *p)".into())],
            transfers: vec![(0x7100_0000_0000, 0x7100_0000_0008, true)],
            thumb: HashSet::new(),
        }
    }

    fn code(address: u64, size: usize) -> Option<Vec<u8>> {
        // bl +8 ; ret ; ret
        let image: Vec<u8> = [0x9400_0002u32, 0xD65F_03C0, 0xD65F_03C0].iter().flat_map(|w| w.to_le_bytes()).collect();
        let offset = (address - 0x7100_0000_0000) as usize;
        image.get(offset..offset + size).map(|b| b.to_vec())
    }

    #[test]
    fn scaffold_writes_config_sources_targets_and_objdiff() {
        let manifest = Manifest::builtin();
        let facts = facts();
        let inputs = ScaffoldInputs {
            target: target("switch").unwrap(),
            image_name: "main",
            project_name: "game",
            image_sha256: sha256_hex(b"image"),
            image_size: 5,
            modules: vec![ModuleInput {
                id: "main".into(),
                program: "game".into(),
                facts: &facts,
                code: &code,
                build_id: Some("ab".repeat(32)),
                mapped_sha256: "0".repeat(64),
            }],
            manifest: &manifest,
            compiler: compiler_for(target("switch").unwrap(), None, None, &manifest).unwrap(),
            profile: None,
            romwright_version: "0.0.0",
        };
        let units = layout(&inputs);
        assert_eq!(units.len(), 2);
        // The map-file style name becomes a C identifier and the file stem follows it.
        assert_eq!(units[0].cname, "a__run_int");
        assert_eq!(units[0].tu, "main/71000000/a__run_int");
        let mut sources = HashMap::new();
        sources.insert(units[0].tu.clone(), "void a::run(int(void) { b(); }\n".to_string());
        let (files, report) = plan(&inputs, &units, &sources).unwrap();
        let get = |path: &str| files.iter().find(|f| f.path == path).map(|f| String::from_utf8_lossy(&f.bytes).into_owned());
        let src = get("src/main/71000000/a__run_int.c").expect("source");
        assert!(src.contains("NON_MATCHING") && src.contains("romwright_types.h"));
        let symbols = get("config/symbols.txt").unwrap();
        assert!(symbols.contains("a__run_int = .text:0x710000000000; // type:function size:0x8 orig:\"a::run(int\""), "{symbols}");
        assert!(symbols.contains("sceKernelFoo = .text:0x710000000100; // type:import"), "{symbols}");
        assert!(files.iter().all(|f| !f.path.starts_with("src/main/71000000/b")), "units without text get no file");
        let objdiff: serde_json::Value = serde_json::from_str(&get("objdiff.json").unwrap()).unwrap();
        assert_eq!(objdiff["units"].as_array().unwrap().len(), 1);
        assert_eq!(objdiff["units"][0]["target_path"], "orig/target/main/71000000/a__run_int.o");
        assert_eq!(report.relocated_calls, 1);
        let object = files.iter().find(|f| f.path == "orig/target/main/71000000/a__run_int.o").unwrap();
        assert_eq!(&object.bytes[..4], b"\x7fELF");
        let modules: serde_json::Value = serde_json::from_str(&get("config/modules.json").unwrap()).unwrap();
        assert_eq!(modules["modules"][0]["build_id"], "ab".repeat(32));
        assert_eq!(modules["modules"][0]["sections"][0]["start"], "0x710000000000");
        // Only types the base header defines survive in the prototype header.
        let protos = get("include/protos_main.h").unwrap();
        assert!(protos.contains("void a__run_int(char *p);") && !protos.contains("struct S"), "{protos}");
        assert!(get("config/toolchain.json").unwrap().contains("clang-22.1.8"));
        assert!(!files.iter().any(|f| f.path.contains("key")), "no key material is ever written");
    }

    #[test]
    fn powerpc_targets_get_target_objects_but_no_objdiff_json() {
        let manifest = Manifest::builtin();
        let mut facts = facts();
        facts.facts.language = "PowerPC:BE:64:64-32addr".into();
        let inputs = ScaffoldInputs {
            target: target("ps3").unwrap(),
            image_name: "EBOOT.ELF",
            project_name: "game",
            image_sha256: "0".repeat(64),
            image_size: 0,
            modules: vec![ModuleInput {
                id: "main".into(),
                program: "game".into(),
                facts: &facts,
                code: &|_, size| Some(vec![0x60; size]),
                build_id: None,
                mapped_sha256: String::new(),
            }],
            manifest: &manifest,
            compiler: compiler_for(target("ps3").unwrap(), None, None, &manifest).unwrap(),
            profile: None,
            romwright_version: "0.0.0",
        };
        let units = layout(&inputs);
        let sources: HashMap<_, _> = units.iter().map(|u| (u.tu.clone(), "void f(void) {}".to_string())).collect();
        let (files, report) = plan(&inputs, &units, &sources).unwrap();
        assert!(files.iter().all(|f| f.path != "objdiff.json"));
        assert_eq!(report.objdiff_units, 0);
        assert_eq!(report.target_objects, 2);
        let toolchain = String::from_utf8_lossy(&files.iter().find(|f| f.path == "config/toolchain.json").unwrap().bytes).into_owned();
        assert!(!toolchain.contains("objdiff-cli"));
    }

    #[test]
    fn modules_in_a_language_the_platform_cannot_build_keep_config_only() {
        let manifest = Manifest::builtin();
        let mut facts = facts();
        facts.facts.language = "SPU:BE:128:default".into();
        let inputs = ScaffoldInputs {
            target: target("ps3").unwrap(),
            image_name: "x",
            project_name: "game",
            image_sha256: String::new(),
            image_size: 0,
            modules: vec![ModuleInput { id: "spu0".into(), program: "g.spu0".into(), facts: &facts, code: &|_, _| None, build_id: None, mapped_sha256: String::new() }],
            manifest: &manifest,
            compiler: compiler_for(target("ps3").unwrap(), None, None, &manifest).unwrap(),
            profile: None,
            romwright_version: "0",
        };
        assert!(layout(&inputs).is_empty());
        let (files, report) = plan(&inputs, &[], &HashMap::new()).unwrap();
        assert_eq!(report.buildable_modules, 0);
        assert!(files.iter().any(|f| f.path == "config/symbols.txt"));
    }

    #[test]
    fn platform_detection_reads_magic_not_names() {
        let mut ncch = vec![0u8; 0x200];
        ncch[0x100..0x104].copy_from_slice(b"NCCH");
        assert_eq!(detect_platform(&ncch), Some("3ds"));
        let mut nso = vec![0u8; 0x100];
        nso[..4].copy_from_slice(b"NSO0");
        assert_eq!(detect_platform(&nso), Some("switch"));
        assert_eq!(nso_build_id(&nso).unwrap().len(), 64);
        let mut xex = vec![0u8; 64];
        xex[..4].copy_from_slice(b"XEX2");
        assert_eq!(detect_platform(&xex), Some("x360"));
        let mut ps4 = vec![0u8; 64];
        ps4[..4].copy_from_slice(b"\x7fELF");
        ps4[4] = 2;
        ps4[5] = 1;
        ps4[7] = 9;
        ps4[18] = 62;
        assert_eq!(detect_platform(&ps4), Some("ps4"));
        ps4[7] = 0;
        assert_eq!(detect_platform(&ps4), None);
        let mut ps3 = vec![0u8; 64];
        ps3[..4].copy_from_slice(b"\x7fELF");
        ps3[4] = 2;
        ps3[5] = 2;
        ps3[19] = 21;
        assert_eq!(detect_platform(&ps3), Some("ps3"));
    }

    #[test]
    fn every_scaffold_platform_pins_its_tools_in_the_manifest() {
        let manifest = Manifest::builtin();
        for t in TARGETS {
            let ids = if t.objdiff { vec![CLANG_ID, OBJDIFF_ID] } else { vec![CLANG_ID] };
            manifest.subset(&ids).unwrap();
        }
        assert_eq!(manifest.tool(CLANG_ID).unwrap().assets["linux-x86_64"].sha256.len(), 64);
    }

    #[test]
    fn names_never_collide_with_types_keywords_or_each_other() {
        let mut names = Names::default();
        assert_eq!(names.claim(c_ident("int", 0x10), 0x10), "int_10");
        assert_eq!(names.claim(c_ident("Foo", 0x20), 0x20), "Foo");
        assert_eq!(names.claim(c_ident("foo", 0x30), 0x30), "foo_30");
        assert_eq!(c_ident(".ARM.Collect$$libshutdown$$00000002", 0), "_ARM_Collect__libshutdown__00000002");
        assert_eq!(c_ident("$$", 0x44), "sub_44");
        assert_eq!(c_ident("1abc", 0), "_1abc");
    }

    #[test]
    fn a_3ds_scaffold_takes_an_armcc_build_and_only_that_platform_does() {
        let manifest = Manifest::builtin();
        let n3ds = target("3ds").unwrap();
        let armcc = compiler_for(n3ds, Some("armcc-4.1-b713"), Some(vec!["-O3".into(), "-Otime".into()]), &manifest).unwrap();
        assert_eq!(armcc.family, "armcc");
        assert_eq!(armcc.flags, ["--cpu=MPCore", "--fpmode=fast", "--apcs=/interwork", "--c99", "-O3", "-Otime"]);
        assert_eq!(compiler_for(n3ds, Some("armcc-4.1-b713"), None, &manifest).unwrap().flags[4..], ["-O2", "-Ospace"]);
        assert_eq!(compiler_for(n3ds, None, None, &manifest).unwrap().tool, CLANG_ID);
        // --cflags only means something for a retail compiler; another platform's or an unknown id is refused.
        assert!(compiler_for(n3ds, None, Some(vec!["-O3".into()]), &manifest).is_err());
        assert!(compiler_for(target("switch").unwrap(), Some("armcc-4.1-b713"), None, &manifest).is_err());
        assert!(compiler_for(n3ds, Some("msvc6.0"), None, &manifest).is_err());
    }

    #[test]
    fn an_armcc_3ds_project_relocates_tail_calls_and_pool_addresses() {
        use object::{Object, ObjectSection, ObjectSymbol};
        let manifest = Manifest::builtin();
        let region = |name: &str, start: u64, permissions: &str| MemoryRegion {
            name: name.into(),
            start: Address::ram(start),
            size: 0x1000,
            permissions: permissions.into(),
            source: "native-import".into(),
        };
        let facts = ScaffoldFacts {
            facts: ExportFacts {
                program: "game".into(),
                language: "ARM:LE:32:v6".into(),
                // The analysis sized f to its code: its pool word at +0xC lies past it.
                functions: vec![function(0x10_0000, "f", 0xC), function(0x10_0100, "g", 4)],
                regions: vec![region(".text", 0x10_0000, "r-x"), region(".data", 0x20_0000, "rw-")],
                ..Default::default()
            },
            // No transfer recorded: the tail call is found from the bytes.
            ..Default::default()
        };
        // f: ldr r0, [pc, #4] ; b g ; bx lr ; .word 0x00200010     g: bx lr
        let image: HashMap<u64, u32> = [(0x10_0000, 0xE59F_0004), (0x10_0004, 0xEA00_003D), (0x10_0008, 0xE12F_FF1E), (0x10_000C, 0x0020_0010), (0x10_0100, 0xE12F_FF1E)].into();
        let code = |address: u64, size: usize| -> Option<Vec<u8>> {
            (0..size as u64).step_by(4).map(|at| image.get(&(address + at)).map(|w| w.to_le_bytes())).collect::<Option<Vec<_>>>().map(|words| words.concat())
        };
        let n3ds = target("3ds").unwrap();
        let inputs = ScaffoldInputs {
            target: n3ds,
            image_name: "game.cxi",
            project_name: "game",
            image_sha256: sha256_hex(b"image"),
            image_size: 5,
            modules: vec![ModuleInput { id: "_code".into(), program: "game".into(), facts: &facts, code: &code, build_id: None, mapped_sha256: "0".repeat(64) }],
            manifest: &manifest,
            compiler: compiler_for(n3ds, Some("armcc-4.1-b713"), Some(vec!["-O3".into(), "-Otime".into()]), &manifest).unwrap(),
            profile: None,
            romwright_version: "0.0.0",
        };
        let units = layout(&inputs);
        let sources: HashMap<String, String> = units.iter().map(|u| (u.tu.clone(), "void f(void) {}\n".to_string())).collect();
        let (files, _) = plan(&inputs, &units, &sources).unwrap();
        let get = |path: &str| files.iter().find(|f| f.path == path).map(|f| f.bytes.clone()).unwrap();
        let project: serde_json::Value = serde_json::from_slice(&get("config/project.json")).unwrap();
        assert_eq!(project["compiler"]["family"], "armcc");
        assert_eq!(project["compiler"]["modes"]["arm"], "--arm");
        let toolchain = String::from_utf8(get("config/toolchain.json")).unwrap();
        assert!(toolchain.contains("\"armcc-4.1-b713\"") && toolchain.contains("\"wibo\"") && !toolchain.contains(CLANG_ID));
        let object = get("orig/target/_code/0010/f.o");
        let file = object::File::parse(&*object).unwrap();
        let names: HashMap<usize, String> = file.symbols().map(|s| (s.index().0, s.name().unwrap().to_string())).collect();
        let relocs: Vec<(u64, u32, String)> = file
            .section_by_name(".text")
            .unwrap()
            .relocations()
            .map(|(offset, r)| {
                let object::RelocationFlags::Elf { r_type } = r.flags() else { unreachable!() };
                let object::RelocationTarget::Symbol(index) = r.target() else { unreachable!() };
                (offset, r_type, names[&index.0].clone())
            })
            .collect();
        assert_eq!(relocs, [(4, 29, "g".to_string()), (12, 2, "DAT_00200010".to_string())]);
        assert!(file.symbols().any(|s| s.name() == Ok("$d") && s.address() == 12));
        // The pool is in the section after the code, outside the function symbol, as armcc writes it.
        assert_eq!(file.section_by_name(".text").unwrap().size(), 0x10);
        let f = file.symbols().find(|s| s.name() == Ok("f")).unwrap();
        assert_eq!(f.size(), 0xC);
        assert!(file.section_by_name(".ARM.attributes").is_some());
    }
}
