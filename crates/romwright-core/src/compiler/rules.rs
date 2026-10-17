//! Compiler rules: compiler knowledge as embedded data, keyed by compiler id.
//!
//! A rule file (`crates/romwright-core/compiler_rules/<family>.json`) lists
//! rules; a rule names the engine that executes it (`kind`), the compilers it
//! covers, where it came from and whether it ships. The engines are code in
//! the crates that act on the data (the importer's discovery, the worker's
//! spec patcher, the C printer); a rule only parameterises one. A `kind`
//! without an engine is a load error, so a rule file can never promise
//! behaviour nothing executes.
//!
//! Applicability of a rule to a program:
//!
//! 1. `languages` / `formats`, when present, must match the program (these
//!    are the hardware and container facts the rule needs, not a compiler
//!    choice);
//! 2. a program whose compiler is known is covered when one of `compilers`
//!    covers its id ([`covers`](super::covers));
//! 3. a program whose compiler is [`UNKNOWN`] is covered when `unknown` is
//!    true: the rule then behaves as it did before compilers were detected,
//!    keyed by platform alone;
//! 4. `status` `on` rules are active; `off` and `candidate` rules are active
//!    only through `ROMWRIGHT_COMPILER_RULES_ENABLE`, which is how the
//!    leave-one-out harness measures them.
//!
//! Switches (read once per process):
//!
//! * `ROMWRIGHT_NO_COMPILER_RULES=1` -- every rule inactive;
//! * `ROMWRIGHT_COMPILER_RULES_DISABLE=<id,id>` -- those rules inactive
//!   (wins over `ENABLE`);
//! * `ROMWRIGHT_COMPILER_RULES_ENABLE=<id,id>` -- those rules active when
//!   they cover the program, whatever their status.
//!
//! The switches join the import-cache key through [`fingerprint`], so a
//! cached import is never served across a rule change.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use serde::Deserialize;

use super::{covers, UNKNOWN};

/// The embedded rule files, by family.
const FILES: [(&str, &str); 4] = [
    ("common.json", include_str!("../../compiler_rules/common.json")),
    ("gcc.json", include_str!("../../compiler_rules/gcc.json")),
    ("mwcc.json", include_str!("../../compiler_rules/mwcc.json")),
    ("pe.json", include_str!("../../compiler_rules/pe.json")),
];

/// The rule that defines the CodeWarrior register-save sleds; the importer's
/// naming pass and the worker's call fixups both read the layout from it.
pub const MWCC_SLEDS: &str = "mwcc-register-sleds";

/// The kinds an engine exists for.
pub const KINDS: [&str; 5] = ["register-sled", "nonreturn-names", "flag", "c-canonical", "literal-pool-extent"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    On,
    Off,
    Candidate,
}

/// Why a rule exists: moved out of code as it was, or learned afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// Behaviour that shipped before the rule layer existed, moved to data
    /// unchanged. Its leave-one-out bar is "hurts no held-out game".
    Migrated,
    /// Added with leave-one-out evidence. Its bar is "helps at least one
    /// held-out game and hurts none".
    Learned,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub kind: String,
    /// Compiler ids or families the rule covers; `*` is every detected one.
    #[serde(default)]
    pub compilers: Vec<String>,
    /// Also covers a program whose compiler is unknown (today's platform key).
    #[serde(default)]
    pub unknown: bool,
    /// Language-id prefixes the program must have, when any.
    #[serde(default)]
    pub languages: Vec<String>,
    /// Loader formats the program must have, when any.
    #[serde(default)]
    pub formats: Vec<String>,
    pub status: Status,
    pub origin: Origin,
    /// Corpus games the rule was learned or tuned on; never held out.
    #[serde(default)]
    pub derived_from: Vec<String>,
    /// What the rule does and why, in a sentence or two.
    pub note: String,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(skip)]
    engine: Engine,
}

#[derive(Debug, Clone, Default)]
enum Engine {
    #[default]
    Flag,
    Sled(SledSet),
    Names(HashSet<String>),
    Canonical(String),
    /// Which instruction sets' literal pools a function's size runs through: `(thumb, arm)`.
    Pool(bool, bool),
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    family: String,
    rules: Vec<Rule>,
}

/// One register-save/restore helper family: `<prefix>N` for each register
/// `first..=last` runs `op rN,-slot*(32-N)(r11)` down to rN's slot, then `blr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SledFamily {
    pub prefix: String,
    /// `r` (general) or `f` (floating-point) register names.
    pub class: char,
    /// The D-form opcode of the sled's instruction.
    pub opcode: u32,
    /// True for a save (`stw`/`stfd`), false for a restore.
    pub store: bool,
    /// Bytes per register slot.
    pub slot: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SledSet {
    pub families: Vec<SledFamily>,
    pub first: u32,
    pub last: u32,
}

impl SledSet {
    /// Every helper name the set defines, e.g. `_savegpr_14`.
    pub fn names(&self) -> Vec<String> {
        self.families
            .iter()
            .flat_map(|family| (self.first..=self.last).map(move |number| format!("{}{number}", family.prefix)))
            .collect()
    }

    /// Whether `name` is one of [`Self::names`].
    pub fn is_helper(&self, name: &str) -> bool {
        self.families.iter().any(|family| {
            name.strip_prefix(family.prefix.as_str())
                .and_then(|number| number.parse::<u32>().ok())
                .is_some_and(|number| (self.first..=self.last).contains(&number))
        })
    }
}

/// The program facts a rule is matched against.
#[derive(Debug, Clone, Copy)]
pub struct Ctx<'a> {
    pub compiler: &'a str,
    pub language: &'a str,
    pub format: &'a str,
}

impl<'a> Ctx<'a> {
    pub fn new(compiler: &'a str, language: &'a str, format: &'a str) -> Self {
        Self { compiler, language, format }
    }
}

/// The three switches, parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Switches {
    pub none: bool,
    pub disabled: BTreeSet<String>,
    pub enabled: BTreeSet<String>,
}

impl Switches {
    pub fn parse(none: Option<&str>, disable: Option<&str>, enable: Option<&str>) -> Self {
        let list = |value: Option<&str>| -> BTreeSet<String> {
            value
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
                .collect()
        };
        Self {
            none: none.is_some_and(|value| !value.is_empty() && value != "0"),
            disabled: list(disable),
            enabled: list(enable),
        }
    }

    pub fn from_env() -> Self {
        let get = |name: &str| std::env::var(name).ok();
        Self::parse(
            get("ROMWRIGHT_NO_COMPILER_RULES").as_deref(),
            get("ROMWRIGHT_COMPILER_RULES_DISABLE").as_deref(),
            get("ROMWRIGHT_COMPILER_RULES_ENABLE").as_deref(),
        )
    }

    /// Whether `rule` is switched on, before asking whether it covers a program.
    pub fn active(&self, rule: &Rule) -> bool {
        if self.none || self.disabled.contains(&rule.id) {
            return false;
        }
        rule.status == Status::On || self.enabled.contains(&rule.id)
    }

    /// Stable text of the switches, for cache keys.
    pub fn key(&self) -> String {
        format!(
            "none={}|disable={}|enable={}",
            self.none,
            self.disabled.iter().cloned().collect::<Vec<_>>().join(","),
            self.enabled.iter().cloned().collect::<Vec<_>>().join(",")
        )
    }
}

struct Registry {
    rules: Vec<Rule>,
    by_id: HashMap<String, usize>,
    switches: Switches,
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let rules = load_embedded().unwrap_or_else(|error| panic!("embedded compiler rules are invalid: {error}"));
    let by_id = rules.iter().enumerate().map(|(index, rule)| (rule.id.clone(), index)).collect();
    Registry { rules, by_id, switches: Switches::from_env() }
});

fn registry() -> &'static Registry {
    &REGISTRY
}

/// Parses and validates the embedded files.
pub fn load_embedded() -> Result<Vec<Rule>, String> {
    let mut all = Vec::new();
    for (file, text) in FILES {
        all.extend(parse_file(file, text)?);
    }
    validate(&all)?;
    Ok(all)
}

fn parse_file(file: &str, text: &str) -> Result<Vec<Rule>, String> {
    let parsed: RuleFile = serde_json::from_str(text).map_err(|error| format!("{file}: {error}"))?;
    // A rule lives in the file of its family, so a reader finds it by compiler.
    if file.strip_suffix(".json") != Some(parsed.family.as_str()) {
        return Err(format!("{file}: family `{}` does not match the file name", parsed.family));
    }
    let mut rules = parsed.rules;
    for rule in &mut rules {
        rule.engine = build_engine(rule).map_err(|error| format!("{file}: rule `{}`: {error}", rule.id))?;
    }
    Ok(rules)
}

fn build_engine(rule: &Rule) -> Result<Engine, String> {
    match rule.kind.as_str() {
        "flag" => Ok(Engine::Flag),
        "nonreturn-names" => {
            let names = rule
                .params
                .get("names")
                .and_then(|names| names.as_array())
                .ok_or("`names` array is required")?;
            let set: HashSet<String> = names
                .iter()
                .map(|name| name.as_str().map(str::to_string).ok_or("`names` holds a non-string"))
                .collect::<Result<_, _>>()?;
            if set.is_empty() {
                return Err("`names` is empty".into());
            }
            Ok(Engine::Names(set))
        }
        "literal-pool-extent" => {
            let isas = rule
                .params
                .get("isas")
                .and_then(|isas| isas.as_array())
                .ok_or("`isas` array is required")?;
            let (mut thumb, mut arm) = (false, false);
            for isa in isas {
                match isa.as_str() {
                    Some("thumb") => thumb = true,
                    Some("arm") => arm = true,
                    other => return Err(format!("`isas` names {other:?}; the engine knows thumb and arm")),
                }
            }
            Ok(Engine::Pool(thumb, arm))
        }
        "c-canonical" => {
            let function = rule.params.get("fn").and_then(|f| f.as_str()).ok_or("`fn` is required")?;
            Ok(Engine::Canonical(function.to_string()))
        }
        "register-sled" => {
            let number = |key: &str| -> Result<u32, String> {
                rule.params
                    .get(key)
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| format!("`{key}` is required"))
            };
            let (first, last) = (number("first")?, number("last")?);
            if !(first <= last && last <= 31) {
                return Err("`first`..=`last` must lie within 0..=31".into());
            }
            let families = rule
                .params
                .get("families")
                .and_then(|families| families.as_array())
                .ok_or("`families` array is required")?;
            let mut out = Vec::new();
            for family in families {
                let text = |key: &str| family.get(key).and_then(|value| value.as_str()).ok_or_else(|| format!("family `{key}` is required"));
                let (opcode, store) = match text("op")? {
                    "stw" => (36, true),
                    "lwz" => (32, false),
                    "stfd" => (54, true),
                    "lfd" => (50, false),
                    other => return Err(format!("no engine for sled op `{other}` (stw, lwz, stfd, lfd)")),
                };
                let class = match text("class")? {
                    "r" => 'r',
                    "f" => 'f',
                    other => return Err(format!("sled class `{other}` is not r or f")),
                };
                let slot = family.get("slot").and_then(|slot| slot.as_u64()).filter(|slot| matches!(slot, 4 | 8)).ok_or("family `slot` must be 4 or 8")?;
                out.push(SledFamily { prefix: text("prefix")?.to_string(), class, opcode, store, slot: slot as u32 });
            }
            if out.is_empty() {
                return Err("`families` is empty".into());
            }
            Ok(Engine::Sled(SledSet { families: out, first, last }))
        }
        other => Err(format!("kind `{other}` has no engine (known: {})", KINDS.join(", "))),
    }
}

fn validate(rules: &[Rule]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for rule in rules {
        if !seen.insert(rule.id.as_str()) {
            return Err(format!("duplicate rule id `{}`", rule.id));
        }
        if rule.id.is_empty() || rule.id.contains(',') || rule.id.contains(char::is_whitespace) {
            return Err(format!("rule id `{}` must be non-empty, without commas or spaces", rule.id));
        }
        if rule.note.trim().is_empty() {
            return Err(format!("rule `{}` has no note", rule.id));
        }
        if rule.compilers.is_empty() && !rule.unknown {
            return Err(format!("rule `{}` covers no compiler and not `unknown`", rule.id));
        }
        if rule.status == Status::On && rule.derived_from.is_empty() && rule.origin == Origin::Learned {
            return Err(format!("learned rule `{}` ships on without `derived_from`", rule.id));
        }
    }
    Ok(())
}

/// Every embedded rule, in file order.
pub fn all() -> &'static [Rule] {
    &registry().rules
}

/// The rule with `id`, whatever its status or switches say.
pub fn rule(id: &str) -> Option<&'static Rule> {
    let registry = registry();
    registry.by_id.get(id).map(|&index| &registry.rules[index])
}

/// Whether `rule` covers the program, ignoring status and switches.
pub fn covers_program(rule: &Rule, ctx: &Ctx) -> bool {
    if !rule.languages.is_empty() && !rule.languages.iter().any(|prefix| ctx.language.starts_with(prefix.as_str())) {
        return false;
    }
    if !rule.formats.is_empty() && !rule.formats.iter().any(|format| format == ctx.format) {
        return false;
    }
    if ctx.compiler.is_empty() || ctx.compiler == UNKNOWN {
        rule.unknown
    } else {
        rule.compilers.iter().any(|pattern| covers(pattern, ctx.compiler))
    }
}

fn active_in(registry: &Registry, rule: &Rule, ctx: &Ctx) -> bool {
    registry.switches.active(rule) && covers_program(rule, ctx)
}

/// Whether rule `id` is active for the program.
pub fn applies(id: &str, ctx: &Ctx) -> bool {
    let registry = registry();
    registry
        .by_id
        .get(id)
        .is_some_and(|&index| active_in(registry, &registry.rules[index], ctx))
}

fn active_of_kind<'a>(kind: &'a str, ctx: &'a Ctx<'a>) -> impl Iterator<Item = &'static Rule> + 'a {
    let registry = registry();
    registry
        .rules
        .iter()
        .filter(move |rule| rule.kind == kind && active_in(registry, rule, ctx))
}

/// The sled set of the active `register-sled` rule for the program.
pub fn register_sleds(ctx: &Ctx) -> Option<&'static SledSet> {
    active_of_kind("register-sled", ctx).find_map(|rule| match &rule.engine {
        Engine::Sled(set) => Some(set),
        _ => None,
    })
}

/// The sled set a rule defines, whatever the program: the definition the
/// engines read their layout from (`mwcc-register-sleds`).
pub fn sled_definition(id: &str) -> Option<&'static SledSet> {
    rule(id).and_then(|rule| match &rule.engine {
        Engine::Sled(set) => Some(set),
        _ => None,
    })
}

/// The instruction sets `(thumb, arm)` whose literal pools a function's size
/// runs through, when an active `literal-pool-extent` rule covers the program.
pub fn literal_pool_isas(ctx: &Ctx) -> Option<(bool, bool)> {
    active_of_kind("literal-pool-extent", ctx).find_map(|rule| match &rule.engine {
        Engine::Pool(thumb, arm) => Some((*thumb, *arm)),
        _ => None,
    })
}

/// Whether an active `nonreturn-names` rule names `name` (leading
/// underscores ignored, as Ghidra's `NoReturnFunctionAnalyzer` does).
pub fn known_no_return(ctx: &Ctx, name: &str) -> bool {
    let name = name.trim_start_matches('_');
    active_of_kind("nonreturn-names", ctx).any(|rule| matches!(&rule.engine, Engine::Names(names) if names.contains(name)))
}

/// Whether the `c-canonical` rule for the printer function `function` is
/// active for `compiler`. A function with no rule is not governed by the
/// layer and stays on.
pub fn canonical_enabled(function: &str, compiler: &str) -> bool {
    let registry = registry();
    let ctx = Ctx::new(compiler, "", "");
    let mut governed = false;
    for rule in registry.rules.iter().filter(|rule| rule.kind == "c-canonical") {
        if matches!(&rule.engine, Engine::Canonical(name) if name == function) {
            governed = true;
            if active_in(registry, rule, &ctx) {
                return true;
            }
        }
    }
    !governed
}

/// One rule as the CLI and the leave-one-out harness read it.
#[derive(Debug, serde::Serialize)]
pub struct RuleView {
    pub id: String,
    pub kind: String,
    pub compilers: Vec<String>,
    pub unknown: bool,
    pub languages: Vec<String>,
    pub formats: Vec<String>,
    pub status: &'static str,
    pub origin: &'static str,
    pub derived_from: Vec<String>,
    pub note: String,
    /// Switched on under the current environment switches (whatever it covers).
    pub active: bool,
}

/// Every embedded rule with its switch state.
pub fn describe() -> Vec<RuleView> {
    let registry = registry();
    registry
        .rules
        .iter()
        .map(|rule| RuleView {
            id: rule.id.clone(),
            kind: rule.kind.clone(),
            compilers: rule.compilers.clone(),
            unknown: rule.unknown,
            languages: rule.languages.clone(),
            formats: rule.formats.clone(),
            status: match rule.status {
                Status::On => "on",
                Status::Off => "off",
                Status::Candidate => "candidate",
            },
            origin: match rule.origin {
                Origin::Migrated => "migrated",
                Origin::Learned => "learned",
            },
            derived_from: rule.derived_from.clone(),
            note: rule.note.clone(),
            active: registry.switches.active(rule),
        })
        .collect()
}

/// Digest of the embedded rule text and the switches: what a cached import
/// depends on beyond the executable.
pub fn fingerprint() -> String {
    let registry = registry();
    let mut text = String::new();
    for (name, body) in FILES {
        text.push_str(name);
        text.push_str(body);
    }
    text.push_str(&registry.switches.key());
    crate::import_cache::digest_bytes(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(compiler: &'a str, language: &'a str, format: &'a str) -> Ctx<'a> {
        Ctx::new(compiler, language, format)
    }

    fn rule_of(json: &str) -> Rule {
        let mut rule: Rule = serde_json::from_str(json).unwrap();
        rule.engine = build_engine(&rule).unwrap();
        rule
    }

    #[test]
    fn the_embedded_files_load_and_validate() {
        let rules = load_embedded().unwrap();
        assert!(!rules.is_empty());
        for rule in &rules {
            assert!(KINDS.contains(&rule.kind.as_str()));
        }
    }

    #[test]
    fn an_unknown_compiler_gets_the_platform_rule_and_a_detected_one_gets_its_own() {
        let rule = rule_of(
            r#"{"id":"r","kind":"flag","compilers":["agbcc","gcc"],"unknown":true,"languages":["ARM"],
                "status":"on","origin":"migrated","note":"n"}"#,
        );
        assert!(covers_program(&rule, &ctx("agbcc", "ARM:LE:32:v4t", "gba")));
        assert!(covers_program(&rule, &ctx("gcc-4", "ARM:LE:32:v4t", "gba")));
        assert!(!covers_program(&rule, &ctx("mwcc-arm", "ARM:LE:32:v5t", "nds")), "a detected compiler the rule does not list");
        assert!(covers_program(&rule, &ctx("unknown", "ARM:LE:32:v4t", "gba")), "undetected: today's platform key");
        assert!(covers_program(&rule, &ctx("", "ARM:LE:32:v4t", "gba")));
        assert!(!covers_program(&rule, &ctx("unknown", "MIPS:LE:32:default", "ELF")), "the language is a hard constraint");
    }

    #[test]
    fn an_off_rule_runs_only_when_enabled_and_disable_beats_enable() {
        let on = rule_of(r#"{"id":"a","kind":"flag","compilers":["*"],"status":"on","origin":"migrated","note":"n"}"#);
        let off = rule_of(r#"{"id":"b","kind":"flag","compilers":["*"],"status":"candidate","origin":"learned","note":"n"}"#);
        let plain = Switches::parse(None, None, None);
        assert!(plain.active(&on) && !plain.active(&off));
        let enabled = Switches::parse(None, None, Some("b"));
        assert!(enabled.active(&off));
        let both = Switches::parse(None, Some("a,b"), Some("b"));
        assert!(!both.active(&on) && !both.active(&off), "disable wins over enable");
        let none = Switches::parse(Some("1"), None, Some("b"));
        assert!(!none.active(&on) && !none.active(&off), "NO_COMPILER_RULES turns everything off");
        assert!(!Switches::parse(Some("0"), None, None).none);
    }

    #[test]
    fn a_kind_without_an_engine_is_a_load_error() {
        let text = r#"{"family":"x","rules":[{"id":"r","kind":"made-up","compilers":["*"],"status":"on","origin":"learned","note":"n"}]}"#;
        assert!(parse_file("x.json", text).unwrap_err().contains("no engine"));
    }

    #[test]
    fn a_wildcard_covers_a_detected_compiler_and_not_an_unknown_one() {
        let rule = rule_of(r#"{"id":"r","kind":"nonreturn-names","compilers":["*"],"formats":["ELF"],"status":"on","origin":"migrated","note":"n","params":{"names":["abort"]}}"#);
        assert!(covers_program(&rule, &ctx("ee-gcc-2.9x", "r5900:LE:32:default", "ELF")));
        assert!(!covers_program(&rule, &ctx("unknown", "r5900:LE:32:default", "ELF")));
        assert!(!covers_program(&rule, &ctx("agbcc", "ARM:LE:32:v4t", "PE")));
    }
}
