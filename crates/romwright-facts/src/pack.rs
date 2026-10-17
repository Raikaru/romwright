//! The universal fact pack: a shipped, versioned, read-only SQLite file that
//! names functions whose relocation-masked body matches one a decomp already
//! named, and says how long they are.
//!
//! The pack holds no code. A body is stored as its length plus one-way
//! digests of its masked bytes ([`crate::mask::mask`]): `prefix` (the first 8
//! bytes of the SHA-1 of the masked first [`PREFIX_BYTES`] bytes, used to find
//! candidates) and `digest` (SHA-1 of the whole masked body, used to confirm).
//! Beside each digest sits a fact — a name, a verified flag, the donor — and
//! each donor carries its repo, commit and license.
//!
//! Consensus is computed at query time, so one pack serves every
//! leave-one-out evaluation: [`Pack::lookup`] drops the excluded games (and
//! their twin group) before it decides anything.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use rusqlite::{params, Connection, OpenFlags};
use sha1::{Digest, Sha1};

use crate::mask::{mask, Family, MASK_VERSION};
use crate::{FactsError, Result};

/// Donor game id to its name and platform.
type DonorGames = HashMap<i64, (String, Option<String>)>;

/// `PRAGMA user_version` of a pack this code reads and writes.
pub const FORMAT_VERSION: i64 = 2;

/// `meta` keys of the rename gate, and what applies when a pack has none.
pub const META_GATE_SHORT_BODY: &str = "gate_short_body";
pub const META_GATE_MIN_DONORS: &str = "gate_min_donors";
pub const DEFAULT_GATE_SHORT_BODY: usize = 128;
pub const DEFAULT_GATE_MIN_DONORS: usize = 2;

/// Bytes of masked body the prefix hash covers; also the shortest body a pack
/// holds, which is why it is the default `min_body`.
pub const PREFIX_BYTES: usize = 32;

fn pack_error(message: impl Into<String>) -> FactsError {
    FactsError::Pack(message.into())
}

/// Whether a function name carries no information: a generated placeholder
/// or an address-suffixed label. Such a body still occupies its digest (it
/// counts for ambiguity) but names nothing.
pub fn is_generic(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let hex = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit());
    if lower.starts_with("fun_") || lower.starts_with("sub_") {
        return true;
    }
    if let Some((_, tail)) = lower.rsplit_once('_')
        && tail.len() == 8
        && hex(tail)
    {
        return true;
    }
    for prefix in ["func", "fun", "sub", "fn", "lbl", "text", "code"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            let rest = rest.strip_prefix('_').unwrap_or(rest);
            if (6..=8).contains(&rest.len()) && hex(rest) {
                return true;
            }
        }
    }
    false
}

/// A name's identity for consensus: leading underscores stripped, case folded.
pub fn normalize(name: &str) -> String {
    name.trim_start_matches('_').to_ascii_lowercase()
}

/// One donor game: where its facts came from and under what license.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Donor {
    pub game: String,
    pub platform: String,
    pub repo: String,
    pub commit: String,
    /// SPDX id exactly as the repo declares it; `NONE` when it has no
    /// license file, `NOASSERTION` when GitHub could not classify one.
    pub license: String,
    pub truth_kind: String,
    /// Donors sharing a twin group are one game; they never evaluate each
    /// other.
    #[serde(default)]
    pub twin_group: Option<String>,
    /// The `compiler` string of the donor's `truth/meta.json`, verbatim
    /// (`MWCC PS2 2.3.3 (…)`, `agbcc`, `psyq`, ...): what toolchain produced
    /// the bytes whose facts the donor contributes.
    #[serde(default)]
    pub compiler: Option<String>,
}

/// What a masked body matched, after exclusions and consensus.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Candidate {
    /// Exact byte length of the donor body: boundary evidence.
    pub length: usize,
    /// The consensus name; `None` when every donor's name is generic, or the
    /// donors disagree (`ambiguous`).
    pub name: Option<String>,
    /// Games that contribute the name (all matching games when unnamed).
    pub donors: Vec<String>,
    /// Whether any naming donor marks the function verified.
    pub verified: bool,
    /// More than one normalized non-generic name among the donors.
    pub ambiguous: bool,
    /// Distinct compilers of the donors that back the consensus (donors
    /// whose repo does not say are absent).
    pub compilers: Vec<String>,
    /// Independent donors behind the name: naming donors with a twin group
    /// counted once per group. 0 when the candidate has no consensus name.
    pub independent: usize,
}

struct Row {
    length: usize,
    digest: Vec<u8>,
    name: Option<String>,
    donor: i64,
    verified: bool,
}

/// An open pack.
pub struct Pack {
    db: Connection,
    min_body: usize,
    prefixes: RefCell<Option<HashSet<i64>>>,
    donor_games: RefCell<Option<DonorGames>>,
    exclusion: RefCell<Option<(Vec<String>, HashSet<i64>)>>,
}

const SCHEMA: &str = "
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE donors(
    id INTEGER PRIMARY KEY,
    game TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL,
    repo TEXT NOT NULL,
    \"commit\" TEXT NOT NULL,
    license TEXT NOT NULL,
    truth_kind TEXT NOT NULL,
    twin_group TEXT,
    compiler TEXT
);
CREATE TABLE bodies(
    family TEXT NOT NULL,
    prefix INTEGER NOT NULL,
    length INTEGER NOT NULL,
    digest BLOB NOT NULL,
    name TEXT,
    donor INTEGER NOT NULL REFERENCES donors(id),
    verified INTEGER NOT NULL,
    program TEXT NOT NULL
);
CREATE INDEX bodies_prefix ON bodies(family, prefix);
CREATE INDEX bodies_donor ON bodies(donor, program);
CREATE TABLE prototypes(
    name TEXT NOT NULL,
    donor INTEGER NOT NULL REFERENCES donors(id),
    decl TEXT NOT NULL,
    PRIMARY KEY(name, donor)
) WITHOUT ROWID;
";

fn sha1(bytes: &[u8]) -> [u8; 20] {
    Sha1::digest(bytes).into()
}

/// The `prefix` column value for an already-masked head.
fn prefix_of(masked_head: &[u8]) -> i64 {
    let digest = sha1(masked_head);
    i64::from_be_bytes(digest[..8].try_into().expect("sha1 is 20 bytes"))
}

fn now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

impl Pack {
    /// Creates a new, empty pack at `path`. `tools` is a free-form
    /// fingerprint of the build tooling, recorded in `meta`. Fails if the
    /// file exists.
    pub fn create(path: &Path, min_body: usize, tools: &str) -> Result<Pack> {
        if path.exists() {
            return Err(pack_error(format!("{} already exists", path.display())));
        }
        if min_body < PREFIX_BYTES {
            return Err(pack_error(format!("min_body must be at least {PREFIX_BYTES}")));
        }
        let db = Connection::open(path)?;
        db.execute_batch(SCHEMA)?;
        db.pragma_update(None, "user_version", FORMAT_VERSION)?;
        let meta = [
            ("format", FORMAT_VERSION.to_string()),
            ("mask_version", MASK_VERSION.to_string()),
            ("min_body", min_body.to_string()),
            ("built_at", now()),
            ("tools", tools.to_string()),
            (META_GATE_SHORT_BODY, DEFAULT_GATE_SHORT_BODY.to_string()),
            (META_GATE_MIN_DONORS, DEFAULT_GATE_MIN_DONORS.to_string()),
        ];
        for (key, value) in meta {
            db.execute("INSERT INTO meta(key, value) VALUES (?1, ?2)", params![key, value])?;
        }
        Ok(Self::wrap(db, min_body))
    }

    /// Opens a pack for appending donors (the build path).
    pub fn open_rw(path: &Path) -> Result<Pack> {
        Self::open_with(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
    }

    /// Opens a pack read-only (the apply path and every user).
    pub fn open(path: &Path) -> Result<Pack> {
        Self::open_with(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
    }

    fn open_with(path: &Path, flags: OpenFlags) -> Result<Pack> {
        if !path.is_file() {
            return Err(pack_error(format!("{}: no such fact pack", path.display())));
        }
        let db = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != FORMAT_VERSION {
            return Err(pack_error(format!(
                "{}: pack format {version}, this build reads {FORMAT_VERSION}",
                path.display()
            )));
        }
        let read = |key: &str| -> Result<String> {
            db.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| row.get(0))
                .map_err(|_| pack_error(format!("{}: pack has no `{key}` meta", path.display())))
        };
        let mask_version: u32 = read("mask_version")?
            .parse()
            .map_err(|_| pack_error("mask_version is not a number"))?;
        if mask_version != MASK_VERSION {
            return Err(pack_error(format!(
                "{}: pack was masked with rules v{mask_version}, this build applies v{MASK_VERSION}",
                path.display()
            )));
        }
        let min_body: usize = read("min_body")?
            .parse()
            .map_err(|_| pack_error("min_body is not a number"))?;
        Ok(Self::wrap(db, min_body))
    }

    fn wrap(db: Connection, min_body: usize) -> Pack {
        Pack {
            db,
            min_body,
            prefixes: RefCell::new(None),
            donor_games: RefCell::new(None),
            exclusion: RefCell::new(None),
        }
    }

    /// The shortest body the pack holds.
    pub fn min_body(&self) -> usize {
        self.min_body
    }

    /// One `meta` value.
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        match self.db.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| row.get(0)) {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Sets a gate parameter (`gate_short_body`, `gate_min_donors`); any other
    /// key is refused, because the rest of `meta` describes how the pack was
    /// built. The value must be a non-negative integer.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        if ![META_GATE_SHORT_BODY, META_GATE_MIN_DONORS].contains(&key) {
            return Err(pack_error(format!(
                "meta key `{key}` is not settable (only {META_GATE_SHORT_BODY}, {META_GATE_MIN_DONORS})"
            )));
        }
        let number: usize = value.parse().map_err(|_| pack_error(format!("{key}: `{value}` is not a number")))?;
        self.db.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, number.to_string()],
        )?;
        Ok(())
    }

    /// The rename gate this pack asks for: `meta` values, or the defaults
    /// when absent.
    pub fn gate(&self) -> Result<Gate> {
        let read = |key: &str, default: usize| -> Result<usize> {
            match self.meta(key)? {
                None => Ok(default),
                Some(text) => text.parse().map_err(|_| pack_error(format!("meta {key}: `{text}` is not a number"))),
            }
        };
        Ok(Gate {
            short_body: read(META_GATE_SHORT_BODY, DEFAULT_GATE_SHORT_BODY)?,
            min_donors: read(META_GATE_MIN_DONORS, DEFAULT_GATE_MIN_DONORS)?,
        })
    }

    /// Cheap identity of this pack's contents for reuse keys: build time,
    /// mask version and the body count.
    pub fn identity(&self) -> Result<String> {
        let bodies: i64 = self.db.query_row("SELECT count(*) FROM bodies", [], |row| row.get(0))?;
        Ok(format!(
            "{}:{}:{}",
            self.meta("built_at")?.unwrap_or_default(),
            MASK_VERSION,
            bodies
        ))
    }

    /// Runs `f` in one transaction: a build that fails half way leaves the
    /// pack as it was.
    pub fn batch<R>(&self, f: impl FnOnce(&Pack) -> Result<R>) -> Result<R> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        match f(self) {
            Ok(value) => {
                self.db.execute("UPDATE meta SET value = ?1 WHERE key = 'built_at'", params![now()])?;
                self.db.execute_batch("COMMIT")?;
                self.invalidate();
                Ok(value)
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn invalidate(&self) {
        *self.prefixes.borrow_mut() = None;
        *self.donor_games.borrow_mut() = None;
        *self.exclusion.borrow_mut() = None;
    }

    /// Records a donor, or updates the one with the same game id. Returns its
    /// row id.
    pub fn add_donor(&self, donor: &Donor) -> Result<i64> {
        self.db.execute(
            "INSERT INTO donors(game, platform, repo, \"commit\", license, truth_kind, twin_group, compiler)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(game) DO UPDATE SET platform = excluded.platform, repo = excluded.repo,
                 \"commit\" = excluded.\"commit\", license = excluded.license,
                 truth_kind = excluded.truth_kind, twin_group = excluded.twin_group,
                 compiler = excluded.compiler",
            params![
                donor.game,
                donor.platform,
                donor.repo,
                donor.commit,
                donor.license,
                donor.truth_kind,
                donor.twin_group,
                donor.compiler
            ],
        )?;
        self.invalidate();
        Ok(self
            .db
            .query_row("SELECT id FROM donors WHERE game = ?1", params![donor.game], |row| row.get(0))?)
    }

    /// Forgets every body a donor's program contributed, so a re-run of the
    /// same program replaces rather than duplicates (a duplicate would read
    /// as a stub).
    pub fn clear_program(&self, donor: i64, program: &str) -> Result<usize> {
        Ok(self.db.execute("DELETE FROM bodies WHERE donor = ?1 AND program = ?2", params![donor, program])?)
    }

    /// Adds one function body: masks `code` and stores its digests, never the
    /// bytes. Returns false (and stores nothing) when the body is shorter
    /// than the pack's `min_body`.
    pub fn add_body(
        &self,
        donor: i64,
        program: &str,
        family: Family,
        code: &[u8],
        name: &str,
        verified: bool,
    ) -> Result<bool> {
        if code.len() < self.min_body {
            return Ok(false);
        }
        let masked = mask(family, code);
        let prefix = prefix_of(&mask(family, &code[..PREFIX_BYTES]));
        *self.prefixes.borrow_mut() = None;
        let stored_name = if is_generic(name) || name.trim().is_empty() { None } else { Some(name) };
        self.db
            .prepare_cached(
                "INSERT INTO bodies(family, prefix, length, digest, name, donor, verified, program)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?
            .execute(params![
                family.as_str(),
                prefix,
                code.len() as i64,
                sha1(&masked).as_slice(),
                stored_name,
                donor,
                verified,
                program
            ])?;
        Ok(true)
    }

    /// Records the prototype declaration a donor gives a function name,
    /// replacing that donor's earlier one.
    pub fn add_prototype(&self, donor: i64, name: &str, decl: &str) -> Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO prototypes(name, donor, decl) VALUES (?1, ?2, ?3)",
            params![name, donor, decl],
        )?;
        Ok(())
    }

    /// Every donor, by game id.
    pub fn donors(&self) -> Result<Vec<Donor>> {
        let mut statement = self.db.prepare(
            "SELECT game, platform, repo, \"commit\", license, truth_kind, twin_group, compiler
             FROM donors ORDER BY game",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(Donor {
                    game: row.get(0)?,
                    platform: row.get(1)?,
                    repo: row.get(2)?,
                    commit: row.get(3)?,
                    license: row.get(4)?,
                    truth_kind: row.get(5)?,
                    twin_group: row.get(6)?,
                    compiler: row.get(7)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Stored body and prototype counts, for reports.
    pub fn counts(&self) -> Result<PackCounts> {
        let count = |sql: &str| -> Result<usize> {
            Ok(self.db.query_row(sql, [], |row| row.get::<_, i64>(0))? as usize)
        };
        Ok(PackCounts {
            donors: count("SELECT count(*) FROM donors")?,
            bodies: count("SELECT count(*) FROM bodies")?,
            named_bodies: count("SELECT count(*) FROM bodies WHERE name IS NOT NULL")?,
            prototypes: count("SELECT count(*) FROM prototypes")?,
        })
    }

    fn has_prefix(&self, prefix: i64) -> Result<bool> {
        if self.prefixes.borrow().is_none() {
            let mut statement = self.db.prepare("SELECT DISTINCT prefix FROM bodies")?;
            let set = statement
                .query_map([], |row| row.get::<_, i64>(0))?
                .collect::<std::result::Result<HashSet<_>, _>>()?;
            *self.prefixes.borrow_mut() = Some(set);
        }
        Ok(self.prefixes.borrow().as_ref().is_some_and(|set| set.contains(&prefix)))
    }

    fn with_games<R>(&self, f: impl FnOnce(&HashMap<i64, (String, Option<String>)>) -> R) -> Result<R> {
        if self.donor_games.borrow().is_none() {
            let mut statement = self.db.prepare("SELECT id, game, twin_group FROM donors")?;
            let map = statement
                .query_map([], |row| Ok((row.get::<_, i64>(0)?, (row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?))))?
                .collect::<std::result::Result<HashMap<_, _>, _>>()?;
            *self.donor_games.borrow_mut() = Some(map);
        }
        let guard = self.donor_games.borrow();
        Ok(f(guard.as_ref().expect("just filled")))
    }

    /// Donor ids removed by excluding `games`: the games themselves and every
    /// donor sharing a twin group with one of them. Cached for repeated calls
    /// with the same list (a scan probes thousands of offsets).
    fn excluded(&self, games: &[&str]) -> Result<HashSet<i64>> {
        if let Some((held, ids)) = self.exclusion.borrow().as_ref()
            && held.len() == games.len()
            && held.iter().zip(games).all(|(a, b)| a == b)
        {
            return Ok(ids.clone());
        }
        let ids = self.with_games(|map| {
            let groups: HashSet<&str> = map
                .values()
                .filter(|(game, _)| games.contains(&game.as_str()))
                .filter_map(|(_, group)| group.as_deref())
                .collect();
            map.iter()
                .filter(|(_, (game, group))| {
                    games.contains(&game.as_str()) || group.as_deref().is_some_and(|g| groups.contains(g))
                })
                .map(|(id, _)| *id)
                .collect::<HashSet<_>>()
        })?;
        *self.exclusion.borrow_mut() = Some((games.iter().map(|g| g.to_string()).collect(), ids.clone()));
        Ok(ids)
    }

    /// Everything the pack knows about the body at the start of `window`.
    ///
    /// `window` is the bytes from the candidate's start to the end of its
    /// mapping; the pack tells which prefix of it is a known body, by length.
    /// `exclude_games` (and their twin groups) are removed before consensus.
    /// A body occurring more than once inside one donor is a stub and names
    /// nothing for that donor.
    pub fn lookup(&self, family: Family, window: &[u8], exclude_games: &[&str]) -> Result<Vec<Candidate>> {
        if window.len() < self.min_body.max(PREFIX_BYTES) {
            return Ok(Vec::new());
        }
        let prefix = prefix_of(&mask(family, &window[..PREFIX_BYTES]));
        if !self.has_prefix(prefix)? {
            return Ok(Vec::new());
        }
        let excluded = self.excluded(exclude_games)?;
        let mut statement = self.db.prepare_cached(
            "SELECT length, digest, name, donor, verified FROM bodies WHERE family = ?1 AND prefix = ?2",
        )?;
        let rows = statement
            .query_map(params![family.as_str(), prefix], |row| {
                Ok(Row {
                    length: row.get::<_, i64>(0)? as usize,
                    digest: row.get(1)?,
                    name: row.get(2)?,
                    donor: row.get(3)?,
                    verified: row.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut lengths: Vec<usize> = rows.iter().map(|r| r.length).collect();
        lengths.sort_unstable();
        lengths.dedup();
        let mut found = Vec::new();
        for length in lengths.into_iter().filter(|&l| l <= window.len()) {
            let digest = sha1(&mask(family, &window[..length]));
            let matching: Vec<&Row> = rows
                .iter()
                .filter(|r| r.length == length && r.digest == digest && !excluded.contains(&r.donor))
                .collect();
            let mut per_donor: HashMap<i64, usize> = HashMap::new();
            for row in &matching {
                *per_donor.entry(row.donor).or_default() += 1;
            }
            let kept: Vec<&Row> = matching.into_iter().filter(|r| per_donor[&r.donor] == 1).collect();
            if kept.is_empty() {
                continue;
            }
            let mut candidate = self.consensus(length, &kept)?;
            candidate.compilers = self.compilers_of(&candidate.donors)?;
            found.push(candidate);
        }
        Ok(found)
    }

    fn consensus(&self, length: usize, rows: &[&Row]) -> Result<Candidate> {
        // normalized name -> spelling -> (count, verified)
        let mut groups: BTreeMap<String, BTreeMap<&str, (usize, bool)>> = BTreeMap::new();
        for row in rows {
            if let Some(name) = &row.name {
                let entry = groups.entry(normalize(name)).or_default().entry(name).or_default();
                entry.0 += 1;
                entry.1 |= row.verified;
            }
        }
        let games = |ids: &mut dyn Iterator<Item = i64>| -> Result<Vec<String>> {
            self.with_games(|map| {
                let mut games: Vec<String> = ids.filter_map(|id| map.get(&id).map(|(g, _)| g.clone())).collect();
                games.sort();
                games.dedup();
                games
            })
        };
        match groups.len() {
            0 => Ok(Candidate {
                length,
                name: None,
                donors: games(&mut rows.iter().map(|r| r.donor))?,
                verified: rows.iter().any(|r| r.verified),
                ambiguous: false,
                compilers: Vec::new(),
                independent: 0,
            }),
            1 => {
                let (key, spellings) = groups.iter().next().expect("one group");
                // Most used spelling; fewest leading underscores; then text order.
                let name = spellings
                    .iter()
                    .max_by_key(|(spelling, (count, _))| {
                        (*count, std::cmp::Reverse(spelling.len() - spelling.trim_start_matches('_').len()))
                    })
                    .map(|(spelling, _)| spelling.to_string())
                    .expect("a group has a spelling");
                debug_assert_eq!(normalize(&name), *key);
                Ok(Candidate {
                    length,
                    donors: games(&mut rows.iter().filter(|r| r.name.is_some()).map(|r| r.donor))?,
                    verified: rows.iter().any(|r| r.name.is_some() && r.verified),
                    name: Some(name),
                    ambiguous: false,
                    compilers: Vec::new(),
                    independent: self.independent(&mut rows.iter().filter(|r| r.name.is_some()).map(|r| r.donor))?,
                })
            }
            _ => Ok(Candidate {
                length,
                name: None,
                donors: games(&mut rows.iter().filter(|r| r.name.is_some()).map(|r| r.donor))?,
                verified: false,
                ambiguous: true,
                compilers: Vec::new(),
                independent: 0,
            }),
        }
    }

    /// Donors counted once per twin group (a donor without one counts alone).
    fn independent(&self, ids: &mut dyn Iterator<Item = i64>) -> Result<usize> {
        self.with_games(|map| {
            ids.filter_map(|id| map.get(&id))
                .map(|(game, group)| group.clone().unwrap_or_else(|| format!("game:{game}")))
                .collect::<HashSet<_>>()
                .len()
        })
    }

    /// Distinct compilers recorded for the given donor games.
    fn compilers_of(&self, games: &[String]) -> Result<Vec<String>> {
        let mut statement = self
            .db
            .prepare_cached("SELECT compiler FROM donors WHERE game = ?1 AND compiler IS NOT NULL")?;
        let mut out: Vec<String> = Vec::new();
        for game in games {
            for compiler in statement.query_map(params![game], |row| row.get::<_, String>(0))? {
                out.push(compiler?);
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// The donor record for a game id.
    pub fn donor(&self, game: &str) -> Result<Option<Donor>> {
        Ok(self.donors()?.into_iter().find(|d| d.game == game))
    }

    /// The prototype declaration for `name` among donors not excluded. Donors
    /// vote by type signature (return type and parameter types, parameter
    /// names ignored; see [`type_key`]); the most common signature wins and a
    /// tie gives none. The declaration returned is the most frequent full
    /// text within the winning signature, ties broken by text order.
    pub fn prototype(&self, name: &str, exclude_games: &[&str]) -> Result<Option<(String, Vec<String>)>> {
        let excluded = self.excluded(exclude_games)?;
        let mut statement = self.db.prepare_cached("SELECT donor, decl FROM prototypes WHERE name = ?1")?;
        let rows = statement
            .query_map(params![name], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut votes: BTreeMap<String, Vec<(i64, String)>> = BTreeMap::new();
        for (donor, decl) in rows {
            if !excluded.contains(&donor) {
                votes.entry(type_key(&decl)).or_default().push((donor, decl));
            }
        }
        let Some(best) = votes.values().map(Vec::len).max() else {
            return Ok(None);
        };
        let mut leaders = votes.into_values().filter(|donors| donors.len() == best);
        let winners = leaders.next().expect("a maximum exists");
        if leaders.next().is_some() {
            return Ok(None);
        }
        let mut texts: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, decl) in &winners {
            *texts.entry(decl).or_default() += 1;
        }
        // BTreeMap iterates in text order and `max_by_key` keeps the last maximum,
        // so walk it reversed to keep the first.
        let decl = texts
            .iter()
            .rev()
            .max_by_key(|(_, count)| **count)
            .map(|(decl, _)| decl.to_string())
            .expect("a winning signature has a text");
        let games = self.with_games(|map| {
            let mut games: Vec<String> =
                winners.iter().filter_map(|(id, _)| map.get(id).map(|(g, _)| g.clone())).collect();
            games.sort();
            games
        })?;
        Ok(Some((decl, games)))
    }
}

/// A declaration's type signature: return type and parameter types joined
/// with parameter names (and the function name) removed, whitespace around
/// `*` normalised, `...` kept, and a receiver named `this` kept as part of
/// its type. `memcpy(void * dst, ...)` and `memcpy(void *s1, ...)` share a key.
pub fn type_key(decl: &str) -> String {
    fn tokens(text: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut word = String::new();
        for c in text.chars() {
            if c.is_alphanumeric() || c == '_' {
                word.push(c);
                continue;
            }
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            if !c.is_whitespace() {
                out.push(c.to_string());
            }
        }
        if !word.is_empty() {
            out.push(word);
        }
        out
    }
    let identifier = |t: &str| t.starts_with(|c: char| c.is_alphabetic() || c == '_');
    let decl = decl.trim().trim_end_matches(';').trim();
    let (Some(open), true) = (decl.find('('), decl.ends_with(')')) else {
        return tokens(decl).join(" ");
    };
    let mut head = tokens(&decl[..open]);
    if head.last().is_some_and(|t| identifier(t)) {
        head.pop();
    }
    let mut parameters = Vec::new();
    for part in decl[open + 1..decl.len() - 1].split(',') {
        let mut words = tokens(part);
        let is_name = words.len() >= 2
            && words.last().is_some_and(|last| {
                identifier(last)
                    && last != "this"
                    && !matches!(last.as_str(), "int" | "char" | "short" | "long" | "unsigned" | "signed" | "float" | "double" | "void")
                    && !matches!(words[words.len() - 2].as_str(), "struct" | "union" | "enum")
            });
        if is_name {
            words.pop();
        }
        parameters.push(words.join(" "));
    }
    if parameters.len() == 1 && parameters[0] == "void" {
        parameters.clear();
    }
    format!("{}({})", head.join(" "), parameters.join(","))
}

/// The rename gate: a candidate shorter than `short_body` bytes renames only
/// when at least `min_donors` independent donors back its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Gate {
    pub short_body: usize,
    pub min_donors: usize,
}

impl Gate {
    /// Whether `candidate` is held back by the gate.
    pub fn holds(&self, candidate: &Candidate) -> bool {
        candidate.length < self.short_body && candidate.independent < self.min_donors
    }
}

/// Row counts of a pack.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct PackCounts {
    pub donors: usize,
    pub bodies: usize,
    pub named_bodies: usize,
    pub prototypes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// A MIPS body of `n` words: a prologue, `seed`-dependent immediates (the
    /// compiler's output, which survive masking), a masked call and a return.
    fn body(seed: u32, n: usize, jal_target: u32, hi: u32) -> Vec<u8> {
        let mut words = vec![0x27BD_FFE0, 0xAFBF_0018];
        for i in 0..n.saturating_sub(5) {
            words.push(0x2402_0000 | (seed + i as u32)); // addiu v0, zero, seed+i
        }
        words.push(0x0C00_0000 | jal_target);
        words.push(0x3C04_0000 | hi);
        words.push(0x03E0_0008);
        le(&words)
    }

    fn donor(game: &str, twin: Option<&str>) -> Donor {
        Donor {
            game: game.into(),
            platform: "ps2".into(),
            repo: format!("https://example.org/{game}"),
            commit: "abc123".into(),
            license: "MIT".into(),
            truth_kind: "decomp-build".into(),
            twin_group: twin.map(str::to_string),
            compiler: Some("test-cc 1.0".into()),
        }
    }

    fn pack_in(name: &str) -> (Pack, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("romwright-pack-{}-{name}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        (Pack::create(&path, 32, "test").expect("create"), path)
    }

    fn add(pack: &Pack, game: &str, bytes: &[u8], name: &str) {
        let id = pack.add_donor(&donor(game, None)).unwrap();
        pack.add_body(id, "main", Family::MipsLe, bytes, name, true).unwrap();
    }

    #[test]
    fn matches_across_relocations_and_returns_the_donor_facts() {
        let (pack, path) = pack_in("basic");
        add(&pack, "a", &body(10, 12, 0x1000, 0x8001), "ReadSector");
        // Another build: different link addresses, same function.
        let mut window = body(10, 12, 0x2468, 0x8123);
        window.extend_from_slice(&[0xFF; 64]); // whatever follows in memory
        let found = pack.lookup(Family::MipsLe, &window, &[]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].length, 48);
        assert_eq!(found[0].name.as_deref(), Some("ReadSector"));
        assert_eq!(found[0].donors, vec!["a".to_string()]);
        assert!(found[0].verified && !found[0].ambiguous);
        assert_eq!(found[0].compilers, vec!["test-cc 1.0".to_string()]);
        // A different body does not match.
        assert!(pack.lookup(Family::MipsLe, &body(99, 12, 0x1000, 0x8001), &[]).unwrap().is_empty());
        // Nor does the same bytes read as another family.
        assert!(pack.lookup(Family::MipsBe, &window, &[]).unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_pack_stores_digests_not_code() {
        let (pack, path) = pack_in("nocode");
        let code = body(10, 12, 0x1000, 0x8001);
        add(&pack, "a", &code, "ReadSector");
        drop(pack);
        let raw = std::fs::read(&path).unwrap();
        // Neither the raw nor the masked body appears anywhere in the file.
        let masked = mask(Family::MipsLe, &code);
        for needle in [&code[..16], &masked[..16], &code[16..32]] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle));
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn exclusions_remove_donors_and_their_twins_before_consensus() {
        let (pack, path) = pack_in("exclude");
        let code = body(10, 12, 0x1000, 0x8001);
        let a = pack.add_donor(&donor("rc", Some("rc"))).unwrap();
        let b = pack.add_donor(&donor("rc-pal", Some("rc"))).unwrap();
        let c = pack.add_donor(&donor("other", None)).unwrap();
        pack.add_body(a, "main", Family::MipsLe, &code, "Foo", false).unwrap();
        pack.add_body(b, "main", Family::MipsLe, &code, "Foo", true).unwrap();
        let both = pack.lookup(Family::MipsLe, &code, &[]).unwrap();
        assert_eq!(both[0].donors, vec!["rc".to_string(), "rc-pal".to_string()]);
        // Excluding one twin excludes the other: nothing remains.
        assert!(pack.lookup(Family::MipsLe, &code, &["rc"]).unwrap().is_empty());
        assert!(pack.lookup(Family::MipsLe, &code, &["rc-pal"]).unwrap().is_empty());
        // A third donor survives the twin exclusion.
        pack.add_body(c, "main", Family::MipsLe, &code, "Foo", false).unwrap();
        let rest = pack.lookup(Family::MipsLe, &code, &["rc-pal"]).unwrap();
        assert_eq!(rest[0].donors, vec!["other".to_string()]);
        // Excluding something that is not a donor changes nothing.
        assert_eq!(pack.lookup(Family::MipsLe, &code, &["nobody"]).unwrap().len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn disagreeing_donors_abstain_and_agreeing_spellings_merge() {
        let (pack, path) = pack_in("ambiguous");
        let code = body(10, 12, 0x1000, 0x8001);
        let (a, b, c) = (
            pack.add_donor(&donor("a", None)).unwrap(),
            pack.add_donor(&donor("b", None)).unwrap(),
            pack.add_donor(&donor("c", None)).unwrap(),
        );
        pack.add_body(a, "main", Family::MipsLe, &code, "strstr", false).unwrap();
        pack.add_body(b, "main", Family::MipsLe, &code, "_STRSTR", false).unwrap();
        let merged = pack.lookup(Family::MipsLe, &code, &[]).unwrap();
        assert_eq!(merged[0].name.as_deref(), Some("strstr"), "fewest underscores wins the tie");
        assert!(!merged[0].ambiguous);
        assert_eq!(merged[0].donors.len(), 2);
        pack.add_body(c, "main", Family::MipsLe, &code, "FindSubstring", false).unwrap();
        let split = pack.lookup(Family::MipsLe, &code, &[]).unwrap();
        assert!(split[0].ambiguous);
        assert_eq!(split[0].name, None);
        // Excluding the dissenter restores the consensus.
        assert_eq!(pack.lookup(Family::MipsLe, &code, &["c"]).unwrap()[0].name.as_deref(), Some("strstr"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn generic_names_occupy_the_body_but_name_nothing() {
        let (pack, path) = pack_in("generic");
        let code = body(10, 12, 0x1000, 0x8001);
        let (a, b) = (pack.add_donor(&donor("a", None)).unwrap(), pack.add_donor(&donor("b", None)).unwrap());
        pack.add_body(a, "main", Family::MipsLe, &code, "func_80123456", false).unwrap();
        let only_generic = pack.lookup(Family::MipsLe, &code, &[]).unwrap();
        assert_eq!(only_generic[0].name, None);
        assert!(!only_generic[0].ambiguous);
        assert_eq!(only_generic[0].donors, vec!["a".to_string()]);
        // A generic name never disagrees with a real one.
        pack.add_body(b, "main", Family::MipsLe, &code, "Real", false).unwrap();
        let named = pack.lookup(Family::MipsLe, &code, &[]).unwrap();
        assert_eq!(named[0].name.as_deref(), Some("Real"));
        assert_eq!(named[0].donors, vec!["b".to_string()]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_body_repeated_inside_one_donor_is_a_stub() {
        let (pack, path) = pack_in("stub");
        let code = body(10, 12, 0x1000, 0x8001);
        let (a, b) = (pack.add_donor(&donor("a", None)).unwrap(), pack.add_donor(&donor("b", None)).unwrap());
        pack.add_body(a, "main", Family::MipsLe, &code, "Thunk1", false).unwrap();
        pack.add_body(a, "main", Family::MipsLe, &code, "Thunk2", false).unwrap();
        assert!(pack.lookup(Family::MipsLe, &code, &[]).unwrap().is_empty(), "stubs name nothing");
        // Another donor holding it once still names it, and is not made ambiguous by the stubs.
        pack.add_body(b, "main", Family::MipsLe, &code, "Real", false).unwrap();
        let found = pack.lookup(Family::MipsLe, &code, &[]).unwrap();
        assert_eq!(found[0].name.as_deref(), Some("Real"));
        assert!(!found[0].ambiguous);
        // Re-adding a program replaces its bodies instead of making stubs.
        pack.clear_program(b, "main").unwrap();
        pack.add_body(b, "main", Family::MipsLe, &code, "Real", false).unwrap();
        assert_eq!(pack.lookup(Family::MipsLe, &code, &[]).unwrap().len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn short_bodies_are_not_stored_and_lengths_are_exact() {
        let (pack, path) = pack_in("length");
        let id = pack.add_donor(&donor("a", None)).unwrap();
        assert!(!pack.add_body(id, "main", Family::MipsLe, &body(1, 5, 0, 0), "Tiny", false).unwrap());
        let short = body(10, 10, 0x1000, 0x8001);
        let long = {
            let mut bytes = short.clone();
            bytes.extend_from_slice(&le(&[0x2402_0063, 0x03E0_0008]));
            bytes
        };
        pack.add_body(id, "main", Family::MipsLe, &short, "Short", false).unwrap();
        pack.add_body(id, "main", Family::MipsLe, &long, "Long", false).unwrap();
        let found = pack.lookup(Family::MipsLe, &long, &[]).unwrap();
        let lengths: Vec<_> = found.iter().map(|c| (c.length, c.name.clone().unwrap())).collect();
        assert_eq!(lengths, vec![(short.len(), "Short".into()), (long.len(), "Long".into())]);
        // A window shorter than the long body only reaches the short one.
        assert_eq!(pack.lookup(Family::MipsLe, &short, &[]).unwrap().len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn prototypes_follow_exclusions_and_majority() {
        let (pack, path) = pack_in("proto");
        let (a, b, c) = (
            pack.add_donor(&donor("a", None)).unwrap(),
            pack.add_donor(&donor("b", None)).unwrap(),
            pack.add_donor(&donor("c", None)).unwrap(),
        );
        pack.add_prototype(a, "Foo", "int Foo(int x)").unwrap();
        pack.add_prototype(b, "Foo", "int Foo(int y)").unwrap();
        pack.add_prototype(c, "Foo", "void Foo(void)").unwrap();
        // Donors agreeing on the types but naming the parameter differently vote together;
        // equal spellings tie to the lexicographically first.
        let (decl, games) = pack.prototype("Foo", &[]).unwrap().unwrap();
        assert_eq!(decl, "int Foo(int x)");
        assert_eq!(games, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(pack.prototype("Foo", &["a"]).unwrap(), None, "a one-one tie abstains");
        assert_eq!(pack.prototype("Foo", &["a", "b"]).unwrap().unwrap().0, "void Foo(void)");
        assert_eq!(pack.prototype("Bar", &[]).unwrap(), None);
        // Within the winning type key the most frequent full text wins.
        pack.add_prototype(c, "Baz", "int Baz(int y)").unwrap();
        pack.add_prototype(b, "Baz", "int Baz(int y)").unwrap();
        pack.add_prototype(a, "Baz", "int Baz(int x)").unwrap();
        assert_eq!(pack.prototype("Baz", &[]).unwrap().unwrap().0, "int Baz(int y)");
        assert_eq!(pack.prototype("Baz", &["b"]).unwrap().unwrap().0, "int Baz(int x)");
        assert_eq!(
            type_key("void * memcpy(void * dst, void * src, uint n)"),
            type_key("void *memcpy(void* s1, void *s2, uint count)")
        );
        assert_ne!(type_key("int f(int a)"), type_key("int f(uint a)"));
        assert_ne!(type_key("int f(int a)"), type_key("int f(int a, ...)"));
        assert_eq!(type_key("void f(void * this, int a)"), "void(void * this,int)");
        assert_eq!(type_key("int f(unsigned int, struct S * p)"), "int(unsigned int,struct S *)");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn independent_donors_count_a_twin_group_once() {
        let (pack, path) = pack_in("independent");
        let code = body(10, 12, 0x1000, 0x8001);
        let (a, b, c) = (
            pack.add_donor(&donor("rc", Some("rc"))).unwrap(),
            pack.add_donor(&donor("rc-pal", Some("rc"))).unwrap(),
            pack.add_donor(&donor("other", None)).unwrap(),
        );
        pack.add_body(a, "main", Family::MipsLe, &code, "Foo", false).unwrap();
        pack.add_body(b, "main", Family::MipsLe, &code, "Foo", false).unwrap();
        let found = pack.lookup(Family::MipsLe, &code, &[]).unwrap();
        assert_eq!((found[0].donors.len(), found[0].independent), (2, 1));
        pack.add_body(c, "main", Family::MipsLe, &code, "Foo", false).unwrap();
        assert_eq!(pack.lookup(Family::MipsLe, &code, &[]).unwrap()[0].independent, 2);
        let gate = pack.gate().unwrap();
        assert_eq!(gate, Gate { short_body: 128, min_donors: 2 });
        assert!(gate.holds(&found[0]) && !gate.holds(&pack.lookup(Family::MipsLe, &code, &[]).unwrap()[0]));
        pack.set_meta(META_GATE_MIN_DONORS, "3").unwrap();
        assert_eq!(pack.gate().unwrap().min_donors, 3);
        assert!(pack.set_meta("mask_version", "1").is_err());
        assert!(pack.set_meta(META_GATE_SHORT_BODY, "x").is_err());
        pack.db.execute("DELETE FROM meta WHERE key LIKE 'gate_%'", []).unwrap();
        assert_eq!(pack.gate().unwrap(), Gate { short_body: 128, min_donors: 2 }, "absent keys fall back");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn open_checks_format_and_mask_version() {
        let (pack, path) = pack_in("version");
        add(&pack, "a", &body(10, 12, 0x1000, 0x8001), "Foo");
        drop(pack);
        assert!(Pack::open(&path).is_ok());
        let db = Connection::open(&path).unwrap();
        db.execute("UPDATE meta SET value = '999' WHERE key = 'mask_version'", []).unwrap();
        drop(db);
        assert!(Pack::open(&path).err().unwrap().to_string().contains("rules v999"));
        let db = Connection::open(&path).unwrap();
        db.execute("UPDATE meta SET value = ?1 WHERE key = 'mask_version'", params![MASK_VERSION.to_string()]).unwrap();
        db.pragma_update(None, "user_version", 7).unwrap();
        drop(db);
        assert!(Pack::open(&path).err().unwrap().to_string().contains("pack format 7"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn generic_name_rules() {
        for generic in [
            "func_80123456", "FUN_00123456", "sub_1234ABCD", "fn_8001ABCD", "lbl_80123456",
            "Func_080000c0", "func_ABCDEF", "SomeThing_80123456", "unk_func_0800abcd",
        ] {
            assert!(is_generic(generic), "{generic}");
        }
        for real in ["ReadSector", "_strstr", "sub", "fn_main", "Func_Init", "lbl_loop", "memcpy", "func_1234"] {
            assert!(!is_generic(real), "{real}");
        }
        assert_eq!(normalize("__StrStr"), "strstr");
    }
}
