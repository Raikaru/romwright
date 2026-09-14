//! Shared trace-hook vocabulary for every emulator adapter.
//!
//! Each protocol client converts its own breakpoint/stop/watchpoint hit
//! into a [`TraceHit`]. A hit serializes to exactly one `import-trace`
//! CSV row (`addr,kind[,thread]`), which is the durable feed into the
//! `trace_events` table (m20-011 path): the CLI parses that CSV and marks
//! `exec`/`call`/`bp` addresses traced. Provenance is always
//! `emulator:<name>` so trace-derived facts stay distinguishable from
//! static analysis.

/// Event kinds accepted by the `import-trace` ingest path.
pub const IMPORT_TRACE_KINDS: &[&str] = &["exec", "call", "read", "write", "bp"];

/// One trace event kind, restricted to what `import-trace` understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceKind {
    Exec,
    Call,
    Read,
    Write,
    Bp,
}

impl TraceKind {
    /// The `import-trace` CSV spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Call => "call",
            Self::Read => "read",
            Self::Write => "write",
            Self::Bp => "bp",
        }
    }

    /// Parses an `import-trace` kind spelling.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "exec" => Some(Self::Exec),
            "call" => Some(Self::Call),
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "bp" => Some(Self::Bp),
            _ => None,
        }
    }
}

/// One breakpoint/watchpoint/sample hit, ready to feed `trace_events`.
///
/// `provenance` is always `emulator:<name>` (e.g. `emulator:ppsspp`);
/// `thread` is empty when the emulator does not attribute the hit to a
/// thread (PPSSPP hit broadcasts carry no thread id; GDB-RSP stops
/// likewise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceHit {
    pub address: u64,
    pub kind: TraceKind,
    pub thread: String,
    pub provenance: String,
}

impl TraceHit {
    /// Builds a hit for `emulator` (bare name, e.g. `"mgba"`).
    pub fn new(address: u64, kind: TraceKind, emulator: &str) -> Self {
        Self {
            address,
            kind,
            thread: String::new(),
            provenance: format!("emulator:{emulator}"),
        }
    }

    /// Attaches a thread/context label (melonDS core, PPSSPP thread uid).
    pub fn with_thread(mut self, thread: impl Into<String>) -> Self {
        self.thread = thread.into();
        self
    }

    /// Exactly one `import-trace` CSV row: `addr,kind[,thread]`.
    pub fn to_csv_row(&self) -> String {
        if self.thread.is_empty() {
            format!("{:x},{}", self.address, self.kind.as_str())
        } else {
            format!("{:x},{},{}", self.address, self.kind.as_str(), self.thread)
        }
    }
}

/// An ordered batch of hits; [`TraceBatch::to_csv`] is directly consumable
/// by `import-trace <program> <trace.csv>`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TraceBatch {
    hits: Vec<TraceHit>,
}

impl TraceBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, hit: TraceHit) {
        self.hits.push(hit);
    }

    pub fn len(&self) -> usize {
        self.hits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }

    pub fn hits(&self) -> &[TraceHit] {
        &self.hits
    }

    /// Multi-line CSV document, one row per hit plus a trailing newline.
    /// Empty batches render as an empty document.
    pub fn to_csv(&self) -> String {
        let mut out = String::new();
        for hit in &self.hits {
            out.push_str(&hit.to_csv_row());
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip_through_import_trace_spellings() {
        for kind in IMPORT_TRACE_KINDS {
            let parsed = TraceKind::parse(kind).expect("documented kind parses");
            assert_eq!(parsed.as_str(), *kind);
        }
        assert_eq!(TraceKind::parse("breakpoint"), None);
    }

    #[test]
    fn csv_rows_match_import_trace_shape() {
        let bare = TraceHit::new(0x0880_4010, TraceKind::Exec, "ppsspp");
        assert_eq!(bare.to_csv_row(), "8804010,exec");
        assert_eq!(bare.provenance, "emulator:ppsspp");

        let threaded = TraceHit::new(0x200_0100, TraceKind::Bp, "melonds")
            .with_thread("arm9");
        assert_eq!(threaded.to_csv_row(), "2000100,bp,arm9");

        // Every emitted kind must be one import-trace accepts.
        for kind in [TraceKind::Exec, TraceKind::Call, TraceKind::Read, TraceKind::Write, TraceKind::Bp] {
            assert!(IMPORT_TRACE_KINDS.contains(&TraceKind::parse(kind.as_str()).unwrap().as_str()));
        }
    }

    #[test]
    fn batch_csv_is_import_trace_document() {
        let mut batch = TraceBatch::new();
        assert!(batch.is_empty());
        batch.push(TraceHit::new(0x1000, TraceKind::Exec, "mgba"));
        batch.push(TraceHit::new(0x1004, TraceKind::Write, "mgba"));
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.to_csv(), "1000,exec\n1004,write\n");

        // The rows must survive the same split the CLI performs.
        for line in batch.to_csv().lines() {
            let mut fields = line.split(',');
            let addr = u64::from_str_radix(fields.next().unwrap(), 16).unwrap();
            let kind = fields.next().unwrap();
            assert!(addr > 0 && TraceKind::parse(kind).is_some());
        }
    }
}
