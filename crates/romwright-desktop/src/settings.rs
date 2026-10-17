//! Per-user preferences (Qt `QSettings("Romwright", "Romwright")`): theme,
//! recent projects and the dock layout saved per program. Headless modes do
//! not read or write them, so a gate run is independent of the user's desk.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

const RECENT: usize = 10;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub recent_projects: Vec<String>,
    /// Serialized `egui_dock::DockState<String>` keyed by program ("" when
    /// no program is open), as Qt scoped `windowState` by program.
    #[serde(default)]
    pub layouts: BTreeMap<String, serde_json::Value>,
}

impl Settings {
    pub fn path() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
        Some(base.join("romwright").join("desktop.json"))
    }

    /// A missing or unreadable file is an empty preference set, not an error
    /// that keeps the window from opening.
    pub fn load() -> Self {
        Self::path()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::path().ok_or("no configuration directory")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
        std::fs::rename(&temporary, &path).map_err(|error| error.to_string())
    }

    pub fn remember_project(&mut self, project: &str) {
        self.recent_projects.retain(|path| path != project);
        self.recent_projects.insert(0, project.to_string());
        self.recent_projects.truncate(RECENT);
    }
}
