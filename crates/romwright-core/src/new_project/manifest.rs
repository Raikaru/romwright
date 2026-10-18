//! The pinned tool manifest: where a generated project fetches its build
//! tools from, and the sha256 every download must match.
//!
//! The table is data (`toolchains.json`, embedded at build time), so a pin can
//! be updated by editing the file. romwright itself never downloads or bundles
//! a tool: it writes the entries a project needs into `config/toolchain.json`,
//! and the generated `tools/download_tool.py` does the fetching and checking.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

const BUILTIN: &str = include_str!("toolchains.json");
pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    /// `raw`, `tar.gz`, `tar.xz` or `zip`.
    pub archive: String,
    /// Archive members to extract (path prefixes); empty extracts everything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolEntry {
    pub id: String,
    pub version: String,
    /// `binutils`, `runtime`, `compiler`, `support` (an assembler pass or the
    /// binutils a compiler drives), `cross-compiler` (clang, for the
    /// non-matching scaffolds' compile check) or `report`.
    pub role: String,
    pub platform: String,
    /// Compiler family (`mwcc-ps2`, `ee-gcc`); compilers only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// How the executable runs: `wibo` (Windows .exe) or `i386-linux`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Compiler driver path inside the extracted archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    /// Logical tool name -> member name, for multi-tool archives.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provides: BTreeMap<String, String>,
    /// Other manifest tools this one needs installed next to it (a gcc's
    /// binutils, the PSY-Q compiler's wibo and maspsx).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    pub license: String,
    pub provenance: String,
    /// Host key (`linux-x86_64`, `macos-arm64`, `windows-x86_64`, `any`) -> asset.
    pub assets: BTreeMap<String, Asset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub revision: String,
    #[serde(default)]
    pub note: String,
    pub tools: Vec<ToolEntry>,
}

impl Manifest {
    /// The table compiled into this build.
    pub fn builtin() -> Manifest {
        Manifest::parse(BUILTIN).expect("toolchains.json is validated by a unit test")
    }

    pub fn parse(text: &str) -> Result<Manifest, String> {
        let manifest: Manifest = serde_json::from_str(text).map_err(|e| format!("tool manifest: {e}"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn tool(&self, id: &str) -> Option<&ToolEntry> {
        self.tools.iter().find(|tool| tool.id == id)
    }

    /// Every entry names real bytes: https (or file, for offline copies) URL,
    /// a 64-digit sha256, a known archive kind, and unique ids.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err(format!("tool manifest schema {} (this romwright reads {SCHEMA})", self.schema));
        }
        let mut seen = std::collections::BTreeSet::new();
        for tool in &self.tools {
            if !seen.insert(tool.id.as_str()) {
                return Err(format!("tool manifest: duplicate id `{}`", tool.id));
            }
            if tool.assets.is_empty() {
                return Err(format!("tool manifest: `{}` has no assets", tool.id));
            }
            if tool.license.trim().is_empty() || tool.provenance.trim().is_empty() {
                return Err(format!("tool manifest: `{}` must record license and provenance", tool.id));
            }
            for (host, asset) in &tool.assets {
                let sha_ok = asset.sha256.len() == 64 && asset.sha256.bytes().all(|b| b.is_ascii_hexdigit());
                if !sha_ok {
                    return Err(format!("tool manifest: `{}`/{host}: sha256 must be 64 hex digits", tool.id));
                }
                if !(asset.url.starts_with("https://") || asset.url.starts_with("file://")) {
                    return Err(format!("tool manifest: `{}`/{host}: url must be https:// or file://", tool.id));
                }
                if !matches!(asset.archive.as_str(), "raw" | "tar.gz" | "tar.xz" | "zip") {
                    return Err(format!("tool manifest: `{}`/{host}: unknown archive `{}`", tool.id, asset.archive));
                }
            }
        }
        Ok(())
    }

    /// The entries named by `ids`, in that order; an unknown id is an error.
    pub fn subset(&self, ids: &[&str]) -> Result<Manifest, String> {
        let mut tools = Vec::new();
        for id in ids {
            let tool = self.tool(id).ok_or_else(|| {
                format!("tool `{id}` is not in the manifest (known compilers: {})", self.compiler_ids().join(", "))
            })?;
            if !tools.iter().any(|t: &ToolEntry| t.id == tool.id) {
                tools.push(tool.clone());
            }
        }
        Ok(Manifest { schema: self.schema, revision: self.revision.clone(), note: self.note.clone(), tools })
    }

    pub fn compiler_ids(&self) -> Vec<&str> {
        self.tools.iter().filter(|t| t.role == "compiler").map(|t| t.id.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_manifest_is_valid_and_pins_every_tool_a_ps2_project_uses() {
        let manifest = Manifest::builtin();
        for id in ["binutils-mips-ps2-decompals", "wibo", "objdiff-cli", "mwcps2-3.0.1b210-060308", "ee-gcc2.9-991111"] {
            assert!(manifest.tool(id).is_some(), "{id}");
        }
        let b210 = manifest.tool("mwcps2-3.0.1b210-060308").unwrap();
        assert_eq!(b210.runtime.as_deref(), Some("wibo"));
        assert_eq!(b210.entry.as_deref(), Some("mwccps2.exe"));
        // Every default the detector can suggest is a manifest compiler.
        for id in [
            "mwcps2-2.3.3-000906",
            "mwcps2-3.0.1b210-060308",
            "ee-gcc2.96",
            "ee-gcc2.9-991111",
            "ee-gcc3.2-030926",
            "ee-gcc2.95.3-136",
            "ee-gcc2.95.2-273a",
        ] {
            assert_eq!(manifest.tool(id).map(|t| t.role.as_str()), Some("compiler"), "{id}");
        }
    }

    #[test]
    fn mips_platform_compilers_pin_what_they_drive() {
        let manifest = Manifest::builtin();
        // Every default a MIPS detector can suggest is a manifest compiler of its platform, and its requirements exist.
        for (id, platform) in [
            ("ido5.3", "n64"),
            ("ido7.1", "n64"),
            ("gcc2.7.2kmc", "n64"),
            ("gcc2.8.1pm", "n64"),
            ("psyq3.5", "psx"),
            ("psyq4.0", "psx"),
            ("psyq4.3", "psx"),
            ("psp-gcc-1.7.1", "psp"),
            ("mwccpsp-3.0.1-219", "psp"),
        ] {
            let tool = manifest.tool(id).unwrap_or_else(|| panic!("{id}"));
            assert_eq!((tool.role.as_str(), tool.platform.as_str()), ("compiler", platform), "{id}");
            for required in &tool.requires {
                assert!(manifest.tool(required).is_some(), "{id} requires {required}");
            }
        }
        assert_eq!(manifest.tool("gcc2.7.2kmc").unwrap().requires, ["binutils-mips-2.6"]);
        assert!(manifest.tool("maspsx").unwrap().assets.values().all(|a| a.archive == "zip"));
    }

    #[test]
    fn rejects_unpinned_or_insecure_entries() {
        let mut manifest = Manifest::builtin();
        manifest.tools[0].assets.values_mut().next().unwrap().sha256 = "abc".into();
        assert!(manifest.validate().unwrap_err().contains("sha256"));
        let mut manifest = Manifest::builtin();
        manifest.tools[0].assets.values_mut().next().unwrap().url = "http://example.com/x".into();
        assert!(manifest.validate().unwrap_err().contains("https"));
    }

    #[test]
    fn subset_keeps_order_and_reports_unknown_ids() {
        let manifest = Manifest::builtin();
        let subset = manifest.subset(&["wibo", "binutils-mips-ps2-decompals", "wibo"]).unwrap();
        assert_eq!(subset.tools.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), ["wibo", "binutils-mips-ps2-decompals"]);
        assert!(manifest.subset(&["nope"]).unwrap_err().contains("nope"));
    }

    #[test]
    fn arm_binutils_has_a_windows_asset_that_extracts_only_the_standalone_tools() {
        let manifest = Manifest::builtin();
        let binutils = manifest.tool("binutils-arm-none-eabi").unwrap();
        let asset = &binutils.assets["windows-x86_64"];
        assert_eq!(asset.archive, "zip");
        assert_eq!(asset.sha256, "e46fda043c0ce83582bc8db4b3ef85f77f4beb7333344c2f4193c17e1167a095");
        assert_eq!(asset.size, 297_871_203);
        // One version-named top directory; the members are exact paths (download_tool.py matches prefixes).
        let wanted: Vec<String> = ["as", "ld", "nm", "objcopy", "objdump", "readelf"]
            .iter()
            .map(|tool| format!("arm-gnu-toolchain-13.3.rel1-mingw-w64-i686-arm-none-eabi/bin/arm-none-eabi-{tool}.exe"))
            .collect();
        assert_eq!(asset.include, wanted);
    }
}
