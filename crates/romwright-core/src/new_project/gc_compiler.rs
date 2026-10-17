//! Which Metrowerks CodeWarrior a GameCube or Wii executable came from, as far
//! as the DOL itself says.
//!
//! A DOL carries no compiler stamp (no `.comment`, no symbol table), and the
//! one thing every game links, Nintendo's SDK, is built by Nintendo with
//! whatever CodeWarrior Nintendo then shipped, not the game studio's. What the
//! image does hold is:
//!
//! * the console (`RVL_SDK` / `Revolution` strings, the `0x80004000` load
//!   address of a Wii DOL, `MetroTRK for Revolution v0.N`);
//! * SDK library banners with build dates (`<< Dolphin SDK - OS release build:
//!   Nov 26 2003 ... >>`), which date the SDK and so bound the CodeWarrior
//!   releases the studio can have been using;
//! * the Metrowerks target-resident-kernel string.
//!
//! The answer is therefore an era class, not a build: a default compiler
//! directory (`GC/1.3.2`, `Wii/1.5`) for the evidence, a confidence, and the
//! evidence itself. `docs/new-project.md` lists how it did on the corpus.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Console {
    GameCube,
    Wii,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize)]
pub struct GcCompilerDetection {
    pub console: Console,
    /// `mwcc-gc` or `mwcc-wii`: the family ids `import` records.
    pub family: &'static str,
    /// The version class (`gc-2004`, `wii-2007-08`, ...): what the evidence supports.
    pub version_class: String,
    /// Compiler directory in the compilers bundle (`GC/2.6`, `Wii/1.5`).
    pub mw_version: &'static str,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    /// Latest SDK banner date as `(year, month)`.
    pub sdk_date: Option<(u32, u32)>,
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Every `<< Dolphin SDK - X ... build: Mon dd yyyy` / `<< RVL_SDK - ...` banner:
/// `(library, year, month)`.
fn banners(image: &[u8]) -> Vec<(String, u32, u32)> {
    let text = String::from_utf8_lossy(image);
    let mut out = Vec::new();
    for start in text.match_indices("<< ").map(|(i, _)| i) {
        let line: String = text[start..].chars().take(120).take_while(|c| *c != '\0' && *c != '\n').collect();
        if !(line.starts_with("<< Dolphin SDK") || line.starts_with("<< RVL_SDK") || line.starts_with("<< RVL_MWM")) {
            continue;
        }
        let Some(build) = line.find("build:") else { continue };
        let mut parts = line[build + 6..].split_whitespace();
        let (Some(month), Some(_day), Some(year)) = (parts.next(), parts.next(), parts.next()) else { continue };
        let (Some(month), Ok(year)) = (MONTHS.iter().position(|m| *m == month), year.parse::<u32>()) else { continue };
        let library = line.split('-').nth(1).and_then(|l| l.split_whitespace().next()).unwrap_or("").to_string();
        out.push((library, year, month as u32 + 1));
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// `MetroTRK for Revolution v0.N` -> `N`.
fn trk_revision(image: &[u8]) -> Option<u32> {
    let at = image.windows(25).position(|w| w == b"MetroTRK for Revolution v")?;
    let tail = &image[at + 25..image.len().min(at + 40)];
    let text = String::from_utf8_lossy(tail);
    text.strip_prefix("0.")?.chars().next()?.to_digit(10)
}

/// The era class and default compiler for `image` (a DOL's bytes) whose entry
/// point is `entry`.
pub fn detect_gc_compiler(image: &[u8], entry: u32) -> GcCompilerDetection {
    let mut evidence = Vec::new();
    let found = banners(image);
    let latest = found.iter().map(|(_, y, m)| (*y, *m)).max();
    let rvl_banner = found.iter().any(|(_, y, _)| *y >= 2006) && contains(image, b"<< RVL_SDK");
    let wii = rvl_banner || contains(image, b"Revolution OS") || contains(image, b"RVL SDK") || contains(image, b"MetroTRK for Revolution") || (0x8000_4000..0x8000_5000).contains(&entry) && !contains(image, b"<< Dolphin SDK");
    let console = if wii { Console::Wii } else { Console::GameCube };
    if wii {
        evidence.push("Wii SDK strings (`<< RVL_SDK`, `Revolution OS`, `MetroTRK for Revolution`) or a 0x80004000 load address".to_string());
    }
    if let Some((year, month)) = latest {
        evidence.push(format!(
            "{} SDK banners; the latest library build is {} {year}",
            found.len(),
            MONTHS[month as usize - 1]
        ));
    } else {
        evidence.push("no SDK banner strings (stripped, or an SDK before them)".to_string());
    }
    let trk = trk_revision(image);
    if let Some(n) = trk {
        evidence.push(format!("`MetroTRK for Revolution v0.{n}`"));
    }
    if contains(image, b"Metrowerks Target Resident Kernel") {
        evidence.push("Metrowerks Target Resident Kernel string".to_string());
    }
    let (family, class, version, confidence): (&'static str, String, &'static str, Confidence) = if wii {
        // Wii SDKs 2006-2008 (TRK 0.1) were built with the 3.0a CodeWarrior; the
        // 2009+ SDKs (TRK 0.4) with the Wii/1.x line.
        let late = trk.is_some_and(|n| n >= 4) || latest.is_some_and(|(y, _)| y >= 2009);
        match (late, latest) {
            (true, Some((y, _))) if y >= 2010 => ("mwcc-wii", format!("wii-{y}"), "Wii/1.5", Confidence::Medium),
            (true, _) => ("mwcc-wii", "wii-2009".to_string(), "Wii/1.3", Confidence::Medium),
            (false, _) => ("mwcc-wii", "wii-2006-2008".to_string(), "GC/3.0a5", Confidence::Medium),
        }
    } else {
        match latest {
            Some((y, m)) if (y, m) >= (2004, 9) => ("mwcc-gc", "gc-late-2004".to_string(), "GC/3.0a5", Confidence::Medium),
            Some((y, m)) if (y, m) >= (2004, 4) => ("mwcc-gc", "gc-2004".to_string(), "GC/1.3.2", Confidence::Low),
            Some((y, m)) if (y, m) >= (2003, 4) => ("mwcc-gc", "gc-2003-04".to_string(), "GC/2.6", Confidence::Medium),
            Some((y, m)) if (y, m) >= (2002, 6) => ("mwcc-gc", "gc-2002".to_string(), "GC/1.3.2", Confidence::Medium),
            Some(_) => ("mwcc-gc", "gc-2001".to_string(), "GC/1.2.5n", Confidence::Medium),
            None => ("mwcc-gc", "gc-unbannered".to_string(), "GC/1.3.2", Confidence::Low),
        }
    };
    GcCompilerDetection { console, family, version_class: class, mw_version: version, confidence, evidence, sdk_date: latest }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(strings: &[&str]) -> Vec<u8> {
        let mut image = vec![0u8; 64];
        for text in strings {
            image.extend_from_slice(text.as_bytes());
            image.push(0);
        }
        image
    }

    #[test]
    fn banners_date_the_sdk_and_pick_an_era() {
        let image = with(&[
            "<< Dolphin SDK - AI\trelease build: Apr 17 2003 12:33:54 (0x2301) >>",
            "<< Dolphin SDK - OS\trelease build: Nov 26 2003 05:18:37 (0x2301) >>",
        ]);
        let found = detect_gc_compiler(&image, 0x8000_5240);
        assert_eq!(found.console, Console::GameCube);
        assert_eq!(found.sdk_date, Some((2003, 11)));
        assert_eq!(found.mw_version, "GC/2.6");
    }

    #[test]
    fn a_revolution_sdk_is_a_wii_and_trk_revision_separates_the_eras() {
        let early = with(&["<< RVL_SDK - AI \trelease build: Aug  8 2007 01:58:12 (0x4199_60831) >>", "MetroTRK for Revolution v0.1"]);
        let late = with(&["<< RVL_SDK - AI \trelease build: Aug 23 2010 17:29:47 (0x4302_145) >>", "MetroTRK for Revolution v0.4"]);
        assert_eq!(detect_gc_compiler(&early, 0x8000_4100).console, Console::Wii);
        assert_eq!(detect_gc_compiler(&early, 0x8000_4100).mw_version, "GC/3.0a5");
        assert_eq!(detect_gc_compiler(&late, 0x8000_4100).mw_version, "Wii/1.5");
    }

    #[test]
    fn no_banner_is_a_low_confidence_default() {
        let found = detect_gc_compiler(&with(&["Metrowerks Target Resident Kernel for PowerPC"]), 0x8000_5240);
        assert_eq!(found.confidence, Confidence::Low);
        assert_eq!(found.mw_version, "GC/1.3.2");
    }
}
