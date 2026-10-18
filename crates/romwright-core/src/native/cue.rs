//! CUE sheets: the text file that names a CD image's track files. A
//! PlayStation disc dump is a `.bin` (or one `.bin` per track) beside a `.cue`
//! (psx-spx "CDROM Disk Images": cue sheets; the cdrdao/CDRWIN cue grammar).
//! The importer reads the data track: the first `TRACK` whose mode is
//! `MODE1/*` or `MODE2/*`, in the `FILE` the sheet puts it in.
//!
//! Only what that needs is read: `FILE "name" BINARY` opens a file,
//! `TRACK nn MODE/size` a track, `INDEX nn mm:ss:ff` where it starts in the
//! file. `INDEX 01` of the data track must be the start of its file (every
//! one-file-per-track dump, and a one-file dump whose data track comes
//! first); a data track that starts later in a shared file is refused by
//! name rather than read from the wrong offset.

use super::{ImportError, Result};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// A cue sheet is a few hundred bytes; this is a generous bound, not a format.
const MAX_SHEET: u64 = 1 << 20;

/// The data track a sheet names.
#[derive(Debug, PartialEq, Eq)]
struct DataTrack {
    file: String,
    mode: String,
}

/// Splits a cue line into words, a double-quoted run being one word.
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let (mut quoted, mut started) = (false, false);
    for ch in line.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        out.push(current);
    }
    out
}

fn is_data_mode(mode: &str) -> bool {
    let upper = mode.to_ascii_uppercase();
    upper.starts_with("MODE1/") || upper.starts_with("MODE2/")
}

/// The first data track of the sheet and the file it lives in.
fn data_track(sheet: &str) -> Result<DataTrack> {
    let mut file: Option<String> = None;
    // (file, mode, INDEX 01 seen as `mm:ss:ff`) of the track being read.
    let mut track: Option<(String, String, Option<String>)> = None;
    for line in sheet.lines() {
        let line = line.trim_start_matches('\u{feff}');
        let word = words(line);
        match word.first().map(|first| first.to_ascii_uppercase()).as_deref() {
            Some("FILE") if word.len() >= 2 => file = Some(word[1].clone()),
            Some("TRACK") if word.len() >= 3 => {
                if let Some(done) = track.take().filter(|(_, mode, _)| is_data_mode(mode)) {
                    return finish(done);
                }
                let current = file
                    .clone()
                    .ok_or_else(|| ImportError::Bad("cue sheet: TRACK before any FILE".into()))?;
                track = Some((current, word[2].clone(), None));
            }
            Some("INDEX") if word.len() >= 3 && word[1] == "01" => {
                if let Some(current) = track.as_mut() {
                    current.2 = Some(word[2].clone());
                }
            }
            _ => {}
        }
    }
    match track.filter(|(_, mode, _)| is_data_mode(mode)) {
        Some(done) => finish(done),
        None => Err(ImportError::Bad("cue sheet names no data track (MODE1 or MODE2)".into())),
    }
}

fn finish((file, mode, start): (String, String, Option<String>)) -> Result<DataTrack> {
    match start.as_deref() {
        Some("00:00:00") | None => Ok(DataTrack { file, mode }),
        Some(other) => Err(ImportError::Bad(format!(
            "cue sheet: the data track starts at {other} in {file}, not at the start of its file"
        ))),
    }
}

/// `path` spelled as its directory entry is: a case-insensitive file system
/// (Windows, macOS) opens `disc.bin` for `Disc.BIN`, and the import should
/// carry the file's own name wherever the sheet's spelling happens to differ.
fn on_disk(path: PathBuf) -> PathBuf {
    let (Some(dir), Some(leaf)) = (path.parent(), path.file_name().and_then(|leaf| leaf.to_str())) else {
        return path;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return path;
    };
    let mut folded = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == leaf {
            return path;
        }
        if folded.is_none() && name.eq_ignore_ascii_case(leaf) {
            folded = Some(entry.path());
        }
    }
    folded.unwrap_or(path)
}

/// The track file as it sits beside the sheet: the name as written, with
/// either path separator, else the one directory entry that matches it
/// ignoring case (sheets travel between file systems). The path returned
/// carries the file's name as the directory spells it.
fn locate(dir: &Path, name: &str) -> Result<PathBuf> {
    let relative = PathBuf::from(name.replace('\\', "/"));
    let exact = dir.join(&relative);
    if exact.is_file() {
        return Ok(on_disk(exact));
    }
    if let Some(leaf) = relative.file_name().and_then(|leaf| leaf.to_str()) {
        let flat = dir.join(leaf);
        if flat.is_file() {
            return Ok(on_disk(flat));
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().eq_ignore_ascii_case(leaf) && entry.path().is_file() {
                    return Ok(entry.path());
                }
            }
        }
    }
    Err(ImportError::Bad(format!("cue sheet names {name}, which is not beside it")))
}

/// The file an import of `path` reads: `path` itself, unless it is a `.cue`
/// sheet, in which case the data track's `.bin` beside it.
pub(crate) fn resolve(path: &Path) -> Result<Cow<'_, Path>> {
    let is_cue = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("cue"));
    if !is_cue {
        return Ok(Cow::Borrowed(path));
    }
    let io = |error: std::io::Error| ImportError::Bad(format!("{}: {error}", path.display()));
    if std::fs::metadata(path).map_err(io)?.len() > MAX_SHEET {
        return Err(ImportError::Bad(format!("{}: too large for a cue sheet", path.display())));
    }
    let bytes = std::fs::read(path).map_err(io)?;
    let sheet = String::from_utf8_lossy(&bytes);
    let track = data_track(&sheet).map_err(|error| ImportError::Bad(format!("{}: {error}", path.display())))?;
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or(Path::new("."));
    Ok(Cow::Owned(locate(dir, &track.file)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_data_track_and_its_file_are_found() {
        let sheet = "FILE \"Game (USA).bin\" BINARY\r\n  TRACK 01 MODE2/2352\r\n    INDEX 01 00:00:00\r\n";
        assert_eq!(
            data_track(sheet).unwrap(),
            DataTrack { file: "Game (USA).bin".into(), mode: "MODE2/2352".into() }
        );
        // One file per track: the audio tracks after the data track are never read.
        let sheet = "FILE \"a.bin\" BINARY\n TRACK 01 MODE2/2352\n  INDEX 01 00:00:00\n\
                     FILE \"b.bin\" BINARY\n TRACK 02 AUDIO\n  INDEX 00 00:00:00\n  INDEX 01 00:02:00\n";
        assert_eq!(data_track(sheet).unwrap().file, "a.bin");
        // Audio first, data second, in a file of its own.
        let sheet = "FILE a.wav WAVE\n TRACK 01 AUDIO\n  INDEX 01 00:00:00\nFILE d.bin BINARY\n TRACK 02 MODE1/2048\n  INDEX 01 00:00:00\n";
        assert_eq!(data_track(sheet).unwrap().file, "d.bin");
    }

    #[test]
    fn a_data_track_inside_a_shared_file_is_refused_by_name() {
        let sheet = "FILE \"all.bin\" BINARY\n TRACK 01 AUDIO\n  INDEX 01 00:00:00\n TRACK 02 MODE2/2352\n  INDEX 00 03:10:00\n  INDEX 01 03:12:00\n";
        let error = data_track(sheet).unwrap_err().to_string();
        assert!(error.contains("03:12:00") && error.contains("all.bin"), "{error}");
    }

    #[test]
    fn sheets_without_a_data_track_or_a_file_are_refused() {
        assert!(data_track("FILE \"a.wav\" WAVE\n TRACK 01 AUDIO\n").is_err());
        assert!(data_track("TRACK 01 MODE2/2352\n").is_err());
        assert!(data_track("").is_err());
    }

    #[test]
    fn a_sheet_resolves_to_its_bin_and_other_files_pass_through() {
        let dir = std::env::temp_dir().join(format!("rw-cue-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Disc.BIN"), b"x").unwrap();
        // The sheet's spelling differs in case from the file on disk.
        std::fs::write(dir.join("Disc.cue"), "FILE \"disc.bin\" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n").unwrap();
        assert_eq!(resolve(&dir.join("Disc.cue")).unwrap(), dir.join("Disc.BIN"));
        let plain = dir.join("Disc.BIN");
        assert!(matches!(resolve(&plain).unwrap(), Cow::Borrowed(_)));
        std::fs::write(dir.join("Gone.cue"), "FILE \"gone.bin\" BINARY\n TRACK 01 MODE2/2352\n").unwrap();
        assert!(resolve(&dir.join("Gone.cue")).unwrap_err().to_string().contains("gone.bin"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
