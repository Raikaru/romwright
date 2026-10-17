//! Per-game segment layouts for Nintendo 64 ROMs whose code is packed.
//!
//! A retail cartridge rarely holds its code where the CPU runs it: the boot
//! code (or the game's own loader) unpacks segments from the ROM into RDRAM,
//! and some games page overlays in and out of the same addresses. What the
//! ROM header names is only the first stage. The rest is the game's own
//! convention, so the loader needs a per-game description of where each
//! segment lives in the ROM, how it is compressed and where it runs.
//!
//! The description is data, not code: `n64_layouts.json` is a catalog of
//! layouts, each detected from the header (the two CRC words at 0x10 and
//! 0x14 and the game code at 0x3b, n64brew "ROM header") and each a list of
//! segments. A segment is one or more ROM parts (each raw or packed with a
//! [`Codec`]) decoded and concatenated, placed at a fixed address, at the
//! header's boot address, or right after another segment. `load` produces
//! one mapping and one module row per segment, so cross-segment calls are
//! module-to-module references, as for GameCube RELs.
//!
//! A layout is checked as it is applied: every ROM range must lie inside the
//! ROM, each decoded segment must have the size the layout expects, and no
//! two segments may overlap. A layout that fails any of these is an error
//! the caller reports; it is never applied in part.
//!
//! Limits. Only layouts in the catalog are written down. A ROM the catalog
//! does not list is laid out by `n64_discovery` from its own bytes where
//! the evidence settles it, and imports through the linear boot-segment view
//! (what the stock Ghidra N64 loader also builds) where it does not. The
//! catalog stays for what discovery cannot prove: Perfect Dark's segments
//! run at TLB-mapped addresses (`0x7...`), which no byte of the ROM carries.
//! `Layout::from_json` takes a description of a game the catalog does not
//! list, and `n64_overlays` places caller-supplied overlays through the same
//! codecs.

use super::n64_codec::Codec;
use super::{Mapping, NativeModule};
use serde::Deserialize;
use std::sync::LazyLock;

const CATALOG: &str = include_str!("n64_layouts.json");
/// ROM header: the two CRC words and the game code (n64brew "ROM header").
const CRC1: usize = 0x10;
const CRC2: usize = 0x14;
const GAME_CODE: usize = 0x3b;
/// No segment of a retail game unpacks past RDRAM with the Expansion Pak.
const SEGMENT_LIMIT: usize = 8 << 20;

fn hex<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        Plain(u64),
        Text(String),
    }
    match Number::deserialize(deserializer)? {
        Number::Plain(value) => Ok(value),
        Number::Text(text) => {
            let digits = text.strip_prefix("0x").unwrap_or(&text);
            u64::from_str_radix(digits, 16).map_err(serde::de::Error::custom)
        }
    }
}

fn hex_pair<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(u64, u64), D::Error> {
    #[derive(Deserialize)]
    struct Item(#[serde(deserialize_with = "hex")] u64);
    let [start, end] = <[Item; 2]>::deserialize(deserializer)?;
    Ok((start.0, end.0))
}

fn hex_option<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    struct Item(#[serde(deserialize_with = "hex")] u64);
    Ok(Option::<Item>::deserialize(deserializer)?.map(|item| item.0))
}

fn codec(name: &str) -> Result<Codec, String> {
    Ok(match name {
        "raw" => Codec::Raw,
        "deflate" => Codec::Deflate,
        "rare-1172" => Codec::Rare1172,
        "rare-1172-sized" => Codec::Rare1172Sized,
        "rare-1173" => Codec::Rare1173,
        "mio0" => Codec::Mio0,
        "yay0" => Codec::Yay0,
        "yaz0" => Codec::Yaz0,
        other => match other.strip_prefix("rare-1173-pages:") {
            Some(page) => Codec::Rare1173Pages {
                page: page.parse().map_err(|_| format!("bad page size in codec {other:?}"))?,
            },
            None => return Err(format!("unknown codec {other:?}")),
        },
    })
}

#[derive(Debug, Deserialize)]
struct RawPart {
    #[serde(deserialize_with = "hex_pair")]
    rom: (u64, u64),
    codec: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawPlace {
    Keyword(String),
    At {
        #[serde(deserialize_with = "hex")]
        at: u64,
    },
    After {
        after: String,
        #[serde(deserialize_with = "hex")]
        plus: u64,
    },
}

#[derive(Debug, Deserialize)]
struct RawSegment {
    name: String,
    /// `r`, `w`, `x` in any combination.
    flags: String,
    /// `overlay` for a segment the game swaps; code and data otherwise.
    #[serde(default)]
    kind: Option<String>,
    place: RawPlace,
    #[serde(default, deserialize_with = "hex_option")]
    size: Option<u64>,
    parts: Vec<RawPart>,
}

#[derive(Debug, Deserialize)]
struct RawDetect {
    #[serde(deserialize_with = "hex")]
    crc1: u64,
    #[serde(deserialize_with = "hex")]
    crc2: u64,
    game_code: String,
}

#[derive(Debug, Deserialize)]
struct RawLayout {
    id: String,
    title: String,
    detect: RawDetect,
    segments: Vec<RawSegment>,
}

/// Where a segment runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    /// The header's boot address.
    Boot,
    At(u64),
    /// The end of an earlier segment plus a constant.
    After { segment: String, plus: u64 },
}

#[derive(Clone, Debug)]
pub struct Part {
    pub rom: (u64, u64),
    pub codec: Codec,
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub flags: u64,
    pub kind: String,
    pub place: Place,
    /// The decoded size the layout expects, when it knows.
    pub size: Option<u64>,
    pub parts: Vec<Part>,
}

#[derive(Clone, Debug)]
pub struct Layout {
    pub id: String,
    pub title: String,
    pub crc1: u32,
    pub crc2: u32,
    pub game_code: [u8; 4],
    pub segments: Vec<Segment>,
}

impl Layout {
    /// Parses one layout, or an array of them, from the catalog's JSON.
    pub fn from_json(text: &str) -> Result<Vec<Layout>, String> {
        let raws: Vec<RawLayout> = match serde_json::from_str::<Vec<RawLayout>>(text) {
            Ok(many) => many,
            Err(_) => vec![serde_json::from_str(text).map_err(|error| format!("layout JSON: {error}"))?],
        };
        raws.into_iter().map(Layout::from_raw).collect()
    }

    fn from_raw(raw: RawLayout) -> Result<Layout, String> {
        let id = raw.id.clone();
        let fail = |message: String| format!("layout {id}: {message}");
        let game_code: [u8; 4] = raw
            .detect
            .game_code
            .as_bytes()
            .try_into()
            .map_err(|_| fail("game_code must be four ASCII characters".into()))?;
        let mut segments = Vec::new();
        for segment in raw.segments {
            let mut flags = 0;
            for letter in segment.flags.chars() {
                flags |= match letter {
                    'w' => 1,
                    'r' => 2,
                    'x' => 4,
                    other => return Err(fail(format!("segment {}: unknown flag {other:?}", segment.name))),
                };
            }
            let place = match segment.place {
                RawPlace::Keyword(word) if word == "boot" => Place::Boot,
                RawPlace::Keyword(word) => {
                    return Err(fail(format!("segment {}: unknown place {word:?}", segment.name)))
                }
                RawPlace::At { at } => Place::At(at),
                RawPlace::After { after, plus } => {
                    if !segments.iter().any(|earlier: &Segment| earlier.name == after) {
                        return Err(fail(format!("segment {} follows {after:?}, which is not an earlier segment", segment.name)));
                    }
                    Place::After { segment: after, plus }
                }
            };
            let parts = segment
                .parts
                .iter()
                .map(|part| Ok(Part { rom: part.rom, codec: codec(&part.codec)? }))
                .collect::<Result<Vec<_>, String>>()
                .map_err(|message| fail(format!("segment {}: {message}", segment.name)))?;
            let kind = segment.kind.unwrap_or_else(|| if flags & 4 != 0 { "code".into() } else { "data".into() });
            segments.push(Segment { name: segment.name, flags, kind, place, size: segment.size, parts });
        }
        Ok(Layout {
            id: raw.id,
            title: raw.title,
            crc1: raw.detect.crc1 as u32,
            crc2: raw.detect.crc2 as u32,
            game_code,
            segments,
        })
    }

    fn matches(&self, rom: &[u8]) -> bool {
        let word = |at: usize| rom.get(at..at + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        word(CRC1) == Some(self.crc1)
            && word(CRC2) == Some(self.crc2)
            && rom.get(GAME_CODE..GAME_CODE + 4) == Some(&self.game_code[..])
    }
}

/// The layouts this build knows.
pub fn catalog() -> &'static [Layout] {
    static LAYOUTS: LazyLock<Vec<Layout>> =
        LazyLock::new(|| Layout::from_json(CATALOG).expect("built-in N64 layout catalog is valid"));
    &LAYOUTS
}

/// The catalog's layout for `rom`, by its header.
pub fn detect(rom: &[u8]) -> Option<&'static Layout> {
    catalog().iter().find(|layout| layout.matches(rom))
}

/// The segments of a layout applied to a ROM.
#[derive(Debug)]
pub struct Placed {
    pub mappings: Vec<Mapping>,
    pub names: Vec<String>,
    pub modules: Vec<NativeModule>,
}

/// Decodes and places every segment of `layout`.
pub fn load(layout: &Layout, rom: &[u8], boot: u64) -> Result<Placed, String> {
    let fail = |message: String| format!("{}: {message}", layout.id);
    let mut placed = Placed { mappings: Vec::new(), names: Vec::new(), modules: Vec::new() };
    for segment in &layout.segments {
        let mut bytes = Vec::new();
        for part in &segment.parts {
            let (start, end) = part.rom;
            let source = usize::try_from(start)
                .ok()
                .zip(usize::try_from(end).ok())
                .and_then(|(start, end)| rom.get(start..end))
                .ok_or_else(|| {
                    fail(format!("segment {}: ROM range {start:#x}..{end:#x} is outside the {:#x}-byte ROM", segment.name, rom.len()))
                })?;
            let decoded = part
                .codec
                .decode(source, SEGMENT_LIMIT)
                .map_err(|error| fail(format!("segment {} ({} at {start:#x}): {error}", segment.name, part.codec.name())))?;
            bytes.extend_from_slice(&decoded);
        }
        if let Some(expected) = segment.size
            && bytes.len() as u64 != expected {
                return Err(fail(format!(
                    "segment {} decodes to {:#x} bytes, the layout says {expected:#x}",
                    segment.name,
                    bytes.len()
                )));
            }
        let vaddr = match &segment.place {
            Place::Boot => boot,
            Place::At(address) => *address,
            Place::After { segment: earlier, plus } => {
                let index = layout.segments.iter().position(|s| &s.name == earlier).unwrap_or(usize::MAX);
                let mapping = placed
                    .mappings
                    .get(index)
                    .ok_or_else(|| fail(format!("segment {} follows {earlier:?}, which is not placed yet", segment.name)))?;
                mapping.vaddr + mapping.size + plus
            }
        };
        let size = bytes.len() as u64;
        if let Some(clash) = placed.mappings.iter().zip(&placed.names).find(|(m, _)| vaddr < m.vaddr + m.size && m.vaddr < vaddr + size) {
            return Err(fail(format!("segment {} overlaps {} in RDRAM", segment.name, clash.1)));
        }
        let first = segment.parts.first().map_or(0, |part| part.rom.0);
        let last = segment.parts.last().map_or(0, |part| part.rom.1);
        placed.modules.push(NativeModule {
            name: segment.name.clone(),
            kind: segment.kind.clone(),
            file_id: format!("rom:{first:#x}-{last:#x}"),
            load_vaddr: vaddr,
            size,
            file_off: first,
        });
        placed.names.push(segment.name.clone());
        placed.mappings.push(Mapping { vaddr, size, file_off: first, flags: segment.flags, bytes });
    }
    Ok(placed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rare(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x11, 0x73, (data.len() >> 16) as u8, (data.len() >> 8) as u8, data.len() as u8];
        out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
        out
    }

    fn rom_with(crc1: u32, crc2: u32, code: &[u8; 4], length: usize) -> Vec<u8> {
        let mut rom = vec![0u8; length];
        rom[CRC1..CRC1 + 4].copy_from_slice(&crc1.to_be_bytes());
        rom[CRC2..CRC2 + 4].copy_from_slice(&crc2.to_be_bytes());
        rom[GAME_CODE..GAME_CODE + 4].copy_from_slice(code);
        rom
    }

    const TEST_LAYOUT: &str = r#"{
        "id": "synthetic", "title": "synthetic",
        "detect": {"crc1": "0x11111111", "crc2": "0x22222222", "game_code": "NTST"},
        "segments": [
          {"name": "boot", "flags": "rx", "place": "boot", "size": "0x10",
           "parts": [{"rom": ["0x1000", "0x1010"], "codec": "raw"}]},
          {"name": "main", "flags": "rwx", "place": {"at": "0x80100000"},
           "parts": [{"rom": ["0x2000", "0x2010"], "codec": "raw"}, {"rom": ["0x3000", "0x3400"], "codec": "rare-1173"}]},
          {"name": "data", "flags": "rw", "place": {"after": "main", "plus": "0x10"},
           "parts": [{"rom": ["0x4000", "0x4400"], "codec": "rare-1173"}]}
        ]
    }"#;

    fn synthetic_rom() -> Vec<u8> {
        let mut rom = rom_with(0x1111_1111, 0x2222_2222, b"NTST", 0x8000);
        rom[0x1000..0x1010].copy_from_slice(&[0xAA; 16]);
        rom[0x2000..0x2010].copy_from_slice(&[0xBB; 16]);
        let main: Vec<u8> = (0..0x400u32).map(|i| (i * 7) as u8).collect();
        let packed = rare(&main);
        rom[0x3000..0x3000 + packed.len()].copy_from_slice(&packed);
        let data = vec![0xCCu8; 0x400];
        let packed = rare(&data);
        rom[0x4000..0x4000 + packed.len()].copy_from_slice(&packed);
        rom
    }

    #[test]
    fn the_shipped_catalog_parses() {
        let layouts = catalog();
        assert!(layouts.iter().any(|l| l.id == "perfect-dark-ntsc-final"));
        let pd = &layouts[0];
        assert_eq!(pd.segments.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["preamble", "lib-boot", "lib", "data", "inflate", "game"]);
        assert_eq!(pd.segments[3].place, Place::After { segment: "lib".into(), plus: 0x1000_0000 });
    }

    #[test]
    fn a_layout_places_raw_and_packed_parts_and_names_modules() {
        let layout = &Layout::from_json(TEST_LAYOUT).unwrap()[0];
        let rom = synthetic_rom();
        assert!(layout.matches(&rom));
        let placed = load(layout, &rom, 0x8000_1000).unwrap();
        assert_eq!(placed.names, ["boot", "main", "data"]);
        assert_eq!(placed.mappings[0].vaddr, 0x8000_1000);
        assert_eq!(placed.mappings[1].vaddr, 0x8010_0000);
        assert_eq!(placed.mappings[1].size, 0x410);
        assert_eq!(&placed.mappings[1].bytes[..16], &[0xBB; 16]);
        assert_eq!(placed.mappings[1].bytes[16 + 3], 3 * 7);
        // `after` is the end of main plus the constant.
        assert_eq!(placed.mappings[2].vaddr, 0x8010_0000 + 0x410 + 0x10);
        assert_eq!(placed.modules[2].file_id, "rom:0x4000-0x4400");
        assert_eq!(placed.modules[0].kind, "code");
        assert_eq!(placed.modules[2].kind, "data");
    }

    #[test]
    fn detection_needs_both_crcs_and_the_game_code() {
        let layout = &Layout::from_json(TEST_LAYOUT).unwrap()[0];
        assert!(!layout.matches(&rom_with(0x1111_1111, 0x2222_2223, b"NTST", 0x8000)));
        assert!(!layout.matches(&rom_with(0x1111_1111, 0x2222_2222, b"NTSX", 0x8000)));
        assert!(detect(&rom_with(0, 0, b"NTST", 0x8000)).is_none());
    }

    #[test]
    fn a_wrong_size_or_overlap_or_range_is_an_error() {
        let mut layouts = Layout::from_json(TEST_LAYOUT).unwrap();
        let rom = synthetic_rom();
        layouts[0].segments[0].size = Some(0x20);
        assert!(load(&layouts[0], &rom, 0x8000_1000).unwrap_err().contains("decodes to 0x10"));

        let mut layout = Layout::from_json(TEST_LAYOUT).unwrap().remove(0);
        layout.segments[1].place = Place::At(0x8000_1008);
        assert!(load(&layout, &rom, 0x8000_1000).unwrap_err().contains("overlaps boot"));

        let mut layout = Layout::from_json(TEST_LAYOUT).unwrap().remove(0);
        layout.segments[2].parts[0].rom = (0x7f00, 0x8100);
        assert!(load(&layout, &rom, 0x8000_1000).unwrap_err().contains("outside"));

        // A packed part that is not what the layout says names the segment.
        let mut broken = rom.clone();
        broken[0x3001] = 0x72;
        let layout = Layout::from_json(TEST_LAYOUT).unwrap().remove(0);
        let error = load(&layout, &broken, 0x8000_1000).unwrap_err();
        assert!(error.contains("segment main") && error.contains("magic"), "{error}");
    }

    #[test]
    fn bad_layout_json_is_refused_by_name() {
        let bad = TEST_LAYOUT.replace("rare-1173", "lzss");
        assert!(Layout::from_json(&bad).unwrap_err().contains("unknown codec"));
        let bad = TEST_LAYOUT.replace("\"after\": \"main\"", "\"after\": \"nowhere\"");
        assert!(Layout::from_json(&bad).unwrap_err().contains("not an earlier segment"));
        let bad = TEST_LAYOUT.replace("\"rx\"", "\"rq\"");
        assert!(Layout::from_json(&bad).unwrap_err().contains("unknown flag"));
    }
}
