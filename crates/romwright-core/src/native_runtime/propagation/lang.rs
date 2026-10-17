//! What the propagation reads off the language, once per image.
//!
//! The decompiler console answered these from its `Architecture`: the address
//! spaces, the stack pointer and default prototype of the compiler spec
//! (`ProtoModel::decode` for `<unaffected>`, `<killedbycall>`,
//! `<returnaddress>`, `extrapop` and the `<input>`/`<output>` entry lists in
//! `fspec.cc`; `Architecture::parseStackPointer`, `defaultReturnAddr` in
//! `architecture.cc`) and the type factory (`TypeFactory::getSizeOfPointer`,
//! `type.cc`). Ghidra 12.1.3 is Apache-2.0; the behaviours below are those
//! sources', restricted to what the propagation asks of them.
use super::super::lift::SleighLifter;
use super::state::Word;
use kuna_base::space::spacetype;
use kuna_base::xml::Element;
use kuna_num::float::FloatFormat;
use kuna_num::opbehavior::FloatFormatProvider;
use kuna_sleigh::translate::Translate;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SpaceKind {
    Constant,
    /// `IPTR_PROCESSOR`: RAM, registers.
    Processor,
    /// `IPTR_INTERNAL`: the unique space.
    Internal,
    Other,
}

#[derive(Clone, Debug)]
pub(super) struct SpaceInfo {
    pub kind: SpaceKind,
    pub word_size: u64,
    pub addr_size: u32,
    pub highest: u64,
    pub big_endian: bool,
}

impl SpaceInfo {
    /// `AddrSpace::wrapOffset`.
    pub fn wrap(&self, offset: u64) -> u64 {
        if offset <= self.highest {
            return offset;
        }
        let modulus = self.highest.wrapping_add(1) as i64;
        let mut result = (offset as i64).wrapping_rem(modulus);
        if result < 0 {
            result = result.wrapping_add(modulus);
        }
        result as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Storage {
    pub space: i32,
    pub offset: Word,
    pub size: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EffectKind {
    Unaffected,
    KilledByCall,
    ReturnAddress,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
struct EffectRecord {
    storage: Storage,
    kind: EffectKind,
}

/// `ProtoModel::extrapop_unknown`.
pub(super) const EXTRAPOP_UNKNOWN: i32 = 0x8000;

/// One `<callfixup>` of the compiler spec: the p-code that replaces a call
/// to a function whose name (here: whose pattern label) is one of `targets`.
pub(super) struct CallFixup {
    pub name: String,
    pub targets: Vec<String>,
    pub body: String,
}

/// One `<callotherfixup>`: the p-code that replaces every use of a user-defined
/// operation (`SetThumbMode`'s `setISAMode` becomes `r0 = r0`).
pub(super) struct CallotherFixup {
    pub userop: u64,
    pub name: String,
    pub body: String,
}

pub(super) struct Lang {
    pub spaces: Vec<SpaceInfo>,
    pub data_space: i32,
    pub code_space: i32,
    pub unique_space: i32,
    pub constant_space: i32,
    pub space_names: Vec<String>,
    /// `Architecture::defaultReturnAddr`: where a function finds its return address.
    pub return_address: Option<Storage>,
    /// The compiler spec's call fixups in the order the injection library
    /// keeps them (by name), which is the order a label is matched in.
    pub callfixups: Vec<CallFixup>,
    /// The compiler spec's user-op fixups (`setISAMode` is a no-op copy).
    pub callotherfixups: Vec<CallotherFixup>,
    pub pointer_size: i32,
    pub big_endian: bool,
    /// `Translate::getAlignment`.
    pub alignment: u32,
    /// The stack pointer the cspec names (`getSpacebase(0)` of the stack space).
    pub stack_pointer: Option<Storage>,
    /// The language's own `ISAModeSwitch` register.
    pub mode_register: Option<Storage>,
    pub x86: bool,
    pub extra_pop: i32,
    effects: Vec<EffectRecord>,
    /// Where the default prototype puts a pointer-sized unsigned return value
    /// (index 0) and each of eight pointer-sized unsigned arguments
    /// (`ProtoModel::assignParameterStorage`); `None` for storage that is not
    /// a processor-space varnode (the stack). An error when the model cannot
    /// place the arguments.
    pub pointer_storage: Result<Vec<Option<Storage>>, String>,
}

/// `Address::decode` on a `<register>`, `<addr>` or `<varnode>` element.
fn decode_varnode(lifter: &SleighLifter, element: &Element, default_size: i32) -> Option<Storage> {
    let sleigh = &lifter.sleigh;
    match element.get_name() {
        "register" => {
            let name = element.get_attribute_value("name").ok()?;
            let varnode = sleigh.get_register_varnode(name).ok()?;
            Some(Storage {
                space: varnode.space.as_ref()?.get_index(),
                offset: varnode.offset,
                size: varnode.size as i32,
            })
        }
        "addr" | "varnode" => {
            let space = element.get_attribute_value("space").ok()?;
            let space = sleigh.base().manager().get_space_by_name(&String::from_utf8_lossy(space))?;
            let offset = parse_integer(&String::from_utf8_lossy(element.get_attribute_value("offset").ok()?))?;
            let size = element
                .get_attribute_value("size")
                .ok()
                .and_then(|size| parse_integer(&String::from_utf8_lossy(size)))
                .map_or(default_size, |size| size as i32);
            Some(Storage { space: space.get_index(), offset, size })
        }
        _ => None,
    }
}

fn parse_integer(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

fn children<'a>(element: &'a Element, name: &'a str) -> impl Iterator<Item = &'a Rc<Element>> {
    element.get_children().iter().filter(move |child| child.get_name() == name)
}

fn attribute(element: &Element, name: &str) -> Option<String> {
    element.get_attribute_value(name).ok().map(|value| String::from_utf8_lossy(value).into_owned())
}

/// One `<pentry>`: where a parameter of a class and size range is stored.
struct ParamEntry {
    /// `None` for storage outside the language's spaces (the stack, a join).
    storage: Option<Storage>,
    minsize: i32,
    size: i32,
    /// Slot width of an aligned entry; 0 when the entry is one slot.
    alignment: i32,
    numslots: i32,
    general: bool,
    big_endian_space: bool,
    /// `force_left_justify`.
    left_justified: bool,
    overlapping: bool,
    group_set: Vec<i32>,
}

impl ParamEntry {
    /// `ParamEntry::getAddrBySlot` for the registers and slots the
    /// propagation can name: the address in the entry's space, or `None` when
    /// the size does not fit or no slot is left.
    fn address_by_slot(&self, slot: &mut i32, size: i32) -> Option<Option<Storage>> {
        if size < self.minsize {
            return None;
        }
        let used;
        let mut offset = self.storage.map_or(0, |s| s.offset);
        if self.alignment == 0 {
            if *slot != 0 || size > self.size {
                return None;
            }
            used = self.size;
        } else {
            let slots = (size + self.alignment - 1) / self.alignment;
            if *slot + slots > self.numslots {
                return None;
            }
            used = slots * self.alignment;
            offset += (*slot * self.alignment) as u64;
            *slot += slots;
        }
        let justify_right = !(self.left_justified || !self.big_endian_space);
        if justify_right {
            offset += (used - size) as u64;
        }
        Some(self.storage.map(|s| Storage { space: s.space, offset, size }))
    }
}

/// `ParamListStandard`: ordered entries and the number of resource groups.
struct ParamList {
    entries: Vec<ParamEntry>,
    numgroup: i32,
}

impl ParamList {
    /// `ParamEntry::decode` of one `<pentry>` in `group`.
    fn decode_entry(lifter: &SleighLifter, element: &Element, group: i32, earlier: &[ParamEntry], spaces: &[SpaceInfo]) -> ParamEntry {
        let minsize = attribute(element, "minsize").and_then(|v| v.parse().ok()).unwrap_or(-1);
        let size = attribute(element, "maxsize").and_then(|v| v.parse().ok()).unwrap_or(-1);
        let mut alignment: i32 = attribute(element, "align")
            .or_else(|| attribute(element, "size"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let class = attribute(element, "storage").or_else(|| attribute(element, "metatype"));
        let general = matches!(class.as_deref(), None | Some("general") | Some("unknown"));
        if alignment == size {
            alignment = 0;
        }
        let numslots = if alignment != 0 { size / alignment } else { 1 };
        let storage = element.get_children().first().and_then(|child| decode_varnode(lifter, child, size));
        let space_info = storage.map(|s| &spaces[s.space as usize]);
        let mut entry = ParamEntry {
            storage,
            minsize,
            size,
            alignment,
            numslots,
            general,
            big_endian_space: space_info.is_some_and(|s| s.big_endian),
            left_justified: false,
            overlapping: false,
            group_set: vec![group],
        };
        // `resolveOverlap`: an entry that contains earlier ones takes their
        // groups, so using it uses them up (an earlier entry that itself
        // overlaps counted its resources already).
        if let Some(own) = entry.storage {
            let own_end = own.offset + entry.size.max(0) as u64;
            let mut overlap: Vec<i32> = Vec::new();
            for before in earlier {
                let Some(other) = before.storage else { continue };
                let other_end = other.offset + before.size.max(0) as u64;
                if other.space != own.space || other.offset >= own_end || own.offset >= other_end {
                    continue;
                }
                if own.offset <= other.offset && other_end <= own_end && !before.overlapping {
                    overlap.extend(before.group_set.iter().copied());
                }
            }
            if !overlap.is_empty() {
                overlap.sort_unstable();
                entry.group_set = overlap;
                entry.overlapping = true;
            }
        }
        entry
    }

    fn decode(lifter: &SleighLifter, list: &Element, spaces: &[SpaceInfo]) -> Self {
        let mut entries: Vec<ParamEntry> = Vec::new();
        let mut numgroup = 0;
        for child in list.get_children().iter() {
            let members: Vec<(&Element, i32)> = match child.get_name() {
                "pentry" => vec![(&**child, numgroup)],
                "group" => children(child, "pentry").map(|member| (&**member, numgroup)).collect(),
                _ => continue,
            };
            let base = numgroup;
            for (member, group) in members {
                let entry = Self::decode_entry(lifter, member, group, &entries, spaces);
                numgroup = numgroup.max(entry.group_set.last().copied().unwrap_or(0) + 1);
                entries.push(entry);
            }
            let _ = base;
        }
        Self { entries, numgroup }
    }

    /// `ParamListStandard::assignAddressFallback` for a general-class value.
    fn assign(&self, status: &mut [i32], size: i32) -> Option<Option<Storage>> {
        for entry in &self.entries {
            let group = entry.group_set[0] as usize;
            if status[group] < 0 || !entry.general {
                continue;
            }
            let mut slot = status[group];
            let Some(address) = entry.address_by_slot(&mut slot, size) else { continue };
            status[group] = slot;
            // An entry that holds one parameter exclusively (`isExclusion`)
            // takes up all the groups it overlaps.
            if entry.alignment == 0 {
                for &taken in &entry.group_set {
                    status[taken as usize] = -1;
                }
            }
            return Some(address);
        }
        None
    }
}

/// `FloatFormatProvider` over the formats the translator knows.
pub(super) struct Formats(Vec<(i32, FloatFormat)>);

impl FloatFormatProvider for Formats {
    fn get_float_format(&self, size: i32) -> Option<&FloatFormat> {
        self.0.iter().find(|(known, _)| *known == size).map(|(_, format)| format)
    }
}

impl Lang {
    /// The language's float formats, else the IEEE single and double the
    /// decompiler installs by default (`Translate::setDefaultFloats`).
    pub fn formats(lifter: &SleighLifter) -> Formats {
        let mut formats: Vec<(i32, FloatFormat)> = (1..=16)
            .filter_map(|size| lifter.sleigh.get_float_format(size).map(|format| (size, format.clone())))
            .collect();
        if formats.is_empty() {
            formats = vec![(4, FloatFormat::new(4)), (8, FloatFormat::new(8))];
        }
        Formats(formats)
    }

    pub fn new(lifter: &SleighLifter, language: &str) -> Result<Self, String> {
        let sleigh = &lifter.sleigh;
        let manager = sleigh.base().manager();
        let spaces: Vec<SpaceInfo> = (0..manager.num_spaces())
            .map(|index| match manager.get_space(index) {
                Some(space) => SpaceInfo {
                    kind: match space.get_type() {
                        spacetype::IPTR_CONSTANT => SpaceKind::Constant,
                        spacetype::IPTR_PROCESSOR => SpaceKind::Processor,
                        spacetype::IPTR_INTERNAL => SpaceKind::Internal,
                        _ => SpaceKind::Other,
                    },
                    word_size: u64::from(space.get_word_size()),
                    addr_size: space.get_addr_size(),
                    highest: space.get_highest(),
                    big_endian: space.is_big_endian(),
                },
                None => SpaceInfo { kind: SpaceKind::Other, word_size: 1, addr_size: 0, highest: 0, big_endian: false },
            })
            .collect();
        let code_space = lifter.code_space.get_index();
        let pspec = lifter.pspec().map_err(|error| error.to_string())?;
        let cspec = lifter.cspec().map_err(|error| error.to_string())?;
        let data_space = children(pspec, "data_space")
            .filter_map(|child| child.get_attribute_value("space").ok())
            .filter_map(|name| manager.get_space_by_name(&String::from_utf8_lossy(name)))
            .last()
            .map_or(code_space, |space| space.get_index());
        let unique_space = manager
            .get_unique_space()
            .map(|space| space.get_index())
            .ok_or("SLEIGH: no unique space")?;
        let constant_space = manager
            .get_constant_space()
            .map(|space| space.get_index())
            .ok_or("SLEIGH: no constant space")?;
        let space_names: Vec<String> = (0..manager.num_spaces())
            .map(|index| manager.get_space(index).map_or_else(String::new, |space| space.get_name().to_string()))
            .collect();
        let stack_pointer = children(cspec, "stackpointer").next().and_then(|element| {
            let name = element.get_attribute_value("register").ok()?;
            let varnode = sleigh.get_register_varnode(name).ok()?;
            Some(Storage { space: varnode.space.as_ref()?.get_index(), offset: varnode.offset, size: varnode.size as i32 })
        });
        let mode_register = sleigh.get_register_varnode(b"ISAModeSwitch").ok().and_then(|varnode| {
            Some(Storage { space: varnode.space.as_ref()?.get_index(), offset: varnode.offset, size: varnode.size as i32 })
        });
        let pointer_size = children(cspec, "data_organization")
            .flat_map(|organization| children(organization, "pointer_size"))
            .filter_map(|element| attribute(element, "value").and_then(|value| value.parse().ok()))
            .last()
            .unwrap_or(spaces[data_space as usize].addr_size as i32);
        let default_return = children(cspec, "returnaddress")
            .next()
            .and_then(|element| element.get_children().first().and_then(|child| decode_varnode(lifter, child, 0)));
        let proto = children(cspec, "default_proto")
            .flat_map(|default| children(default, "prototype"))
            .next()
            .ok_or("compiler spec has no default prototype")?;
        let extra_pop = match attribute(proto, "extrapop").as_deref() {
            Some("unknown") => EXTRAPOP_UNKNOWN,
            Some(value) => value.parse::<i32>().map_err(|_| "bad extrapop")?,
            None => return Err("default prototype has no extrapop".into()),
        };
        let mut effects: Vec<EffectRecord> = Vec::new();
        let mut sawretaddr = false;
        let strategy = attribute(proto, "strategy").unwrap_or_default();
        if !(strategy.is_empty() || strategy == "standard") {
            return Err(format!("unsupported parameter strategy {strategy}"));
        }
        let mut input = None;
        let mut output = None;
        for child in proto.get_children().iter() {
            let kind = match child.get_name() {
                "input" | "output" => {
                    let list = ParamList::decode(lifter, child, &spaces);
                    // `<input killedbycall="true">`: every register entry of
                    // the list is killed by a call (`parsePentry`).
                    if attribute(child, "killedbycall").as_deref() == Some("true") {
                        for entry in children(child, "pentry").chain(children(child, "group").flat_map(|g| children(g, "pentry"))) {
                            if let Some(storage) = entry.get_children().first().and_then(|c| decode_varnode(lifter, c, 0)) {
                                if spaces[storage.space as usize].kind == SpaceKind::Processor {
                                    let size = attribute(entry, "maxsize").and_then(|v| v.parse().ok()).unwrap_or(storage.size);
                                    effects.push(EffectRecord { storage: Storage { size, ..storage }, kind: EffectKind::KilledByCall });
                                }
                            }
                        }
                    }
                    if child.get_name() == "input" {
                        input = Some(list);
                    } else {
                        output = Some(list);
                    }
                    continue;
                }
                "unaffected" => EffectKind::Unaffected,
                "killedbycall" => EffectKind::KilledByCall,
                "returnaddress" => {
                    sawretaddr = true;
                    EffectKind::ReturnAddress
                }
                _ => continue,
            };
            for entry in child.get_children().iter() {
                if let Some(storage) = decode_varnode(lifter, entry, 0) {
                    effects.push(EffectRecord { storage, kind });
                }
            }
        }
        if !sawretaddr {
            if let Some(storage) = default_return {
                effects.push(EffectRecord { storage, kind: EffectKind::ReturnAddress });
            }
        }
        effects.sort_by_key(|effect| (effect.storage.space, effect.storage.offset));
        let pointer_storage = Self::assign_pointer_storage(input.as_ref(), output.as_ref(), pointer_size);
        let mut callfixups: Vec<CallFixup> = children(cspec, "callfixup")
            .filter_map(|fixup| {
                let body = children(fixup, "pcode")
                    .flat_map(|pcode| children(pcode, "body"))
                    .map(|body| String::from_utf8_lossy(body.get_content()).into_owned())
                    .next()?;
                Some(CallFixup {
                    name: attribute(fixup, "name")?,
                    targets: children(fixup, "target").filter_map(|target| attribute(target, "name")).collect(),
                    body,
                })
            })
            .collect();
        callfixups.sort_by(|left, right| left.name.cmp(&right.name));
        // The user ops a `<callotherfixup>` replaces, by their index in the
        // language (the first input of a CALLOTHER).
        let userops = lifter.user_op_names();
        let callotherfixups: Vec<CallotherFixup> = children(cspec, "callotherfixup")
            .filter_map(|fixup| {
                let target = attribute(fixup, "targetop")?;
                let userop = userops.iter().position(|name| *name == target)?;
                let body = children(fixup, "pcode")
                    .flat_map(|pcode| children(pcode, "body"))
                    .map(|body| String::from_utf8_lossy(body.get_content()).into_owned())
                    .next()?;
                Some(CallotherFixup { userop: userop as u64, name: target, body })
            })
            .collect();
        Ok(Self {
            spaces,
            data_space,
            code_space,
            unique_space,
            constant_space,
            space_names,
            return_address: default_return,
            callfixups,
            callotherfixups,
            pointer_size,
            big_endian: sleigh.translate_base().is_big_endian(),
            alignment: sleigh.translate_base().get_alignment() as u32,
            stack_pointer,
            mode_register,
            x86: language.starts_with("x86:"),
            extra_pop,
            effects,
            pointer_storage,
        })
    }

    /// `ProtoModel::assignParameterStorage` for one `uint` return value and
    /// eight `uint` parameters of pointer size, with the model's rules
    /// reduced to the fallback assignment: for an unsigned integer the
    /// pinned specs' `any` rules (`join`, `consume`) take the first free
    /// general entry the fallback takes.
    fn assign_pointer_storage(
        input: Option<&ParamList>,
        output: Option<&ParamList>,
        size: i32,
    ) -> Result<Vec<Option<Storage>>, String> {
        let mut result = Vec::with_capacity(9);
        let returned = output.and_then(|list| list.assign(&mut vec![0; list.numgroup as usize], size));
        // A return value the model cannot place is assumed void, and the
        // hidden return pointer then takes the first argument slot: neither
        // the pinned specs' integer entries nor this tool reach it.
        let hidden = output.is_some() && returned.is_none();
        result.push(returned.flatten());
        if hidden {
            return Err("the default prototype cannot place a pointer-sized return value".into());
        }
        let list = input.ok_or("default prototype has no input list")?;
        let mut status = vec![0; list.numgroup as usize];
        for _ in 0..8 {
            match list.assign(&mut status, size) {
                Some(storage) => result.push(storage),
                None => return Err("Cannot assign parameter address for uint".into()),
            }
        }
        Ok(result)
    }

    pub fn space(&self, index: i32) -> &SpaceInfo {
        &self.spaces[index as usize]
    }

    /// `ProtoModel::lookupEffect`.
    fn effect(&self, space: i32, offset: Word, size: i32) -> EffectKind {
        if self.spaces[space as usize].kind == SpaceKind::Internal {
            return EffectKind::Unaffected;
        }
        let position = self.effects.partition_point(|e| (e.storage.space, e.storage.offset) <= (space, offset));
        if position == 0 {
            return EffectKind::Unknown;
        }
        let hit = &self.effects[position - 1];
        if hit.storage.size == 0 && hit.storage.space == space {
            return EffectKind::Unaffected;
        }
        if hit.storage.space != space {
            return EffectKind::Unknown;
        }
        let info = &self.spaces[space as usize];
        let distance = info.wrap(offset.wrapping_sub(hit.storage.offset));
        if distance < hit.storage.size as i64 as u64 && distance as i64 + i64::from(size) <= i64::from(hit.storage.size) {
            hit.kind
        } else {
            EffectKind::Unknown
        }
    }

    /// Whether a call leaves this storage as it found it.
    pub fn call_unaffected(&self, space: i32, offset: Word, size: i32) -> bool {
        self.effect(space, offset, size) == EffectKind::Unaffected
    }
}
