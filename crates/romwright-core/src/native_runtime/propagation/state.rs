//! Sparse known-bit storage for the reference propagation.
//!
//! Register slices and joins follow `VarnodeContext`/`RegisterValue`
//! (Ghidra 12.1.3, Apache-2.0, `Ghidra/Features/Base/.../SymbolicPropogator`
//! and `ghidra.program.model.lang.RegisterValue`): absence means unknown, not
//! zero, and a value is known bit by bit. A value may instead be a symbolic
//! offset from an abstract base (`VarnodeContext`'s `Address(space, offset)`
//! for an unknown incoming register).
use std::collections::BTreeMap;

pub(super) type Word = u64;

pub(super) fn width_mask(size: i32) -> Word {
    if size >= 8 {
        !0
    } else if size > 0 {
        (1u64 << (size * 8)) - 1
    } else {
        0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Value {
    pub bits: Word,
    pub known: Word,
    pub base: i32,
    pub size: i32,
}

impl Default for Value {
    fn default() -> Self {
        Self { bits: 0, known: 0, base: -1, size: 0 }
    }
}

impl Value {
    pub fn new(value: Word, mask: Word, base: i32, size: i32) -> Self {
        Self { bits: value & mask, known: mask, base, size }
    }

    pub fn constant(value: Word, size: i32) -> Self {
        Self::new(value, width_mask(size), -1, size)
    }

    pub fn relative(base: i32, offset: Word, size: i32) -> Self {
        Self::new(offset, width_mask(size), base, size)
    }

    pub fn complete(&self, size: i32) -> bool {
        self.base < 0 && size > 0 && size <= 8 && (self.known & width_mask(size)) == width_mask(size)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Location {
    pub space: i32,
    pub offset: Word,
}

#[derive(Clone, Copy, Default)]
struct Bits {
    bits: Word,
    known: Word,
}

#[derive(Clone, Copy)]
struct Relative {
    base: i32,
    size: i32,
    offset: Word,
}

/// One cell per aligned eight bytes, not one allocation per register byte.
/// Bits are stored in address order; `get`/`put` apply the language byte order.
#[derive(Clone)]
pub(super) struct State {
    cells: BTreeMap<Location, Bits>,
    /// Relative values have no literal address bits. A partial overwrite loses
    /// the relation rather than turning an offset into a reported pointer.
    relations: BTreeMap<Location, Relative>,
    big_endian: bool,
    unique_space: i32,
    instruction_space: i32,
    instruction_offset: Word,
}

/// `lastByte`: the storage range must not wrap (`std::overflow_error` in C++).
fn last_byte(offset: Word, size: i32) -> Option<Word> {
    if size <= 0 || (size - 1) as Word > Word::MAX - offset {
        None
    } else {
        Some(offset + (size - 1) as Word)
    }
}

impl State {
    pub fn new(big_endian: bool, unique_space: i32) -> Self {
        Self {
            cells: BTreeMap::new(),
            relations: BTreeMap::new(),
            big_endian,
            unique_space,
            instruction_space: -1,
            instruction_offset: 0,
        }
    }

    fn kill_relations(&mut self, space: i32, offset: Word, last: Word) {
        // The entry that starts before `offset` but still covers it, then every
        // entry that starts inside `[offset, last]`.
        let mut doomed = Vec::new();
        if let Some((key, relation)) = self.relations.range(..Location { space, offset }).next_back() {
            if key.space == space && offset - key.offset < relation.size as Word {
                doomed.push(*key);
            }
        }
        for (key, _) in self.relations.range(Location { space, offset }..) {
            if key.space != space || key.offset > last {
                break;
            }
            doomed.push(*key);
        }
        for key in doomed {
            self.relations.remove(&key);
        }
    }

    pub fn get(&self, space: i32, offset: Word, size: i32) -> Value {
        if size <= 0 || size > 8 || (size - 1) as Word > !0 - offset {
            return Value::default();
        }
        if let Some(relative) = self.relations.get(&Location { space, offset }) {
            if relative.size == size {
                return Value::relative(relative.base, relative.offset, size);
            }
        }
        let mut bits = 0;
        let mut known = 0;
        let mut previous = 0;
        let mut cell: Option<&Bits> = None;
        for i in 0..size {
            let at = offset + i as Word;
            let base = at & !7;
            if i == 0 || base != previous {
                cell = self.cells.get(&Location { space, offset: base });
                previous = base;
            }
            let Some(cell) = cell else { continue };
            let source = ((at & 7) * 8) as u32;
            let target = ((if self.big_endian { size - 1 - i } else { i }) * 8) as u32;
            bits |= ((cell.bits >> source) & 0xff) << target;
            known |= ((cell.known >> source) & 0xff) << target;
        }
        Value::new(bits, known, -1, size)
    }

    pub fn kill(&mut self, space: i32, offset: Word, size: i32) {
        let Some(last) = last_byte(offset, size) else { return };
        self.kill_relations(space, offset, last);
        let mut empty = Vec::new();
        for (key, cell) in self.cells.range_mut(Location { space, offset: offset & !7 }..) {
            if key.space != space || key.offset > last {
                break;
            }
            let base = key.offset;
            let first = if offset > base { (offset - base) as u32 } else { 0 };
            let final_byte = if last - base < 7 { (last - base) as u32 } else { 7 };
            let mask = width_mask((final_byte - first + 1) as i32) << (first * 8);
            cell.bits &= !mask;
            cell.known &= !mask;
            if cell.known == 0 {
                empty.push(*key);
            }
        }
        for key in empty {
            self.cells.remove(&key);
        }
    }

    pub fn put(&mut self, space: i32, offset: Word, size: i32, value: Value) {
        if last_byte(offset, size).is_none() {
            return;
        }
        if size > 8 || value.known == 0 {
            self.kill(space, offset, size);
            return;
        }
        if value.base >= 0 {
            let here = Location { space, offset };
            if let Some(existing) = self.relations.get_mut(&here) {
                if existing.size == size && value.size == size && value.known == width_mask(size) {
                    *existing = Relative { base: value.base, size, offset: value.bits };
                    return;
                }
            }
            self.kill(space, offset, size);
            if value.size == size && value.known == width_mask(size) {
                self.relations.insert(here, Relative { base: value.base, size, offset: value.bits });
            }
            return;
        }
        self.kill_relations(space, offset, offset + (size - 1) as Word);
        let mut previous = 0;
        let mut key: Option<Location> = None;
        for i in 0..size {
            let at = offset + i as Word;
            let base = at & !7;
            if i == 0 || base != previous {
                let here = Location { space, offset: base };
                key = self.cells.contains_key(&here).then_some(here);
                previous = base;
            }
            let source = ((if self.big_endian { size - 1 - i } else { i }) * 8) as u32;
            if key.is_none() {
                if (value.known >> source) & 0xff == 0 {
                    continue;
                }
                let here = Location { space, offset: base };
                self.cells.insert(here, Bits::default());
                key = Some(here);
            }
            let here = key.expect("cell was just ensured");
            let target = ((at & 7) * 8) as u32;
            let mask = 0xffu64 << target;
            let cell = self.cells.get_mut(&here).expect("cell exists");
            cell.bits = (cell.bits & !mask) | (((value.bits >> source) & 0xff) << target);
            cell.known = (cell.known & !mask) | (((value.known >> source) & 0xff) << target);
            if (at & 7) == 7 || i == size - 1 {
                if cell.known == 0 {
                    self.cells.remove(&here);
                    key = None;
                }
            }
        }
    }

    fn clear_space(&mut self, space: i32) {
        let low = Location { space, offset: 0 };
        let high = Location { space, offset: !0 };
        let doomed: Vec<Location> = self.cells.range(low..=high).map(|(key, _)| *key).collect();
        for key in doomed {
            self.cells.remove(&key);
        }
        let doomed: Vec<Location> = self.relations.range(low..=high).map(|(key, _)| *key).collect();
        for key in doomed {
            self.relations.remove(&key);
        }
    }

    /// Keeps what `keep(space, offset, size)` says survives: a cell is probed
    /// whole first, then byte by byte where the whole is refused.
    pub fn retain(&mut self, mut keep: impl FnMut(i32, Word, i32) -> bool) {
        self.cells.retain(|key, cell| {
            if !keep(key.space, key.offset, 8) {
                for byte in 0..8u32 {
                    let mask = 0xffu64 << (byte * 8);
                    if cell.known & mask != 0 && !keep(key.space, key.offset + byte as Word, 1) {
                        cell.bits &= !mask;
                        cell.known &= !mask;
                    }
                }
            }
            cell.known != 0
        });
        self.relations.retain(|key, relation| keep(key.space, key.offset, relation.size));
    }

    pub fn forget_relative_base(&mut self, base: i32) {
        self.relations.retain(|_, relation| relation.base != base);
    }

    pub fn begin_instruction(&mut self, space: i32, offset: Word) {
        if space != self.instruction_space || offset != self.instruction_offset {
            if self.unique_space >= 0 {
                self.clear_space(self.unique_space);
            }
            self.instruction_space = space;
            self.instruction_offset = offset;
        }
    }

    /// Intersects `self` with `other`; `true` when `self` changed.
    pub fn merge(&mut self, other: &State) -> bool {
        let mut changed = false;
        // A bit remains known only if every reached predecessor agrees on it.
        self.cells.retain(|key, cell| {
            let mask = match other.cells.get(key) {
                None => 0,
                Some(incoming) => cell.known & incoming.known & !(cell.bits ^ incoming.bits),
            };
            if mask != cell.known {
                changed = true;
                cell.known = mask;
                cell.bits &= mask;
            }
            mask != 0
        });
        self.relations.retain(|key, relation| match other.relations.get(key) {
            Some(incoming)
                if incoming.base == relation.base
                    && incoming.size == relation.size
                    && incoming.offset == relation.offset =>
            {
                true
            }
            _ => {
                changed = true;
                false
            }
        });
        if self.instruction_space != other.instruction_space || self.instruction_offset != other.instruction_offset {
            if self.unique_space >= 0 {
                let low = Location { space: self.unique_space, offset: 0 };
                changed |= self.cells.range(low..).next().is_some_and(|(key, _)| key.space == self.unique_space);
                changed |= self.relations.range(low..).next().is_some_and(|(key, _)| key.space == self.unique_space);
                self.clear_space(self.unique_space);
            }
            self.instruction_space = -1;
            self.instruction_offset = 0;
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn little_endian_slices_follow_address_order() {
        let mut state = State::new(false, 9);
        state.put(1, 0x10, 4, Value::constant(0x1122_3344, 4));
        assert_eq!(state.get(1, 0x10, 4).bits, 0x1122_3344);
        assert_eq!(state.get(1, 0x11, 1).bits, 0x33);
        assert!(state.get(1, 0x13, 2).known != width_mask(2));
    }

    #[test]
    fn big_endian_slices_follow_address_order() {
        let mut state = State::new(true, 9);
        state.put(1, 0x10, 4, Value::constant(0x1122_3344, 4));
        assert_eq!(state.get(1, 0x10, 1).bits, 0x11);
        assert_eq!(state.get(1, 0x12, 2).bits, 0x3344);
    }

    #[test]
    fn partial_overwrite_loses_a_relation_and_merge_keeps_agreement() {
        let mut state = State::new(false, 9);
        state.put(1, 0x20, 4, Value::relative(3, 8, 4));
        assert_eq!(state.get(1, 0x20, 4).base, 3);
        state.put(1, 0x21, 1, Value::constant(0xaa, 1));
        assert_eq!(state.get(1, 0x20, 4).base, -1);
        let mut left = State::new(false, 9);
        let mut right = State::new(false, 9);
        left.put(1, 0, 4, Value::constant(0xff00_ff00, 4));
        right.put(1, 0, 4, Value::constant(0x0f00_0f00, 4));
        assert!(left.merge(&right));
        let merged = left.get(1, 0, 4);
        assert_eq!(merged.known, 0x0f00_0f00 | 0x00ff_00ff & 0xf000_f000 | 0x00ff_00ff);
    }
}
