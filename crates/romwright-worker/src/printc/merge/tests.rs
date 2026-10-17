use super::model::{
    Addr, Block, Func, High, Op, SPACE_CONSTANT, SPACE_INTERNAL, SPACE_PROCESSOR, Space, Vn, opc, pf, vf,
};
use super::names::{NameEntry, build_name};
use super::sortcxx::sort_cxx;
use super::variant::{VarRef, Variant};
use crate::printc::tree::TypeDesc;
use std::collections::HashSet;

/// One block, registers in space 0, unique space 1, constants 2, one `int` type.
fn func() -> Func {
    let mut f = Func::default();
    f.spaces = vec![
        Some(Space { kind: SPACE_PROCESSOR, big_endian: false }),
        Some(Space { kind: SPACE_INTERNAL, big_endian: false }),
        Some(Space { kind: SPACE_CONSTANT, big_endian: false }),
    ];
    f.unique_space = 1;
    f.next_unique = 0x1000;
    f.next_time = 100;
    f.next_create = 100;
    f.blocks.push(Block::default());
    f.tables.types.push(TypeDesc { name: "int".into(), meta: crate::printc::tree::meta::INT, size: 4, ..TypeDesc::default() });
    f.stripped.push(None);
    f
}

fn vn(f: &mut Func, space: u32, offset: u64, flags: u32) -> usize {
    let id = f.vns.len();
    f.vns.push(Vn {
        create: id as u32,
        size: 4,
        addr: Addr { space, offset },
        flags,
        high: id,
        has_cover_obj: true,
        cover_dirty: true,
        ..Vn::default()
    });
    f.highs.push(High { inst: vec![id], merge_classes: 1, symoff: -1, cover_dirty: true, ..Default::default() });
    id
}

fn op(f: &mut Func, code: u32, ins: &[usize], out: Option<usize>) -> usize {
    let id = f.ops.len();
    let order = 10 * (id as u32 + 1);
    f.ops.push(Op {
        time: id as u64,
        pc: Addr { space: 0, offset: 0x1000 + 4 * id as u64 },
        code,
        block: Some(0),
        order,
        flags: if code == opc::COPY { pf::UNARY } else { pf::BINARY },
        ins: ins.to_vec(),
        out,
        alive_at: Some(id),
        ..Op::default()
    });
    f.alive.push(Some(id));
    f.blocks[0].ops.push(id);
    for &i in ins {
        f.vns[i].desc.push(id);
    }
    if let Some(o) = out {
        f.vns[o].def = Some(id);
        f.vns[o].flags |= vf::WRITTEN | vf::INSERT;
    }
    id
}

fn input(f: &mut Func, offset: u64) -> usize {
    vn(f, 0, offset, vf::INPUT | vf::INSERT)
}

fn written(f: &mut Func, offset: u64) -> usize {
    vn(f, 0, offset, 0)
}

#[test]
fn a_copy_whose_input_dies_at_the_copy_merges_with_its_output() {
    // b = a; return b  -- a is dead after the COPY, so one variable holds both
    let mut f = func();
    let a = input(&mut f, 0);
    let b = written(&mut f, 8);
    op(&mut f, opc::COPY, &[a], Some(b));
    let c = written(&mut f, 16);
    op(&mut f, opc::INT_ADD, &[b, b], Some(c));
    f.merge_opcode(opc::COPY).unwrap();
    assert_eq!(f.vns[a].high, f.vns[b].high);
    assert_eq!(f.log.len(), 1, "one merge, no other edit");
}

#[test]
fn a_copy_and_its_source_merge_even_while_both_are_live() {
    // b = a; c = a + b -- b is a shadow of a (the same value), so their covers may intersect
    let mut f = func();
    let a = input(&mut f, 0);
    let b = written(&mut f, 8);
    op(&mut f, opc::COPY, &[a], Some(b));
    let c = written(&mut f, 16);
    op(&mut f, opc::INT_ADD, &[a, b], Some(c));
    f.merge_opcode(opc::COPY).unwrap();
    assert_eq!(f.vns[a].high, f.vns[b].high);
}

#[test]
fn two_values_that_differ_while_both_live_stay_two_variables() {
    // t = a + a; u = t + a: `a` and `t` hold different values over the second op
    let mut f = func();
    let a = input(&mut f, 0);
    let t = written(&mut f, 8);
    op(&mut f, opc::INT_ADD, &[a, a], Some(t));
    let u = written(&mut f, 16);
    op(&mut f, opc::INT_ADD, &[t, a], Some(u));
    assert!(f.intersection(f.vns[a].high, f.vns[t].high));
    assert!(!f.merge(f.vns[a].high, f.vns[t].high, true).unwrap());
    assert!(f.log.is_empty());
}

#[test]
fn the_variant_stops_a_speculative_merge_it_names() {
    let mut f = func();
    let a = input(&mut f, 0);
    let b = written(&mut f, 8);
    let copy = op(&mut f, opc::COPY, &[a], Some(b));
    let c = written(&mut f, 16);
    op(&mut f, opc::INT_ADD, &[b, b], Some(c));
    f.variant = Variant::parse(&format!("separate=t{}~t{}", f.ops[copy].time, f.ops[copy].time)).unwrap();
    // `a` is an input, so it is named by storage
    f.variant.separate = vec![(VarRef::Def(f.ops[copy].time), VarRef::Def(f.ops[copy].time))];
    f.resolve_variant();
    assert!(f.variant_separates(f.vns[b].high, f.vns[b].high));
}

#[test]
fn variants_round_trip_through_their_spec() {
    let v = Variant::parse("adjacent=off,maxref=3,explicit=t12+i0:0x10:4,separate=t1~t2").unwrap();
    assert!(!v.adjacent && v.datatype);
    assert_eq!(v.max_implied_ref, Some(3));
    assert_eq!(v.explicit, vec![VarRef::Def(12), VarRef::Input { space: 0, offset: 0x10, size: 4 }]);
    assert_eq!(Variant::parse(&v.spec()).unwrap(), v);
    assert!(Variant::parse("default").unwrap().is_default());
    assert!(Variant::parse("adjacent=maybe").is_err());
}

#[test]
fn the_std_sort_of_a_short_range_keeps_tied_elements_in_order() {
    // libstdc++ insertion-sorts up to 16 elements, which is stable.
    let mut v: Vec<(u32, u32)> = (0..16).map(|i| (i % 3, i)).collect();
    sort_cxx(&mut v, &mut |a, b| a.0 < b.0).unwrap();
    let mut expect = v.clone();
    expect.sort_by_key(|x| (x.0, x.1));
    assert_eq!(v, expect);
}

#[test]
fn the_std_sort_of_a_long_range_sorts() {
    let mut v: Vec<u32> = (0..200u32).map(|i| (i * 7919) % 101).collect();
    sort_cxx(&mut v, &mut |a, b| a < b).unwrap();
    assert!(v.windows(2).all(|w| w[0] <= w[1]));
}

fn entry(flags: u32) -> NameEntry {
    NameEntry { flags, has_type: true, type_base: "i".into(), type_size: 4, space_name: "register".into(), addr_size: 4, ..NameEntry::default() }
}

#[test]
fn locals_are_numbered_and_skip_names_the_scope_has() {
    let names: HashSet<String> = ["iVar1".to_string()].into_iter().collect();
    let mut base = 1;
    let (name, unique) = build_name(&entry(0), &mut base, &names);
    assert_eq!((name.as_str(), unique, base), ("iVar2", false, 3));
    let (name, _) = build_name(&entry(0), &mut base, &names);
    assert_eq!(name, "iVar3");
}

#[test]
fn parameters_registers_and_stack_slots_are_named_by_their_storage() {
    let names = HashSet::new();
    let mut base = 1;
    let mut param = entry(0x08);
    param.index = 2;
    assert_eq!(build_name(&param, &mut base, &names).0, "param_2");
    let mut reg = entry(0x08);
    reg.index = -1;
    reg.register = "a0".into();
    assert_eq!(build_name(&reg, &mut base, &names).0, "in_a0");
    let mut unaff = entry(0x10000);
    unaff.register = "s0".into();
    assert_eq!(build_name(&unaff, &mut base, &names).0, "unaff_s0");
    let mut stack = entry(0x8000);
    stack.space_name = "stack".into();
    stack.stack_local = true;
    stack.stack_start = -16;
    assert_eq!(build_name(&stack, &mut base, &names), ("iStackX_10".to_string(), true));
    stack.stack_start = 8;
    stack.stack_unusual = true;
    assert_eq!(build_name(&stack, &mut base, &names).0, "iStackY_8");
    assert_eq!(base, 1, "none of these used the counter");
}
