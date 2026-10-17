#!/usr/bin/env python3
"""Differential: the Rust DWARF 1 reader against the independent Python one.

Both read the `.debug` stream of an unstripped Metrowerks image
(SLUS_209.50). The Rust side is the `#[ignore]` test
`native::mdebug::dwarf1::tests::dump_dwarf1_classes_for_the_differential`
in romwright-core, which writes, per function entry, the name, return class,
parameter classes and the C prototype the importer would apply:

    ROMWRIGHT_DWARF1_ELF=<elf> ROMWRIGHT_DWARF1_OUT=rust.json \\
        cargo test -p romwright-core --lib dump_dwarf1 -- --ignored

The Python side is `dwarf1_types.py` scored through
`console_research.truth_from_nodes`, the path the harness scores with.
Agreement is exact equality of (arity, return class, parameter classes);
disagreements are listed, with the first few by class pair.

    python3 benchmarks/dwarf1_diff.py <elf> rust.json [--out report.json]
"""
import argparse
import collections
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import console_research  # noqa: E402
import dwarf1_types  # noqa: E402


# The C spelling the importer hands the decompiler, back to the class it
# claims: a prototype that spells a type differently from the class the
# stream states would be an importer bug the class comparison cannot see.
C_CLASS = {"void": "void", "char": "int8", "byte": "uint8", "short": "int16", "ushort": "uint16",
           "int": "int32", "uint": "uint32", "longlong": "int64", "ulonglong": "uint64",
           "float": "float32", "double": "float64", "bool": "bool"}


def c_class(text: str) -> str:
    if text.endswith("*"):
        return "code" if text == "code *" else "ptr"
    return C_CLASS.get(text, "unknown")


def compare(elf: Path, rust_path: Path) -> dict:
    nodes, facts = dwarf1_types.read(elf)
    python = console_research.truth_from_nodes(nodes, "dwarf1-python")
    rust = json.loads(rust_path.read_text())["functions"]
    python_rows = {f"{entry:08x}": row for entry, row in python["functions"].items()}
    both = sorted(set(python_rows) & set(rust))
    arity = types = exact = 0
    prototypes = prototype_agree = 0
    prototype_bad = []
    slots = slot_agree = 0
    pairs = collections.Counter()
    disagreements = []
    for key in both:
        p, r = python_rows[key], rust[key]
        arity += p["arity"] == len(r["parameters"])
        want = p["parameters"] + [p["returns"]]
        got = r["parameters"] + [r["returns"]]
        types += want == got
        exact += p["arity"] == len(r["parameters"]) and want == got
        for a, b in zip(want, got):
            slots += 1
            slot_agree += a == b
            if a != b:
                pairs[(a, b)] += 1
        proto = r.get("prototype")
        if proto:
            prototypes += 1
            spelled = [c_class(t) for _, t in proto["parameters"]] + [c_class(proto["returns"])]
            # A pointer to code is spelled `code *` only when the class says
            # `code`; every other class must survive the spelling exactly,
            # except that an `unknown`/aggregate never gets a prototype.
            prototype_agree += spelled == want
            if spelled != want:
                prototype_bad.append({"entry": key, "name": p["name"], "class": want, "spelled": spelled})
        if want != got or p["arity"] != len(r["parameters"]):
            disagreements.append({"entry": key, "name": p["name"], "python": want, "rust": got})
    return {
        "elf": str(elf),
        "python_functions": len(python_rows),
        "python_conflicts_dropped": python["conflicts_dropped"],
        "rust_functions": len(rust),
        "compared": len(both),
        "only_python": sorted(set(python_rows) - set(rust))[:20],
        "only_rust": sorted(set(rust) - set(python_rows))[:20],
        "arity_agreement": arity,
        "type_agreement": types,
        "full_agreement": exact,
        "agreement_rate": round(exact / len(both), 6) if both else None,
        "slots": slots,
        "slot_agreement": round(slot_agree / slots, 6) if slots else None,
        "disagreeing_class_pairs": [[list(k), v] for k, v in pairs.most_common(20)],
        "disagreements": disagreements[:50],
        "disagreement_count": len(disagreements),
        "python_long_size": facts["long_size"],
        "rust_prototypes": json.loads(rust_path.read_text()).get("with_prototype"),
        "prototype_spelling_agreement": [prototype_agree, prototypes],
        "prototype_spelling_disagreements": prototype_bad[:20],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("elf", type=Path)
    parser.add_argument("rust", type=Path)
    parser.add_argument("--out", type=Path)
    arguments = parser.parse_args()
    report = compare(arguments.elf, arguments.rust)
    text = json.dumps(report, indent=1)
    if arguments.out:
        arguments.out.write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
