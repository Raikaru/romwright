#!/usr/bin/env python3
"""Branch-polarity census of an m22-002 run: the `if`/`else` arm-order class.

When the printed arms of an `if`/`else` are in the other order from the
source's, the compiler emits the opposite branch (`beq` for `bne`, `bgez` for
`bltz`, ...) and the arms swap places; objdiff then reports the pair as a
replaced instruction, one branch for its inverse. This counts, over the headline
(`context`) variant of every function of a run's work directory
(`tests/m22-002_ps2_c_output.py --work DIR`), the functions with at least one
such pair (an instruction objdiff marks as replaced by its inverse branch) and
the pairs themselves. It reads the harness' own `objdiff.json`
files; nothing is compiled or decompiled here.

    benchmarks/m22_branch_polarity.py WORK_DIR [WORK_DIR ...]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

INVERSE = {}
for a, b in (("beq", "bne"), ("beql", "bnel"), ("bgez", "bltz"), ("bgezl", "bltzl"), ("blez", "bgtz"),
             ("blezl", "bgtzl"), ("bc1t", "bc1f"), ("bc1tl", "bc1fl"), ("beqz", "bnez")):
    INVERSE[a], INVERSE[b] = b, a


def opcode(instruction: dict) -> str:
    text = (instruction.get("instruction") or {}).get("formatted", "")
    return text.split(" ", 1)[0] if text else ""


def census(work: Path) -> dict:
    functions = pairs = inexact = 0
    names = []
    for path in sorted(work.glob("functions/*/romwright/context/objdiff.json")):
        report = json.loads(path.read_text())
        try:
            left = report["left"]["symbols"][0]["instructions"]
            right = report["right"]["symbols"][0]["instructions"]
        except (KeyError, IndexError):
            continue
        functions += 1
        count = 0
        for a, b in zip(left, right):
            if a.get("diff_kind") != "DIFF_REPLACE" or b.get("diff_kind") != "DIFF_REPLACE":
                continue
            x, y = opcode(a), opcode(b)
            if INVERSE.get(x) == y:
                count += 1
        if any(item.get("diff_kind") for item in left):
            inexact += 1
        if count:
            names.append(path.parts[-4])
            pairs += count
    return {"functions": functions, "inexact": inexact, "with_inverse_branch": len(names),
            "inverse_branch_pairs": pairs, "names": names}


def main() -> int:
    for work in sys.argv[1:]:
        result = census(Path(work))
        print(f"{work}: {result['functions']} functions, {result['inexact']} inexact, "
              f"{result['with_inverse_branch']} with an inverse-branch pair "
              f"({result['inverse_branch_pairs']} pairs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
