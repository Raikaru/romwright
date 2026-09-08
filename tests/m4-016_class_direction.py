#!/usr/bin/env python3
"""m4-016: a warning stock emits about itself is not a gap of ours.

Five of the ten `missing-external-prototype` rows are the oracle's text minus
a warning the oracle emits about its own prototype. The `printf` stub, on four
languages, decompiles identically both ways except for this, which stock
prints and we do not:

    /* WARNING: Unknown calling convention -- yet parameter storage is locked */

`m4-003` counted that against us twice over. Its `flow` class licensed *any*
`/* WARNING: */` comment, in either direction, so a warning only stock emits
was filed as flow we disagree about; and `missing-external-prototype` matched
the callee name in the function's *own signature* while checking for a
prototype at the import *slot*, which never carries one.

Both are accounting defects, and both hide real gaps behind noise. The
direction of a warning is the whole question: one we emit and stock does not
is ours to fix; the reverse is stock's. A prototype is missing when the oracle
*calls* a name in its body that the store holds a function for with no
signature.

Assertions
  1. A warning only the oracle emits is classified `oracle-warning`, not
     `flow`, and licenses only its own tokens.
  2. A warning only we emit is still `flow` -- the control that keeps
     assertion 1 from being an excuse.
  3. Warnings on both sides, differing, are named in both directions.
  4. `missing-external-prototype` does not fire for a name that appears only
     in the decompiled function's own signature, and still fires when the
     oracle calls an import by name in its body and the store holds no
     signature for it.
  5. The real `printf` stub texts, recorded from both decompilers, are
     accounted for with no residue and without `missing-external-prototype`.

Usage:
    python3 tests/m4-016_class_direction.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Recorded from both decompilers for `printf` at 00201720 of
# x86_64_plain_o0.bin (m4-014's pair dump), byte for byte.
NATIVE_STUB = (
    "int printf(char *__format,...)\n{\n  int iVar1;\n  \n"
    "  iVar1 = (*PTR_printf_002038f0)();\n  return iVar1;\n}\n")
ORACLE_STUB = (
    "/* WARNING: Unknown calling convention -- yet parameter storage is locked */\n\n"
    "int printf(char *__format,...)\n{\n  int iVar1;\n  \n"
    "  iVar1 = (*(code *)PTR_printf_002038f0)();\n  return iVar1;\n}\n")


def gate():
    specification = importlib.util.spec_from_file_location(
        "m4_003", ROOT / "tests/m4-003_language_parity.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def context(**overrides) -> dict:
    empty = {"symbols": set(), "prototypes": set(), "externals": {}, "strings": {},
             "definitions": set(), "names": {}, "functions": {}}
    empty.update(overrides)
    return empty


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    module = gate()
    rows = ({"name": "f"}, {"name": "f"})
    store = context()
    findings: dict[str, object] = {}

    # 1. A warning only the oracle emits.
    native = "void f(void){return;}"
    oracle = "/* WARNING: Unknown calling convention */void f(void){return;}"
    classes = module.classify(native, oracle, rows[0], rows[1], 0x1000, store, store)
    assert "oracle-warning" in classes, (
        f"a warning only the oracle emits was classified {sorted(classes)}")
    assert "flow" not in classes, (
        f"a warning only the oracle emits was counted as flow: {classes}")
    left = module.residue(native, oracle, rows[0], rows[1], classes, store)
    assert left == [], f"the oracle's own warning was left unexplained: {left}"
    findings["oracle_only"] = sorted(classes)

    # 2. The control: a warning only we emit is still ours.
    ours = "/* WARNING: Could not recover jumptable at 0x1000 */void f(void){return;}"
    classes = module.classify(ours, native, rows[0], rows[1], 0x1000, store, store)
    assert "flow" in classes, (
        f"a warning only we emit stopped counting as a gap: {sorted(classes)}")
    assert "oracle-warning" not in classes, classes
    findings["ours_only"] = sorted(classes)

    # 3. Both sides warn, differently: both directions are named.
    classes = module.classify(ours, oracle, rows[0], rows[1], 0x1000, store, store)
    assert {"flow", "oracle-warning"} <= set(classes), (
        f"warnings in both directions were not both named: {sorted(classes)}")
    findings["both"] = sorted(classes)

    # 4. The prototype class: not a name in the function's own signature.
    signature_only = context(externals={0x2038f0: "printf"},
                             functions={"printf": 0x201720})
    native_sig = "int printf(char *__format,...){int iVar1;iVar1 = (*PTR_printf_002038f0)();return iVar1;}"
    oracle_sig = "int printf(char *__format,...){int iVar1;iVar1 = (*(code *)PTR_printf_002038f0)();return iVar1;}"
    classes = module.classify(native_sig, oracle_sig, {"name": "printf"},
                              {"name": "printf"}, 0x201720, signature_only,
                              signature_only)
    assert "missing-external-prototype" not in classes, (
        f"a name in the function's own signature was counted as a missing "
        f"prototype: {classes}")
    findings["own_signature"] = sorted(classes)

    # ... and it still fires for a call the oracle makes by name to an import
    # whose signature stock holds and we do not. (m4-019 added the second
    # half: a name *nobody* declares is nobody's gap, so the stock store here
    # has to hold the signature for this to be one.)
    ours_only = context(externals={0x2038f0: "printf"}, functions={"printf": 0x201720})
    stock_has = context(externals={0x2038f0: "printf"}, functions={"printf": 0x201720},
                        prototypes={0x201720})
    native_call = "void f(void){(*PTR_printf_002038f0)();return;}"
    oracle_call = "void f(void){printf(\"hi\");return;}"
    classes = module.classify(native_call, oracle_call, rows[0], rows[1], 0x1000,
                              ours_only, stock_has)
    assert classes.get("missing-external-prototype") == ["printf"], (
        f"a call the oracle makes by name to an import with no signature is a "
        f"gap, and was classified {classes}")
    findings["real_gap"] = sorted(classes)

    # 5. The recorded stub pair: accounted for, and not as a missing prototype.
    stub_store = context(externals={0x2038f0: "printf"},
                         definitions={0x2038f0},
                         functions={"printf": 0x201720})
    classes = module.classify(NATIVE_STUB, ORACLE_STUB, {"name": "printf"},
                              {"name": "printf"}, 0x201720, stub_store, stub_store)
    assert "missing-external-prototype" not in classes, (
        f"the recorded stub pair is still counted as a missing prototype: "
        f"{classes}")
    assert "oracle-warning" in classes, (
        f"the stub pair's only textual difference besides the cast is stock's "
        f"own warning, and it was classified {sorted(classes)}")
    left = module.residue(NATIVE_STUB, ORACLE_STUB, {"name": "printf"},
                          {"name": "printf"}, classes, stub_store)
    assert left == [], f"the recorded stub pair left {left} unexplained"
    findings["recorded_stub"] = sorted(classes)

    summary = ("a warning only stock emits is stock's, one only we emit is ours, "
               "both directions are named, and the prototype class fires on a "
               "call rather than on a signature")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-016",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "classifier acceptance on recorded texts, not a corpus gate",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-016: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
