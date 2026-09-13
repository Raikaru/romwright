#!/usr/bin/env python3
"""Dump IDA's inferred function signatures as JSON, for the type head-to-head.

Opens a binary under idalib (no UI), lets auto-analysis run, then reads each
function's decompiled prototype — the type Hex-Rays actually inferred, not a
DWARF-read signature. Prints {ea: signature} so the gate can score it the
same way it scores Ghidra and romwright.
"""
import json
import sys
import idapro
import ida_auto
import ida_hexrays
import ida_typeinf
import ida_nalt
import ida_idaapi


def main():
    binary = sys.argv[1]
    if idapro.open_database(binary, True) != 0:
        print("open_database failed", file=sys.stderr)
        return 1
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("hexrays unavailable", file=sys.stderr)

    out = {}
    ea = 0
    n = ida_funcs.get_func_qty()
    for i in range(n):
        f = ida_funcs.getn_func(i)
        if f is None:
            continue
        ea = f.start_ea
        sig = None
        # The decompiler's inferred prototype is the strongest signal.
        try:
            cf = ida_hexrays.decompile(ea)
            if cf is not None:
                tif = ida_typeinf.tinfo_t()
                if cf.get_func_type(tif):
                    sig = ida_typeinf.dstr_tinfo(tif)
        except Exception:
            pass
        if not sig:
            # Fall back to the function's stored type.
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, ea):
                sig = ida_typeinf.dstr_tinfo(tif)
        out[hex(ea)] = sig
    print(json.dumps(out))
    idapro.close_database(False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
