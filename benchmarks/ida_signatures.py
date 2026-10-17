#!/usr/bin/env python3
"""IDA / Hex-Rays driver (idalib): one file, three entry points.

  ida_signatures.py BINARY
      Dump IDA's inferred function signatures as JSON, for the type head-to-head
      (benchmarks/type_headtohead.py). Opens the binary headless, lets
      auto-analysis run, then reads each function's decompiled prototype --
      the type Hex-Rays actually inferred, not a DWARF-read signature. Prints
      {ea: signature}, scored the same way as Ghidra and romwright.

  ida_signatures.py analyze SPEC.json OUT.json
  ida_signatures.py decompile SPEC.json OUT.jsonl
      The console research comparator (benchmarks/hexrays_research.py drives
      them; its docstring is the method). `analyze` loads one image, runs
      auto-analysis only, records the wall time, the signatures and
      processor IDA applied, the segments and every function entry, and saves the
      database. `decompile` reopens that database and decompiles the
      sampled addresses with Hex-Rays, one JSON row per function appended to
      OUT.jsonl (flushed per function, so a crash or a hung function keeps
      the rows before it), the pseudocode to SPEC["c_dir"]/<address>.c.

SPEC.json (all keys written by hexrays_research.py):
  binary    file to open (a native container, or a flat raw image it prepared)
  work      scratch directory; the database lives here
  args      idalib command-line (`-p<proc>`, `-b<paragraph>` ...), or null
  flat      true when IDA has no loader for the container: the file is a raw
            image at SPEC["base"], and `analyze` sets the segment up and seeds
            SPEC["entries"] ([{"ea": int, "thumb": bool}])
  features  "r5900" | "psp" | "gekko" | "xenon" | "arm" | "mips" | "ppc":
            which unsupported-instruction categories to count (see FEATURES)
  sample    ["08000100", ...]   (decompile) addresses to decompile
  c_dir     (decompile) where pseudocode goes
Run it under a Python that has `idapro` (the IDA install's `idalib/python`
and `python` directories on PYTHONPATH, or a venv with the wheel installed).
"""
import json
import os
import re
import shutil
import sys
import time

import idapro  # noqa: E402  (must be the first IDA import)
import ida_auto
import ida_bytes
import ida_entry
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_nalt
import ida_segment
import ida_segregs
import ida_typeinf
import ida_ua


# ---------------------------------------------------------------------------
# Legacy: inferred prototypes for benchmarks/type_headtohead.py
# ---------------------------------------------------------------------------

def signatures_main(binary):
    if idapro.open_database(binary, True) != 0:
        print("open_database failed", file=sys.stderr)
        return 1
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("hexrays unavailable", file=sys.stderr)

    out = {}
    for i in range(ida_funcs.get_func_qty()):
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


# ---------------------------------------------------------------------------
# Research: analyze / decompile
# ---------------------------------------------------------------------------

# Mnemonic categories the processor modules may not (fully) support. A function
# is charged a category for every instruction IDA decoded with such a mnemonic
# (`insns`) and for every one Hex-Rays could not lift and printed as `__asm`
# (`asm`). A mnemonic IDA did not decode at all is not code, and is counted
# as `non_code_items`.
FEATURES = {
    "r5900": {
        # Multimedia instructions (MMI), the HI1/LO1 pipe and the shift-amount register.
        "r5900_mmi": r"^(p(?!ref)[a-z0-9]+|mfhi1|mflo1|mthi1|mtlo1|mult1|multu1|madd1|maddu1|div1|divu1|"
                     r"mfsa|mtsa|mtsab|mtsah|qfsrv)$",
        # COP2 / VU0 macro mode.
        "r5900_vu0": r"^(v[a-z0-9_.]+|lqc2|sqc2|qmfc2|qmtc2|cfc2|ctc2)$",
    },
    "psp": {
        "allegrex_vfpu": r"^(v[a-z0-9]+|lv|sv|lvl|lvr|svl|svr|ulv|usv|mfv|mtv|mfvc|mtvc|bvf|bvt|bvfl|bvtl)"
                         r"(\.[sptq])?$",
    },
    "gekko": {"gekko_paired_single": r"^(ps_[a-z0-9_]+|psq_[a-z]+)\.?$"},
    "xenon": {
        "vmx128": r"128\.?$",
        "altivec": r"^(v[a-z0-9_]+|lv[a-z]+|stv[a-z]+|mfvscr|mtvscr|dst[a-z]*)\.?$",
    },
    "arm": {"vfp_neon": r"^v[a-z0-9]+(\.[a-z0-9]+)*$"},
    "mips": {},
    "ppc": {},
}
FEATURES = {arch: {name: re.compile(rx) for name, rx in table.items()} for arch, table in FEATURES.items()}

ASM_BLOCK = re.compile(r"__asm\s*\{\s*([A-Za-z_][\w.]*)")
KEYWORD = re.compile(r"^(?:if|for|while|do|switch|return|goto|case|default|break|continue|else)\b")
FUNCTION_POINTER = re.compile(r"\(\s*(?:__\w+\s+)?\*+\s*(?:const\s+)?([A-Za-z_]\w*)\s*\)\s*\(")
LABEL = re.compile(r"^\s*([A-Za-z_]\w*):\s*$", re.M)


def merr_names():
    return {getattr(ida_hexrays, name): name for name in dir(ida_hexrays) if name.startswith("MERR_")}


def processor_info():
    return {"procname": ida_ida.inf_get_procname(), "big_endian": bool(ida_ida.inf_is_be()),
            "is_64bit": bool(ida_ida.inf_is_64bit()), "is_32bit": bool(ida_ida.inf_is_32bit_exactly()),
            "filetype": ida_loader.get_file_type_name(), "filetype_code": ida_ida.inf_get_filetype()}


def segments():
    rows = []
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        rows.append({"name": ida_segment.get_segm_name(seg), "start": seg.start_ea, "end": seg.end_ea,
                     "perm": seg.perm, "bitness": seg.bitness})
    return rows


def applied_signatures():
    return [list(ida_funcs.get_idasgn_desc(i)) for i in range(ida_funcs.get_idasgn_qty())]


def setup_flat(spec):
    """The raw-image loader makes one data-ish 64-bit segment: make the database and its segment 32-bit
    code (Hex-Rays refuses 32-bit code in a 64-bit database: MERR_ONLY64), seed the entries."""
    ida_ida.inf_set_64bit(False)
    ida_ida.inf_set_32bit(True)
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        seg.bitness = 1
        seg.perm = 7
        ida_segment.set_segm_class(seg, "CODE")
        ida_segment.update_segm(seg)
    thumb = ida_idp.str2reg("T")
    for entry in spec.get("entries", []):
        ea = entry["ea"]
        if entry.get("thumb") and thumb >= 0:
            ida_segregs.split_sreg_range(ea, thumb, 1, ida_segregs.SR_user, False)
        ida_entry.add_entry(ea, ea, f"entry_{ea:x}", True)
    ida_auto.enable_auto(True)


def database_path(spec):
    return os.path.join(spec["work"], os.path.basename(spec["binary"]) + ".i64")


def analyze(spec, out):
    work = spec["work"]
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    copy = os.path.join(work, os.path.basename(spec["binary"]))
    shutil.copy(spec["binary"], copy)
    started = time.monotonic()
    flat = bool(spec.get("flat"))
    rc = idapro.open_database(copy, not flat, spec.get("args"))
    opened = time.monotonic()
    if rc != 0:
        json.dump({"ok": False, "error": f"open_database returned {rc}"}, open(out, "w"))
        return 1
    if flat:
        setup_flat(spec)
    ida_auto.auto_wait()
    analysed = time.monotonic()
    functions = []
    thumb = ida_idp.str2reg("T")
    for index in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(index)
        if f is None:
            continue
        row = {"entry": f.start_ea, "size": f.end_ea - f.start_ea, "flags": f.flags}
        if thumb >= 0 and ida_segregs.get_sreg(f.start_ea, thumb) == 1:
            row["thumb"] = True
        functions.append(row)
    census = {"instructions": {}, "functions": {}, "non_code_items": 0, "code_instructions": 0}
    arch = spec.get("features", "mips")
    for index in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(index)
        if f is None:
            continue
        counts, non_code, insns = function_features(f, arch)
        census["non_code_items"] += non_code
        census["code_instructions"] += insns
        for name, count in counts.items():
            census["instructions"][name] = census["instructions"].get(name, 0) + count
            census["functions"][name] = census["functions"].get(name, 0) + 1
    result = {"ok": True, "census": census, "ida_version": ida_kernwin.get_kernel_version(),
              "hexrays_version": ida_hexrays.get_hexrays_version() if ida_hexrays.init_hexrays_plugin() else None,
              "open_s": round(opened - started, 3), "auto_wait_s": round(analysed - opened, 3),
              "analysis_s": round(analysed - started, 3),
              "processor": processor_info(), "segments": segments(), "signatures": applied_signatures(),
              "entry_points": ida_entry.get_entry_qty(), "args": spec.get("args"), "flat": flat,
              "functions": functions}
    result["worker_peak_rss_mb"] = peak_rss_mb()
    idapro.close_database(True)
    result["database"] = database_path(spec)
    result["save_s"] = round(time.monotonic() - analysed, 3)
    with open(out, "w") as handle:
        json.dump(result, handle)
    return 0


def peak_rss_mb():
    """This process's own high-water RSS (`VmHWM`). wait4's ru_maxrss of a child carries the parent's size
    over the fork, so the driver's number is not the worker's."""
    with open("/proc/self/status") as handle:
        for line in handle:
            if line.startswith("VmHWM:"):
                return round(int(line.split()[1]) / 1024)
    return None


def type_text(tif):
    try:
        return tif.dstr()
    except Exception:
        return str(tif)


def declared_names(lines):
    """Names Hex-Rays declares at the top of the body: the lines after `{` up to the first blank
    line (it prints one between the declarations and the statements) that read `type name;`."""
    names = set()
    started = False
    for line in lines:
        text = line.split("//")[0].strip()
        if not started:
            started = text == "{"
            continue
        if not line.strip():
            break
        pointer = FUNCTION_POINTER.search(text)
        if (not text.endswith(";") or KEYWORD.match(text) or "=" in text
                or ("(" in text and not pointer) or len(text.rstrip(";").split()) < 2):
            continue
        if pointer:
            names.add(pointer.group(1))
            continue
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*;$", text)
        if match:
            names.add(match.group(1))
    return names


def function_features(func, arch):
    """Per-category counts of decoded instructions with a mnemonic of the architecture's feature
    table, and the number of items in the function that did not decode as code."""
    table = FEATURES.get(arch, {})
    counts, non_code, insns = {}, 0, 0
    iterator = ida_funcs.func_item_iterator_t(func)
    ok = iterator.first()
    while ok:
        ea = iterator.current()
        if ida_bytes.is_code(ida_bytes.get_flags(ea)):
            insns += 1
            mnemonic = (ida_ua.print_insn_mnem(ea) or "").lower()
            for name, rx in table.items():
                if rx.search(mnemonic):
                    counts[name] = counts.get(name, 0) + 1
        else:
            non_code += 1
        ok = iterator.next_head()
    return counts, non_code, insns


def entry_relative(func, offset):
    """A Hex-Rays stack variable's offset from the frame's start, as an offset from the stack
    pointer at function entry (the base DWARF's offsets are turned into by locals_truth)."""
    return offset - ida_frame.frame_off_retaddr(func)


def guess_thumb(address):
    """Decode mode for a function this driver creates in an ARM-family image when no oracle gives it: Thumb when
    the first halfword is a `push {.., lr}` (0xB5xx), ARM when the first word has condition AL (0xE), else Thumb.
    Used for creation only; discovery is never given it."""
    raw = ida_bytes.get_bytes(address, 4)
    if not raw or len(raw) < 4:
        return False
    if raw[1] == 0xB5:
        return True
    return (raw[3] >> 4) != 0xE


def decompile_one(address, spec, errors, arch):
    thumb = ida_idp.str2reg("T")
    row = {"address": f"{address:08x}"}
    func = ida_funcs.get_func(address)
    row["existed"] = bool(func and func.start_ea == address)
    if not row["existed"]:
        if func:
            row["inside"] = f"{func.start_ea:08x}"
        else:
            # A function made here is decoded in the mode the spec gives (ARM family), else IDA's default.
            hint = spec.get("thumb_hints", {}).get(row["address"], spec.get("default_thumb"))
            if hint == "auto":
                hint = guess_thumb(address)
            previous = None
            if hint is not None and thumb >= 0:
                previous = ida_segregs.get_sreg(address, thumb)
                ida_segregs.split_sreg_range(address, thumb, 1 if hint else 0, ida_segregs.SR_user, False)
                row["decode_mode"] = "thumb" if hint else "arm"
            if not ida_bytes.is_code(ida_bytes.get_flags(address)):
                ida_ua.create_insn(address)
            if ida_funcs.add_func(address):
                # Let IDA finish its work on the new function (stack-pointer tracing, frame, callees' types) the way
                # it does for one the analysis made: without this Hex-Rays sees "unbalanced stack" and leaves the
                # epilogue as `__asm`.
                ida_auto.auto_wait()
                func = ida_funcs.get_func(address)
                row["created"] = True
                if previous is not None:
                    ida_segregs.split_sreg_range(func.end_ea, thumb, previous, ida_segregs.SR_auto, False)
        if not row.get("created"):
            row.update(ok=False, error="no function at address" if not func else "address inside another function",
                       seconds=0.0)
            return row
    started = time.monotonic()
    failure = ida_hexrays.hexrays_failure_t()
    try:
        cfunc = ida_hexrays.decompile(address, failure)
    except Exception as error:  # an exception inside the plugin
        cfunc, failure = None, None
        row["exception"] = f"{type(error).__name__}: {error}"
    row["seconds"] = round(time.monotonic() - started, 3)
    counts, non_code, insns = function_features(func, arch)
    row.update(size=func.end_ea - func.start_ea, instructions=insns, non_code_items=non_code, feature_insns=counts)
    if cfunc is None:
        row.update(ok=False)
        if failure is not None:
            row["error"] = {"code": errors.get(failure.code, failure.code), "desc": failure.desc(),
                            "errea": f"{failure.errea:08x}" if failure.errea != ida_idaapi.BADADDR else None}
        else:
            row["error"] = {"code": "EXCEPTION", "desc": row.pop("exception"), "errea": None}
        return row
    lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
    text = "\n".join(lines) + "\n"
    tif = ida_typeinf.tinfo_t()
    details = ida_typeinf.func_type_data_t()
    row.update(ok=True, name=cfunc.get_func_name() if hasattr(cfunc, "get_func_name") else None)
    if cfunc.get_func_type(tif) and tif.get_func_details(details):
        row["returns"] = type_text(details.rettype)
        row["parameters"] = [type_text(details[i].type) for i in range(details.size())]
        row["vararg"] = bool(details.is_vararg_cc())
    else:
        row["returns"], row["parameters"] = type_text(tif), None
    row["declaration"] = lines[0] if lines else ""
    warnings = [(f"{w.ea:08x}", w.text) for w in cfunc.get_warnings()]
    row["warnings"] = [w for w in warnings if not w[1].startswith("using guessed type")]
    row["guessed_type_notes"] = len(warnings) - len(row["warnings"])
    asm = {}
    for mnemonic in ASM_BLOCK.findall(text):
        asm[mnemonic.lower()] = asm.get(mnemonic.lower(), 0) + 1
    row["asm_blocks"] = asm
    row["jumpouts"] = text.count("JUMPOUT(")
    row["gotos"] = len(re.findall(r"\bgoto\b", text))
    row["labels"] = sum(1 for label in LABEL.findall(text) if label != "default")
    row["lines"] = sum(1 for line in lines if line.strip())
    declared = declared_names(lines)
    locals_ = []
    delta = cfunc.get_stkoff_delta()
    for lvar in cfunc.get_lvars():
        if lvar.is_arg_var or not lvar.name or lvar.name not in declared:
            continue
        item = {"name": lvar.name, "type": type_text(lvar.tif), "size": lvar.width}
        if lvar.is_stk_var():
            item["stack"] = entry_relative(func, lvar.get_stkoff() + delta)
        locals_.append(item)
    row["locals"] = locals_
    c_dir = spec.get("c_dir")
    if c_dir:
        os.makedirs(c_dir, exist_ok=True)
        with open(os.path.join(c_dir, f"{address:08x}.c"), "w") as handle:
            handle.write(text)
    return row


def decompile(spec, out):
    if idapro.open_database(database_path(spec), False) != 0:
        print("open_database failed", file=sys.stderr)
        return 1
    if not ida_hexrays.init_hexrays_plugin():
        print("hexrays unavailable", file=sys.stderr)
        return 1
    ida_auto.enable_auto(True)
    errors = merr_names()
    arch = spec.get("features", "mips")
    with open(out, "a") as handle:
        for text in spec["sample"]:
            try:
                row = decompile_one(int(text, 16), spec, errors, arch)
            except Exception as error:  # noqa: BLE001 - a driver bug on one function is a row, not a dead worker
                row = {"address": text, "ok": False, "existed": None, "seconds": None,
                       "error": {"code": "DRIVER_EXCEPTION", "desc": f"{type(error).__name__}: {error}", "errea": None}}
            handle.write(json.dumps(row) + "\n")
            handle.flush()
    idapro.close_database(False)
    return 0


def main(argv):
    if len(argv) == 4 and argv[1] in ("analyze", "decompile"):
        spec = json.load(open(argv[2]))
        return (analyze if argv[1] == "analyze" else decompile)(spec, argv[3])
    if len(argv) == 2:
        return signatures_main(argv[1])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
