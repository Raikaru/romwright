#!/usr/bin/env python3
"""Hex-Rays (IDA Pro 9.4, idalib) as a comparator column on console_research.py's images.

A supplement. Nothing here changes a metric: Hex-Rays is one more column, scored
by the definitions console_research.py, m21-001, import_speed.py,
spurious_gotos.py and locals_truth.py already use (their code is imported and
called, not copied). The Romwright column is console_research_final2 (same
images, the same 200-function samples: seed 20261006, the addresses recorded in
that report); the stock Ghidra column is import-speed.json (discovery),
psp_stock_compare.json (PSP) and a stock-Ghidra run of the same samples
(`--run-stock`, benchmarks/locals_stock.py + ghidra/ExportDecompiledC.java).

What is measured, per image
  1 discovery   IDA auto-analysis only (no script, no FLIRT beyond what the
                loader applies by default; the signatures applied are recorded),
                function entries scored by m21-001's `score()` against the
                image's truth, over the ranges Romwright was scored on.
  2 output      Hex-Rays decompiles the sample's addresses. Where auto-analysis
                made no function at an address one is created there (`created`;
                Hex-Rays needs a function) in IDA's default decode state; every
                number is also given for the functions IDA found itself
                (`found`), which isolates decompiler quality from discovery.
                  success / gotos / labels / lines   from the pseudocode text
                  arity, parameter and return type   console_research.dwarf_scores
                  return class, locals, stack slots  locals_truth.score_function
                  spurious gotos                     spurious_gotos.score
                Adapter: Hex-Rays has no `/* irregular */` and no Romwright
                warning list, so those two columns are blank for it. Its types
                are spelled by IDA (`__int64`, `_DWORD`, `unsigned __int8`); they
                are mapped to the C spellings console_research.classify_c reads
                (IDA_SCALARS): sized `_BYTE/_WORD/_DWORD/_QWORD` become
                `undefinedN`, the same "width known, sign unknown" class stock
                Ghidra's `undefinedN` is, and the 32-bit-target `long` is 32 bits as
                in the harness. Stack locals come from `lvar_t` (`get_stkoff` and
                the frame's return-address offset), as entry-relative offsets, the
                base locals_truth turns DWARF's into.
  3 time        wall time of IDA's load plus auto-analysis per image, from the
                process's own clock and from wait4 (CPU, peak RSS, load average
                before and after). Not paired with import_speed.py's runs.
  4 failures    per function: decompile failure (code and text), `__asm` blocks
                Hex-Rays could not lift (by mnemonic), JUMPOUT, and counts of
                instructions in the unsupported-feature categories (R5900 MMI/VU0,
                Allegrex VFPU, Gekko paired singles, VMX128, NEON).

Containers IDA has no loader for are given the raw image the importer and the
stock Ghidra loaders produce (per image: `input` in the report): GBA ROM, NDS
ARM9 static module (decompressed, with its ITCM autoload), GameCube DOL, Vita
SCE ELF segments, XEX2 (decrypted and decompressed to PE). IDA's own loaders
handle the PS2 ELFs, PSX-EXE and the PSP PRX.

Usage
  python3 benchmarks/hexrays_research.py                       # all images, IDA only
  python3 benchmarks/hexrays_research.py --images psx-darkstalkers-3,ps2-dungeon-game
  python3 benchmarks/hexrays_research.py --run-stock            # also run stock Ghidra on the samples
  python3 benchmarks/hexrays_research.py --run-stock --out benchmarks/reports/console_research_hexrays.json
  python3 benchmarks/hexrays_research.py --render-only          # re-render the .md from the .json
Environment: IDA_PYTHON (default ~/idavenv/bin/python, a Python with `idapro`),
IDADIR (default ~/ida-pro-9.4; recorded). Output: benchmarks/reports/
console_research_hexrays.{json,md}. IDA runs are cached under --cache; a re-run
resumes. At most --jobs (default 2, the cap) IDA processes run at once.

IDA configurations. `shipped` (the headline column): IDADIR is a symlink tree of the
install without the three plugins Hex-Rays does not ship (see USER_PLUGINS). For the
MIPS images (PS2, PSX, PSP) the run is repeated as `host-plugins`, on the install as it
is.

License. Hex-Rays' EULA section 2.1(v) restricts benchmarking the Software and
publishing performance data "without first inviting HEX-RAYS to review the results".
The report says so; do not publish it before that invitation.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import dataclasses
import hashlib
import importlib.util
import json
import os
import re
import shutil
import statistics
import struct
import subprocess
import threading
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


import console_research as cr  # noqa: E402
import import_speed as speed  # noqa: E402
import locals_truth as LT  # noqa: E402
import type_headtohead  # noqa: E402

SG = load("spurious_gotos", ROOT / "benchmarks" / "spurious_gotos.py")
M21 = cr.M21
REPORTS = ROOT / "benchmarks" / "reports"
CACHE = Path.home() / ".cache" / "romwright" / "hexrays-eval"
IDA_DIR = Path(os.environ.get("IDADIR", Path.home() / "ida-pro-9.4"))
IDA_PYTHON = Path(os.environ.get("IDA_PYTHON", Path.home() / "idavenv" / "bin" / "python"))
WORKER = ROOT / "benchmarks" / "ida_signatures.py"
REFERENCE = REPORTS / "console_research_final2.json"
IMPORT_SPEED = REPORTS / "import-speed.json"
PSP_STOCK = REPORTS / "psp_stock_compare.json"
LOCALS_TRUTH = REPORTS / "locals_truth.json"
# Ghidra refuses a project location with a path element starting with '.', so not under ~/.cache.
STOCK_WORK = Path("/var/tmp/romwright-hexrays-stock")
COMMAND = ("python3 benchmarks/hexrays_research.py --run-stock --out benchmarks/reports/console_research_hexrays.json\n"
           "# stock Ghidra runs are cached under CACHE/stock; one that cannot finish (gba) is skipped after 3600 s\n"
           "python3 benchmarks/hexrays_research.py --render-only --out benchmarks/reports/console_research_hexrays.json")
STALL_S = 900  # one function may take this long before the worker is killed and the function recorded as a timeout


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def sha256_file(path: Path) -> str:
    return speed.sha256_file(path)


# ---------------------------------------------------------------------------
# Image preparation: what IDA is given
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Prepared:
    path: Path
    flat: bool
    args: str | None
    features: str
    input: str                       # what IDA opens and why
    entries: list = dataclasses.field(default_factory=list)
    base: int = 0
    ranges: list | None = None       # scored ranges when neither M21 nor Romwright's import gives them
    default_thumb: bool | None = None  # decode mode of a function created where IDA found none (ARM family)
    thumb_truth: Path | None = None  # truth ELF whose STT_FUNC low bit gives each sampled address's mode


def elf_exec_ranges(path: Path) -> list[tuple[int, int]]:
    data = path.read_bytes()
    phoff, = struct.unpack_from("<I", data, 28)
    entsize, count = struct.unpack_from("<HH", data, 42)
    out = []
    for index in range(count):
        kind, offset, vaddr, paddr, filesz, memsz, flags = struct.unpack_from("<7I", data, phoff + index * entsize)
        if kind == 1 and flags & 1:
            out.append((vaddr, vaddr + memsz))
    return out


def flatten(chunks: list[tuple[int, bytes]]) -> tuple[int, bytes]:
    """(base, image): the chunks placed at their addresses, gaps zero."""
    base = min(address for address, _ in chunks)
    end = max(address + len(data) for address, data in chunks)
    image = bytearray(end - base)
    for address, data in chunks:
        image[address - base:address - base + len(data)] = data
    return base, bytes(image)


def write_flat(chunks, out: Path) -> int:
    base, image = flatten(chunks)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(image)
    return base


def paragraph_args(processor: str, base: int) -> str:
    return f"-p{processor} -b{base >> 4:x}"


def prepare_gba(spec, corpus: Path, cache: Path) -> Prepared:
    rom = corpus / spec["image"]
    return Prepared(rom, True, paragraph_args("arm", 0x08000000), "arm",
                    "the raw GBA ROM, one segment at 0x08000000 (IDA has no GBA loader; the stock Ghidra column "
                    "uses the gba-ghidra-loader extension for the same layout); processor ARM, entry 0x08000000 "
                    "seeded as ARM code, as the loaders seed the reset vector",
                    entries=[{"ea": 0x08000000, "thumb": False}], base=0x08000000,
                    thumb_truth=corpus / spec["truth"][1])


def uncompress_backward(module: bytes, ram: int, bottom: int) -> bytes | None:
    """NitroSDK `MIi_UncompressBackward`, as crates/romwright-core/src/native/nds.rs ports it."""
    bottom -= ram
    if bottom < 8 or bottom > len(module):
        return None
    footer, original = struct.unpack_from("<II", module, bottom - 8)
    cursor = bottom - (footer >> 24)
    top = bottom - (footer & 0xFFFFFF)
    if top > cursor or original == 0 or original > 0x4000000:
        return None
    out = bytearray(module)
    out.extend(b"\0" * (bottom + original - len(out)))
    del out[bottom + original:]
    position = len(out)
    while cursor > top:
        cursor -= 1
        flag = out[cursor]
        for _ in range(8):
            if cursor <= top:
                break
            if flag & 0x80:
                cursor -= 1
                length = out[cursor]
                cursor -= 1
                index = (((length & 0x0F) << 8) | out[cursor]) + 2
                for _ in range((length >> 4) + 3):
                    source = position + index
                    position -= 1
                    out[position] = out[source]
            else:
                cursor -= 1
                position -= 1
                out[position] = out[cursor]
            flag = (flag << 1) & 0xFF
    return bytes(out) if position >= top else None


def prepare_nds(spec, corpus: Path, cache: Path) -> Prepared:
    data = (corpus / spec["image"]).read_bytes()
    offset, entry, ram, size = struct.unpack_from("<4I", data, 0x20)
    module = data[offset:offset + size]
    at = next(a for a in range(0, len(module) - 8, 4)
              if struct.unpack_from("<2I", module, a) == (0xDEC00621, 0x2106C0DE))
    params = struct.unpack_from("<9I", module, at - 28)
    if params[5]:
        module = uncompress_backward(module, ram, params[5])
        if module is None:
            raise RuntimeError("nds: arm9 static module did not decompress")
    chunks = [(ram, module)]
    # Autoload list: {address, size, bss} per block, data back to back from `params[2]`.
    source = params[2] - ram
    for at in range(params[0] - ram, params[1] - ram, 12):
        address, length, _bss = struct.unpack_from("<3I", module, at)
        if 0x01FF8000 <= address < 0x02000000:
            chunks.append((address, module[source:source + length]))
        source += length
    out = cache / "prepared" / spec["id"] / "arm9.bin"
    base = write_flat(chunks, out)
    return Prepared(out, True, paragraph_args("arm", base), "arm",
                    "the ARM9 static module of the cartridge, decompressed (MIi_UncompressBackward, the same "
                    "unpack the importer and the NTRGhidra loader do) and laid at 0x02000000 with its ITCM "
                    "autoload block at 0x01FF8000, raw (IDA has no NDS loader); processor ARM, entry "
                    f"{entry:#x} seeded as ARM code. ARM7 and overlays not loaded (as the Ghidra column: overlays "
                    "are loaded there but not scored)",
                    entries=[{"ea": entry, "thumb": False}], base=base, thumb_truth=corpus / spec["truth"][1])


def prepare_native(spec, corpus: Path, cache: Path) -> Prepared:
    binary = cr.prepared_binary(spec, corpus, cache)
    note = ("the stripped ELF (llvm-strip --strip-all), the file the importer and stock Ghidra read; IDA's own ELF "
            "loader picks the processor" if spec.get("strip") is True else "the image IDA's own loader reads")
    ranges = elf_exec_ranges(binary) if spec["ranges"] is None and binary.read_bytes()[:4] == b"\x7fELF" else None
    return Prepared(binary, False, None, "mips", note, ranges=ranges)


def prepare_vita(spec, corpus: Path, cache: Path) -> Prepared:
    path = corpus / spec["image"]
    data = path.read_bytes()
    e_entry, phoff = struct.unpack_from("<II", data, 24)[0], struct.unpack_from("<I", data, 28)[0]
    entsize, count = struct.unpack_from("<HH", data, 42)
    chunks, first = [], None
    for index in range(count):
        kind, offset, vaddr, _paddr, filesz, _memsz, _flags = struct.unpack_from("<7I", data, phoff + index * entsize)
        if kind == 1 and filesz:
            chunks.append((vaddr, data[offset:offset + filesz]))
            first = first or (vaddr, offset)
    # SCE ELFs put `sce_module_info` at segment (e_entry >> 30), offset (e_entry & 0x3fffffff); `module_start`
    # is its field 9 (sce.rs): the process entry the importer seeds. Thumb when the low bit is set.
    vaddr, offset = first
    module_start, = struct.unpack_from("<I", data, offset + (e_entry & 0x3FFFFFFF) + 68)
    out = cache / "prepared" / spec["id"] / "eboot.bin"
    base = write_flat(chunks, out)
    entry = vaddr + (module_start & ~1)
    # The module info's field has no Thumb bit in this image; read the first word at the entry: an ARM word
    # carries condition `AL` (0xE) in its top nibble, anything else is read as Thumb-2.
    start_word, = struct.unpack_from("<I", data, offset + (module_start & ~1))
    thumb = bool(module_start & 1) or (start_word >> 28) != 0xE
    return Prepared(out, True, paragraph_args("arm", base), "arm",
                    "the decrypted eboot.elf's PT_LOAD segments, raw at their addresses (IDA's ELF loader refuses the "
                    "SCE e_type 0xFE00 with a load error; stock Ghidra's ELF loader does load it); processor ARM, "
                    f"`module_start` {entry:#x} from the SCE module info seeded ({'Thumb' if thumb else 'ARM'}, by the first word)",
                    entries=[{"ea": entry, "thumb": thumb}], base=base, default_thumb=True)


def aes_cbc_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-CBC, zero IV, through the openssl CLI (no Python AES here)."""
    padded = data + bytes(-len(data) % 16)  # xex.rs zero-pads the last block the same way
    return subprocess.run(["openssl", "enc", "-d", "-aes-128-cbc", "-K", key.hex(), "-iv", "0" * 32, "-nopad"],
                          input=padded, capture_output=True, check=True).stdout[:len(data)]


def prepare_xex(spec, corpus: Path, cache: Path) -> Prepared:
    """The PE inside an XEX2 (the same decrypt and decompress xex.rs and XEXLoaderWV do), laid out as a memory
    image at its base; only basic (zero-run) compression is implemented, which is what this image uses."""
    data = (corpus / spec["image"]).read_bytes()
    be = lambda at, n=4: int.from_bytes(data[at:at + n], "big")  # noqa: E731
    if data[:4] != b"XEX2":
        raise RuntimeError("not an XEX2")
    offset_pe, offset_sec, count = be(8), be(16), be(20)
    encryption = compression = entry = base = 0
    basic = []
    for index in range(count):
        ident, value = be(24 + index * 8), be(28 + index * 8)
        low = ident & 0xFF
        payload = data[value:value + (be(value) if low == 0xFF else low * 4)] if low >= 2 else data[28 + index * 8:32 + index * 8]
        kind = ident >> 8
        if kind == 0x3:
            encryption, compression = int.from_bytes(payload[4:6], "big"), int.from_bytes(payload[6:8], "big")
            if compression == 1:
                basic = [(int.from_bytes(payload[8 + i * 8:12 + i * 8], "big"),
                          int.from_bytes(payload[12 + i * 8:16 + i * 8], "big")) for i in range(len(payload) // 8 - 1)]
        elif kind == 0x101:
            entry = int.from_bytes(payload[:4], "big")
        elif kind == 0x102:
            base = int.from_bytes(payload[:4], "big")
    if compression != 1:
        raise RuntimeError(f"xex: compression {compression} not implemented here (basic only)")
    payload = data[offset_pe:]
    retail = bytes.fromhex("20B185A59D28FDC340583FBB0896BF91")
    image = b""
    for key in (retail, bytes(16)):
        for at in (0x150, 0x11C):
            session = aes_cbc_decrypt(key, data[offset_sec + at:offset_sec + at + 16])
            plain = aes_cbc_decrypt(session, payload) if encryption == 1 else payload
            out, position = bytearray(), 0
            for length, zeros in basic:
                out += plain[position:position + length] + bytes(zeros)
                position += length
            if out[:2] == b"MZ":
                image = bytes(out)
                break
        if image:
            break
    if not image:
        raise RuntimeError("xex: no key decrypted the payload to a PE")
    out = cache / "prepared" / spec["id"] / "image.bin"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(image)
    return Prepared(out, False, None, "xenon",
                    "the PE image inside the XEX2 (AES-128 decrypted with the public retail key, basic-decompressed), "
                    f"written out as a memory image based at {base:#x}; IDA has no XEX loader, so the PE is handed to its "
                    f"own PE loader, which picks PPC big-endian (processor `PPC`, not a Xenon variant) and the PE entry {entry:#x}")


def prepare_dol(spec, corpus: Path, cache: Path) -> Prepared:
    data = (corpus / spec["image"]).read_bytes()
    words = struct.unpack_from(">18I", data, 0), struct.unpack_from(">18I", data, 0x48), struct.unpack_from(">18I", data, 0x90)
    offsets, addresses, sizes = words
    chunks = [(addresses[i], data[offsets[i]:offsets[i] + sizes[i]]) for i in range(18) if sizes[i] and addresses[i]]
    entry, = struct.unpack_from(">I", data, 0xE0)
    out = cache / "prepared" / spec["id"] / "main.bin"
    base = write_flat(chunks, out)
    return Prepared(out, True, paragraph_args("ppc", base), "gekko",
                    "the DOL's text and data sections raw at their load addresses (IDA has no DOL loader; the stock "
                    f"Ghidra column uses GameCubeLoader); processor ppc big-endian, entry {entry:#x} seeded",
                    entries=[{"ea": entry, "thumb": False}], base=base)


# image id -> preparation. `features` (set per Prepared) selects the unsupported-instruction categories.
PREPARE = {
    "gba-pokeemerald": prepare_gba,
    "nds-pokeheartgold-arm9": prepare_nds,
    "ps2-capcom-fighting-evolution": prepare_native,
    "ps2-dungeon-game": prepare_native,
    "psx-darkstalkers-3": prepare_native,
    "psv-need-for-speed-most-wanted": prepare_vita,
    "x360-black-ops-2": prepare_xex,
    "gc-animal-crossing": prepare_dol,
    "psp-puzzle-bobble-pocket": prepare_native,
    "psp-puzzle-bobble-pocket-symtab": prepare_native,
}
FEATURES = {"ps2-capcom-fighting-evolution": "r5900", "ps2-dungeon-game": "r5900",
            "psx-darkstalkers-3": "mips", "psp-puzzle-bobble-pocket": "psp",
            "psp-puzzle-bobble-pocket-symtab": "psp"}
# Extra functions scored for spurious gotos beyond the sample (m22-001's set on GBA).
SPURIOUS = SG.IMAGES


# ---------------------------------------------------------------------------
# Running IDA
# ---------------------------------------------------------------------------

# Plugins in the host's IDA install that Hex-Rays does not ship (all three added after the 2026-07-14 install): a
# third-party EE COP2 disassembler (author oct0xor) and two plugins built from ~/ida-sdk (an EE macro-mode lifter and
# the SDK's `sample8` user-defined-call sample for `svc_exit`). `shipped` runs without them.
USER_PLUGINS = {"ida-emotionengine.py", "ee_mac_lifter.so", "hexrays_udc.so"}


def ida_dir_for(variant: str, args) -> Path:
    """`host-plugins`: the install as it is; `shipped`: a symlink tree of it without USER_PLUGINS, so IDADIR
    points idalib at IDA exactly as Hex-Rays ships it, without touching the install."""
    if variant == "host-plugins":
        return IDA_DIR
    tree = args.cache / "ida-shipped"
    if not (tree / "plugins").is_dir():
        shutil.rmtree(tree, ignore_errors=True)
        (tree / "plugins").mkdir(parents=True)
        for entry in IDA_DIR.iterdir():
            if entry.name != "plugins":
                (tree / entry.name).symlink_to(entry)
        for entry in (IDA_DIR / "plugins").iterdir():
            if entry.name not in USER_PLUGINS:
                (tree / "plugins" / entry.name).symlink_to(entry)
    return tree


def ida_env(ida_dir: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["IDADIR"] = str(ida_dir)
    return env


class AnalysisTimeout(RuntimeError):
    """IDA's load plus auto-analysis did not finish inside the limit (a DNF, never a timing)."""


ANALYSIS_LIMIT_S = 3600


def run_analysis(image_id: str, prepared: Prepared, run_dir: Path, ida_dir: Path) -> dict:
    """IDA load plus auto-analysis, measured like import_speed.py measures a run; cached."""
    key = hashlib.sha256(json.dumps([sha256_file(prepared.path), sha256_file(WORKER), prepared.args,
                                     prepared.entries, prepared.flat, str(ida_dir)]).encode()).hexdigest()[:16]
    done = cr.read_json(run_dir / "analysis.json")
    if done and done.get("key") == key:
        return done
    run_dir.mkdir(parents=True, exist_ok=True)
    spec = {"binary": str(prepared.path), "work": str(run_dir / "db"), "args": prepared.args, "flat": prepared.flat,
            "entries": prepared.entries, "features": prepared.features}
    cr.write_json(run_dir / "spec.json", spec)
    out = run_dir / "analyze.json"
    out.unlink(missing_ok=True)
    log(f"{image_id}: IDA load + auto-analysis of {prepared.path.name}")
    measured = speed.measured([str(IDA_PYTHON), "-W", "ignore", str(WORKER), "analyze", str(run_dir / "spec.json"),
                               str(out)], ida_env(ida_dir), run_dir, ANALYSIS_LIMIT_S)
    result = cr.read_json(out)
    output = measured.pop("output", "")
    (run_dir / "analyze.log").write_text(output)
    if measured.get("timed_out"):
        raise AnalysisTimeout(f"IDA analysis did not finish in {ANALYSIS_LIMIT_S} s")
    if measured.get("returncode") or not result or not result.get("ok"):
        raise RuntimeError(f"IDA analysis failed: {(result or {}).get('error') or output[-600:]}")
    analysis = {"key": key, "process": measured, **{k: v for k, v in result.items()}}
    cr.write_json(run_dir / "analysis.json", analysis)
    log(f"{image_id}: {len(result['functions'])} functions in {result['analysis_s']}s "
        f"({result['processor']['procname']}, {result['processor']['filetype']})")
    return analysis


def rows_of(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass  # a row cut by a kill
    return rows


def elf_thumb_hints(elf: Path) -> dict[str, bool]:
    """address (hex, bit 0 cleared) -> Thumb, for the truth ELF's STT_FUNC symbols: the symbol value's low bit when
    set, else the ARM mapping symbol (`$a`/`$t`) in force at the address (mwcc's NDS ELF marks Thumb only that way)."""
    import bisect
    from elftools.elf.elffile import ELFFile
    functions, mapping = [], []
    with open(elf, "rb") as handle:
        table = ELFFile(handle).get_section_by_name(".symtab")
        for symbol in table.iter_symbols():
            value = symbol["st_value"]
            if symbol.name in ("$a", "$t"):
                mapping.append((value, symbol.name == "$t"))
            elif symbol["st_info"]["type"] == "STT_FUNC" and not symbol.name.startswith("$"):
                functions.append(value)
    mapping.sort()
    starts = [address for address, _ in mapping]
    out = {}
    for value in functions:
        at = bisect.bisect_right(starts, value & ~1) - 1
        out[f"{value & ~1:08x}"] = bool(value & 1) or (at >= 0 and mapping[at][1])
    return out


def run_decompile(image_id: str, prepared: Prepared, analysis: dict, sample: list[str], run_dir: Path,
                  stall_s: int, ida_dir: Path) -> list[dict]:
    """Decompile `sample`, resuming; a function that stalls or kills the process is recorded and skipped."""
    hints = {a: h for a, h in elf_thumb_hints(prepared.thumb_truth).items() if a in set(sample)} if prepared.thumb_truth else {}
    key = hashlib.sha256(json.dumps([analysis["key"], sample, hints, prepared.default_thumb]).encode()).hexdigest()[:16]
    jsonl = run_dir / f"decompile-{key}.jsonl"
    c_dir = run_dir / f"c-{key}"
    attempts = deaths = 0
    while True:
        done = {row["address"] for row in rows_of(jsonl)}
        remaining = [a for a in sample if a not in done]
        if not remaining:
            return [row for row in rows_of(jsonl)]
        attempts += 1
        if attempts > len(sample) + 2:
            raise RuntimeError("decompile: too many restarts")
        spec = {"binary": str(prepared.path), "work": str(run_dir / "db"), "args": prepared.args,
                "features": prepared.features, "sample": remaining, "c_dir": str(c_dir),
                "thumb_hints": hints, "default_thumb": prepared.default_thumb}
        cr.write_json(run_dir / "decompile-spec.json", spec)
        log(f"{image_id}: Hex-Rays on {len(remaining)} of {len(sample)} functions")
        with open(run_dir / "decompile.log", "ab") as logfile:
            process = subprocess.Popen([str(IDA_PYTHON), "-W", "ignore", str(WORKER), "decompile",
                                        str(run_dir / "decompile-spec.json"), str(jsonl)], env=ida_env(ida_dir),
                                       stdout=logfile, stderr=subprocess.STDOUT, start_new_session=True)
            last_size, last_change = -1, time.monotonic()
            while process.poll() is None:
                time.sleep(2)
                size = jsonl.stat().st_size if jsonl.exists() else 0
                if size != last_size:
                    last_size, last_change = size, time.monotonic()
                elif time.monotonic() - last_change > stall_s:
                    os.killpg(process.pid, 9)
                    process.wait()
                    break
        done = {row["address"] for row in rows_of(jsonl)}
        stuck = next((a for a in sample if a not in done), None)
        deaths = deaths + 1 if (stuck is not None and process.returncode != 0) else 0
        if deaths > 5:
            raise RuntimeError(f"decompile: the worker died {deaths} times in a row (see {run_dir}/decompile.log)")
        if stuck is not None and (process.returncode != 0):
            reason = ("timeout" if process.returncode in (-9, 137) else f"worker exit {process.returncode}")
            log(f"{image_id}: {stuck}: {reason}; recorded, resuming after it")
            with open(jsonl, "a") as handle:
                handle.write(json.dumps({"address": stuck, "ok": False, "existed": None, "seconds": None,
                                         "error": {"code": "TIMEOUT" if reason == "timeout" else "WORKER_DIED",
                                                   "desc": f"{reason} (stall limit {stall_s}s)", "errea": None}}) + "\n")


# ---------------------------------------------------------------------------
# Adapters: Hex-Rays rows -> the harness's row shape
# ---------------------------------------------------------------------------

IDA_SCALARS = {
    "__int8": "signed char", "unsigned __int8": "unsigned char",
    "__int16": "short", "unsigned __int16": "unsigned short",
    "__int32": "int", "unsigned __int32": "unsigned int",
    "__int64": "long long", "unsigned __int64": "unsigned long long",
    "_BYTE": "undefined1", "_WORD": "undefined2", "_DWORD": "undefined4", "_QWORD": "undefined8",
    "_OWORD": "undefined16", "_BOOL1": "bool", "_BOOL2": "bool", "_BOOL4": "bool", "_BOOL8": "bool",
    # IDA's BOOL is a typedef of int
    "BOOL": "int", "__int128": "undefined16", "unsigned __int128": "undefined16",
}
IDA_NOISE = re.compile(r"\b(__fastcall|__cdecl|__stdcall|__thiscall|__usercall|__userpurge|__noreturn|__ptr32|"
                       r"__ptr64|__spoils|const|volatile|struct|union|enum)\b")


def ida_c(text: str | None) -> str | None:
    """The C spelling console_research.classify_c reads for IDA's type text (None stays None)."""
    if text is None:
        return None
    text = " ".join(IDA_NOISE.sub(" ", text).split())
    if "*" in text:
        return text  # classify_c: `ptr`, or `code` for a function pointer
    return IDA_SCALARS.get(text, text)


def harness_row(row: dict) -> dict:
    """A decompiled-function row in console_research.decompile_one's shape."""
    out = {"address": row["address"], "success": bool(row.get("ok")), "existed": row.get("existed"),
           "created": row.get("created", False), "seconds": row.get("seconds")}
    if row.get("ok"):
        parameters = row.get("parameters")
        out.update(returns=ida_c(row["returns"]), parameters=None if parameters is None else [ida_c(p) for p in parameters],
                   gotos=row["gotos"], labels=row["labels"], lines=row["lines"],
                   hexrays_warnings=len(row["warnings"]), asm_blocks=sum(row["asm_blocks"].values()),
                   jumpouts=row["jumpouts"])
    return out


C_TEXT = {"gotos": re.compile(r"\bgoto\b"), "warnings": re.compile(r"WARNING")}


def stock_row(address: str, entry: dict) -> dict:
    """A stock-Ghidra decompile (ExportDecompiledC) in console_research.decompile_one's shape."""
    out = {"address": address, "existed": entry.get("existed"), "created": bool(entry.get("created")),
           "success": bool(entry.get("c"))}
    if not entry.get("c"):
        out["error"] = entry.get("error")
        return out
    text = entry["c"]
    found = cr.signature(text, entry["name"])
    out.update(gotos=len(C_TEXT["gotos"].findall(text)),
               labels=sum(1 for label in cr.LABEL.findall(text) if label != "default"),
               text_warnings=text.count("WARNING"), lines=sum(1 for line in text.splitlines() if line.strip()),
               returns=found[0] if found else None, parameters=found[1] if found else None, text=text)
    return out


def subset(rows: list[dict], view: str) -> list[dict]:
    """`all`: every sampled address (a function IDA/Ghidra did not make counts as a failure unless created);
    `found`: only the addresses the tool's own analysis made a function at."""
    return rows if view == "all" else [row for row in rows if row.get("existed")]


def tool_summary(rows: list[dict], dwarf: dict | None, sampled: int | None = None) -> dict:
    ok = [row for row in rows if row.get("success")]
    total = sampled if sampled is not None else len(rows)
    times = [row["seconds"] for row in ok if row.get("seconds") is not None]
    summary = {"sampled": total, "decompiled": len(ok), "success_rate": round(len(ok) / total, 4) if total else None,
               "gotos": sum(row["gotos"] for row in ok), "labels": sum(row["labels"] for row in ok),
               "lines": sum(row["lines"] for row in ok)}
    if any("text_warnings" in row for row in ok):
        summary["text_warnings"] = sum(row.get("text_warnings", 0) for row in ok)
    if any("hexrays_warnings" in row for row in ok):
        summary["hexrays_warnings"] = sum(row.get("hexrays_warnings", 0) for row in ok)
        summary["functions_with_asm"] = sum(1 for row in ok if row.get("asm_blocks"))
        summary["functions_with_jumpout"] = sum(1 for row in ok if row.get("jumpouts"))
    if times:
        summary.update(median_seconds=round(statistics.median(times), 3), max_seconds=round(max(times), 3))
    summary.update(cr.dwarf_scores(rows, dwarf))
    return summary


def locals_scores(image_id: str, rows: list[dict], ida_rows: dict[str, dict] | None, stock_c: dict | None,
                  truth) -> dict:
    """locals_truth.score_function over each tool's printed functions; `rows` selects the addresses."""
    out = {}
    for tool, parsed in (("hexrays", {a: ida_printed(ida_rows[a]) for a in ida_rows if ida_rows[a].get("ok")}
                          if ida_rows is not None else None),
                         ("stock", {a: LT.printed(text) for a, text in stock_c.items()} if stock_c is not None else None)):
        if parsed is None:
            continue
        scored = [LT.score_function(truth.functions[int(a, 16)], p) for a, p in parsed.items()
                  if p and int(a, 16) in truth.functions]
        out[tool] = LT.aggregate(scored) if scored else None
    return out


def ida_printed(row: dict) -> dict:
    """locals_truth's `printed()` structure for a Hex-Rays function (locals from lvar_t, see the docstring)."""
    locals_ = []
    for item in row.get("locals", []):
        text = item["type"]
        klass = ("aggregate", None) if "[" in text or re.search(r"\b(struct|union)\b", text) \
            else cr.classify_c(ida_c(text) or "")
        locals_.append({"name": item["name"], "type": text, "class": klass, "offset": item.get("stack"),
                        "stack": "stack" in item})
    return {"name": row.get("name"), "returns": ida_c(row.get("returns")), "locals": locals_, "frame": set()}


# ---------------------------------------------------------------------------
# Per image
# ---------------------------------------------------------------------------

def ranges_for(spec: dict, prepared: Prepared, speed_row: dict | None):
    if spec["ranges"]:
        return [tuple(r) for r in spec["ranges"]]
    runs = (speed_row or {}).get("ours_runs") or []
    if runs and runs[0].get("ranges"):
        return [tuple(r) for r in runs[0]["ranges"]]
    return prepared.ranges


def categorize(rows: list[dict]) -> dict:
    failures = collections.Counter()
    features = collections.Counter()
    asm = collections.Counter()
    with_feature = collections.Counter()
    for row in rows:
        if not row.get("ok"):
            error = row.get("error")
            failures[(error["code"] if isinstance(error, dict) else str(error))] += 1
        for name, count in (row.get("feature_insns") or {}).items():
            features[name] += count
            with_feature[name] += 1
        for mnemonic, count in (row.get("asm_blocks") or {}).items():
            asm[mnemonic] += count
    return {"failures": dict(failures), "feature_instructions": dict(features),
            "functions_with_feature_instructions": dict(with_feature),
            "asm_mnemonics_top": asm.most_common(25),
            "failure_examples": [{k: row.get(k) for k in ("address", "error", "existed", "created")}
                                 for row in rows if not row.get("ok")][:12],
            "non_code_items": sum(row.get("non_code_items", 0) for row in rows if "non_code_items" in row)}


def load_dwarf(args, image_id: str, source: Path):
    """The DWARF truth console_research.dwarf_truth extracts ({address: arity/classes}), cached; None without DWARF."""
    if image_id not in cr.DWARF:
        return None
    path = args.cache / "dwarf" / f"{image_id}-{sha256_file(source)[:12]}.json"
    cached = cr.read_json(path) or cr.read_json(cr.CACHE / "dwarf" / path.name)
    if cached is None:
        extracted = cr.dwarf_truth(args.corpus / cr.DWARF[image_id])
        cached = dict(extracted, functions={f"{k:08x}": v for k, v in extracted["functions"].items()})
        cr.write_json(path, cached)
    return {int(k, 16): v for k, v in cached["functions"].items()}


def evaluate(spec: dict, args, prepared: Prepared, sample: list[str], extras: list[str], variant: str,
             speed_report: dict, gate) -> dict:
    """One IDA configuration (`variant`) over one image: analysis, discovery, Hex-Rays on the sample."""
    image_id = spec["id"]
    source = args.corpus / spec["image"]
    ida_dir = ida_dir_for(variant, args)
    run_dir = args.cache / "runs" / (image_id if variant == "shipped" else f"{image_id}@{variant}")
    result: dict = {"ida_dir": str(ida_dir), "plugins": sorted(p.name for p in (ida_dir / "plugins").iterdir()
                                                                  if p.name in USER_PLUGINS or p.suffix == ".py")}
    with gate:
        analysis = run_analysis(image_id, prepared, run_dir, ida_dir)
        rows = run_decompile(image_id, prepared, analysis, sample + extras, run_dir, args.stall, ida_dir)
    result["analysis"] = {k: analysis[k] for k in (
        "ida_version", "hexrays_version", "open_s", "auto_wait_s", "analysis_s", "save_s", "processor", "segments",
        "signatures", "entry_points", "args", "flat", "worker_peak_rss_mb", "census")}
    result["analysis"]["process"] = {k: analysis["process"].get(k) for k in (
        "wall_s", "cpu_s", "user_s", "sys_s", "load_before", "load_after")}
    result["analysis"]["functions_total"] = len(analysis["functions"])
    # --- discovery
    truth = cr.function_truth(spec, args.corpus)
    ranges = ranges_for(spec, prepared, speed_report["rows"].get(image_id))
    result["scored_ranges"] = [list(r) for r in ranges] if ranges else None
    if truth is not None and ranges:
        functions = {f["entry"]: f["size"] for f in analysis["functions"]}
        corroborated = speed.corroboration(spec, source, ranges) if image_id in speed.PSX_PRECISION_METRIC else None
        score = speed.score_entries(functions, truth, ranges, run_dir / "score", corroborated)
        result["discovery"] = speed.quality_fields(score)
    elif ranges:
        result["discovery"] = {"found": sum(1 for f in analysis["functions"]
                                            if any(lo <= f["entry"] < hi for lo, hi in ranges)), "truth": None}
    # --- decompile
    dwarf = load_dwarf(args, image_id, source)
    by_address = {r["address"]: r for r in rows}
    harness = {r["address"]: harness_row(r) for r in rows}
    sample_rows = [harness[a] for a in sample]
    result["hexrays"] = {view: tool_summary(subset(sample_rows, view), dwarf,
                                            sampled=len(sample) if view == "all" else None)
                         for view in ("all", "found")}
    if dwarf and prepared.features == "r5900":
        # Diagnostic, not the harness metric: IDA spells an R5900 general register `__int64`. Read as the ILP32
        # ABI's 32-bit `int`, what do the same signatures score?
        narrow = {"long long": "int", "unsigned long long": "unsigned int"}
        alt = [dict(r, returns=narrow.get(r.get("returns"), r.get("returns")),
                    parameters=None if r.get("parameters") is None else [narrow.get(p, p) for p in r["parameters"]])
               for r in sample_rows]
        result["hexrays"]["diag_int64_read_as_32bit"] = {
            view: {k: v for k, v in cr.dwarf_scores(subset(alt, view), dwarf).items()
                   if k in ("arity_accuracy", "type_exact", "type_partial", "type_wrong", "type_exact_rate")}
            for view in ("all", "found")}
    result["hexrays"]["created"] = sum(1 for r in sample_rows if r.get("created"))
    result["hexrays"]["existed"] = sum(1 for r in sample_rows if r.get("existed"))
    result["categories"] = categorize([r for r in rows])
    result["per_function"] = {r["address"]: {k: r.get(k) for k in (
        "ok", "existed", "created", "decode_mode", "error", "seconds", "size", "instructions", "returns", "parameters",
        "gotos", "warnings", "asm_blocks", "jumpouts", "feature_insns", "non_code_items")} for r in rows}
    # --- locals / returns / stack slots against DWARF (locals_truth)
    if image_id in LT.IMAGES:
        truth_lt = LT.Truth(image_id, args.corpus)
        for view in ("all", "found"):
            keep = {a: by_address[a] for a in sample if by_address[a].get("ok") and (view == "all" or by_address[a].get("existed"))}
            result["hexrays"][f"locals_{view}"] = locals_scores(image_id, sample_rows, keep, None, truth_lt)["hexrays"]
    # --- spurious gotos
    if image_id in SPURIOUS:
        info = SPURIOUS[image_id]
        symbols = SG.elf_names(info["elf"], info["files"])
        index = SG.source_index(info["src"])
        scored = {r["address"]: {"gotos": r["gotos"]} for r in rows if r.get("ok")}
        result["spurious_gotos"] = {"gate_set": len(sample) + len(extras),
                                    "hexrays": SG.score(scored, symbols, index)["totals"]}
        # The found-only variant: the functions IDA itself made.
        found = {a: row for a, row in scored.items() if by_exist(rows, a)}
        result["spurious_gotos"]["hexrays_found"] = SG.score(found, symbols, index)["totals"]
    return result


def run_image(spec: dict, args, reference: dict, speed_report: dict, jobs_gate) -> dict:
    image_id = spec["id"]
    source = args.corpus / spec["image"]
    if not source.is_file():
        return {"status": "skipped", "reason": "image absent"}
    sample = list(reference["images"][image_id]["sample"])
    prepared = PREPARE[image_id](spec, args.corpus, args.cache)
    prepared.features = FEATURES.get(image_id, prepared.features)
    extras: list[str] = []
    if image_id == "gba-pokeemerald":
        symbols = SG.elf_names(SPURIOUS[image_id]["elf"], SPURIOUS[image_id]["files"])
        by_name = {name: address for address, (name, _) in symbols.items()}
        extras = [f"{by_name[name]:08x}" for name in SG.m22_names() if name in by_name and f"{by_name[name]:08x}" not in sample]
    result = {"status": "ran", "extra_addresses": extras, "sample_size": len(sample),
              "input": {"file": str(prepared.path), "flat": prepared.flat, "ida_args": prepared.args,
                        "what": prepared.input, "entries": prepared.entries}, "variants": {}}
    for variant in ["shipped"] + (["host-plugins"] if prepared.features in ("r5900", "mips", "psp") else []):
        result["variants"][variant] = evaluate(spec, args, prepared, sample, extras, variant, speed_report, jobs_gate)
    result.update(result["variants"]["shipped"])
    return result


def by_exist(rows: list[dict], address: str) -> bool:
    return next((row.get("existed") for row in rows if row["address"] == address), False)


# ---------------------------------------------------------------------------
# Stock Ghidra on the same samples
# ---------------------------------------------------------------------------

def run_stock(image_id: str, spec: dict, args, reference: dict, extras: list[str]) -> Path | None:
    """locals_stock.py (stock Ghidra headless, default analyzers, import_speed's language/loader) with --create."""
    out = args.stock_dir / f"{image_id}.json"
    if out.is_file():
        return out
    if image_id not in speed.GHIDRA_CONFIG:
        return None
    args.stock_dir.mkdir(parents=True, exist_ok=True)
    (STOCK_WORK / "tmp").mkdir(parents=True, exist_ok=True)
    sample = reference["images"][image_id]["sample"] + extras
    report = args.stock_dir / f"{image_id}.sample.json"
    report.write_text(json.dumps({"images": {image_id: {"sample": sample}}}))
    binary = cr.prepared_binary(spec, args.corpus, args.cache)
    log(f"{image_id}: stock Ghidra on {len(sample)} functions")
    result = subprocess.run([sys.executable, str(ROOT / "benchmarks" / "locals_stock.py"), image_id, "--report", str(report),
                             "--binary", str(binary), "--out", str(out), "--work", str(STOCK_WORK / image_id),
                             "--create", "--timeout", str(speed.LIMIT_S)], capture_output=True, text=True,
                            # The XEX loader writes a 1.4 GB scratch file: not under the 7.5 GB tmpfs /tmp.
                            env=dict(os.environ, JAVA_TOOL_OPTIONS=f"-Djava.io.tmpdir={STOCK_WORK / 'tmp'}"))
    (args.stock_dir / f"{image_id}.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        log(f"{image_id}: stock Ghidra failed: {(result.stdout + result.stderr)[-400:]}")
        return None
    return out


def stock_scores(image_id: str, path: Path, sample: list[str], extras: list[str], dwarf, truth_lt) -> dict:
    rows = json.loads(path.read_text())["functions"]
    harness = {a: stock_row(a, rows[a]) for a in sample + extras if a in rows}
    sample_rows = [harness[a] for a in sample if a in harness]
    out = {view: tool_summary(subset(sample_rows, view), dwarf, sampled=len(sample) if view == "all" else None)
           for view in ("all", "found")}
    out["existed"] = sum(1 for r in sample_rows if r.get("existed"))
    out["created"] = sum(1 for r in sample_rows if r.get("created"))
    if truth_lt is not None:
        for view in ("all", "found"):
            texts = {a: h["text"] for a, h in harness.items() if a in set(sample) and h.get("success")
                     and (view == "all" or h.get("existed"))}
            out[f"locals_{view}"] = locals_scores("", sample_rows, None, texts, truth_lt)["stock"]
    return out, harness


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def fmt(value, digits=4):
    if value is None:
        return "–"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def spurious_for(image_id: str, rows: dict[str, dict]) -> dict | None:
    """spurious_gotos.score over `rows` {address: {"gotos": n}} for the gate set's image."""
    info = SPURIOUS.get(image_id)
    if not info:
        return None
    symbols = SG.elf_names(info["elf"], info["files"])
    return SG.score(rows, symbols, SG.source_index(info["src"]))["totals"]


def romwright_column(ref_image: dict) -> dict:
    summary = (ref_image.get("configs", {}).get("default") or {}).get("summary") or {}
    return summary


def ghidra_discovery(image_id: str, speed_report: dict, psp: dict | None) -> dict | None:
    row = (speed_report["rows"].get(image_id) or {}).get("ghidra") or {}
    if row.get("score"):
        return dict(row["score"], language=(speed_report["rows"][image_id].get("ghidra_config") or {}).get("language"),
                    wall_median_s=row.get("wall_median_s"), load_1min=row.get("load_1min"),
                    peak_rss_mb_max=row.get("peak_rss_mb_max"))
    if psp and image_id.startswith("psp-"):
        twin = "symtab" if image_id.endswith("symtab") else "strip-all"
        out = {}
        for config, label in ((f"{twin}/Allegrex", "allegrex"), (f"{twin}/loader-choice", "loader_mips")):
            row = psp["configs"].get(config)
            if row:
                out[label] = dict(row["discovery"], types=row.get("types_all_dwarf_entries"),
                                  types_found=row.get("types_stock_found_entries"), language=row["language"])
        return out
    return None


def census_cell(census: dict | None) -> str:
    if not census:
        return "–"
    parts = [f"{name} {census['instructions'][name]} / {census['functions'][name]}" for name in sorted(census["instructions"])]
    return (", ".join(parts) or "no instruction in a feature category") + f" (of {census['code_instructions']} insns)"


def tables(report: dict) -> list[str]:
    images = [i for i, row in report["images"].items() if row.get("status") == "ran"]
    R = lambda i: report["images"][i]["romwright"]  # noqa: E731
    H_ = lambda i, view="all": report["images"][i]["hexrays"][view]  # noqa: E731
    S = lambda i: report["images"][i].get("stock") or {}  # noqa: E731
    HV = lambda i: (report["images"][i].get("variants") or {}).get("host-plugins")  # noqa: E731
    D = lambda i: report["images"][i].get("discovery") or {}  # noqa: E731
    G = lambda i: report["images"][i].get("ghidra_discovery") or {}  # noqa: E731

    def stock_disc(i):
        g = G(i)
        return g.get("allegrex", g) if g else {}

    out = ["## Discovery (m21-001 `score()`, truth and ranges as the Romwright column)", "",
           "| image | recall R / G / H | precision R / G / H | found R / G / H | truth |", "|---|---|---|---|---|"]
    for i in images:
        d, g, r = D(i), stock_disc(i), R(i)
        if d.get("recall") is None and not r.get("recall"):
            out.append(f"| {i} | no truth | no truth | R {fmt(r.get('discovered'))} / G {fmt((report['images'][i].get('ghidra_found')))} "
                       f"/ H {fmt(d.get('found'))} | – |")
            continue
        out.append(f"| {i} | {fmt(r.get('recall'))} / {fmt(g.get('recall'))} / {fmt(d.get('recall'))} | "
                   f"{fmt(r.get('precision'))} / {fmt(g.get('precision'))} / {fmt(d.get('precision'))} | "
                   f"{fmt(r.get('discovered'))} / {fmt(g.get('found'))} / {fmt(d.get('found'))} | {fmt(d.get('truth'))} |")
    if "psx-darkstalkers-3" in images:
        out += ["", "PSX: the map names globals only, so precision is a floor for every tool; corroborated precision "
                "(`psx_corroborated`): Romwright 0.9968 (import-speed.json), Ghidra "
                + fmt((G("psx-darkstalkers-3") or {}).get("precision_corroborated")) + ", Hex-Rays "
                + fmt(D("psx-darkstalkers-3").get("precision_corroborated")) + "."]
    out.append("")
    out += ["## Decompiling the sampled functions (200 per image; `all` = every sampled address, a function the tool "
            "did not find is created; `found` = only addresses the tool's own analysis made a function at)", "",
            "| image | tool | view | decompiled / sampled | success | gotos | labels | lines | warnings (tool-defined) |",
            "|---|---|---|---|---|---|---|---|---|"]
    for i in images:
        r = R(i)
        out.append(f"| {i} | Romwright | all | {r.get('decompiled')} / {r.get('sampled')} | {fmt(r.get('success_rate'))} | "
                   f"{fmt(r.get('gotos'))} | {fmt(r.get('labels'))} | {fmt(r.get('lines'))} | "
                   f"{fmt(r.get('native_warnings'))} native, {fmt(r.get('text_warnings'))} text |")
        for view in ("all", "found"):
            s = (S(i).get(view) if S(i) else None)
            if s:
                out.append(f"| {i} | stock Ghidra | {view} | {s['decompiled']} / {s['sampled']} | {fmt(s['success_rate'])} | "
                           f"{s['gotos']} | {s['labels']} | {s['lines']} | {fmt(s.get('text_warnings'))} text |")
        for view in ("all", "found"):
            h = H_(i, view)
            out.append(f"| {i} | Hex-Rays | {view} | {h['decompiled']} / {h['sampled']} | {fmt(h['success_rate'])} | "
                       f"{h['gotos']} | {h['labels']} | {h['lines']} | {fmt(h.get('hexrays_warnings'))} hexrays "
                       f"({h.get('functions_with_asm', 0)} fn with `__asm`, {h.get('functions_with_jumpout', 0)} with JUMPOUT) |")
    for i in images:
        v = HV(i)
        if v:
            h = v["hexrays"]["all"]
            out.append(f"| {i} | Hex-Rays + the host's EE plugins | all | {h['decompiled']} / {h['sampled']} | {fmt(h['success_rate'])} | "
                       f"{h['gotos']} | {h['labels']} | {h['lines']} | {fmt(h.get('hexrays_warnings'))} hexrays "
                       f"({h.get('functions_with_asm', 0)} fn with `__asm`) |")
    out += ["", "Warning counts are tool-defined and not comparable across columns: Romwright counts its native "
            "decompiler warnings and `WARNING` text; stock Ghidra `WARNING` comment text; Hex-Rays its "
            "`cfunc_t::get_warnings()` (the informational \"using guessed type\" notes are excluded). "
            "`/* irregular */` is a Romwright printer marker with no counterpart.", ""]
    typed = [i for i in images if i in cr.DWARF]
    out += ["## Arity, parameter types and return type against DWARF (`console_research.dwarf_scores`)", "",
            "| image | DWARF functions | arity R / G / H(all) / H(found) | type-exact R / G / H(all) / H(found) | slots (H all): exact / partial / wrong |",
            "|---|---|---|---|---|"]
    for i in typed:
        r = R(i)
        sg = S(i).get("all") if S(i) else None
        sf = S(i).get("found") if S(i) else None
        ha, hf = H_(i, "all"), H_(i, "found")
        gp = G(i).get("allegrex") if G(i) else None
        stock_arity = fmt(sg.get("arity_accuracy")) if sg else (fmt(gp["types"]["arity_accuracy"]) if gp else "–")
        stock_type = fmt(sg.get("type_exact_rate")) if sg else (fmt(gp["types"]["type_exact_rate"]) if gp else "–")
        out.append(f"| {i} | {fmt(ha.get('dwarf_functions'))} | {fmt(r.get('arity_accuracy'))} / "
                   f"{stock_arity} / {fmt(ha.get('arity_accuracy'))} / {fmt(hf.get('arity_accuracy'))} | "
                   f"{fmt(r.get('type_exact_rate'))} / "
                   f"{stock_type} / {fmt(ha.get('type_exact_rate'))} / {fmt(hf.get('type_exact_rate'))} | "
                   f"{fmt(ha.get('type_exact'))} / {fmt(ha.get('type_partial'))} / {fmt(ha.get('type_wrong'))} |")
    for i in typed:
        v = HV(i)
        if v:
            ha = v["hexrays"]["all"]
            out.append(f"| {i} (+ host EE plugins, Hex-Rays all) | {fmt(ha.get('dwarf_functions'))} | – / – / – / {fmt(ha.get('arity_accuracy'))} / – | "
                       f"– / – / – / {fmt(ha.get('type_exact_rate'))} / – | {fmt(ha.get('type_exact'))} / {fmt(ha.get('type_partial'))} / {fmt(ha.get('type_wrong'))} |")
    diag = [(i, report["images"][i]["hexrays"].get("diag_int64_read_as_32bit")) for i in typed]
    diag = [(i, d) for i, d in diag if d]
    if diag:
        out += ["", "Diagnostic (not the harness metric): the R5900 images' Hex-Rays signatures with `__int64` read as the ILP32 "
                "ABI's 32-bit `int`: " + "; ".join(f"{i}: arity {fmt(d['all']['arity_accuracy'])}, type-exact {fmt(d['all']['type_exact_rate'])} "
                                                  f"(found-only {fmt(d['found']['type_exact_rate'])})" for i, d in diag) + "."]
    out += ["", "The other images have no type truth (psx, psv, x360, gc: no DWARF), so arity and type exactness are "
            "not comparable there.", ""]
    out += ["## Return class, locals and stack slots (locals_truth.py, same parser rules; DWARF images)", "",
            "| image | tool / view | functions | return exact / partial / wrong | local count exact | MAE | class recall / precision | stack slots recall (MIPS) |",
            "|---|---|---|---|---|---|---|---|"]
    for i in report["images"]:
        row = report["images"][i]
        for tool, key in (("Romwright (locals_truth.json, older sample)", "romwright_locals"),
                          ("stock Ghidra", "stock"), ("Hex-Rays", "hexrays")):
            for view in ("all", "found"):
                if key == "romwright_locals":
                    a = (row.get(key) or {}).get("all_scored") if view == "all" else None
                elif key == "stock":
                    a = (row.get("stock") or {}).get(f"locals_{view}")
                else:
                    a = (row.get("hexrays") or {}).get(f"locals_{view}")
                if not a:
                    continue
                st, rt = a["stack"], a["returns"]
                out.append(f"| {i} | {tool} / {view if key != 'romwright_locals' else 'its sample'} | {a['functions']} | "
                           f"{rt['exact']} / {rt['partial']} / {rt['wrong']} | {fmt(a['count_exact'])} | "
                           f"{fmt(a['mean_abs_error'])} | {fmt(a['class_recall'])} / {fmt(a['class_precision'])} | "
                           f"{st['matched']} / {st['truth_slots']} = {fmt(st['recall'])} |")
    out.append("")
    spurious = [i for i in images if report["images"][i].get("spurious_gotos")]
    if spurious:
        out += ["## Spurious gotos (spurious_gotos.py gate set: the sample, plus m22-001's functions on GBA)", "",
                "| image | tool | functions scored | printed gotos | spurious functions | spurious gotos |", "|---|---|---|---|---|---|"]
        for i in spurious:
            sp = report["images"][i]["spurious_gotos"]
            rows = [("Romwright default (spurious_gotos_final.json, older sample)", sp.get("romwright_recorded")),
                    ("Romwright final2: printed gotos over its 200-function sample (spurious gotos are at most this: the "
                     "source has none in the scored functions)",
                     {"functions": R(i).get("sampled"), "print_gotos": R(i).get("gotos"),
                      "spurious_functions": "–", "spurious_gotos": f"≤ {R(i).get('gotos')}"}),
                    ("stock Ghidra", sp.get("stock")), ("Hex-Rays (all)", sp.get("hexrays")),
                    ("Hex-Rays (found)", sp.get("hexrays_found"))]
            for label, t in rows:
                if t:
                    out.append(f"| {i} | {label} | {t.get('functions', 0)} | {t.get('print_gotos', 0)} | "
                               f"{t.get('spurious_functions', 0)} | {t.get('spurious_gotos', 0)} |")
        out.append("")
    out += ["## IDA auto-analysis time (supplement to import_speed.py)", "",
            "Not paired with import_speed.py's runs: different host load and different times of day. "
            "`process` is the wait4 wall of the whole idalib process (interpreter start, load, analysis, database save); "
            "`analysis` is open_database plus auto_wait inside it. Host: " + str(report["host"]) + ".", "",
            "| image | Romwright import s (import-speed) | Ghidra wall s (import-speed, JVM incl.) | IDA analysis s | IDA process wall s | CPU s | peak RSS MB | 1-min load before / after |",
            "|---|---|---|---|---|---|---|---|"]
    for i in images:
        row = report["images"][i]
        p = row["analysis"]["process"]
        sp = row.get("speed") or {}
        out.append(f"| {i} | {fmt(sp.get('romwright_s'))} | {fmt(sp.get('ghidra_s'))} | {fmt(row['analysis']['analysis_s'])} | "
                   f"{fmt(p.get('wall_s'))} | {fmt(p.get('cpu_s'))} | {fmt(row['analysis'].get('worker_peak_rss_mb'))} | "
                   f"{fmt((p.get('load_before') or [None])[0])} / {fmt((p.get('load_after') or [None])[0])} |")
    out.append("")
    out += ["## What IDA was given, and what it applied", "",
            "| image | input | processor / loader | signatures applied | functions |", "|---|---|---|---|---|"]
    for i in images:
        row = report["images"][i]
        a = row["analysis"]
        sigs = ", ".join(s[0] for s in a["signatures"]) or "none"
        out.append(f"| {i} | {row['input']['what']} | {a['processor']['procname']} "
                   f"({'BE' if a['processor']['big_endian'] else 'LE'}) / {a['processor']['filetype']} | {sigs} | "
                   f"{a['functions_total']} |")
    out.append("")
    out += ["## Failures and unsupported instructions (per sampled function; the census column covers every function IDA found)", "",
            "| image | decompile failures (by Hex-Rays code) | functions with an unsupported-category instruction | instructions by category | top `__asm` mnemonics (not lifted) | non-code items inside sampled functions | census: all IDA functions (instructions / functions with one) |",
            "|---|---|---|---|---|---|---|"]
    for i in images:
        c = report["images"][i]["categories"]
        asm = ", ".join(f"{m}×{n}" for m, n in c["asm_mnemonics_top"][:8]) or "none"
        out.append(f"| {i} | {json.dumps(c['failures']) if c['failures'] else 'none'} | "
                   f"{json.dumps(c['functions_with_feature_instructions']) if c['functions_with_feature_instructions'] else 'none'} | "
                   f"{json.dumps(c['feature_instructions']) if c['feature_instructions'] else 'none'} | {asm} | {c['non_code_items']} | "
                   f"{census_cell(report['images'][i]['analysis'].get('census'))} |")
        v = HV(i)
        if v:
            c = v["categories"]
            asm = ", ".join(f"{m}×{n}" for m, n in c["asm_mnemonics_top"][:8]) or "none"
            out.append(f"| {i} + host EE plugins | {json.dumps(c['failures']) if c['failures'] else 'none'} | "
                       f"{json.dumps(c['functions_with_feature_instructions']) if c['functions_with_feature_instructions'] else 'none'} | "
                       f"{json.dumps(c['feature_instructions']) if c['feature_instructions'] else 'none'} | {asm} | {c['non_code_items']} | "
                       f"{census_cell(v['analysis'].get('census'))} |")
    out.append("")
    return out


def markdown(report: dict) -> str:
    out = [f"# Hex-Rays against Romwright and stock Ghidra on the console research images ({report['generated']})", "",
           "Generated by `benchmarks/hexrays_research.py` (a supplement; metric definitions are those of "
           "`console_research.py`, m21-001, `import_speed.py`, `spurious_gotos.py` and `locals_truth.py`, called "
           "unchanged). Columns: **R** Romwright (`" + report["reference"]["report"] + "`, tools `" + report["reference"]["tools"]
           + "`, the same images and 200-function samples), **G** stock Ghidra " + report["stock_note"] + ", **H** Hex-Rays: IDA "
           + str(report.get("ida_version")) + " / Hex-Rays " + str(report.get("hexrays_version"))
           + " via idalib, auto-analysis only.", ""]
    out += ["## License notice", "",
            "Hex-Rays' EULA (`license.txt` in the IDA install, section 2.1(v)) forbids using the Software \"in any manner that "
            "competes with HEX-RAYS, including but not limited to, benchmarking, collecting and publishing data or analysis relating "
            "to the performance of the Software, or developing or marketing a product that is competitive with any Software or "
            "service without first inviting HEX-RAYS to review the results\". This report is benchmarking data of that kind. It was "
            "produced for the Romwright project's own use; Hex-Rays has **not** been invited to review it. Do not publish it (commit "
            "it to a public repository, quote it externally) before that invitation, and have the licence question for a competing "
            "decompiler's developers settled first.", ""]
    out += tables(report)
    out += ["## Gaps: what could not be compared, and why", ""]
    out += [f"- {gap}" for gap in report["gaps"]]
    out += ["", "## Reproduce", "", "```", report["command"], "```", ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=M21.CORPUS)
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--reference", type=Path, default=REFERENCE, help="console_research JSON with the samples and the Romwright column")
    parser.add_argument("--out", type=Path, default=REPORTS / "console_research_hexrays.json")
    parser.add_argument("--images", default="", help="comma-separated image ids (default: all)")
    parser.add_argument("--jobs", type=int, default=2, help="concurrent IDA processes (max 2 on the shared host)")
    parser.add_argument("--stall", type=int, default=STALL_S, help="seconds without a finished function before Hex-Rays is killed")
    parser.add_argument("--render-only", action="store_true", help="re-render the markdown from an existing --out JSON")
    parser.add_argument("--run-stock", action="store_true", help="run stock Ghidra on each sample (locals_stock.py --create)")
    parser.add_argument("--stock-dir", type=Path, default=None, help="stock Ghidra C exports (default: CACHE/stock)")
    args = parser.parse_args()
    if args.render_only:
        report = json.loads(args.out.read_text())
        report["gaps"] = gaps(report)
        report["command"] = COMMAND
        cr.write_json(args.out, report)
        args.out.with_suffix(".md").write_text(markdown(report))
        return 0
    args.jobs = min(args.jobs, 2)
    args.stock_dir = args.stock_dir or args.cache / "stock"
    reference = json.loads(args.reference.read_text())
    speed_report = json.loads(IMPORT_SPEED.read_text())
    psp = cr.read_json(PSP_STOCK)
    locals_report = {r["image"]: r for r in (cr.read_json(LOCALS_TRUTH) or {}).get("reports", [])}
    wanted = {i for i in args.images.split(",") if i}
    specs = [dict(s) for s in cr.IMAGES if not wanted or s["id"] in wanted]
    unknown = wanted - {s["id"] for s in specs}
    if unknown:
        parser.error(f"unknown image: {sorted(unknown)}")
    gate = threading.Semaphore(args.jobs)
    report = {"schema": "console-research-hexrays/1", "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "reference": {"report": str(args.reference.relative_to(ROOT)) if args.reference.is_relative_to(ROOT) else str(args.reference),
                            "tools": reference["tools"], "n": reference["n"], "seed": reference["seed"]},
              "ida_dir": str(IDA_DIR), "ida_python": str(IDA_PYTHON),
              "host": {"cpus": os.cpu_count(), "load_at_start": [round(x, 2) for x in os.getloadavg()]},
              "command": COMMAND,
              "stock_note": "", "images": {},
              "import_speed_status": {i: row.get("status") for i, row in speed_report["rows"].items()}}
    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_image, spec, args, reference, speed_report, gate): spec for spec in specs
                   if spec["id"] in reference["images"]}
        for future in concurrent.futures.as_completed(futures):
            spec = futures[future]
            try:
                results[spec["id"]] = future.result()
            except Exception as error:  # noqa: BLE001 - one image failing must not lose the others
                log(f"{spec['id']}: ERROR {type(error).__name__}: {str(error)[-400:]}")
                results[spec["id"]] = {"status": "error", "reason": f"{type(error).__name__}: {str(error)[-600:]}"}
    for spec in specs:
        image = results.get(spec["id"], {"status": "skipped", "reason": "not in the reference report"})
        report["images"][spec["id"]] = image
        if image.get("status") != "ran":
            continue
        ref_image = reference["images"][spec["id"]]
        image["romwright"] = romwright_column(ref_image)
        image["romwright_import_s"] = (ref_image["configs"]["default"].get("import") or {}).get("seconds")
        image["ghidra_discovery"] = ghidra_discovery(spec["id"], speed_report, psp)
        if image["ghidra_discovery"]:
            image["ghidra_found"] = (image["ghidra_discovery"].get("allegrex") or image["ghidra_discovery"]).get("found")
        srow = speed_report["rows"].get(spec["id"]) or {}
        image["speed"] = {"romwright_s": (srow.get("ours") or {}).get("wall_median_s"),
                          "ghidra_s": (srow.get("ghidra") or {}).get("wall_median_s")}
        if spec["id"] in locals_report:
            image["romwright_locals"] = locals_report[spec["id"]]["tools"].get("ours:default")
        image["hexrays_summary"] = image["hexrays"]["all"]
        # --- stock Ghidra on the same samples
        stock_path = run_stock(spec["id"], spec, args, reference, image["extra_addresses"]) \
            if args.run_stock or (args.stock_dir / f"{spec['id']}.json").is_file() else None
        if stock_path:
            dwarf = load_dwarf(args, spec["id"], args.corpus / spec["image"])
            truth_lt = LT.Truth(spec["id"], args.corpus) if spec["id"] in LT.IMAGES else None
            stock, stock_rows = stock_scores(spec["id"], stock_path, reference["images"][spec["id"]]["sample"],
                                             image["extra_addresses"], dwarf, truth_lt)
            image["stock"] = stock
            if image.get("spurious_gotos"):
                gate_rows = {a: {"gotos": r["gotos"]} for a, r in stock_rows.items() if r.get("success")}
                image["spurious_gotos"]["stock"] = spurious_for(spec["id"], gate_rows)
        if spec["id"] in SPURIOUS:
            recorded = cr.read_json(REPORTS / "spurious_gotos_final.json")
            if recorded and spec["id"] in recorded["images"]:
                image["spurious_gotos"]["romwright_recorded"] = recorded["images"][spec["id"]]["configs"]["default"]["totals"]
        report["ida_version"] = image["analysis"]["ida_version"]
        report["hexrays_version"] = image["analysis"]["hexrays_version"]
    report["stock_note"] = ("(import-speed.json discovery; psp_stock_compare.json for the PSP twins; "
                            + ("stock-Ghidra C on the samples, `" + str(args.stock_dir) + "`)" if args.run_stock or args.stock_dir.is_dir()
                               else "no stock-Ghidra C run for the sample metrics)"))
    report["gaps"] = gaps(report)
    cr.write_json(args.out, {k: v for k, v in report.items()})
    args.out.with_suffix(".md").write_text(markdown(report))
    log(f"report {args.out} / {args.out.with_suffix('.md')}")
    return 0


def gaps(report: dict) -> list[str]:
    """What could not be compared, with the reason: fixed facts of the setup plus what this run's data shows."""
    out = [
        "**Perfect Dark (N64)** is not an image of `console_research.py` (it has its own gate, `n64_segments_score.py`) and was "
        "not run: its truth is addresses derived from the n64decomp/perfect_dark sources by `pd_ido_truth.py`, and neither that "
        "clone nor its truth JSON is on this host (`benchmarks/reports/n64_segments.json` keeps only samples of the missed/invented "
        "entries, which cannot score a different tool). IDA's `n64rom` loader maps the ROM but does not inflate the Rare-zlib game "
        "segment, so a run would first need the raw inflated segment `pd_ido_truth.py extract` writes, which the stock-Ghidra column "
        "also needed.",
        "**Animal Crossing REL** is not in `console_research.py` either: its image there is `main.dol`, which has no truth, so only "
        "function counts and the decompile/failure rows exist (`gc-animal-crossing`). The REL (`foresta.rel`, inside the CISO) has "
        "truth in ac-decomp's dtk `symbols.txt` (not on this host) and IDA has no REL loader and applies no REL relocations, so "
        "the REL half of `gc_rel_gate.py` cannot be reproduced for IDA.",
        "**Arity, parameter types, return class, locals, stack slots** need DWARF: only gba, nds, capcom, dungeon (20 libgcc "
        "functions) and the two PSP twins have it. psx, psv, x360 and gc have none; their rows compare success, gotos, labels, lines "
        "and warnings only.",
        "**Stack-slot recall** (locals_truth) is scored for the MIPS images only (capcom, dungeon, PSP): DWARF's offsets are "
        "relative to the post-prologue `sp`, and locals_truth decodes the frame size for MIPS alone.",
        "**Romwright on the same functions for locals and spurious gotos**: console_research_final2 records no printed C, and the "
        "tools that produced it (`ea27c70333bb669d`) are not on this host. The only Romwright binary here "
        "(`target/release`, 16:13) was run on these samples and imports every console image at recall 0.00-0.77 (psp 0.003, gba 0.0) "
        "while console support is being retired in the tree, so its output is not a Romwright measurement and was discarded. "
        "Romwright's locals and stack-slot numbers are therefore `locals_truth.json` (its own, older sample, tools `6071cd339255a3d8`) "
        "and its spurious-gotos numbers `spurious_gotos_final.json` (older sample), shown as such, plus final2's printed-goto count as "
        "an upper bound; they are not scored on the final2 functions the other two columns use.",
        "**`/* irregular */` functions and Romwright's native warning list** are Romwright printer/decompiler markers with no "
        "Hex-Rays or Ghidra counterpart; warning columns compare each tool's own counter and are not like for like.",
        "**m22-001 objdiff similarity** (pokeemerald, 33 functions) compiles the printed C with agbcc and diffs the object. "
        "Hex-Rays pseudocode is not compilable C for agbcc (IDA type words, `a1:` call-argument labels, `sub_*`/`dword_*` names "
        "for functions and data the context header declares by symbol); making it compile means renaming against the ELF "
        "symbol table and a defs header, which would feed the compiler names the Romwright column also gets only through "
        "`assert-names`. It was not built; the m2c column of m22 (mean 46.126 in context, 7 exact, 20 of 33 compiled, 0 standalone; "
        "STATUS, P4.6 plan gate) is the only other tool scored there, and m2c is scored nowhere else.",
        "**Timing is not paired** with `import_speed.py`: that harness alternates tools run by run on one host load; the IDA runs "
        "were taken on a different host state (the 1-min load is in the table), and other agents were building. The process wall "
        "includes interpreter start and the database save (`save_s` in the JSON).",
        "**PSP stock Ghidra** has no printed-C run: its column comes from `psp_stock_compare.json` (discovery and types only; "
        "the Allegrex language, with the stock loader's MIPS language in the JSON). Gotos, labels, lines and locals are blank for it.",
        "**Stock-Ghidra C rows need `--run-stock`** (stock Ghidra headless on the samples, JVM + analysis per image); an image "
        "whose run is missing or failed shows `–`.",
        "**No FLIRT and no Lumina**: auto-analysis only. The signature files IDA applied are in the setup table: the PSX loader "
        "applies `psyq`; none was applied to the ELF, PE, PSP or raw images.",
        "**Plugins.** The host's IDA install carries three plugins Hex-Rays does not ship, all added after the 2026-07-14 install: "
        "`ida-emotionengine.py` (third-party EE COP2/VU0 disassembler, author oct0xor), `ee_mac_lifter.so` (built from ~/ida-sdk; "
        "lifts R5900 FPU accumulator chains, MMI `pcpyld`/`pcpyud` and COP0 `bc0f`/`bc0t` to pseudocode) and `hexrays_udc.so` (the "
        "SDK's `sample8` user-defined call for `svc_exit`). The headline Hex-Rays column runs with `IDADIR` on a symlink tree "
        "without them (`shipped`, IDA as Hex-Rays ships it); for the MIPS images (PS2, PSX, PSP) the run is repeated on the install "
        "as it is (`host-plugins`) and shown as extra rows.",
        "**Raw-image discovery is not a loader comparison**: for gba, nds, psv and gc IDA has no loader, so it sees one flat "
        "segment and one seeded entry point (the reset vector, ARM9 entry or `module_start`, as the importers seed), and its "
        "flow-following analysis finds only what that entry reaches. Romwright and stock Ghidra find far more of the same images "
        "(see the discovery table); `[INFERENCE]` the difference is their function-start pattern and table seeding on top of flow "
        "analysis. IDA's recall on those four says what its default analysis does with an unannotated image, not what its "
        "decompiler does (the `found` rows isolate that).",
        "**Created functions** (where IDA made none at a sampled address) are made with `add_func`, then IDA's analysis is run to "
        "completion on them (stack-pointer tracing and frame; without that Hex-Rays reports an unbalanced stack and leaves an ARM "
        "`pop {..., pc}` epilogue as `__asm`), in the ARM-family mode the truth ELF gives for that address (the STT_FUNC low bit "
        "or the `$a`/`$t` mapping symbol in force; gba, nds) or as Thumb (Vita, which has no truth ELF): the mode is an oracle "
        "input for creation only; discovery is never given it. The `found` rows involve no creation.",
        "**R5900 types**: IDA spells R5900 general registers `__int64`, which the harness scores as 64-bit against DWARF's 32-bit "
        "`int`. The diagnostic row `diag_int64_read_as_32bit` in the JSON rescoring those slots as 32-bit is not the harness metric.",
        "**Xenon VMX128 and Vita NEON**: IDA decodes both (VMX128 mnemonics such as `vaddfp128`/`lvx128`; VFP/NEON such as "
        "`vceq.f32`) but Hex-Rays prints the ones it cannot lift as `__asm` blocks (counts in the failures table, whole-image "
        "census beside them). The PE loader picked processor `PPC` for the XEX image; no Xenon-specific option was set, and none "
        "was looked for.",
    ]
    for image_id, row in report["images"].items():
        if row.get("status") != "ran":
            out.append(f"**{image_id}** not run: {row.get('reason')}")
        elif not row.get("stock") and image_id in speed.GHIDRA_CONFIG:
            incomplete = (report.get("import_speed_status") or {}).get(image_id) == "incomplete"
            out.append(f"**{image_id}: no stock-Ghidra decompile rows.** "
                       + ("Stock Ghidra does not finish analysing this image: import-speed.json records it `incomplete` "
                          f"(no result inside import_speed.py's {speed.LIMIT_S} s limit), and this run's attempt (`locals_stock.py`, same "
                          "language and loader, default analyzers) was stopped after 35 min without a result. " if incomplete
                          else "The stock run is absent or failed (see the stock log under the cache).")
                       + "Its stock discovery, types and C rows are blank; Romwright and Hex-Rays are compared without it.")
    return out


if __name__ == "__main__":
    sys.exit(main())
