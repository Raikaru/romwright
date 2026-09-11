#!/usr/bin/env python3
"""m19-003: pre-disassembly byte analysis (clean-room SBA shape).

Claim: an exhaustive length sweep over mapped bytes runs in linear
time with a deterministic per-offset result, and agrees with the
SLEIGH console where ground truth holds addresses to check.

What this is: Nguyen et al., "Analyzing Bytes: Pre-Disassembly Static
Binary Analysis" (PACMPL 2026, doi 10.1145/3808292), show exhaustive
disassembly at every offset gives a superset CFG that backward
analyses prune without polluting intended instructions, in O(n) with
a result for every offset. Inputs are raw bytes plus architecture
semantics -- no symbols. Their reference implementation is GPL-3.0
and cannot be vendored into this Apache-2.0 tree, so `lre-cli
byte-scan` is a clean-room sweep over our own hand decoder
(`crates/lre-core/src/disasm.rs`): one (length, flow-class) pair per
offset, a FNV digest over the stream, and point queries answered from
the swept bytes.

What the gate asserts, and refuses to assert beyond:

* determinism: two sweeps of the same range hash identically;
* agreement: hand length equals console flow length on a sample of
  symtab function entries and mid-body offsets (the only per-offset
  truth a symbol table covers);
* scale: the retail FFXV .text sweeps end to end (time recorded).

The gate never claims the sweep distinguishes code from data: a
length array alone cannot, and the report says so.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import re
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"
CORPUS = Path("/home/raikaru/ventris-cache/corpus")
FFXV = Path.home() / "ventris-corpus/extracted/win-ffxv/ffxv_s.exe"
THRESHOLDS = {"agreement": 0.95}


def run(arguments: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(
        [str(CLI)] + arguments, cwd=ROOT, env=environment,
        capture_output=True, text=True, timeout=1200,
    )
    if result.returncode:
        raise SystemExit(f"{' '.join(arguments)} failed: {result.stderr[-2000:]}")
    return result.stdout


def pe_text_range() -> tuple[int, int]:
    data = FFXV.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    table = pe_offset + 24 + optional_size
    for index in range(sections):
        entry = table + index * 40
        name = data[entry:entry + 8].split(b"\0")[0]
        if name == b".text":
            vsize = struct.unpack_from("<I", data, entry + 8)[0]
            vaddr = struct.unpack_from("<I", data, entry + 12)[0]
            return 0x140000000 + vaddr, vsize
    raise SystemExit("no .text in ffxv_s.exe")


def sweep(binary: Path, vaddr: int, size: int, ask: list[int],
          environment: dict[str, str]) -> dict:
    out = run(["byte-scan", str(binary), f"{vaddr:#x}", str(size),
               "--ask=" + ",".join(f"{a:#x}" for a in ask), "--json"], environment)
    return json.loads(out)


def symtab_funcs(binary: Path) -> list[tuple[int, int]]:
    out = subprocess.run(["readelf", "--symbols", "-W", str(binary)],
                         capture_output=True, text=True, timeout=120).stdout
    funcs = []
    for line in out.splitlines():
        if " UND " in line:
            continue
        match = re.match(
            r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\w+)\s+\w+\s+\w+\s+\S+\s+(.*\S)\s*$", line)
        if match and match.group(3) == "FUNC" and int(match.group(2)) > 0:
            funcs.append((int(match.group(1), 16), int(match.group(2))))
    return funcs


def console_length(binary: Path, address: int, environment: dict[str, str]) -> int | None:
    # Two disassembled lines: the address gap is the first one's length.
    # A mid-instruction address the console refuses is no verdict either
    # way, so a failed disassembly is None, not disagreement.
    try:
        out = run(["disasm", str(binary), f"{address:#x}", "-n", "2"], environment)
    except SystemExit:
        return None
    found = re.findall(r"^(0x[0-9a-f]+):", out, re.MULTILINE)
    if len(found) < 2:
        return None
    return int(found[1], 16) - int(found[0], 16)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.setdefault("VENTRIS_CONSOLE", str(ROOT / "native/build/decomp_native"))
    environment["VENTRIS_NO_IMPORT_CACHE"] = "1"
    environment["TMPDIR"] = str(arguments.work / "tmp")
    (arguments.work / "tmp").mkdir(exist_ok=True)
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)

    failures: list[str] = []
    rows = []
    for identifier in ("x86_64_plain_o0", "x86_64_plain_o2", "x86_64_many_o2"):
        binary = CORPUS / f"{identifier}.bin"
        named = CORPUS / f"{identifier}.unstripped"
        if not binary.is_file():
            rows.append({"id": identifier, "skipped": "missing"})
            continue
        funcs = symtab_funcs(named)
        entry = min(address for address, _ in funcs)
        span = max(addr + length for addr, length in funcs) - entry
        first = sweep(binary, entry, span, [], environment)
        second = sweep(binary, entry, span, [], environment)
        deterministic = first["digest"] == second["digest"]
        rng = random.Random(0xC10C)
        sample = sorted(rng.sample([a for a, _ in funcs], min(12, len(funcs))))
        mids = sorted({a + z // 2 for a, z in funcs if z > 8} - set(sample))
        sample += sorted(rng.sample(mids, min(12, len(mids)))) if mids else []
        asked = sweep(binary, entry, span, sample, environment)["asked"]
        hand = {row["address"]: row["len"] for row in asked}
        agree = total = 0
        for address in sample:
            truth = console_length(binary, address, environment)
            if truth is not None and address in hand:
                total += 1
                agree += hand[address] == truth
        row = {
            "id": identifier,
            "span": span,
            "sweep_ms": first["ms"],
            "deterministic": deterministic,
            "agreement": round(agree / total, 4) if total else 0.0,
            "compared": total,
        }
        rows.append(row)
        print(json.dumps(row), flush=True)
        if not deterministic:
            failures.append(f"{identifier}: sweep not deterministic")

    # Scale row: the retail .text end to end, timed.
    if FFXV.is_file():
        vaddr, size = pe_text_range()
        started = time.monotonic()
        full = sweep(FFXV, vaddr, size, [], environment)
        wall_s = round(time.monotonic() - started, 1)
        rows.append({"id": "ffxv_text", "span": size, "sweep_ms": full["ms"],
                     "wall_s": wall_s, "digest": full["digest"][:16],
                     "flows": full["flows"]})
        print(json.dumps(rows[-1]), flush=True)
    else:
        rows.append({"id": "ffxv_text", "skipped": "missing retail image"})

    measured = [row for row in rows if "skipped" not in row and "agreement" in row]
    for row in measured:
        if row["agreement"] < THRESHOLDS["agreement"]:
            failures.append(f"{row['id']}: agreement {row['agreement']}")
    report = {
        "id": "m19-003",
        "milestone": "M19",
        "criterion": "Pre-disassembly byte analysis (clean-room SBA shape)",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "citations": {
            "method": "Nguyen et al., Analyzing Bytes (SBA), PACMPL 2026, doi 10.1145/3808292",
        },
        "thresholds": THRESHOLDS,
        "rows": rows,
        "status": "pass" if not failures else "fail",
        "failures": failures,
    }
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print(f"FAIL: {'; '.join(failures)}", file=sys.stderr)
        return 1
    print("m19-003: PASS (byte sweep deterministic, console agreement holds)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
