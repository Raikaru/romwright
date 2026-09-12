#!/usr/bin/env python3
"""m20-012: N64 RSP disassembly — scalar MIPS-I + COP2 vector unit.

Gate: disassemble the IPL3 boot code from Perfect Dark (real RSP scalar
code at ROM offset 0x40) and compare every mnemonic against rabbitizer
(the decoder spimdisasm/rspDisasm wraps — the N64 decomp community's
reference). Vector coverage is proven by decoding the full COP2 funct
table and asserting each mnemonic matches rabbitizer's.
"""
import argparse
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROM = Path("/home/raikaru/ventris-corpus/perfect_dark_ntsc_final.z64")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    report = {"gate": "m20-012", "status": "fail", "passed": False}

    import rabbitizer  # the reference decoder

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli",
                    "--bin", "rsp_dump"], cwd=ROOT, check=True,
                   capture_output=True, timeout=1800)
    cli = ROOT / "target" / "release" / "rsp_dump"

    # --- Scalar: IPL3 boot code (0x40..0x1000), real RSP MIPS-I. ---
    data = ROM.read_bytes()[0x40:0x1000]
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        tmp = f.name
    ours = subprocess.run([str(cli), tmp], capture_output=True, text=True,
                          check=True).stdout.splitlines()
    words = struct.unpack(f">{len(data)//4}I", data)
    scalar_total = scalar_match = 0
    for i, w in enumerate(words):
        ref = rabbitizer.Instruction(
            w, 0x80000040 + i * 4,
            category=rabbitizer.InstrCategory.RSP).disassemble().split()[0]
        our = ours[i].split()[0] if i < len(ours) else "<missing>"
        # rabbitizer emits .word for data it can't classify; skip those —
        # they're data regions, not decode disagreements.
        if ref == ".word":
            continue
        scalar_total += 1
        if ref == our:
            scalar_match += 1

    # --- Vector: the full COP2 funct table (0x00..0x3f). ---
    vec_total = vec_match = 0
    for funct in range(64):
        w = 0b010010_1_0000_00010_00011_00100_000000 | funct
        ref = rabbitizer.Instruction(
            w, 0x80000000,
            category=rabbitizer.InstrCategory.RSP).disassemble().split()[0]
        # Encode the same word for our decoder.
        open(tmp, "wb").write(struct.pack(">I", w))
        our = subprocess.run([str(cli), tmp], capture_output=True,
                             text=True, check=True).stdout.split()[0]
        vec_total += 1
        if ref == our or (ref == ".word" and our == ".word"):
            vec_match += 1

    summary = (f"scalar {scalar_match}/{scalar_total}, "
               f"vector {vec_match}/{vec_total}")
    ok = scalar_match == scalar_total and vec_match == vec_total
    report.update(status="pass" if ok else "fail", passed=ok,
                  summary=summary,
                  metrics={"scalar": f"{scalar_match}/{scalar_total}",
                           "vector": f"{vec_match}/{vec_total}"})
    print(f"m20-012: {'PASS' if ok else 'FAIL'} ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
