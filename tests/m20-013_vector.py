#!/usr/bin/env python3
"""m20-013: vector units — PS2 VU (EE COP2) + PSX GTE (R3000 COP2).

Gate:
  VU: every VU instruction word embedded in nightfire-ps2's .s listing
      comments (/* off addr HEXWORD */ mnemonic ...) decodes to the same
      mnemonic under our decoder — 19k+ real shipped-game instructions.
  GTE: all 64 command words + the full mvmva flag matrix + sf variants
      match rabbitizer's R3000GTE decoder.
"""
import argparse
import glob
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NIGHTFIRE = Path("/home/raikaru/Projects/nightfire-ps2/asm")


def extract_vu_pairs():
    pairs = []
    pat = re.compile(
        r"\s*/\*\s*[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+([0-9A-Fa-f]{8})\s*\*/\s*(.+)")
    for f in glob.glob(str(NIGHTFIRE / "**/*.s"), recursive=True):
        for line in open(f, errors="replace"):
            m = pat.match(line)
            if not m:
                continue
            word = struct.unpack("<I", struct.pack(">I", int(m.group(1), 16)))[0]
            text = m.group(2).strip()
            if text and not text.startswith("."):
                pairs.append((word, text))
    return [p for p in pairs
            if re.match(r"(v|lqc2|sqc2|qmfc2|qmtc2|cfc2|ctc2|bc2|mfc2|mtc2)",
                        p[1])]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    report = {"gate": "m20-013", "status": "fail", "passed": False}

    import rabbitizer

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli",
                    "--bin", "vu_dump", "--bin", "gte_dump"],
                   cwd=ROOT, check=True, capture_output=True, timeout=1800)

    # --- VU: real game code ---
    vu = extract_vu_pairs()
    data = b"".join(struct.pack("<I", w) for w, _ in vu)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        tmp = f.name
    ours = subprocess.run([str(ROOT / "target/release/vu_dump"), tmp],
                          capture_output=True, text=True,
                          check=True).stdout.splitlines()
    vu_match = sum(
        1 for i, (_, exp) in enumerate(vu)
        if i < len(ours)
        and ours[i].split()[0] == exp.split()[0].rstrip(","))

    # --- GTE: exhaustive command + flag sweep vs rabbitizer ---
    words = [(0b010010 << 26) | (1 << 25) | c for c in range(64)]
    for mx in range(4):
        for v in range(4):
            for cv in range(4):
                for lm in range(2):
                    for sf in range(2):
                        words.append((0b010010 << 26) | (1 << 25)
                                     | (mx << 17) | (v << 15) | (cv << 13)
                                     | (lm << 10) | (sf << 19) | 0x12)
    for cmd in (0x0c, 0x28, 0x3d, 0x3e):
        for sf in range(2):
            words.append((0b010010 << 26) | (1 << 25) | (sf << 19) | cmd)
    open(tmp, "wb").write(b"".join(struct.pack("<I", w) for w in words))
    ours = subprocess.run([str(ROOT / "target/release/gte_dump"), tmp],
                          capture_output=True, text=True,
                          check=True).stdout.splitlines()
    gte_match = sum(
        1 for i, w in enumerate(words)
        if i < len(ours)
        and ours[i].split()[0] == rabbitizer.Instruction(
            w, 0x80000000,
            category=rabbitizer.InstrCategory.R3000GTE)
        .disassemble().split()[0])

    summary = f"VU {vu_match}/{len(vu)}, GTE {gte_match}/{len(words)}"
    ok = vu_match == len(vu) and gte_match == len(words)
    report.update(status="pass" if ok else "fail", passed=ok,
                  summary=summary,
                  metrics={"vu": f"{vu_match}/{len(vu)}",
                           "gte": f"{gte_match}/{len(words)}"})
    print(f"m20-013: {'PASS' if ok else 'FAIL'} ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
