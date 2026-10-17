#!/usr/bin/env python3
"""Write the two header fields ds-rom cannot recompute: romfix.py RAW OUT

* the secure area CRC (header 0x6C): the retail header records the CRC-16 of the
  *encrypted* secure area; a decrypted dump has no key to reproduce it, so the retail
  value (config/header.json) is written back;
* the header CRC (0x15E): CRC-16 (polynomial 0xA001, initial 0xFFFF) of header bytes 0..0x15D,
  recomputed after the edit.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def main():
    raw, out = sys.argv[1:3]
    header = json.loads((ROOT / "config" / "header.json").read_text())
    data = bytearray(Path(raw).read_bytes())
    data[0x6C:0x6E] = bytes.fromhex(header["secure_area_crc"])
    data[0x15E:0x160] = crc16(bytes(data[:0x15E])).to_bytes(2, "little")
    Path(out).write_bytes(bytes(data))


main()
