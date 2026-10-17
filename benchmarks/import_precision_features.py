#!/usr/bin/env python3
"""Byte features of function entries on MIPS images, for `import_precision.py features`.

For one image (a result row of `import_precision.py run` plus the staged binary), reads the executable
regions of the import through `romwright-cli mem` and describes how each entry is reached: what its first
word is, what sits right before it, who branches, jumps, calls or points at it, and how long our function is.
The same description is made for the truth starts (found or not) and for the invented entries of both tools,
so a candidate rule can be read as "of the truth starts with this shape N, of the invented ones M".
"""
from __future__ import annotations

import collections
import os
import sqlite3
import struct
import subprocess
from pathlib import Path


def regions(project: Path, program: str) -> list[tuple[int, int]]:
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    out = [(int(start, 16), size) for start, size, perms in db.execute(
        "SELECT start, size, permissions FROM memory_regions WHERE program_id = ?", (pid,)) if "x" in perms]
    db.close()
    return out


def read_words(cli: str, binary: Path, spans, big_endian: bool, env: dict) -> dict[int, int]:
    words: dict[int, int] = {}
    fmt = ">I" if big_endian else "<I"
    for start, size in spans:
        text = subprocess.run([cli, "mem", str(binary), f"{start:x}", str(size)], capture_output=True, text=True,
                              env=env).stdout.split()
        data = bytes(int(x, 16) for x in text)
        for i in range(len(data) // 4):
            words[start + 4 * i] = struct.unpack_from(fmt, data, 4 * i)[0]
    return words


def word_class(w: int | None) -> str:
    if w is None:
        return "?"
    if w == 0:
        return "nop"
    if w == 0x03E00008:
        return "jr_ra"
    if w >> 16 == 0x27BD:
        return "frame" if w & 0x8000 else "sp+"
    if w >> 21 == 0x47D:
        return "lw_sp"
    op = w >> 26
    if op == 2:
        return "j"
    if op == 3:
        return "jal"
    if op == 0 and w & 0x3F == 8:
        return "jr"
    if op in (1, 4, 5, 6, 7, 20, 21, 22, 23) or (op == 17 and (w >> 21) & 31 == 8):
        return "branch"
    return "op"


class Index:
    """Inbound edges of a MIPS word map: calls, jumps, branches (source address lists) and data words."""

    def __init__(self, words: dict[int, int]):
        self.words = words
        self.calls: dict[int, list[int]] = collections.defaultdict(list)
        self.jumps: dict[int, list[int]] = collections.defaultdict(list)
        self.branches: dict[int, list[int]] = collections.defaultdict(list)
        for a, w in words.items():
            op = w >> 26
            if op in (2, 3):
                target = ((a + 4) & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
                (self.calls if op == 3 else self.jumps)[target].append(a)
            elif op in (1, 4, 5, 6, 7, 20, 21, 22, 23) or (op == 17 and (w >> 21) & 31 == 8):
                off = w & 0xFFFF
                off = off - 0x10000 if off & 0x8000 else off
                self.branches[a + 4 + off * 4].append(a)

    def describe(self, entry: int, size: int, previous_entry: int | None, data_words: set[int]) -> tuple:
        w = self.words
        first = word_class(w.get(entry))
        before = word_class(w.get(entry - 8))
        gap = word_class(w.get(entry - 4))
        lo = previous_entry if previous_entry is not None else 0
        inbound = []
        if self.calls.get(entry):
            inbound.append("call")
        if self.jumps.get(entry):
            inbound.append("jump")
        near = [s for s in self.branches.get(entry, ()) if lo <= s < entry]
        far = [s for s in self.branches.get(entry, ()) if not lo <= s < entry]
        if near:
            inbound.append("branch_above")
        if far:
            inbound.append("branch_elsewhere")
        if entry in data_words:
            inbound.append("data")
        bucket = "<=8" if size <= 8 else "<=16" if size <= 16 else "<=32" if size <= 32 else ">32"
        return (first, f"{before}/{gap}", "+".join(inbound) or "none", bucket)
