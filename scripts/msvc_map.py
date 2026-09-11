"""MSVC LINK map oracle: publics by value as ground-truth addresses.

Parses the `Publics by Value ... Rva+Base ... Lib:Object` section of an
MSVC linker map (see STATUS.md, "FFXV PE against its MAP"). A row looks
like::

     0001:00000000       HCAMixer_Initialize        0000000140001000 f   seadr64:HCAMixer.obj

`Address` is segment:offset with the offset relative to the segment's
section. The oracle VA is derived, never trusted, from the PE itself:
segment N (1-based) is the Nth PE section in virtual-address order, so
``RVA = section[N-1].VirtualAddress - image_base + offset`` and
``VA = image base + RVA``. Each derived VA is cross-checked against the
row's own `Rva+Base` column; rows that disagree are dropped and counted
rather than trusted from either side.

Kept rows are flagged `f` (functions). Dropped: segment 0000
(`<absolute>` linker constants), non-`f` rows (data, imports), and rows
whose derivation disagrees with `Rva+Base` (usually section-merge
artifacts where the segment order no longer matches the output order).
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

PUBLICS_HEADER = "Publics by Value"
ROW = re.compile(
    r"^ ([0-9a-fA-F]{4}):([0-9a-fA-F]+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([f ])\s*(\S.*)?$"
)


@dataclass
class MapOracle:
    """Function addresses from a LINK map: VA -> public name."""
    functions: dict[int, str] = field(default_factory=dict)
    total_publics: int = 0
    function_rows: int = 0
    verified: int = 0
    disagreed: int = 0
    data_rows: int = 0
    data: dict[int, str] = field(default_factory=dict)


def pe_sections(image: Path) -> tuple[int, list[tuple[str, int]]]:
    """Image base and (name, virtual address) per section, in VA order."""
    data = image.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"{image} is not a PE")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{image} has no PE signature")
    coff = pe_offset + 4
    sections_count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    base_offset = optional + 28 if magic == 0x10B else optional + 24
    base = struct.unpack_from("<Q" if magic == 0x20B else "<I", data, base_offset)[0]
    table = coff + 20 + optional_size
    sections = []
    for index in range(sections_count):
        entry = table + index * 40
        name = data[entry:entry + 8].split(b"\0")[0].decode("ascii", "replace")
        vaddr = struct.unpack_from("<I", data, entry + 12)[0]
        sections.append((name, base + vaddr))
    sections.sort(key=lambda section: section[1])
    return base, sections


def parse_map(map_path: Path, image: Path) -> MapOracle:
    """Derives the function oracle, cross-checked row by row."""
    base, sections = pe_sections(image)
    oracle = MapOracle()
    in_publics = False
    with map_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not in_publics:
                if PUBLICS_HEADER in line:
                    in_publics = True
                continue
            match = ROW.match(line.rstrip("\n"))
            if not match:
                continue
            segment = int(match.group(1), 16)
            offset = int(match.group(2), 16)
            name = match.group(3)
            stated = int(match.group(4), 16)
            flag = match.group(5)
            oracle.total_publics += 1
            if segment == 0 or name == "<absolute>":
                continue
            if not 1 <= segment <= len(sections):
                oracle.disagreed += 1
                continue
            derived = sections[segment - 1][1] + offset
            if derived != stated:
                oracle.disagreed += 1
                continue
            if flag == "f":
                oracle.function_rows += 1
                oracle.functions[derived] = name
                oracle.verified += 1
            else:
                oracle.data_rows += 1
                oracle.data[derived] = name
    return oracle
