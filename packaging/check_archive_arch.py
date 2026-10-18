#!/usr/bin/env python3
"""Fail unless every native binary in a portable archive has the archive's architecture.

    python packaging/check_archive_arch.py dist-portable            # every archive in it
    python packaging/check_archive_arch.py romwright-0.5.0-macos-aarch64.tar.gz

`packaging/stage_portable.py` names an archive `romwright-<version>-<os>-<arch>`
after the machine it ran on. That says nothing about what was compiled: a
vendored Makefile that hard-codes `-arch x86_64` once put an Intel `ghidra_opt` in
an archive named `macos-aarch64`. This reads the executable header of every file
in the archive and requires

  * every file under `bin/` to be a native executable of the archive's OS
    (PE on windows, Mach-O on macos, ELF on linux) built for exactly its arch
    (a macOS universal binary must hold that one architecture and no other);
  * every other file that is a native executable (a library, say) to match too.

The headers are parsed here, not by `lipo`/`file`, so the same check runs on all
three release runners and in tests/m6-008. Standard library only.
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

# The `arch` field stage_portable.py puts in an archive name -> machine codes.
ELF_MACHINE = {"x86_64": {62}, "aarch64": {183}}
PE_MACHINE = {"x86_64": {0x8664}, "aarch64": {0xAA64}}
MACHO_CPU = {"x86_64": {0x01000007}, "aarch64": {0x0100000C}}
FORMAT = {"windows": "PE", "macos": "Mach-O", "linux": "ELF"}
NAME = re.compile(r"^romwright-.+-(windows|macos|linux)-([A-Za-z0-9_]+)\.(?:zip|tar\.gz)$")
HEADER = 4096


def elf_machines(head: bytes) -> set[int] | None:
    if head[:4] != b"\x7fELF" or len(head) < 20:
        return None
    order = "<" if head[5] == 1 else ">"
    return {struct.unpack_from(order + "H", head, 18)[0]}


def pe_machines(head: bytes) -> set[int] | None:
    if head[:2] != b"MZ" or len(head) < 0x40:
        return None
    offset = struct.unpack_from("<I", head, 0x3C)[0]
    if offset + 6 > len(head) or head[offset:offset + 4] != b"PE\0\0":
        return None
    return {struct.unpack_from("<H", head, offset + 4)[0]}


def macho_machines(head: bytes) -> set[int] | None:
    """The cpu types in a thin or fat (universal) Mach-O image."""
    if len(head) < 8:
        return None
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):  # little-endian thin
        return {struct.unpack_from("<I", head, 4)[0]}
    if head[:4] in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):  # big-endian thin
        return {struct.unpack_from(">I", head, 4)[0]}
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):  # fat, big-endian
        count = struct.unpack_from(">I", head, 4)[0]
        if count == 0 or count > 16:  # Java class files share the 0xcafebabe magic
            return None
        stride = 20 if head[3] == 0xBE else 32
        if 8 + count * stride > len(head):
            return None
        return {struct.unpack_from(">I", head, 8 + i * stride)[0] for i in range(count)}
    return None


def identify(head: bytes) -> tuple[str, set[int]] | None:
    for kind, parse in (("ELF", elf_machines), ("PE", pe_machines), ("Mach-O", macho_machines)):
        machines = parse(head)
        if machines is not None:
            return kind, machines
    return None


def members(archive: Path):
    """Yields (path inside the archive, first HEADER bytes) for every file."""
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                if not info.is_dir():
                    with bundle.open(info) as handle:
                        yield info.filename, handle.read(HEADER)
    else:
        with tarfile.open(archive) as bundle:
            for info in bundle:
                if info.isfile():
                    handle = bundle.extractfile(info)
                    yield info.name, handle.read(HEADER)


def check(archive: Path) -> list[str]:
    """Returns one message per binary whose architecture is not the archive's."""
    match = NAME.match(archive.name)
    if not match:
        return [f"{archive.name}: not named romwright-<version>-<os>-<arch>"]
    os_name, arch = match.groups()
    if arch not in ELF_MACHINE:
        return [f"{archive.name}: unknown architecture '{arch}' (expected x86_64 or aarch64)"]
    expected_kind = FORMAT[os_name]
    table = {"ELF": ELF_MACHINE, "PE": PE_MACHINE, "Mach-O": MACHO_CPU}
    problems: list[str] = []
    checked = 0
    for name, head in members(archive):
        found = identify(head)
        in_bin = name.split("/")[1:2] == ["bin"]  # <top>/bin/<file>
        if found is None:
            if in_bin:
                problems.append(f"{name}: under bin/ but not a native executable")
            continue
        kind, machines = found
        checked += 1
        if kind != expected_kind:
            problems.append(f"{name}: a {kind} binary in a {os_name} archive (expected {expected_kind})")
        elif machines != table[kind][arch]:
            problems.append(f"{name}: machine {sorted(hex(m) for m in machines)} is not "
                            f"{arch} ({sorted(hex(m) for m in table[kind][arch])})")
    if not checked and not problems:
        problems.append(f"{archive.name}: holds no native binary")
    return problems


def archives_in(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found += sorted(p for p in path.iterdir() if p.name.endswith((".zip", ".tar.gz")))
        else:
            found.append(path)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", type=Path, help="archives, or directories holding them")
    arguments = parser.parse_args()
    archives = archives_in(arguments.paths)
    if not archives:
        print("error: no archive to check", file=sys.stderr)
        return 1
    failed = False
    for archive in archives:
        problems = check(archive)
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        failed = failed or bool(problems)
        if not problems:
            print(f"ok: every binary in {archive.name} is {NAME.match(archive.name).group(2)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
