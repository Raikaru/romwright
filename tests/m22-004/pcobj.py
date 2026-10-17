"""x86 PE/COFF helpers for the PC C-output lane (tests/m22-004_pc_c_output.py).

* `PeImage`   -- the retail PE's sections as a virtual-address map.
* `CoffObject` -- a candidate object MSVC wrote (COFF, i386): the function's bytes and its relocation fields.
* `object_for_objdiff` -- a one-function ELF32 i386 object (relocations kept) for objdiff-cli, which has an x86 backend
  for ELF and COFF; the lane writes both sides itself so the target and the candidate share one symbol and relocation
  shape.
* `compare`, `field_mask` -- the byte comparison outside relocation fields (the m22 comparator, for i386).
"""
from __future__ import annotations

import re
import struct

IMAGE_REL_I386_DIR32 = 0x0006
IMAGE_REL_I386_DIR32NB = 0x0007
IMAGE_REL_I386_REL32 = 0x0014
IMAGE_REL_I386_SECTION = 0x000A
IMAGE_REL_I386_SECREL = 0x000B
# the relocation types whose 4-byte field the linker rewrites
FIELD_TYPES = {IMAGE_REL_I386_DIR32, IMAGE_REL_I386_DIR32NB, IMAGE_REL_I386_REL32, IMAGE_REL_I386_SECREL}

R_386_32 = 1
R_386_PC32 = 2
STT_FUNC = 2
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_REL = 1, 2, 3, 9


class PcObjError(ValueError):
    pass


class PeImage:
    """A PE32 image's sections as a virtual-address map (what the loader would map)."""

    def __init__(self, path):
        data = open(path, "rb").read()
        if data[:2] != b"MZ":
            raise PcObjError(f"{path}: not a PE")
        pe, = struct.unpack_from("<I", data, 0x3C)
        if data[pe:pe + 4] != b"PE\0\0":
            raise PcObjError(f"{path}: no PE signature")
        machine, nsec, _stamp, _sym, _nsym, opt_size, _chars = struct.unpack_from("<HHIIIHH", data, pe + 4)
        if machine != 0x14C:
            raise PcObjError(f"{path}: machine {machine:#x} is not i386")
        magic, = struct.unpack_from("<H", data, pe + 24)
        if magic != 0x10B:
            raise PcObjError(f"{path}: not a PE32 optional header")
        self.image_base, = struct.unpack_from("<I", data, pe + 24 + 28)
        self.data = data
        self.sections = []
        table = pe + 24 + opt_size
        for index in range(nsec):
            name, vsize, va, rsize, roff, _r, _l, _nr, _nl, chars = struct.unpack_from("<8sIIIIIIHHI", data, table + 40 * index)
            self.sections.append((name.rstrip(b"\0").decode("latin1"), self.image_base + va, max(vsize, rsize), roff, rsize, chars))

    def bytes_at(self, address: int, length: int) -> bytes:
        for _name, base, size, roff, rsize, _chars in self.sections:
            if base <= address and address + length <= base + size:
                offset = address - base
                have = max(0, min(length, rsize - offset))
                return self.data[roff + offset:roff + offset + have] + b"\0" * (length - have)
        # a window running past the end of the section: what is mapped, zero beyond
        for _name, base, size, roff, rsize, _chars in self.sections:
            if base <= address < base + size:
                have = self.bytes_at(address, base + size - address)
                return have + b"\0" * (length - len(have))
        raise KeyError(f"{address:#x}+{length} is not inside a section")


class CoffObject:
    """An i386 COFF object (what cl.exe writes)."""

    def __init__(self, data: bytes):
        if len(data) < 20:
            raise PcObjError("short COFF object")
        machine, nsec, _stamp, symptr, nsym, opt, _chars = struct.unpack_from("<HHIIIHH", data, 0)
        if machine != 0x14C:
            raise PcObjError(f"COFF machine {machine:#x} is not i386")
        self.data = data
        strings_at = symptr + 18 * nsym
        strtab = data[strings_at:strings_at + struct.unpack_from("<I", data, strings_at)[0]] if nsym and strings_at + 4 <= len(data) else b""

        def string(offset):
            end = strtab.find(b"\0", offset)
            return strtab[offset:end if end >= 0 else None].decode("latin1")

        self.symbols = []
        index = 0
        while index < nsym:
            raw = data[symptr + 18 * index: symptr + 18 * (index + 1)]
            if raw[:4] == b"\0\0\0\0":
                name = string(struct.unpack_from("<I", raw, 4)[0])
            else:
                name = raw[:8].rstrip(b"\0").decode("latin1")
            value, section, kind, storage, aux = struct.unpack_from("<IhHBB", raw, 8)
            self.symbols.append({"name": name, "value": value, "section": section, "type": kind, "storage": storage})
            for _ in range(aux):
                self.symbols.append({"name": "", "value": 0, "section": 0, "type": 0, "storage": 0, "aux": True})
            index += 1 + aux
        self.sections = []
        table = 20 + opt
        for index in range(nsec):
            name, _vs, _va, rsize, roff, relptr, _ln, nrel, _nln, chars = struct.unpack_from("<8sIIIIIIHHI", data, table + 40 * index)
            body = data[roff:roff + rsize] if roff and not chars & 0x80 else b""
            relocs = []
            for r in range(nrel):
                offset, sym, kind = struct.unpack_from("<IIH", data, relptr + 10 * r)
                relocs.append({"offset": offset, "sym": sym, "type": kind})
            self.sections.append({"name": name.rstrip(b"\0").decode("latin1"), "body": body, "relocs": relocs, "chars": chars})

    def functions(self):
        """Defined symbols of code sections: (name, section index (1-based), value)."""
        found = []
        for symbol in self.symbols:
            if symbol.get("aux") or symbol["section"] <= 0 or not symbol["name"]:
                continue
            section = self.sections[symbol["section"] - 1]
            if not section["chars"] & 0x20:  # IMAGE_SCN_CNT_CODE
                continue
            if symbol["storage"] in (2, 3) and symbol["type"] & 0xF0 == 0x20:  # external/static, DTYPE_FUNCTION
                found.append((symbol["name"], symbol["section"], symbol["value"]))
        return found

    def function(self, name: str):
        """-> (body, relocations): the bytes of the function symbol `name` (up to the next function symbol of its
        section) and the relocation fields inside it, offsets relative to the function."""
        located = [f for f in self.functions() if f[0] == name]
        if not located:
            raise KeyError(name)
        _name, shndx, value = located[0]
        section = self.sections[shndx - 1]
        ends = sorted(v for _n, s, v in self.functions() if s == shndx and v > value)
        end = ends[0] if ends else len(section["body"])
        body = section["body"][value:end]
        relocations = []
        for reloc in section["relocs"]:
            if value <= reloc["offset"] < end:
                symbol = self.symbols[reloc["sym"]] if reloc["sym"] < len(self.symbols) else None
                relocations.append({"offset": reloc["offset"] - value, "r_type": reloc["type"],
                                    "symbol": symbol["name"] if symbol and symbol["name"] else f"sec{reloc['sym']}"})
        return body, relocations


def trim_padding(body: bytes) -> bytes:
    """A linker pads between functions with int3 (0xCC); an object's last function may carry it too."""
    return body.rstrip(b"\xcc")


def field_mask(length: int, relocations) -> bytes:
    """0xFF where a byte of the function is compared, 0 inside the 4-byte relocation fields."""
    mask = bytearray(b"\xff" * length)
    for reloc in relocations:
        if reloc["r_type"] not in FIELD_TYPES:
            continue
        offset = reloc["offset"]
        for byte in range(4):
            if offset + byte < length:
                mask[offset + byte] = 0
    return bytes(mask)


def compare(body: bytes, relocations, retail: bytes) -> int:
    """Number of differing bytes between `body` and the start of `retail`, outside relocation fields."""
    mask = field_mask(len(body), relocations)
    other = bytes(retail[:len(body)]).ljust(len(body), b"\0")
    return sum(1 for index in range(len(body)) if (body[index] ^ other[index]) & mask[index])


def object_for_objdiff(body: bytes, relocations, name: str) -> bytes:
    """A relocatable i386 ELF object with one function `name` (.text = body, REL relocations kept) for objdiff-cli."""
    strtab, symbols = bytearray(b"\0"), [(0, 0, 0, 0, 0, 0)]

    def add_string(text: str) -> int:
        offset = len(strtab)
        strtab.extend(text.encode() + b"\0")
        return offset

    symbols.append((0, 0, 0, 3, 0, 1))  # section symbol for .text
    func = len(symbols)
    symbols.append((add_string(name), 0, len(body), (1 << 4) | STT_FUNC, 0, 1))
    ids, rel = {}, bytearray()
    for reloc in relocations:
        if reloc["r_type"] not in FIELD_TYPES:
            continue
        symbol = reloc["symbol"]
        if symbol not in ids:
            ids[symbol] = len(symbols)
            symbols.append((add_string(symbol), 0, 0, (1 << 4), 0, 0))
        kind = R_386_PC32 if reloc["r_type"] == IMAGE_REL_I386_REL32 else R_386_32
        rel += struct.pack("<II", reloc["offset"], (ids[symbol] << 8) | kind)
    symtab = b"".join(struct.pack("<IIIBBH", *symbol) for symbol in symbols)
    shstr = bytearray(b"\0")
    names = {}
    for section in (".text", ".symtab", ".strtab", ".shstrtab", ".rel.text"):
        names[section] = len(shstr)
        shstr.extend(section.encode() + b"\0")
    blobs = [b"", body, symtab, bytes(strtab), bytes(shstr), bytes(rel)]
    offset, offsets = 52, []
    for blob in blobs:
        offset = (offset + 3) & ~3
        offsets.append(offset)
        offset += len(blob)
    shoff = (offset + 3) & ~3
    headers = [struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
               struct.pack("<IIIIIIIIII", names[".text"], SHT_PROGBITS, 6, 0, offsets[1], len(body), 0, 0, 16, 0),
               struct.pack("<IIIIIIIIII", names[".symtab"], SHT_SYMTAB, 0, 0, offsets[2], len(symtab), 3, func, 4, 16),
               struct.pack("<IIIIIIIIII", names[".strtab"], SHT_STRTAB, 0, 0, offsets[3], len(strtab), 0, 0, 1, 0),
               struct.pack("<IIIIIIIIII", names[".shstrtab"], SHT_STRTAB, 0, 0, offsets[4], len(shstr), 0, 0, 1, 0),
               struct.pack("<IIIIIIIIII", names[".rel.text"], SHT_REL, 0x40, 0, offsets[5], len(rel), 2, 1, 4, 8)]
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    header = ident + struct.pack("<HHIIIIIHHHHHH", 1, 3, 1, 0, 0, shoff, 0, 52, 0, 0, 40, len(headers), 4)
    out = bytearray(header)
    for blob, start in zip(blobs, offsets):
        out.extend(b"\0" * (start - len(out)))
        out.extend(blob)
    out.extend(b"\0" * (shoff - len(out)))
    for entry in headers:
        out.extend(entry)
    return bytes(out)


DECORATED = re.compile(r"^(?:@|_)?(?P<name>[A-Za-z_$?][\w$?@]*?)(?:@(?P<args>\d+))?$")


def undecorate(symbol: str):
    """`_f@12` -> ("f", "stdcall", 12); `@f@8` -> ("f", "fastcall", 8); `_f` -> ("f", "cdecl", None)."""
    if symbol.startswith("@") and symbol.count("@") >= 2:
        name, _, args = symbol[1:].rpartition("@")
        return name, "fastcall", int(args) if args.isdigit() else None
    if symbol.startswith("_"):
        name, at, args = symbol[1:].rpartition("@")
        if at and args.isdigit():
            return name, "stdcall", int(args)
        return symbol[1:], "cdecl", None
    return symbol, "cdecl", None


ADDRESS_NAME = re.compile(r"_([0-9a-f]{8})(?:@\d+)?$")


def check_relocation_targets(body: bytes, relocations, retail: bytes, address: int):
    """-> (checked, wrong): of the candidate's DIR32/REL32 relocations whose symbol name ends in the 8-digit address romwright
    named it by (`FUN_00401230`, `DAT_00461210`, `PTR_x_00461210`), how many were checked and how many resolve to a different
    operand than the retail instruction has. A section symbol, an import or an unnamed symbol has no address to check."""
    checked = wrong = 0
    for reloc in relocations:
        if reloc["r_type"] not in (IMAGE_REL_I386_DIR32, IMAGE_REL_I386_REL32):
            continue
        named = ADDRESS_NAME.search(reloc["symbol"])
        offset = reloc["offset"]
        if not named or offset + 4 > len(body) or offset + 4 > len(retail):
            continue
        symbol_address = int(named.group(1), 16)
        if symbol_address < 0x10000:
            continue
        addend = struct.unpack_from("<i", body, offset)[0]
        retail_field = struct.unpack_from("<I", retail, offset)[0]
        if reloc["r_type"] == IMAGE_REL_I386_DIR32:
            expected = (symbol_address + addend) & 0xFFFFFFFF
        else:
            expected = (symbol_address + addend - (address + offset + 4)) & 0xFFFFFFFF
        checked += 1
        wrong += expected != retail_field
    return checked, wrong


def retail_relocations(code: bytes, address: int, image_lo: int, image_hi: int):
    """The relocation fields the retail function has: what a linker filled in, read back off the linked bytes. Each instruction
    is decoded (variable length, so the fields cannot be read off another stream's offsets); a 4-byte displacement or immediate
    that is an image address (`[abs]`, `push offset`, `mov eax, offset`) is a DIR32 field and a `call`/`jmp rel32` whose target
    is outside the function is a REL32 field. Symbols are named by the address they resolve to (`DAT_...`, `FUN_...`). Needs capstone."""
    import capstone
    from capstone import x86

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    out = []
    end = address + len(code)
    for ins in md.disasm(code, address):
        start = ins.address - address
        if ins.id in (x86.X86_INS_CALL, x86.X86_INS_JMP) or ins.mnemonic.startswith("j") or ins.mnemonic.startswith("loop"):
            op = ins.operands[0] if ins.operands else None
            if op is not None and op.type == x86.X86_OP_IMM and ins.imm_size == 4 and not address <= op.imm < end:
                out.append({"offset": start + ins.imm_offset, "r_type": IMAGE_REL_I386_REL32, "symbol": f"FUN_{op.imm & 0xFFFFFFFF:08x}"})
                continue
        for op in ins.operands:
            if op.type == x86.X86_OP_MEM and ins.disp_size == 4 and image_lo <= (op.mem.disp & 0xFFFFFFFF) < image_hi:
                out.append({"offset": start + ins.disp_offset, "r_type": IMAGE_REL_I386_DIR32, "symbol": f"DAT_{op.mem.disp & 0xFFFFFFFF:08x}"})
            elif op.type == x86.X86_OP_IMM and ins.imm_size == 4 and image_lo <= (op.imm & 0xFFFFFFFF) < image_hi \
                    and not ins.mnemonic.startswith(("j", "call", "loop")):
                out.append({"offset": start + ins.imm_offset, "r_type": IMAGE_REL_I386_DIR32, "symbol": f"DAT_{op.imm & 0xFFFFFFFF:08x}"})
    return out

