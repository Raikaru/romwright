"""ELF32 little-endian objects and executables for the m22-003 lanes.

Three things the harness needs and no repo script is allowed to supply:

  ElfObject     a relocatable object: sections, symbols, `.text` relocations,
                the functions it defines, and the bytes of each.
  RetailImage   the retail ELF as a virtual-address -> bytes map (PT_LOAD).
  compare()     m22's comparator: a function body equals the retail bytes if
                every byte is equal outside the relocation fields of the object
                (the object's `.text` relocations say which bits the linker
                fills); `exact` additionally needs the same length and zero
                padding after it in the retail window.
  object_for_objdiff()  a minimal relocatable object holding one function, so
                objdiff-cli can score a candidate against the retail bytes.

Written from the ELF and MIPS psABI specifications; nothing here is taken from
a decompilation repository.
"""
from __future__ import annotations

import struct

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_REL = 1, 2, 3, 4, 9
SHF_EXECINSTR = 4
STT_FUNC, STT_SECTION = 2, 3

# MIPS relocation types -> the bits of the 32-bit instruction/word the linker rewrites.
R_MIPS_16, R_MIPS_32, R_MIPS_REL32, R_MIPS_26, R_MIPS_HI16, R_MIPS_LO16 = 1, 2, 3, 4, 5, 6
R_MIPS_GPREL16, R_MIPS_LITERAL, R_MIPS_GOT16, R_MIPS_PC16, R_MIPS_CALL16, R_MIPS_GPREL32 = 7, 8, 9, 10, 11, 12
FIELD_MASK = {
    R_MIPS_16: 0x0000FFFF, R_MIPS_32: 0xFFFFFFFF, R_MIPS_REL32: 0xFFFFFFFF, R_MIPS_26: 0x03FFFFFF,
    R_MIPS_HI16: 0x0000FFFF, R_MIPS_LO16: 0x0000FFFF, R_MIPS_GPREL16: 0x0000FFFF, R_MIPS_LITERAL: 0x0000FFFF,
    R_MIPS_GOT16: 0x0000FFFF, R_MIPS_PC16: 0x0000FFFF, R_MIPS_CALL16: 0x0000FFFF, R_MIPS_GPREL32: 0xFFFFFFFF,
}


class ElfError(ValueError):
    pass


def cstr(blob: bytes, offset: int) -> str:
    end = blob.find(b"\0", offset)
    return blob[offset:end if end >= 0 else len(blob)].decode("latin-1")


class ElfObject:
    """A 32-bit little-endian ELF relocatable object."""

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
            raise ElfError("not an ELF32 little-endian file")
        self.data = data
        (self.e_type, self.e_machine, _v, _entry, _phoff, shoff, self.e_flags, _eh, _phes, _phn, shentsize,
         shnum, shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        self.sections = []
        for index in range(shnum):
            fields = struct.unpack_from("<IIIIIIIIII", data, shoff + index * shentsize)
            self.sections.append(dict(zip(("name", "type", "flags", "addr", "offset", "size", "link", "info",
                                           "addralign", "entsize"), fields)))
        names = self.sections[shstrndx] if shnum else None
        for section in self.sections:
            section["name"] = cstr(data[names["offset"]:names["offset"] + names["size"]], section["name"]) if names else ""
        self.symbols = []
        for section in self.sections:
            if section["type"] == SHT_SYMTAB:
                strtab = self.sections[section["link"]]
                strings = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
                for index in range(section["size"] // 16):
                    name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", data, section["offset"] + index * 16)
                    self.symbols.append({"name": cstr(strings, name), "value": value, "size": size, "info": info,
                                         "shndx": shndx, "index": index})
                break
        self.relocs = {}
        for index, section in enumerate(self.sections):
            if section["type"] in (SHT_REL, SHT_RELA):
                rows = []
                step = 12 if section["type"] == SHT_RELA else 8
                for slot in range(section["size"] // step):
                    fields = struct.unpack_from("<IIi" if step == 12 else "<II", data, section["offset"] + slot * step)
                    offset, info = fields[0], fields[1]
                    rows.append({"offset": offset, "sym": info >> 8, "type": info & 0xFF,
                                 "addend": fields[2] if step == 12 else None})
                self.relocs.setdefault(section["info"], []).extend(rows)

    def section_bytes(self, index: int) -> bytes:
        section = self.sections[index]
        if section["type"] == 8:  # NOBITS
            return b"\0" * section["size"]
        return self.data[section["offset"]:section["offset"] + section["size"]]

    def functions(self):
        """(name, section index, offset, size) of every sized function symbol in an executable section."""
        found = []
        for symbol in self.symbols:
            shndx = symbol["shndx"]
            if symbol["info"] & 0xF != STT_FUNC or not 0 < shndx < len(self.sections) or symbol["size"] == 0:
                continue
            if not self.sections[shndx]["flags"] & SHF_EXECINSTR:
                continue
            found.append((symbol["name"], shndx, symbol["value"], symbol["size"]))
        return found

    def function(self, name: str):
        """(body bytes, relocations inside it with offsets relative to the function) or raise KeyError."""
        for fname, shndx, value, size in self.functions():
            if fname == name:
                return self.function_at(shndx, value, size)
        raise KeyError(name)

    def function_at(self, shndx: int, value: int, size: int):
        body = self.section_bytes(shndx)[value:value + size]
        relocations = []
        for reloc in self.relocs.get(shndx, []):
            if value <= reloc["offset"] < value + size:
                symbol = self.symbols[reloc["sym"]] if reloc["sym"] < len(self.symbols) else None
                word = int.from_bytes(body[reloc["offset"] - value:reloc["offset"] - value + 4], "little") \
                    if reloc["offset"] - value + 4 <= len(body) else 0
                name = symbol["name"] if symbol and reloc["sym"] else None
                if symbol and reloc["sym"] and symbol["info"] & 0xF == STT_SECTION:
                    # a call to a function in another section is relocated against the section symbol (named after the
                    # section, `.text.f`, by some assemblers): the target is section + the field's offset, so the name is
                    # the function that starts there
                    name = None
                    if reloc["type"] == R_MIPS_26:
                        target = ((word & 0x03FFFFFF) << 2) if reloc["addend"] is None else reloc["addend"]
                        name = next((f[0] for f in self.functions() if f[1] == symbol["shndx"] and f[2] == target), None)
                relocations.append({"offset": reloc["offset"] - value, "r_type": reloc["type"],
                                    "symbol": name,
                                    "sym_section": symbol["shndx"] if symbol else None,
                                    "sym_value": symbol["value"] if symbol else 0,
                                    "addend": reloc["addend"], "word": word})
        return body, relocations


def reloc_mask(r_type: int) -> int:
    return FIELD_MASK.get(r_type, 0xFFFFFFFF)


def compare(body: bytes, relocations, retail: bytes):
    """Number of differing bytes between `body` and the start of `retail`, outside relocation fields."""
    mask = bytearray(b"\xff" * len(body))
    for reloc in relocations:
        offset = reloc["offset"]
        if offset + 4 > len(mask):
            continue
        field = reloc_mask(reloc["r_type"])
        for byte in range(4):
            mask[offset + byte] = (~(field >> (8 * byte))) & 0xFF
    other = bytes(retail[:len(body)]).ljust(len(body), b"\0")
    return sum(1 for index in range(len(body)) if (body[index] ^ other[index]) & mask[index])


def field_mask(length: int, relocations) -> bytes:
    """0xFF where a byte of the function is compared, 0 inside the relocation fields (the same masking as compare())."""
    mask = bytearray(b"\xff" * length)
    for reloc in relocations:
        offset = reloc["offset"]
        if offset + 4 > length:
            continue
        field = reloc_mask(reloc["r_type"])
        for byte in range(4):
            mask[offset + byte] = (~(field >> (8 * byte))) & 0xFF
    return bytes(mask)


def exact(body: bytes, relocations, retail_window: bytes, size: int) -> bool:
    """m22's exact: same length as the retail function, every byte equal outside relocation fields,
    zero padding after it in the retail window."""
    return len(body) == size and compare(body, relocations, retail_window) == 0 and not any(retail_window[len(body):])


class RetailImage:
    """The retail ELF's loadable segments as a virtual-address map."""

    def __init__(self, path):
        data = open(path, "rb").read()
        if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
            raise ElfError(f"{path}: not an ELF32 little-endian executable")
        self.path = str(path)
        self.data = data
        phoff, = struct.unpack_from("<I", data, 28)
        phentsize, phnum = struct.unpack_from("<HH", data, 42)
        self.segments = []
        for index in range(phnum):
            p_type, offset, vaddr, _paddr, filesz, memsz, flags, _align = struct.unpack_from(
                "<IIIIIIII", data, phoff + index * phentsize)
            if p_type == 1 and memsz:
                self.segments.append((vaddr, memsz, offset, filesz, flags))
        self.entry, = struct.unpack_from("<I", data, 24)

    def bytes_at(self, address: int, length: int) -> bytes:
        for vaddr, memsz, offset, filesz, _flags in self.segments:
            if vaddr <= address and address + length <= vaddr + memsz:
                start = offset + address - vaddr
                have = max(0, min(length, filesz - (address - vaddr)))
                return self.data[start:start + have] + b"\0" * (length - have)
        raise KeyError(f"{address:#x}+{length} is not inside a loadable segment")

    def contains(self, address: int, length: int = 4) -> bool:
        return any(vaddr <= address and address + length <= vaddr + memsz for vaddr, memsz, *_ in self.segments)

    def code_segments(self):
        return [(vaddr, filesz, offset) for vaddr, memsz, offset, filesz, flags in self.segments if flags & 1]


def object_for_objdiff(body: bytes, relocations, name: str, e_flags: int) -> bytes:
    """A relocatable MIPS object with one function `name` (.text = body, REL relocations kept) for objdiff-cli."""
    strtab, symbols = bytearray(b"\0"), [(0, 0, 0, 0, 0, 0)]

    def add_string(text: str) -> int:
        offset = len(strtab)
        strtab.extend(text.encode() + b"\0")
        return offset

    symbols.append((0, 0, 0, 3, 0, 1))  # section symbol for .text
    func = len(symbols)
    symbols.append((add_string(name), 0, len(body), (1 << 4) | STT_FUNC, 0, 1))
    first_global = func
    ids, rel = {}, bytearray()
    for reloc in relocations:
        if not reloc.get("symbol"):
            continue
        if reloc["symbol"] not in ids:
            ids[reloc["symbol"]] = len(symbols)
            symbols.append((add_string(reloc["symbol"]), 0, 0, (1 << 4), 0, 0))
        rel += struct.pack("<II", reloc["offset"], (ids[reloc["symbol"]] << 8) | reloc["r_type"])
    symtab = b"".join(struct.pack("<IIIBBH", *symbol) for symbol in symbols)
    shstr = bytearray(b"\0")
    names = {}
    for section in (".text", ".symtab", ".strtab", ".shstrtab", ".rel.text"):
        names[section] = len(shstr)
        shstr.extend(section.encode() + b"\0")
    blobs = [(b"", 0), (body, 0), (symtab, 0), (bytes(strtab), 0), (bytes(shstr), 0), (bytes(rel), 0)]
    offset, offsets = 52, []
    for blob, _ in blobs:
        offset = (offset + 3) & ~3
        offsets.append(offset)
        offset += len(blob)
    shoff = (offset + 3) & ~3
    headers = [struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
               struct.pack("<IIIIIIIIII", names[".text"], SHT_PROGBITS, 6, 0, offsets[1], len(body), 0, 0, 16, 0),
               struct.pack("<IIIIIIIIII", names[".symtab"], SHT_SYMTAB, 0, 0, offsets[2], len(symtab), 3, first_global, 4, 16),
               struct.pack("<IIIIIIIIII", names[".strtab"], SHT_STRTAB, 0, 0, offsets[3], len(strtab), 0, 0, 1, 0),
               struct.pack("<IIIIIIIIII", names[".shstrtab"], SHT_STRTAB, 0, 0, offsets[4], len(shstr), 0, 0, 1, 0),
               struct.pack("<IIIIIIIIII", names[".rel.text"], SHT_REL, 0x40, 0, offsets[5], len(rel), 2, 1, 4, 8)]
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    header = ident + struct.pack("<HHIIIIIHHHHHH", 1, 8, 1, 0, 0, shoff, e_flags, 52, 0, 0, 40, len(headers), 4)
    out = bytearray(header)
    for (blob, _), start in zip(blobs, offsets):
        out.extend(b"\0" * (start - len(out)))
        out.extend(blob)
    out.extend(b"\0" * (shoff - len(out)))
    for entry in headers:
        out.extend(entry)
    return bytes(out)
