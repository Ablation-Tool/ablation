#!/usr/bin/env python3
"""
ELF Parser
Sources: Learning Linux Binary Analysis ch2 (ELF format, program headers,
         section headers, dynamic linking, GOT/PLT),
         Practical Binary Analysis ch5 (binary analysis),
         Hacking: The Art of Exploitation ch5 (exploitation surface).

Pure-Python, no external dependencies. Supports ELF32 and ELF64.
"""

import struct
import os
import re
import math
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# ELF Constants
# ---------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"

# e_type
ET_NONE   = 0
ET_REL    = 1   # relocatable object
ET_EXEC   = 2   # executable
ET_DYN    = 3   # shared object / PIE
ET_CORE   = 4

ET_NAMES = {ET_NONE: "ET_NONE", ET_REL: "ET_REL",
            ET_EXEC: "ET_EXEC", ET_DYN: "ET_DYN", ET_CORE: "ET_CORE"}

# e_machine
EM_NONE    = 0
EM_386     = 3
EM_MIPS    = 8
EM_PPC     = 20
EM_PPC64   = 21
EM_ARM     = 40
EM_X86_64  = 62
EM_AARCH64 = 183

EM_NAMES = {
    EM_NONE: "None", EM_386: "i386", EM_MIPS: "MIPS",
    EM_PPC: "PowerPC", EM_PPC64: "PowerPC64",
    EM_ARM: "ARM", EM_X86_64: "x86-64", EM_AARCH64: "AArch64",
}

# Program header types (p_type)
PT_NULL    = 0
PT_LOAD    = 1
PT_DYNAMIC = 2
PT_INTERP  = 3
PT_NOTE    = 4
PT_PHDR    = 6
PT_TLS     = 7
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK    = 0x6474E551
PT_GNU_RELRO    = 0x6474E552

PT_NAMES = {
    PT_NULL: "PT_NULL", PT_LOAD: "PT_LOAD", PT_DYNAMIC: "PT_DYNAMIC",
    PT_INTERP: "PT_INTERP", PT_NOTE: "PT_NOTE", PT_PHDR: "PT_PHDR",
    PT_TLS: "PT_TLS", PT_GNU_EH_FRAME: "PT_GNU_EH_FRAME",
    PT_GNU_STACK: "PT_GNU_STACK", PT_GNU_RELRO: "PT_GNU_RELRO",
}

# Program header flags
PF_X = 1   # execute
PF_W = 2   # write
PF_R = 4   # read

# Section header types (sh_type)
SHT_NULL     = 0
SHT_PROGBITS = 1
SHT_SYMTAB   = 2
SHT_STRTAB   = 3
SHT_RELA     = 4
SHT_HASH     = 5
SHT_DYNAMIC  = 6
SHT_NOTE     = 7
SHT_NOBITS   = 8
SHT_REL      = 9
SHT_DYNSYM   = 11
SHT_GNU_HASH = 0x6FFFFFF6

SHT_NAMES = {
    SHT_NULL: "SHT_NULL", SHT_PROGBITS: "SHT_PROGBITS",
    SHT_SYMTAB: "SHT_SYMTAB", SHT_STRTAB: "SHT_STRTAB",
    SHT_RELA: "SHT_RELA", SHT_HASH: "SHT_HASH",
    SHT_DYNAMIC: "SHT_DYNAMIC", SHT_NOTE: "SHT_NOTE",
    SHT_NOBITS: "SHT_NOBITS", SHT_REL: "SHT_REL",
    SHT_DYNSYM: "SHT_DYNSYM", SHT_GNU_HASH: "SHT_GNU_HASH",
}

# Section header flags
SHF_WRITE     = 0x1
SHF_ALLOC     = 0x2
SHF_EXECINSTR = 0x4

# Dynamic section tags (d_tag)
DT_NULL     = 0
DT_NEEDED   = 1
DT_PLTRELSZ = 2
DT_PLTGOT   = 3
DT_HASH     = 4
DT_STRTAB   = 5
DT_SYMTAB   = 6
DT_RELA     = 7
DT_RELASZ   = 8
DT_RELAENT  = 9
DT_STRSZ    = 10
DT_SYMENT   = 11
DT_INIT     = 12
DT_FINI     = 13
DT_SONAME   = 14
DT_RPATH    = 15
DT_SYMBOLIC = 16
DT_REL      = 17
DT_RELSZ    = 18
DT_RELENT   = 19
DT_PLTREL   = 20
DT_DEBUG    = 21
DT_TEXTREL  = 22
DT_JMPREL   = 23
DT_BIND_NOW = 24
DT_RUNPATH  = 29
DT_FLAGS    = 30
DT_FLAGS_1  = 0x6FFFFFFB

DT_NAMES = {
    DT_NULL: "DT_NULL", DT_NEEDED: "DT_NEEDED", DT_PLTGOT: "DT_PLTGOT",
    DT_HASH: "DT_HASH", DT_STRTAB: "DT_STRTAB", DT_SYMTAB: "DT_SYMTAB",
    DT_RELA: "DT_RELA", DT_STRSZ: "DT_STRSZ", DT_SYMENT: "DT_SYMENT",
    DT_INIT: "DT_INIT", DT_FINI: "DT_FINI", DT_SONAME: "DT_SONAME",
    DT_RPATH: "DT_RPATH", DT_RUNPATH: "DT_RUNPATH",
    DT_FLAGS: "DT_FLAGS", DT_FLAGS_1: "DT_FLAGS_1",
    DT_BIND_NOW: "DT_BIND_NOW", DT_DEBUG: "DT_DEBUG",
    DT_REL: "DT_REL", DT_JMPREL: "DT_JMPREL",
}

# Symbol table types (st_info low nibble)
STT_NOTYPE  = 0
STT_OBJECT  = 1
STT_FUNC    = 2
STT_SECTION = 3
STT_FILE    = 4
STT_TLS     = 6

STT_NAMES = {
    STT_NOTYPE: "NOTYPE", STT_OBJECT: "OBJECT", STT_FUNC: "FUNC",
    STT_SECTION: "SECTION", STT_FILE: "FILE", STT_TLS: "TLS",
}

# Symbol binding (st_info high nibble)
STB_LOCAL  = 0
STB_GLOBAL = 1
STB_WEAK   = 2

STB_NAMES = {STB_LOCAL: "LOCAL", STB_GLOBAL: "GLOBAL", STB_WEAK: "WEAK"}

# DT_FLAGS_1 values relevant to security
DF_1_NOW     = 0x00000001  # BIND_NOW
DF_1_PIE     = 0x08000000  # Position-independent executable


# ---------------------------------------------------------------------------
# ELF Header Structs
# ---------------------------------------------------------------------------

# ELF32 header: 52 bytes
_ELF32_EHDR_FMT = "<16sHHIIIIIHHHHHH"
_ELF32_EHDR_FIELDS = [
    "e_ident", "e_type", "e_machine", "e_version",
    "e_entry", "e_phoff", "e_shoff", "e_flags",
    "e_ehsize", "e_phentsize", "e_phnum",
    "e_shentsize", "e_shnum", "e_shstrndx",
]

# ELF64 header: 64 bytes
_ELF64_EHDR_FMT = "<16sHHIQQQIHHHHHH"
_ELF64_EHDR_FIELDS = _ELF32_EHDR_FIELDS  # same names, different widths

# ELF32 program header
_ELF32_PHDR_FMT    = "<IIIIIIII"
_ELF32_PHDR_FIELDS = ["p_type","p_offset","p_vaddr","p_paddr",
                       "p_filesz","p_memsz","p_flags","p_align"]

# ELF64 program header
_ELF64_PHDR_FMT    = "<IIQQQQQQ"
_ELF64_PHDR_FIELDS = ["p_type","p_flags","p_offset","p_vaddr","p_paddr",
                       "p_filesz","p_memsz","p_align"]

# ELF32 section header
_ELF32_SHDR_FMT    = "<IIIIIIIIII"
_ELF32_SHDR_FIELDS = ["sh_name","sh_type","sh_flags","sh_addr","sh_offset",
                       "sh_size","sh_link","sh_info","sh_addralign","sh_entsize"]

# ELF64 section header
_ELF64_SHDR_FMT    = "<IIQQQQIIQQ"
_ELF64_SHDR_FIELDS = ["sh_name","sh_type","sh_flags","sh_addr","sh_offset",
                       "sh_size","sh_link","sh_info","sh_addralign","sh_entsize"]

# ELF32 symbol table entry
_ELF32_SYM_FMT    = "<IIIBBH"
_ELF32_SYM_FIELDS = ["st_name","st_value","st_size","st_info","st_other","st_shndx"]

# ELF64 symbol table entry
_ELF64_SYM_FMT    = "<IBBHQQ"
_ELF64_SYM_FIELDS = ["st_name","st_info","st_other","st_shndx","st_value","st_size"]

# ELF32/64 dynamic entry
_ELF32_DYN_FMT    = "<iI"   # signed tag, value/ptr
_ELF64_DYN_FMT    = "<qQ"


def _unpack_struct(fmt: str, fields: list, data: bytes, offset: int = 0) -> dict:
    size = struct.calcsize(fmt)
    values = struct.unpack_from(fmt, data, offset)
    return dict(zip(fields, values))


def _cstring(data: bytes, offset: int) -> str:
    """Extract null-terminated string from bytes at offset."""
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("utf-8", errors="replace")


def _shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy in bits per byte.

    Normal compiled code sits below 6.5; packed or encrypted regions exceed 7.0.
    Source: Learning Linux Binary Analysis ch4 (ELF anti-debugging and packing
            techniques -- runtime packers raise text section entropy).
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / n
            entropy -= p * math.log2(p)
    return entropy


# Regex: standard shared library name lib<name>.so.<version> (e.g. libc.so.6)
_RE_STANDARD_LIB = re.compile(r'^lib[^/]+\.so\.\d')


# ---------------------------------------------------------------------------
# ELF Parser
# ---------------------------------------------------------------------------

class ELFParser:
    """
    Pure-Python ELF32/64 parser.

    Parses: header, program headers, section headers, dynamic section,
    symbol tables (dynsym + symtab), and detects security features
    (PIE, NX, RELRO, stack canary).

    Source: Learning Linux Binary Analysis ch2 (elfparse.c reference implementation),
            Practical Binary Analysis ch5 (ldd, readelf, binary inspection).
    """

    def __init__(self, path: str):
        self.path    = Path(path)
        self._data   = b""
        self.bits    = 0       # 32 or 64
        self.endian  = "<"     # '<' little, '>' big
        self.ehdr    = {}
        self.phdrs   = []
        self.shdrs   = []
        self.dynamic = []
        self.dynsyms = []
        self.symtabs = []
        self._shstrtab = b""
        self._dynstrtab = b""
        self._strtab    = b""
        self._parsed    = False

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def parse(self) -> "ELFParser":
        """Parse the ELF file. Returns self for chaining."""
        self._data = self.path.read_bytes()
        self._validate_magic()
        self._parse_ident()
        self._parse_ehdr()
        self._parse_phdrs()
        self._parse_shdrs()
        self._load_shstrtab()
        self._parse_dynamic_from_phdr()
        self._load_dynstrtab()
        self._parse_symbols()
        self._parsed = True
        return self

    def validate_magic(self) -> bool:
        """Return True if file starts with ELF magic 0x7F 'ELF'."""
        try:
            return self._data[:4] == ELF_MAGIC
        except Exception:
            return False

    @property
    def entry_point(self) -> int:
        return self.ehdr.get("e_entry", 0)

    @property
    def elf_type(self) -> str:
        return ET_NAMES.get(self.ehdr.get("e_type", 0), "UNKNOWN")

    @property
    def machine(self) -> str:
        return EM_NAMES.get(self.ehdr.get("e_machine", 0), "UNKNOWN")

    def get_section(self, name: str) -> Optional[dict]:
        """Return section header dict by name, or None."""
        for shdr in self.shdrs:
            if shdr.get("name") == name:
                return shdr
        return None

    def get_section_data(self, name: str) -> Optional[bytes]:
        """Return raw bytes of a named section."""
        shdr = self.get_section(name)
        if shdr is None:
            return None
        off  = shdr["sh_offset"]
        size = shdr["sh_size"]
        return self._data[off:off + size]

    def get_phdr_by_type(self, ptype: int) -> list:
        """Return all program headers of the given PT_* type."""
        return [p for p in self.phdrs if p["p_type"] == ptype]

    # -----------------------------------------------------------------------
    # ELF Header
    # -----------------------------------------------------------------------

    def _validate_magic(self):
        if len(self._data) < 4 or self._data[:4] != ELF_MAGIC:
            raise ValueError(f"{self.path}: not an ELF file (bad magic)")

    def _parse_ident(self):
        """Parse e_ident to determine bit-width and endianness."""
        ei = self._data[:16]
        ei_class = ei[4]  # 1=32-bit, 2=64-bit
        ei_data  = ei[5]  # 1=little-endian, 2=big-endian

        if ei_class == 1:
            self.bits = 32
        elif ei_class == 2:
            self.bits = 64
        else:
            raise ValueError(f"Unknown ELF class byte: {ei_class}")

        if ei_data == 1:
            self.endian = "<"
        elif ei_data == 2:
            self.endian = ">"
        else:
            raise ValueError(f"Unknown ELF data encoding byte: {ei_data}")

    def _parse_ehdr(self):
        """Parse ELF file header."""
        if self.bits == 32:
            fmt    = self.endian + _ELF32_EHDR_FMT[1:]  # strip endian prefix
            fields = _ELF32_EHDR_FIELDS
        else:
            fmt    = self.endian + _ELF64_EHDR_FMT[1:]
            fields = _ELF64_EHDR_FIELDS

        fmt = self.endian + ("16sHHIIIIIHHHHHH" if self.bits == 32
                              else "16sHHIQQQIHHHHHH")
        size = struct.calcsize(fmt)
        vals = struct.unpack_from(fmt, self._data, 0)
        self.ehdr = dict(zip(fields, vals))
        self.ehdr["_bits"]   = self.bits
        self.ehdr["_endian"] = self.endian

    # -----------------------------------------------------------------------
    # Program Headers
    # -----------------------------------------------------------------------

    def _parse_phdrs(self):
        """
        Enumerate program headers.
        Source: Learning Linux Binary Analysis ch2 (ELF program headers):
          PT_LOAD segments describe loadable regions.
          PT_DYNAMIC points to the dynamic linker info.
          PT_INTERP contains path to the program interpreter.
          PT_GNU_RELRO marks the region made read-only after relocation.
          PT_GNU_STACK: absence of PF_X = NX stack.
        """
        phoff   = self.ehdr.get("e_phoff", 0)
        phnum   = self.ehdr.get("e_phnum", 0)
        phentsz = self.ehdr.get("e_phentsize", 0)

        if phoff == 0 or phnum == 0:
            return

        for i in range(phnum):
            off = phoff + i * phentsz
            if self.bits == 32:
                fmt    = self.endian + "IIIIIIII"
                fields = _ELF32_PHDR_FIELDS
            else:
                fmt    = self.endian + "IIQQQQQQ"
                fields = _ELF64_PHDR_FIELDS

            size = struct.calcsize(fmt)
            if off + size > len(self._data):
                break

            vals = struct.unpack_from(fmt, self._data, off)
            phdr = dict(zip(fields, vals))
            phdr["type_name"] = PT_NAMES.get(phdr["p_type"], f"0x{phdr['p_type']:08X}")

            # Decode flags
            flags_val = phdr["p_flags"]
            phdr["flags_str"] = (
                ("R" if flags_val & PF_R else "-") +
                ("W" if flags_val & PF_W else "-") +
                ("X" if flags_val & PF_X else "-")
            )

            # PT_INTERP: extract interpreter path
            if phdr["p_type"] == PT_INTERP:
                off2 = phdr["p_offset"]
                phdr["interp"] = _cstring(self._data, off2)

            self.phdrs.append(phdr)

    # -----------------------------------------------------------------------
    # Section Headers
    # -----------------------------------------------------------------------

    def _parse_shdrs(self):
        """
        Enumerate section headers.
        Source: Learning Linux Binary Analysis ch2 (ELF section headers):
          .text: code (SHT_PROGBITS, SHF_EXECINSTR)
          .data: initialized globals
          .bss:  uninitialized globals (SHT_NOBITS)
          .got.plt: GOT for PLT -- primary hooking surface
          .dynsym: dynamic symbols
          .symtab: full symbol table (often stripped)
          .dynamic: dynamic linker tags
          .rodata: read-only data
        """
        shoff   = self.ehdr.get("e_shoff", 0)
        shnum   = self.ehdr.get("e_shnum", 0)
        shentsz = self.ehdr.get("e_shentsize", 0)

        if shoff == 0 or shnum == 0:
            return

        for i in range(shnum):
            off = shoff + i * shentsz
            if self.bits == 32:
                fmt    = self.endian + "IIIIIIIIII"
                fields = _ELF32_SHDR_FIELDS
            else:
                fmt    = self.endian + "IIQQQQIIQQ"
                fields = _ELF64_SHDR_FIELDS

            size = struct.calcsize(fmt)
            if off + size > len(self._data):
                break

            vals = struct.unpack_from(fmt, self._data, off)
            shdr = dict(zip(fields, vals))
            shdr["type_name"]  = SHT_NAMES.get(shdr["sh_type"], f"0x{shdr['sh_type']:X}")
            shdr["name"]       = ""  # filled after shstrtab is loaded
            shdr["flags_str"]  = (
                ("W" if shdr["sh_flags"] & SHF_WRITE else "-") +
                ("A" if shdr["sh_flags"] & SHF_ALLOC else "-") +
                ("X" if shdr["sh_flags"] & SHF_EXECINSTR else "-")
            )
            self.shdrs.append(shdr)

    def _load_shstrtab(self):
        """Load section-name string table and resolve section names."""
        shstrndx = self.ehdr.get("e_shstrndx", 0)
        if shstrndx == 0 or shstrndx >= len(self.shdrs):
            return

        shstrtab_shdr = self.shdrs[shstrndx]
        off  = shstrtab_shdr["sh_offset"]
        size = shstrtab_shdr["sh_size"]
        self._shstrtab = self._data[off:off + size]

        for shdr in self.shdrs:
            name_off = shdr["sh_name"]
            if name_off < len(self._shstrtab):
                shdr["name"] = _cstring(self._shstrtab, name_off)

    # -----------------------------------------------------------------------
    # Dynamic Section
    # -----------------------------------------------------------------------

    def _parse_dynamic_from_phdr(self):
        """
        Parse the dynamic segment (PT_DYNAMIC) to extract DT_NEEDED, DT_RPATH,
        DT_RUNPATH, DT_PLTGOT, and other linker tags.

        Source: Learning Linux Binary Analysis ch2 (ELF dynamic linking):
          DT_NEEDED: names of required shared libraries.
          DT_RPATH/DT_RUNPATH: library search paths (RUNPATH can be an injection point).
          DT_PLTGOT: address of Global Offset Table.
          DT_BIND_NOW / DT_FLAGS_1 DF_1_NOW: full RELRO indicator.
        """
        dyn_phdrs = self.get_phdr_by_type(PT_DYNAMIC)
        if not dyn_phdrs:
            return

        phdr    = dyn_phdrs[0]
        dyn_off = phdr["p_offset"]
        dyn_sz  = phdr["p_filesz"]

        if self.bits == 32:
            fmt      = self.endian + "iI"
            ent_size = 8
        else:
            fmt      = self.endian + "qQ"
            ent_size = 16

        pos = dyn_off
        end = dyn_off + dyn_sz

        while pos + ent_size <= end and pos < len(self._data):
            vals  = struct.unpack_from(fmt, self._data, pos)
            d_tag = vals[0]
            d_val = vals[1]

            entry = {
                "d_tag":     d_tag,
                "d_val":     d_val,
                "tag_name":  DT_NAMES.get(d_tag, f"0x{d_tag:X}"),
            }
            self.dynamic.append(entry)

            if d_tag == DT_NULL:
                break
            pos += ent_size

    def _load_dynstrtab(self):
        """
        Load .dynstr (dynamic string table) for resolving DT_NEEDED names.
        Fall back to scanning dynamic entries for DT_STRTAB address.
        """
        # Try section-based lookup first
        shdr = self.get_section(".dynstr")
        if shdr:
            off  = shdr["sh_offset"]
            size = shdr["sh_size"]
            self._dynstrtab = self._data[off:off + size]

        # Resolve DT_NEEDED into library names now that dynstrtab is loaded
        if self._dynstrtab:
            for entry in self.dynamic:
                if entry["d_tag"] == DT_NEEDED:
                    name_off = entry["d_val"]
                    if name_off < len(self._dynstrtab):
                        entry["name"] = _cstring(self._dynstrtab, name_off)
                elif entry["d_tag"] in (DT_RPATH, DT_RUNPATH, DT_SONAME):
                    name_off = entry["d_val"]
                    if name_off < len(self._dynstrtab):
                        entry["name"] = _cstring(self._dynstrtab, name_off)

        # Load .strtab for symtab
        strtab_shdr = self.get_section(".strtab")
        if strtab_shdr:
            off  = strtab_shdr["sh_offset"]
            size = strtab_shdr["sh_size"]
            self._strtab = self._data[off:off + size]

    # -----------------------------------------------------------------------
    # Symbol Tables
    # -----------------------------------------------------------------------

    def _parse_symbols(self):
        """
        Extract symbols from .dynsym and .symtab.

        .dynsym: dynamic symbols -- imported/exported functions visible to linker.
         Crucial for identifying shared library hooks (PLT/GOT targets).
        .symtab: full static symbol table (present in non-stripped binaries).

        Source: Learning Linux Binary Analysis ch2 (ELF symbols),
                Practical Binary Analysis ch5 (nm, readelf -s).
        """
        # Dynamic symbols
        dynsym_shdr = self.get_section(".dynsym")
        if dynsym_shdr:
            strtab_data = self._dynstrtab
            self.dynsyms = self._parse_sym_section(dynsym_shdr, strtab_data, "dynsym")

        # Static symbol table
        symtab_shdr = self.get_section(".symtab")
        if symtab_shdr:
            strtab_data = self._strtab
            self.symtabs = self._parse_sym_section(symtab_shdr, strtab_data, "symtab")

    def _parse_sym_section(self, shdr: dict, strtab: bytes, table_name: str) -> list:
        """Parse a symbol table section and return list of symbol dicts."""
        off     = shdr["sh_offset"]
        size    = shdr["sh_size"]
        entsz   = shdr["sh_entsize"]

        if entsz == 0:
            return []

        if self.bits == 32:
            fmt    = self.endian + "IIIBBH"
            fields = _ELF32_SYM_FIELDS
        else:
            fmt    = self.endian + "IBBHQQ"
            fields = _ELF64_SYM_FIELDS

        expected_entsz = struct.calcsize(fmt)
        if entsz != expected_entsz:
            # Use declared entsize if it differs
            pass

        syms = []
        num  = size // entsz if entsz else 0

        for i in range(num):
            sym_off = off + i * entsz
            if sym_off + entsz > len(self._data):
                break

            vals = struct.unpack_from(fmt, self._data, sym_off)
            sym  = dict(zip(fields, vals))

            info     = sym["st_info"]
            sym_type = info & 0x0F
            sym_bind = (info >> 4) & 0x0F

            sym["type_name"] = STT_NAMES.get(sym_type, f"0x{sym_type:X}")
            sym["bind_name"] = STB_NAMES.get(sym_bind, f"0x{sym_bind:X}")
            sym["table"]     = table_name

            name_off = sym["st_name"]
            if strtab and name_off < len(strtab):
                sym["name"] = _cstring(strtab, name_off)
            else:
                sym["name"] = ""

            syms.append(sym)

        return syms

    # -----------------------------------------------------------------------
    # Needed Libraries / RPATH
    # -----------------------------------------------------------------------

    @property
    def needed_libs(self) -> list:
        """List of DT_NEEDED shared library names."""
        return [e.get("name", f"offset:{e['d_val']}") for e in self.dynamic
                if e["d_tag"] == DT_NEEDED]

    @property
    def rpath(self) -> Optional[str]:
        """DT_RPATH value if present (deprecated; prefer RUNPATH)."""
        for e in self.dynamic:
            if e["d_tag"] == DT_RPATH:
                return e.get("name", f"offset:{e['d_val']}")
        return None

    @property
    def runpath(self) -> Optional[str]:
        """DT_RUNPATH value if present."""
        for e in self.dynamic:
            if e["d_tag"] == DT_RUNPATH:
                return e.get("name", f"offset:{e['d_val']}")
        return None

    # -----------------------------------------------------------------------
    # Security Feature Detection
    # -----------------------------------------------------------------------

    def detect_security(self) -> dict:
        """
        Detect binary hardening features from ELF metadata.

        PIE:       ET_DYN e_type indicates position-independent executable.
        NX Stack:  PT_GNU_STACK present without PF_X flag = NX enabled.
        RELRO:     PT_GNU_RELRO present = partial RELRO.
                   Full RELRO requires PT_GNU_RELRO + DT_BIND_NOW (or DT_FLAGS_1 DF_1_NOW).
        Canary:    Presence of __stack_chk_fail in dynsym = stack canary compiled in.
        Stripped:  Absence of .symtab section.
        PIE (DT):  DT_FLAGS_1 with DF_1_PIE flag also indicates PIE.

        Source: Learning Linux Binary Analysis ch2 (RELRO, GOT, PLT security),
                Hacking: The Art of Exploitation ch3 (exploitation mitigations).
        """
        sec = {}

        # PIE: ET_DYN e_type
        e_type = self.ehdr.get("e_type", 0)
        sec["pie"] = (e_type == ET_DYN)

        # Check DT_FLAGS_1 DF_1_PIE as secondary indicator
        for e in self.dynamic:
            if e["d_tag"] == DT_FLAGS_1 and (e["d_val"] & DF_1_PIE):
                sec["pie"] = True

        # NX Stack: PT_GNU_STACK without PF_X
        gnu_stacks = self.get_phdr_by_type(PT_GNU_STACK)
        if gnu_stacks:
            flags = gnu_stacks[0]["p_flags"]
            sec["nx_stack"] = not bool(flags & PF_X)
        else:
            # No PT_GNU_STACK: kernel default is NX on modern systems,
            # but the binary may be requesting a legacy executable stack.
            sec["nx_stack"] = True   # assume NX if segment absent (modern default)
            sec["nx_stack_note"] = "PT_GNU_STACK absent; assuming kernel default (NX)"

        # RELRO
        has_gnu_relro = bool(self.get_phdr_by_type(PT_GNU_RELRO))
        has_bind_now  = any(e["d_tag"] == DT_BIND_NOW for e in self.dynamic)
        has_flags_now = any(
            e["d_tag"] == DT_FLAGS_1 and (e["d_val"] & DF_1_NOW)
            for e in self.dynamic
        )
        sec["relro"] = (
            "full"    if (has_gnu_relro and (has_bind_now or has_flags_now)) else
            "partial" if has_gnu_relro else
            "none"
        )

        # Stack canary: __stack_chk_fail in dynamic symbols
        canary_syms = [s for s in self.dynsyms if "__stack_chk" in s.get("name", "")]
        sec["stack_canary"] = bool(canary_syms)

        # Stripped: no .symtab
        sec["stripped"] = (self.get_section(".symtab") is None)

        # Fortify: __*_chk functions in dynsym (e.g. __printf_chk, __memcpy_chk)
        fortify_syms = [s for s in self.dynsyms if s.get("name", "").endswith("_chk")
                        and not s.get("name","").startswith("__stack")]
        sec["fortify"] = bool(fortify_syms)

        return sec

    # -----------------------------------------------------------------------
    # GOT / PLT Analysis
    # -----------------------------------------------------------------------

    def got_plt_analysis(self) -> dict:
        """
        Analyse GOT/PLT sections to enumerate function hooking surface.

        The GOT is the primary writable target for heap/BSS write primitives:
        overwriting a GOT entry redirects the next PLT call to attacker-controlled
        code. Full RELRO makes .got.plt read-only after startup.

        .got.plt layout:
          GOT[0] = address of .dynamic section
          GOT[1] = link_map pointer (set by dynamic linker)
          GOT[2] = _dl_runtime_resolve address
          GOT[3+] = per-function entries patched by lazy linking

        Source: Learning Linux Binary Analysis ch2 (PLT/GOT lazy linking),
                Hacking: The Art of Exploitation ch3 (GOT overwrite techniques).
        """
        result = {
            "got_section":      None,
            "got_plt_section":  None,
            "plt_section":      None,
            "got_plt_address":  None,
            "got_plt_size":     None,
            "plt_address":      None,
            "plt_size":         None,
            "dt_pltgot":        None,
            "imported_funcs":   [],
            "exported_funcs":   [],
            "hooking_surface":  [],
        }

        # Section addresses
        for name, key in [(".got", "got_section"), (".got.plt", "got_plt_section"),
                           (".plt", "plt_section")]:
            shdr = self.get_section(name)
            if shdr:
                result[key] = {
                    "name":    name,
                    "address": hex(shdr["sh_addr"]),
                    "offset":  hex(shdr["sh_offset"]),
                    "size":    hex(shdr["sh_size"]),
                    "flags":   shdr["flags_str"],
                    "writable": bool(shdr["sh_flags"] & SHF_WRITE),
                }

        got_plt = self.get_section(".got.plt")
        if got_plt:
            result["got_plt_address"] = hex(got_plt["sh_addr"])
            result["got_plt_size"]    = got_plt["sh_size"]

        plt = self.get_section(".plt")
        if plt:
            result["plt_address"] = hex(plt["sh_addr"])
            result["plt_size"]    = plt["sh_size"]

        # DT_PLTGOT from dynamic section
        for e in self.dynamic:
            if e["d_tag"] == DT_PLTGOT:
                result["dt_pltgot"] = hex(e["d_val"])
                break

        # Imported functions (dynsym FUNC with address 0 = not yet resolved)
        imported = [
            {"name": s["name"], "bind": s["bind_name"]}
            for s in self.dynsyms
            if s["type_name"] == "FUNC" and s.get("st_value", 0) == 0
        ]
        result["imported_funcs"] = imported

        # Exported functions (dynsym FUNC with non-zero address)
        exported = [
            {"name": s["name"], "address": hex(s.get("st_value", 0))}
            for s in self.dynsyms
            if s["type_name"] == "FUNC" and s.get("st_value", 0) != 0
        ]
        result["exported_funcs"] = exported

        # Hooking surface: each imported function's GOT entry is a potential overwrite target.
        # Without full RELRO, GOT[3+] is writable at runtime.
        sec = self.detect_security()
        got_writable = sec["relro"] != "full"
        result["got_writable"]   = got_writable
        result["hooking_surface"] = [
            {
                "function":   f["name"],
                "mechanism":  "GOT overwrite" if got_writable else "GOT read-only (full RELRO)",
                "exploitable": got_writable,
            }
            for f in imported
        ]

        return result

    # -----------------------------------------------------------------------
    # Infection Indicator Scan
    # -----------------------------------------------------------------------

    def scan_infection_indicators(self) -> list:
        """
        Scan for ELF binary infection indicators.

        Covers dynamic section anomalies, entry point relocation, text section
        entropy, and section/segment structural mismatches that match documented
        parasite techniques.

        Source: Learning Linux Binary Analysis ch4 (ELF virus parasite infection
                methods: Silvio padding infection, reverse text infection, data
                segment infection, PT_NOTE->PT_LOAD conversion infection).

        Returns list of {'indicator': str, 'severity': str, 'detail': str}.
        Severity values: CRITICAL, HIGH, MEDIUM.
        """
        indicators = []

        # --- 1. DT_RPATH / DT_RUNPATH relative path (library hijack) ---
        # The dynamic linker searches DT_RPATH before system paths.  A value
        # of '.' or any relative path lets an attacker plant a malicious .so
        # in the working directory to hijack any DT_NEEDED library call.
        # Source: Learning Linux Binary Analysis ch2 (ELF dynamic linking --
        #         DT_RPATH / DT_RUNPATH as shared library search-path vectors).
        for entry in self.dynamic:
            if entry["d_tag"] in (DT_RPATH, DT_RUNPATH):
                path_val = entry.get("name", "")
                tag_name = "DT_RPATH" if entry["d_tag"] == DT_RPATH else "DT_RUNPATH"
                if path_val == "." or (path_val and not path_val.startswith("/")):
                    indicators.append({
                        "indicator": "relative_rpath",
                        "severity":  "HIGH",
                        "detail":    (
                            f"{tag_name}={path_val!r} -- relative search path "
                            "enables shared library hijack via CWD"
                        ),
                    })

        # --- 2. DT_NEEDED non-standard library names ---
        # Standard DT_NEEDED values follow lib<name>.so.<version>.  Names
        # without a version suffix, containing path separators, or matching
        # bare dot patterns signal an injected DT_NEEDED entry used to force
        # load of an attacker-controlled shared object.
        # Source: Learning Linux Binary Analysis ch4 (shared library injection
        #         via DT_NEEDED entry modification in the dynamic segment).
        for entry in self.dynamic:
            if entry["d_tag"] == DT_NEEDED:
                name = entry.get("name", "")
                if not name:
                    continue
                suspicious = (
                    name in (".", "..")
                    or name.startswith("../")
                    or name.startswith("./")
                    or "/" in name
                    or (name.endswith(".so") and not _RE_STANDARD_LIB.match(name))
                )
                if suspicious:
                    indicators.append({
                        "indicator": "suspicious_dt_needed",
                        "severity":  "HIGH",
                        "detail":    (
                            f"DT_NEEDED={name!r} -- non-standard name; "
                            "possible injected dependency for parasite load"
                        ),
                    })

        # --- 3. Multiple DT_INIT entries ---
        # The ELF ABI permits exactly one DT_INIT (constructor) per binary.
        # A second entry indicates dynamic segment tampering: a parasite that
        # appended its own constructor to redirect execution before main().
        # Source: Learning Linux Binary Analysis ch4 (infecting control flow
        #         via .ctors / .dtors section patching and DT_INIT redirection).
        dt_init_entries = [e for e in self.dynamic if e["d_tag"] == DT_INIT]
        if len(dt_init_entries) > 1:
            addrs = [hex(e["d_val"]) for e in dt_init_entries]
            indicators.append({
                "indicator": "multiple_dt_init",
                "severity":  "CRITICAL",
                "detail":    (
                    f"DT_INIT count={len(dt_init_entries)} (spec allows 1); "
                    f"addresses={addrs} -- extra entry = parasite constructor"
                ),
            })

        # --- 4. Entry point outside .text section ---
        # All three main padding-infection variants (Silvio, reverse text,
        # data segment) modify e_entry to redirect execution into the parasite
        # before handing off to the original entry point.  An EP outside the
        # canonical .text address range is a strong infection marker.
        # Source: Learning Linux Binary Analysis ch4 (Silvio padding infection
        #         algorithm step 2: e_entry = phdr[TEXT].p_vaddr + original
        #         p_filesz; reverse text infection step 4: e_entry set to
        #         orig_text_vaddr - PAGE_ROUND(parasite_len) + ehdr_size).
        ep = self.entry_point
        if ep != 0:
            text_shdr = self.get_section(".text")
            if text_shdr:
                text_start = text_shdr["sh_addr"]
                text_end   = text_start + text_shdr["sh_size"]
                if not (text_start <= ep < text_end):
                    indicators.append({
                        "indicator": "ep_outside_text",
                        "severity":  "HIGH",
                        "detail":    (
                            f"entry_point={hex(ep)} is outside .text "
                            f"[{hex(text_start)}-{hex(text_end)}] -- "
                            "possible entry-point infection"
                        ),
                    })

        # --- 5. High entropy .text section ---
        # Packed or encrypted parasite code injected into the text segment
        # raises its Shannon entropy above the ~6.0 typical of compiled code.
        # Threshold >7.0 bits/byte indicates likely compression or encryption.
        # Source: Learning Linux Binary Analysis ch4 (ELF anti-debugging and
        #         packing techniques -- runtime packers compress the text
        #         segment to hinder static analysis).
        text_data = self.get_section_data(".text")
        if text_data and len(text_data) >= 256:
            entropy = _shannon_entropy(text_data)
            if entropy > 7.0:
                indicators.append({
                    "indicator": "high_text_entropy",
                    "severity":  "MEDIUM",
                    "detail":    (
                        f".text Shannon entropy={entropy:.2f} bits/byte "
                        "(threshold 7.0; packed/encrypted code suspected)"
                    ),
                })

        # --- 6. Section header table absent or zeroed ---
        # Packers and infection tools destroy or strip the section header table
        # to defeat static analysis tools that rely on section metadata.  The
        # ELF runtime only requires program headers; sections are optional.
        # e_shnum=0 with e_phnum>0 is the canonical stripped-SHT signature.
        # Source: Learning Linux Binary Analysis ch4 (ELF anti-debugging --
        #         section header table destruction as anti-reverse-engineering).
        phnum = self.ehdr.get("e_phnum", 0)
        shnum = self.ehdr.get("e_shnum", 0)
        shoff = self.ehdr.get("e_shoff", 0)
        if phnum > 0 and shnum == 0:
            indicators.append({
                "indicator": "sht_absent",
                "severity":  "MEDIUM",
                "detail":    (
                    f"e_phnum={phnum} but e_shnum=0 -- section header table "
                    "stripped; common packer / infection anti-analysis technique"
                ),
            })
        elif phnum > 0 and shnum > 0 and shoff == 0:
            indicators.append({
                "indicator": "sht_offset_zero",
                "severity":  "MEDIUM",
                "detail":    (
                    f"e_shnum={shnum} but e_shoff=0 -- section header table "
                    "pointer zeroed while count is non-zero"
                ),
            })

        return indicators

    # -----------------------------------------------------------------------
    # PLT/GOT Table
    # -----------------------------------------------------------------------

    def _vaddr_to_file_offset(self, vaddr: int) -> Optional[int]:
        """
        Translate a virtual address to a file offset using PT_LOAD segments.
        Returns None if the address is not covered by any load segment.
        """
        for p in self.phdrs:
            if p["p_type"] == PT_LOAD and p["p_filesz"] > 0:
                seg_start = p["p_vaddr"]
                seg_end   = seg_start + p["p_filesz"]
                if seg_start <= vaddr < seg_end:
                    return vaddr - seg_start + p["p_offset"]
        return None

    def get_plt_got_table(self) -> list:
        """
        Extract PLT/GOT mapping from .rela.plt (ELF64) or .rel.plt (ELF32).

        Parses the jump-slot relocation section to recover each dynamically
        linked function's GOT slot address and corresponding PLT stub address.
        Also reads the on-disk GOT slot value to detect potential GOT overwrites:
        before dynamic linking, each GOT slot should hold a PLT+N address that
        falls within a mapped PT_LOAD segment; a stored value outside all load
        segments is a strong GOT-hijack indicator.

        Source: Learning Linux Binary Analysis ch2 (PLT/GOT lazy linking --
                GOT[3+] holds per-function entries patched by _dl_runtime_resolve;
                R_386_JMP_SLOT / R_X86_64_JUMP_SLOT relocation types),
                ch4 (GOT hijacking via relocatable code injection -- Quenya
                'hijack' command overwrites GOT entry for target function to
                redirect PLT call to injected parasite).

        Returns list of:
            {
                'function':      str,   -- resolved symbol name
                'got_addr':      str,   -- hex virtual address of GOT slot
                'plt_addr':      str,   -- hex virtual address of PLT stub (or None)
                'sym_idx':       int,   -- dynamic symbol table index
                'got_overwrite': bool,  -- True if stored GOT value is outside PT_LOAD
            }
        """
        entries = []

        # Collect all PT_LOAD virtual address ranges for GOT value validation
        load_ranges = [
            (p["p_vaddr"], p["p_vaddr"] + p["p_memsz"])
            for p in self.phdrs
            if p["p_type"] == PT_LOAD and p["p_memsz"] > 0
        ]

        # PLT base and per-entry size for stub address computation.
        # PLT[0] is the resolver trampoline; per-function stubs start at PLT[1].
        plt_shdr  = self.get_section(".plt")
        plt_base  = plt_shdr["sh_addr"]    if plt_shdr else 0
        plt_entsz = plt_shdr["sh_entsize"] if plt_shdr else 0
        # Fallback: x86/x86-64/AArch64 all use 16-byte PLT stubs
        if plt_base and plt_entsz == 0:
            plt_entsz = 16

        # Prefer .rela.plt (ELF64 explicit addend) over .rel.plt (ELF32 implicit)
        rela_shdr = self.get_section(".rela.plt") or self.get_section(".rel.plt")
        if rela_shdr is None:
            return entries

        use_rela   = (rela_shdr["sh_type"] == SHT_RELA)
        rela_off   = rela_shdr["sh_offset"]
        rela_sz    = rela_shdr["sh_size"]
        rela_entsz = rela_shdr["sh_entsize"]
        if rela_entsz == 0:
            return entries

        # Relocation entry format: (r_offset, r_info[, r_addend])
        if self.bits == 64:
            rel_fmt   = self.endian + ("QQq" if use_rela else "QQ")
            sym_shift = 32   # symbol index = r_info >> 32
        else:
            rel_fmt   = self.endian + ("IIi" if use_rela else "II")
            sym_shift = 8    # symbol index = r_info >> 8

        rel_struct_sz = struct.calcsize(rel_fmt)

        # .dynsym section for symbol name resolution
        dynsym_shdr  = self.get_section(".dynsym")
        dynsym_entsz = dynsym_shdr["sh_entsize"] if dynsym_shdr else 0
        if self.bits == 64:
            sym_fmt    = self.endian + "IBBHQQ"
            sym_fields = _ELF64_SYM_FIELDS
        else:
            sym_fmt    = self.endian + "IIIBBH"
            sym_fields = _ELF32_SYM_FIELDS
        sym_struct_sz = struct.calcsize(sym_fmt)

        # Pointer width for reading on-disk GOT slot values
        ptr_fmt = self.endian + ("Q" if self.bits == 64 else "I")
        ptr_sz  = struct.calcsize(ptr_fmt)

        num_entries = rela_sz // rela_entsz
        plt_idx     = 1   # slot 0 is the PLT resolver stub

        for i in range(num_entries):
            pos = rela_off + i * rela_entsz
            if pos + rel_struct_sz > len(self._data):
                break

            vals     = struct.unpack_from(rel_fmt, self._data, pos)
            r_offset = vals[0]   # virtual address of GOT slot
            r_info   = vals[1]

            sym_idx  = r_info >> sym_shift

            # Resolve symbol name from .dynsym + .dynstr
            sym_name = ""
            if dynsym_shdr and dynsym_entsz and sym_idx > 0:
                sym_off = dynsym_shdr["sh_offset"] + sym_idx * dynsym_entsz
                if sym_off + sym_struct_sz <= len(self._data):
                    sym_vals = struct.unpack_from(sym_fmt, self._data, sym_off)
                    sym      = dict(zip(sym_fields, sym_vals))
                    name_off = sym["st_name"]
                    if self._dynstrtab and name_off < len(self._dynstrtab):
                        sym_name = _cstring(self._dynstrtab, name_off)

            # PLT stub address: PLT[plt_idx] * entsz bytes after PLT base
            plt_stub_addr = None
            if plt_base and plt_entsz:
                plt_stub_addr = plt_base + plt_idx * plt_entsz

            # GOT overwrite detection: read the on-disk value stored in the
            # GOT slot (before dynamic linking this should be a PLT+N address
            # within a PT_LOAD segment).  A value outside all load ranges
            # (and non-zero) indicates a potential GOT hijack.
            got_overwrite = False
            file_off = self._vaddr_to_file_offset(r_offset)
            if file_off is not None and file_off + ptr_sz <= len(self._data):
                stored_val = struct.unpack_from(ptr_fmt, self._data, file_off)[0]
                if stored_val != 0 and load_ranges:
                    in_range = any(lo <= stored_val < hi for lo, hi in load_ranges)
                    if not in_range:
                        got_overwrite = True

            entries.append({
                "function":      sym_name or f"sym_{sym_idx}",
                "got_addr":      hex(r_offset),
                "plt_addr":      hex(plt_stub_addr) if plt_stub_addr is not None else None,
                "sym_idx":       sym_idx,
                "got_overwrite": got_overwrite,
            })
            plt_idx += 1

        return entries

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------

    def report(self) -> str:
        """Human-readable summary report."""
        lines = []
        a = lines.append

        a("=" * 70)
        a(f"ELF ANALYSIS: {self.path.name}")
        a("=" * 70)

        # Header
        a(f"\nType:         {self.elf_type}")
        a(f"Architecture: {self.machine} ({self.bits}-bit)")
        a(f"Entry point:  {hex(self.entry_point)}")
        a(f"Sections:     {len(self.shdrs)}")
        a(f"Segments:     {len(self.phdrs)}")

        # Program headers
        if self.phdrs:
            a("\nProgram Headers:")
            for p in self.phdrs:
                extra = ""
                if p["p_type"] == PT_INTERP:
                    extra = f"  [{p.get('interp', '')}]"
                a(f"  {p['type_name']:<20} offset={hex(p['p_offset']):<12}"
                  f"vaddr={hex(p['p_vaddr']):<12}flags={p['flags_str']}{extra}")

        # Sections
        if self.shdrs:
            a("\nSection Headers:")
            for s in self.shdrs:
                if not s["name"]:
                    continue
                a(f"  {s['name']:<20} {s['type_name']:<14} "
                  f"addr={hex(s['sh_addr']):<14} size={hex(s['sh_size']):<10} "
                  f"flags={s['flags_str']}")

        # Dynamic
        if self.dynamic:
            needed = self.needed_libs
            if needed:
                a(f"\nNeeded Libraries ({len(needed)}):")
                for lib in needed:
                    a(f"  {lib}")
            if self.rpath:
                a(f"\nRPATH:   {self.rpath}")
            if self.runpath:
                a(f"RUNPATH: {self.runpath}")

        # Symbols
        if self.dynsyms:
            funcs = [s for s in self.dynsyms if s["type_name"] == "FUNC"]
            a(f"\nDynamic Symbols: {len(self.dynsyms)} total, {len(funcs)} functions")
            for s in funcs[:20]:
                a(f"  {s['bind_name']:<8} {s['type_name']:<8} {s['name']}")
            if len(funcs) > 20:
                a(f"  ... ({len(funcs) - 20} more)")

        if self.symtabs:
            a(f"\nStatic Symbols: {len(self.symtabs)} entries")

        # Security
        sec = self.detect_security()
        a("\nSecurity Features:")
        a(f"  PIE:          {'yes' if sec['pie'] else 'NO'}")
        a(f"  NX Stack:     {'yes' if sec['nx_stack'] else 'NO'}")
        a(f"  RELRO:        {sec['relro']}")
        a(f"  Stack Canary: {'yes' if sec['stack_canary'] else 'NO'}")
        a(f"  Fortify:      {'yes' if sec['fortify'] else 'no'}")
        a(f"  Stripped:     {'yes' if sec['stripped'] else 'no'}")

        # GOT/PLT
        got = self.got_plt_analysis()
        a("\nGOT/PLT:")
        a(f"  GOT writable: {'YES (RELRO not full)' if got['got_writable'] else 'no (full RELRO)'}")
        a(f"  DT_PLTGOT:    {got['dt_pltgot'] or 'n/a'}")
        a(f"  Imported fns: {len(got['imported_funcs'])}")
        if got['hooking_surface']:
            a("  Hooking surface:")
            for h in got['hooking_surface'][:10]:
                flag = "[HOOK]" if h["exploitable"] else "[SAFE]"
                a(f"    {flag} {h['function']}  ({h['mechanism']})")
            if len(got['hooking_surface']) > 10:
                a(f"    ... ({len(got['hooking_surface']) - 10} more)")

        a("=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Return full parsed data as a serialisable dict."""
        return {
            "path":     str(self.path),
            "bits":     self.bits,
            "endian":   "little" if self.endian == "<" else "big",
            "header":   {k: (hex(v) if isinstance(v, int) else v)
                         for k, v in self.ehdr.items()},
            "type":     self.elf_type,
            "machine":  self.machine,
            "entry":    hex(self.entry_point),
            "phdrs":    self.phdrs,
            "shdrs":    [{k: (hex(v) if isinstance(v, int) and k not in ("sh_name",)
                               else v)
                          for k, v in s.items()}
                         for s in self.shdrs],
            "dynamic":  self.dynamic,
            "dynsyms":  self.dynsyms,
            "symtabs":  self.symtabs,
            "security": self.detect_security(),
            "got_plt":  self.got_plt_analysis(),
        }


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def parse_elf(path: str) -> ELFParser:
    """Parse an ELF file and return a populated ELFParser."""
    p = ELFParser(path)
    p.parse()
    return p


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <elf_binary> [--json]")
        sys.exit(1)

    path = sys.argv[1]
    as_json = "--json" in sys.argv

    try:
        elf = parse_elf(path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if as_json:
        print(json.dumps(elf.to_dict(), indent=2, default=str))
    else:
        print(elf.report())
