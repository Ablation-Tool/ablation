"""
pef_binary_analyzer.py — PowerPC PEF (CFM) container parser and import resolver.

Three things that were not possible before this module:

  1. PPC32TaintTracker cannot load PEF files — it requires ELF. All PEF CFM PPC32
     Mac Classic binaries (PGPuam, PGPuam Server, and all Tool_Chest networking
     utilities) were analyzed entirely by hand across sessions 3–11 because there
     was no PEF-aware loader in ablation.

  2. CFM import stub resolution was manual every session. Each session had to
     re-derive the RTOC-offset formula (sym[i] → i*4 from r2), identify which
     code VAs were stubs, and map them to symbol names. PEFBinaryAnalyzer produces
     the stub table in one call.

  3. No cross-binary PEF analysis was possible. Without a parser, comparing two
     PEF binaries (e.g., PGPuam client vs PGPuam Server) required full manual
     re-parsing of the loader section for each target.

Usage::

    from ablation.analyzers.pef_binary_analyzer import PEFBinaryAnalyzer

    pef = PEFBinaryAnalyzer.from_path('/path/to/PGPuam')
    print(pef.report())

    # Get code section bytes + base VA for BinaryContext or capstone
    code = pef.code_bytes()
    base_va = pef.code_base_va()

    # Resolve all CFM import stubs: {code_va: symbol_name}
    stubs = pef.stubs()
    for va, name in sorted(stubs.items()):
        print(f"  stub @ 0x{va:06x} → {name}")

    # Find a specific import
    imp = pef.import_by_name("BlockMoveData")
    if imp:
        print(f"  BlockMoveData: rtoc_offset=0x{imp.rtoc_offset:x}")

    # Convert code-section VA to file offset for byte verification
    foff = pef.file_offset_of_code_va(0x1988c)
    raw = open('/path/to/PGPuam','rb').read()[foff:foff+4]

Notes:
  - PEF "code-relative VAs" (fn@0x19788 etc.) are offsets from the start of
    the code section — i.e., code_base_va() is usually 0x0 for Mac Classic PEF.
  - The loader section parser handles both 8-library and single-library PEF files.
  - Stub scanning uses the lwz rX, N(r2) pattern (any destination register, not
    just r12) to handle compilers that emit different register choices.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# PEF format constants
# ---------------------------------------------------------------------------

PEF_TAG1         = 0x4A6F7921  # "Joy!"
PEF_TAG2         = 0x70656666  # "peff"
PEF_ARCH_PWPC    = 0x70777063  # "pwpc" — PowerPC
PEF_ARCH_M68K    = 0x6D36386B  # "m68k"

PEF_KIND_CODE           = 0   # executable, read-only (TEXT equivalent)
PEF_KIND_UNPACKED_DATA  = 1   # initialized read-write (DATA equivalent)
PEF_KIND_PATTERN_DATA   = 2   # packed initialized data
PEF_KIND_CONSTANT       = 3   # read-only constant data
PEF_KIND_LOADER         = 4   # import/export/reloc metadata
PEF_KIND_DEBUG          = 5
PEF_KIND_EXEC_DATA      = 6   # executable data (PEF64 extension)
PEF_KIND_EXCEPTION      = 7
PEF_KIND_TRACEBACK      = 8

PEF_KIND_NAMES = {
    PEF_KIND_CODE:          "code",
    PEF_KIND_UNPACKED_DATA: "unpacked_data",
    PEF_KIND_PATTERN_DATA:  "pattern_data",
    PEF_KIND_CONSTANT:      "constant",
    PEF_KIND_LOADER:        "loader",
    PEF_KIND_DEBUG:         "debug",
    PEF_KIND_EXEC_DATA:     "exec_data",
    PEF_KIND_EXCEPTION:     "exception",
    PEF_KIND_TRACEBACK:     "traceback",
}

PEF_SYM_CLASS_CODE    = 0
PEF_SYM_CLASS_DATA    = 1
PEF_SYM_CLASS_TVECTOR = 2
PEF_SYM_CLASS_TOC     = 3
PEF_SYM_CLASS_GLUE    = 4

# Container header: 40 bytes, all big-endian
# tag1(4) tag2(4) arch(4) version(4) ts(4) oldDef(4) oldImp(4) curVer(4) nSect(2) nInst(2) reserved(4)
_CONTAINER_HDR_FMT  = ">IIIIIIII HHI"
_CONTAINER_HDR_SIZE = struct.calcsize(_CONTAINER_HDR_FMT)   # 40 bytes

# Section header: 28 bytes, all big-endian
# nameOffset(4) defaultAddress(4) totalSize(4) unpackedSize(4) packedSize(4)
# containerOffset(4) sectionKind(1) shareKind(1) alignment(1) reserved(1)
_SECT_HDR_FMT  = ">IIIIIIBBBx"
_SECT_HDR_SIZE = struct.calcsize(_SECT_HDR_FMT)    # 28 bytes

# Loader section header: 56 bytes
_LOADER_HDR_FMT  = ">iiiiiIIIIIIIII"
_LOADER_HDR_SIZE = struct.calcsize(_LOADER_HDR_FMT)  # 56 bytes

# Imported library descriptor: 24 bytes
_IMP_LIB_FMT  = ">IIIIIBBxx"
_IMP_LIB_SIZE = struct.calcsize(_IMP_LIB_FMT)   # 24 bytes


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PEFSection:
    index:            int
    name:             str        # empty if nameOffset == -1
    default_address:  int
    total_size:       int
    unpacked_size:    int
    packed_size:      int
    file_offset:      int        # containerOffset — absolute in file
    kind:             int
    share_kind:       int
    alignment:        int        # as power of 2

    @property
    def kind_name(self) -> str:
        return PEF_KIND_NAMES.get(self.kind, f"unknown_{self.kind}")

    @property
    def is_code(self) -> bool:
        return self.kind in (PEF_KIND_CODE, PEF_KIND_EXEC_DATA)

    @property
    def is_data(self) -> bool:
        return self.kind in (PEF_KIND_UNPACKED_DATA, PEF_KIND_PATTERN_DATA, PEF_KIND_CONSTANT)

    @property
    def is_loader(self) -> bool:
        return self.kind == PEF_KIND_LOADER

    def read_from(self, file_data: bytes) -> bytes:
        return file_data[self.file_offset : self.file_offset + self.packed_size]


@dataclass
class PEFImportedLib:
    name:                str
    first_symbol_index:  int
    symbol_count:        int
    old_imp_version:     int
    current_version:     int


@dataclass
class PEFImport:
    index:        int          # global import index (0-based)
    lib_name:     str
    sym_name:     str
    sym_class:    int          # PEF_SYM_CLASS_*
    rtoc_offset:  int          # byte offset from RTOC → TVect pointer slot (= index * 4)


@dataclass
class PEFAnalysis:
    architecture:    int       # PEF_ARCH_PWPC / PEF_ARCH_M68K
    format_version:  int
    sections:        List[PEFSection]
    imports:         List[PEFImport]
    _data:           bytes


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class PEFBinaryAnalyzer:
    """Parse a PowerPC PEF (CFM) container; extract code section and import table."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._analysis: Optional[PEFAnalysis] = None

    # ── constructors ────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str | Path) -> "PEFBinaryAnalyzer":
        data = Path(path).read_bytes()
        return cls.from_bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> "PEFBinaryAnalyzer":
        pef = cls(data)
        pef._parse()
        return pef

    # ── public surface ───────────────────────────────────────────────────────

    def _require(self) -> PEFAnalysis:
        if self._analysis is None:
            raise RuntimeError("PEFBinaryAnalyzer not parsed — use from_bytes() or from_path()")
        return self._analysis

    @property
    def sections(self) -> List[PEFSection]:
        return self._require().sections

    @property
    def imports(self) -> List[PEFImport]:
        return self._require().imports

    @property
    def architecture(self) -> int:
        return self._require().architecture

    def is_powerpc(self) -> bool:
        return self.architecture == PEF_ARCH_PWPC

    def is_68k(self) -> bool:
        return self.architecture == PEF_ARCH_M68K

    def code_section(self) -> PEFSection:
        for s in self.sections:
            if s.is_code:
                return s
        raise KeyError("No code section (kind=0 or 6) found in PEF")

    def data_section(self) -> Optional[PEFSection]:
        for s in self.sections:
            if s.is_data:
                return s
        return None

    def loader_section_raw(self) -> Optional[PEFSection]:
        for s in self.sections:
            if s.is_loader:
                return s
        return None

    def code_bytes(self) -> bytes:
        sect = self.code_section()
        return sect.read_from(self._data)

    def code_base_va(self) -> int:
        return self.code_section().default_address

    def file_offset_of_code_va(self, code_va: int) -> int:
        sect = self.code_section()
        return sect.file_offset + (code_va - sect.default_address)

    def import_by_index(self, idx: int) -> Optional[PEFImport]:
        for imp in self.imports:
            if imp.index == idx:
                return imp
        return None

    def import_by_name(self, sym_name: str) -> Optional[PEFImport]:
        for imp in self.imports:
            if imp.sym_name == sym_name:
                return imp
        return None

    def import_by_rtoc_offset(self, offset: int) -> Optional[PEFImport]:
        for imp in self.imports:
            if imp.rtoc_offset == offset:
                return imp
        return None

    def stubs(self) -> Dict[int, str]:
        """Scan code section for CFM TVect stubs and return {code_va: symbol_name}.

        CFM stub pattern: lwz rX, N(r2) where N is a known RTOC import slot offset.
        The instruction is `0x80 XX 00 XX` in big-endian PPC32:
          - primary opcode = 32 (lwz) → bits[31:26] = 0b100000
          - rA (source) = r2 → bits[15:11] = 0b00010
          - displacement = RTOC offset (= import_index * 4)

        Returns the VA of the lwz instruction (first instruction of each stub), which
        is the branch target callers use to invoke the imported function.
        """
        rtoc_map = {imp.rtoc_offset: imp.sym_name for imp in self.imports}
        if not rtoc_map:
            return {}

        code = self.code_bytes()
        base  = self.code_base_va()
        result: Dict[int, str] = {}

        # PPC32 lwz encoding: opcode(6) | rD(5) | rA(5) | SIMM(16)
        # opcode=32=0b100000, rA=2=0b00010
        # mask: 0xFC1F0000 = 0b11111100_00011111_00000000_00000000
        #   opcode bits[31:26]=0b100000 → 0x80000000 >> 0 = top 6 bits = 0x80 << 2
        # In hex: opcode 32 → 32 << 26 = 0x80000000; rA=2 → 2 << 16 = 0x00020000
        # masked insn = (insn & 0xFC1F0000) == (32 << 26 | 2 << 16)
        LWZ_R2_MASK  = 0xFC1F0000
        LWZ_R2_MATCH = (32 << 26) | (2 << 16)   # lwz rX, N(r2)

        for i in range(0, len(code) - 3, 4):
            raw = struct.unpack_from(">I", code, i)[0]
            if (raw & LWZ_R2_MASK) == LWZ_R2_MATCH:
                # displacement is SIMM16 (signed 16-bit)
                simm = raw & 0xFFFF
                if simm & 0x8000:
                    simm -= 0x10000
                if simm < 0:
                    continue
                rtoc_offset = simm
                sym = rtoc_map.get(rtoc_offset)
                if sym is not None:
                    va = base + i
                    result[va] = sym

        return result

    def report(self) -> str:
        a = self._require()
        arch_str = "pwpc" if a.architecture == PEF_ARCH_PWPC else \
                   "m68k" if a.architecture == PEF_ARCH_M68K else \
                   f"0x{a.architecture:08x}"
        lines = [
            f"PEF  arch={arch_str}  format_version={a.format_version}  "
            f"sections={len(a.sections)}  imports={len(a.imports)}"
        ]
        for s in a.sections:
            lines.append(
                f"  [{s.index}] {s.kind_name:<15s} foff=0x{s.file_offset:08x}  "
                f"va=0x{s.default_address:08x}  packed={s.packed_size}  "
                f"total={s.total_size}  name={s.name!r}"
            )
        if a.imports:
            lines.append(f"  imports ({len(a.imports)}):")
            for imp in a.imports[:20]:
                lines.append(
                    f"    [{imp.index:3d}] rtoc+0x{imp.rtoc_offset:04x}  "
                    f"{imp.lib_name}:{imp.sym_name}"
                )
            if len(a.imports) > 20:
                lines.append(f"    ... ({len(a.imports) - 20} more)")
        return "\n".join(lines)

    # ── static helpers ───────────────────────────────────────────────────────

    @staticmethod
    def is_pef(data: bytes) -> bool:
        if len(data) < 8:
            return False
        tag1, tag2 = struct.unpack_from(">II", data, 0)
        return tag1 == PEF_TAG1 and tag2 == PEF_TAG2

    # ── parser internals ─────────────────────────────────────────────────────

    def _parse(self) -> None:
        data = self._data

        if len(data) < _CONTAINER_HDR_SIZE:
            raise ValueError(
                f"PEF: data too short ({len(data)} bytes, need ≥{_CONTAINER_HDR_SIZE})"
            )

        (tag1, tag2, arch, fmt_ver, _ts, _old_def, _old_imp, _cur_ver,
         section_count, _inst_count, _reserved) = struct.unpack_from(_CONTAINER_HDR_FMT, data, 0)

        if tag1 != PEF_TAG1 or tag2 != PEF_TAG2:
            raise ValueError(
                f"Not a PEF file: tag1=0x{tag1:08x} tag2=0x{tag2:08x}"
            )

        # Parse section headers immediately following container header (40 bytes)
        sections: List[PEFSection] = []
        hdr_offset = _CONTAINER_HDR_SIZE
        for i in range(section_count):
            if hdr_offset + _SECT_HDR_SIZE > len(data):
                raise ValueError(f"PEF: section header {i} at offset {hdr_offset} exceeds data")
            (name_off, def_addr, total_sz, unpack_sz, pack_sz,
             cont_off, kind, share, align) = struct.unpack_from(_SECT_HDR_FMT, data, hdr_offset)
            sections.append(PEFSection(
                index=i,
                name=self._read_section_name(data, name_off, section_count),
                default_address=def_addr,
                total_size=total_sz,
                unpacked_size=unpack_sz,
                packed_size=pack_sz,
                file_offset=cont_off,
                kind=kind,
                share_kind=share,
                alignment=align,
            ))
            hdr_offset += _SECT_HDR_SIZE

        # Parse imports from loader section
        imports = self._parse_imports(data, sections)

        self._analysis = PEFAnalysis(
            architecture=arch,
            format_version=fmt_ver,
            sections=sections,
            imports=imports,
            _data=data,
        )

    def _read_section_name(self, data: bytes, name_offset: int, section_count: int) -> str:
        if name_offset == 0xFFFFFFFF or name_offset < 0:
            return ""
        # Name table follows section headers (at _CONTAINER_HDR_SIZE + section_count * _SECT_HDR_SIZE)
        name_table_offset = _CONTAINER_HDR_SIZE + section_count * _SECT_HDR_SIZE
        abs_offset = name_table_offset + name_offset
        if abs_offset >= len(data):
            return ""
        end = data.find(b"\x00", abs_offset)
        if end < 0:
            return data[abs_offset:].decode("ascii", errors="replace")
        return data[abs_offset:end].decode("ascii", errors="replace")

    def _parse_imports(self, data: bytes, sections: List[PEFSection]) -> List[PEFImport]:
        loader_sect = next((s for s in sections if s.is_loader), None)
        if loader_sect is None:
            return []

        loff = loader_sect.file_offset  # absolute file offset of loader section
        if loff + _LOADER_HDR_SIZE > len(data):
            return []

        (main_sec, main_off, init_sec, init_off, term_sec, term_off,
         imp_lib_count, total_imp_sym_count, reloc_sect_count, reloc_instr_off,
         loader_str_off, export_hash_off, export_hash_power, export_sym_count
         ) = struct.unpack_from(_LOADER_HDR_FMT, data, loff)

        # Absolute offset of loader string table
        strings_abs = loff + loader_str_off

        # Parse imported library descriptors
        lib_cursor = loff + _LOADER_HDR_SIZE
        libs: List[PEFImportedLib] = []
        for _ in range(imp_lib_count):
            if lib_cursor + _IMP_LIB_SIZE > len(data):
                break
            (lib_name_off, old_imp_ver, cur_ver, imp_sym_count,
             first_imp_sym, opts, _reserved) = struct.unpack_from(_IMP_LIB_FMT, data, lib_cursor)
            lib_name = self._read_cstring(data, strings_abs + lib_name_off)
            libs.append(PEFImportedLib(
                name=lib_name,
                first_symbol_index=first_imp_sym,
                symbol_count=imp_sym_count,
                old_imp_version=old_imp_ver,
                current_version=cur_ver,
            ))
            lib_cursor += _IMP_LIB_SIZE

        # Parse imported symbol table (4 bytes each)
        # Located immediately after library descriptors
        sym_table_off = loff + _LOADER_HDR_SIZE + imp_lib_count * _IMP_LIB_SIZE
        imports: List[PEFImport] = []

        # Build reverse map: sym_index → lib
        sym_to_lib: Dict[int, PEFImportedLib] = {}
        for lib in libs:
            for j in range(lib.symbol_count):
                sym_to_lib[lib.first_symbol_index + j] = lib

        for i in range(total_imp_sym_count):
            sym_off = sym_table_off + i * 4
            if sym_off + 4 > len(data):
                break
            word = struct.unpack_from(">I", data, sym_off)[0]
            sym_class = (word >> 24) & 0xFF
            name_offset = word & 0x00FFFFFF
            sym_name = self._read_cstring(data, strings_abs + name_offset)
            lib = sym_to_lib.get(i)
            lib_name = lib.name if lib else ""
            imports.append(PEFImport(
                index=i,
                lib_name=lib_name,
                sym_name=sym_name,
                sym_class=sym_class,
                rtoc_offset=i * 4,
            ))

        return imports

    @staticmethod
    def _read_cstring(data: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(data):
            return ""
        end = data.find(b"\x00", offset)
        if end < 0:
            return data[offset:].decode("ascii", errors="replace")
        return data[offset:end].decode("ascii", errors="replace")
