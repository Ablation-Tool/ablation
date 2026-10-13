"""IBM XCOFF32/XCOFF64 binary parser for AIX PowerPC executables.

Parses the eXtended Common Object File Format (XCOFF) used by IBM AIX on
PowerPC (RS/6000, POWER) systems.  Supported variants:

- XCOFF32  magic 0x01DF  (AIX 4.x / 5.x 32-bit, PPC32, big-endian)
- XCOFF64  magic 0x01EF  (AIX 5.x / 6.x 64-bit, PPC64, big-endian)

Why this exists
---------------
1. LIEF does not support XCOFF.  Calling ``lief.parse()`` on an XCOFF binary
   returns ``None``; ``BinaryContext`` then falls through to a default
   ``x86_64`` context with no sections, no symbols, and no function starts.
   Every AIX analysis session using the existing stack was silently broken.
2. XCOFF introduces the ``.loader`` section, which survives stripping
   (``nsyms == 0`` in the file header is common for AIX production builds)
   and holds all import and export symbol names with their virtual addresses.
   This section is the primary RE surface for stripped AIX binaries.
3. XCOFF uses a function-descriptor ABI on PPC32/PPC64: exported functions
   appear as ``[code_va, toc_va]`` descriptor pairs in ``.data``, not as
   direct code-section pointers.  Resolving descriptors to code VAs requires
   explicit parsing of the ``.data`` section that LIEF never attempted.
4. XCOFF64 section headers are 72 bytes (vs 40 for XCOFF32); the struct
   difference must be handled in the same parser rather than in two separate
   tools that diverge over time.

Format reference
----------------
IBM AIX 5.1 XCOFF Object File Format specification;
"XCOFF Reference" in IBM OpenXL C/C++ documentation;
empirical analysis of AIX 4.3.3 ML11 kernel extension binaries.

Usage::

    from ablation.core.xcoff_parser import parse, XcoffBinary

    binary = parse('/path/to/xcoff_binary')
    print(binary.arch, binary.entry)
    for sym in binary.exports:
        print(f'{sym.name}  code_va={sym.code_va:#010x}')
    for sym in binary.imports:
        print(f'{sym.name}  from={sym.lib}')
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

XCOFF32_MAGIC = 0x01DF
XCOFF64_MAGIC = 0x01EF

# XCOFF section flags (s_flags)
STYP_TEXT   = 0x0020
STYP_DATA   = 0x0040
STYP_BSS    = 0x0080
STYP_LOADER = 0x1000

# Loader symbol smclas values
XMC_PR  = 0x04   # program code
XMC_RO  = 0x05   # read-only constant
XMC_DB  = 0x06   # debug
XMC_GL  = 0x07   # global linkage (descriptor glue)
XMC_XO  = 0x08   # extended operation linkage
XMC_SV  = 0x09   # supervisor call linkage
XMC_UA  = 0x0A   # undefined
XMC_RW  = 0x05   # read-write data (same as XMC_RO tag)
XMC_TC0 = 0x0F   # TOC anchor
XMC_TC  = 0x03   # TOC entry
XMC_DS  = 0x0A   # function descriptor (value of XMC_UA, reused)

# Loader symbol smtype values
XTY_ER = 0x00   # external reference (import)
XTY_SD = 0x01   # section definition
XTY_LD = 0x02   # label definition
XTY_CM = 0x03   # common (BSS) definition

_FILE_HDR_FMT32 = '>HHIIIHH'   # magic, nscns, timdat, symptr, nsyms, opthdr, flags
_FILE_HDR_SZ    = 20

# XCOFF32 optional header: 72 bytes (only first 48 parsed here)
_OPT_HDR32_FMT = '>HHIIIIII'   # magic, vstamp, tsize, dsize, bsize, entry, text_start, data_start
_OPT_HDR32_TOC_OFF = 28        # o_toc is at byte 28 within the optional header (4 bytes)

# XCOFF32 section header: 40 bytes
_SCNHDR32_FMT = '>8sIIIIIIHHI'
_SCNHDR32_SZ  = 40

# XCOFF64 section header: 72 bytes
_SCNHDR64_FMT = '>8sQQQQQQIII'   # name(8), paddr(8), vaddr(8), size(8), scnptr(8), relptr(8), lnnoptr(8), nreloc(4), nlnno(4), flags(4)
_SCNHDR64_SZ  = 72

# XCOFF32 .loader header: 32 bytes
_LDHDR32_FMT = '>IIIIIIII'   # version, nsyms, nreloc, istlen, nimpid, impoff, stlen, stoff

# XCOFF32 loader symbol: 24 bytes
# [name(8) OR zeroes(4)+offset(4)] + value(4) + scnum(H) + smtype(B) + smclas(B) + ifile(I) + parm(I)
_LDSYM32_TAIL_FMT = '>IHBBI'   # value, scnum, smtype, smclas, ifile
_LDSYM32_SZ = 24


@dataclass
class XcoffSection:
    """One section from an XCOFF binary."""
    name:   str
    vaddr:  int
    size:   int
    offset: int     # file offset (0 for BSS)
    flags:  int
    data:   bytes = field(repr=False)

    @property
    def is_text(self) -> bool:
        return bool(self.flags & STYP_TEXT)

    @property
    def is_data(self) -> bool:
        return bool(self.flags & STYP_DATA)

    @property
    def is_bss(self) -> bool:
        return bool(self.flags & STYP_BSS)

    def contains_va(self, va: int) -> bool:
        return self.vaddr <= va < self.vaddr + self.size


@dataclass
class XcoffSymbol:
    """One loader-section symbol (import or export)."""
    name:     str
    va:       int       # descriptor VA (for functions) or data VA; 0 for imports
    lib:      str       # import library name (non-empty for imports)
    smclas:   int       # storage mapping class
    code_va:  int = 0   # resolved code VA (non-zero after descriptor resolution)

    @property
    def is_import(self) -> bool:
        return bool(self.lib)


@dataclass
class XcoffBinary:
    """Parsed XCOFF32 or XCOFF64 binary."""

    path:       str
    arch:       str             # 'ppc32' or 'ppc64'
    entry:      int             # entry point (descriptor VA for XCOFF32)
    text_start: int
    data_start: int
    toc_va:     int
    sections:   List[XcoffSection] = field(default_factory=list)
    exports:    List[XcoffSymbol]  = field(default_factory=list)
    imports:    List[XcoffSymbol]  = field(default_factory=list)
    _sec_map:   Dict[str, XcoffSection] = field(default_factory=dict, repr=False)

    def section(self, name: str) -> Optional[XcoffSection]:
        return self._sec_map.get(name)

    @property
    def text(self) -> Optional[XcoffSection]:
        return self._sec_map.get('.text')

    @property
    def data(self) -> Optional[XcoffSection]:
        return self._sec_map.get('.data')


def _read_cstring(data: bytes, off: int) -> bytes:
    """Read a null-terminated byte string starting at off."""
    end = data.index(b'\x00', off)
    return data[off:end]


def _parse_import_table(ldr: bytes, impoff: int, nimpid: int) -> List[str]:
    """Parse the import file ID table and return a flat list of import IDs.

    Each import ID is a triple of null-terminated strings:
    ``path \\0 archive_member \\0 object_name \\0``
    The list index is 1-based (entry 0 = this module itself).
    """
    ids: List[str] = ['']   # index 0 = this module
    off = impoff
    for _ in range(nimpid):
        if off >= len(ldr):
            break
        # path
        try:
            path_end   = ldr.index(b'\x00', off)
            arch_end   = ldr.index(b'\x00', path_end + 1)
            obj_end    = ldr.index(b'\x00', arch_end + 1)
        except ValueError:
            break
        path_s = ldr[off:path_end].decode('utf-8', errors='replace')
        arch_s = ldr[path_end+1:arch_end].decode('utf-8', errors='replace')
        obj_s  = ldr[arch_end+1:obj_end].decode('utf-8', errors='replace')
        # Use archive member name as lib label; fallback to object name
        lib = arch_s or obj_s or path_s or '?'
        ids.append(lib)
        off = obj_end + 1
    return ids


def _parse_loader32(ldr: bytes, sections: List[XcoffSection]) -> tuple:
    """Parse XCOFF32 .loader section; return (exports, imports)."""
    if len(ldr) < 32:
        return [], []

    (l_version, l_nsyms, l_nreloc, l_istlen,
     l_nimpid, l_impoff, l_stlen, l_stoff) = struct.unpack_from(_LDHDR32_FMT, ldr, 0)

    # String table (names for symbols whose l_zeroes == 0)
    stab = ldr[l_stoff:l_stoff + l_stlen] if l_stoff + l_stlen <= len(ldr) else b''

    # Import file ID table
    imp_ids = _parse_import_table(ldr, l_impoff, l_nimpid)

    exports: List[XcoffSymbol] = []
    imports: List[XcoffSymbol] = []

    sym_base = 32   # loader header is 32 bytes
    for i in range(l_nsyms):
        off = sym_base + i * _LDSYM32_SZ
        if off + _LDSYM32_SZ > len(ldr):
            break

        name8     = ldr[off:off + 8]
        l_zeroes  = struct.unpack_from('>I', name8, 0)[0]
        l_stoff_i = struct.unpack_from('>I', name8, 4)[0]

        # Name: inline (l_zeroes != 0) or from string table
        if l_zeroes != 0:
            sym_name = name8.rstrip(b'\x00').decode('ascii', errors='replace')
        elif l_stoff_i < len(stab):
            try:
                null_pos = stab.index(b'\x00', l_stoff_i)
                sym_name = stab[l_stoff_i:null_pos].decode('utf-8', errors='replace')
            except ValueError:
                sym_name = stab[l_stoff_i:].decode('utf-8', errors='replace')
        else:
            sym_name = f'_sym_{i}'

        l_value, l_scnum, l_smtype, l_smclas, l_ifile = struct.unpack_from(
            _LDSYM32_TAIL_FMT, ldr, off + 8
        )

        if l_ifile > 0:
            # Imported symbol
            lib = imp_ids[l_ifile] if l_ifile < len(imp_ids) else f'ifile_{l_ifile}'
            imports.append(XcoffSymbol(name=sym_name, va=0, lib=lib, smclas=l_smclas))
        else:
            # Defined symbol (exported or local descriptor)
            exports.append(XcoffSymbol(
                name=sym_name, va=l_value, lib='', smclas=l_smclas
            ))

    return exports, imports


def _resolve_descriptors(binary: XcoffBinary) -> None:
    """For PPC32 function descriptors in .data, resolve to code VAs.

    A descriptor at .data[va] is an 8-byte struct ``{code_va (4), toc_va (4)}``.
    Sets ``sym.code_va`` on each export symbol that has a descriptor.
    """
    dsec = binary.data
    if dsec is None or not dsec.data:
        return
    tsec = binary.text
    if tsec is None:
        return

    for sym in binary.exports:
        if sym.va == 0:
            continue
        if not dsec.contains_va(sym.va):
            continue
        off = sym.va - dsec.vaddr
        if off + 4 > len(dsec.data):
            continue
        code_va = struct.unpack_from('>I', dsec.data, off)[0]
        if code_va != 0 and tsec.contains_va(code_va):
            sym.code_va = code_va


def parse(path: str | Path, data: Optional[bytes] = None) -> XcoffBinary:
    """Parse an XCOFF32 or XCOFF64 binary.

    Args:
        path : path to the XCOFF file (used for error messages and in result)
        data : raw bytes if already read; if None, the file is read from path

    Raises:
        ValueError: if the magic bytes are not 0x01DF or 0x01EF
        struct.error: if the file is truncated
    """
    if data is None:
        data = Path(path).read_bytes()

    if len(data) < _FILE_HDR_SZ:
        raise ValueError(f"file too short ({len(data)} bytes) for XCOFF header")

    magic, nscns, timdat, symptr, nsyms, opthdr_sz, flags = struct.unpack_from(
        _FILE_HDR_FMT32, data, 0
    )

    if magic == XCOFF32_MAGIC:
        arch = 'ppc32'
        scnhdr_fmt, scnhdr_sz = _SCNHDR32_FMT, _SCNHDR32_SZ
    elif magic == XCOFF64_MAGIC:
        arch = 'ppc64'
        scnhdr_fmt, scnhdr_sz = _SCNHDR64_FMT, _SCNHDR64_SZ
    else:
        raise ValueError(f"not an XCOFF binary: magic={magic:#06x} (expected 0x01df or 0x01ef)")

    # Optional header — parse entry, text_start, data_start, toc
    entry = text_start = data_start = toc_va = 0
    if opthdr_sz >= 28 and len(data) >= _FILE_HDR_SZ + 28:
        _, _, _, _, _, entry, text_start, data_start = struct.unpack_from(
            _OPT_HDR32_FMT, data, _FILE_HDR_SZ
        )
    if opthdr_sz >= 32 and len(data) >= _FILE_HDR_SZ + 32:
        toc_va = struct.unpack_from('>I', data, _FILE_HDR_SZ + _OPT_HDR32_TOC_OFF)[0]

    # Section headers
    scn_base = _FILE_HDR_SZ + opthdr_sz
    sections: List[XcoffSection] = []
    sec_map: Dict[str, XcoffSection] = {}
    loader_data: bytes = b''

    for i in range(nscns):
        off = scn_base + i * scnhdr_sz
        if off + scnhdr_sz > len(data):
            break

        if arch == 'ppc32':
            name_raw, paddr, vaddr, size, scnptr, _, _, _, _, scn_flags = struct.unpack_from(
                _SCNHDR32_FMT, data, off
            )
        else:   # ppc64: paddr/vaddr/size/scnptr are 8-byte (Q)
            name_raw, paddr, vaddr, size, scnptr, _, _, _, _, scn_flags = struct.unpack_from(
                _SCNHDR64_FMT, data, off
            )

        name = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')

        if scnptr > 0 and size > 0 and scnptr + size <= len(data):
            sec_data = data[scnptr:scnptr + size]
        else:
            sec_data = b'\x00' * min(size, 0)   # BSS or zero-size

        sec = XcoffSection(name=name, vaddr=vaddr, size=size,
                           offset=scnptr, flags=scn_flags, data=sec_data)
        sections.append(sec)
        sec_map[name] = sec

        if scn_flags & STYP_LOADER:
            loader_data = sec_data

    binary = XcoffBinary(
        path=str(path),
        arch=arch,
        entry=entry,
        text_start=text_start,
        data_start=data_start,
        toc_va=toc_va,
        sections=sections,
        _sec_map=sec_map,
    )

    # Parse .loader section
    if loader_data:
        exports, imports = _parse_loader32(loader_data, sections)
        binary.exports = exports
        binary.imports = imports
        _resolve_descriptors(binary)

    return binary
