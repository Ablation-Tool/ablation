"""IBM XCOFF32/XCOFF64 binary parser for AIX PowerPC executables.

Parses the eXtended Common Object File Format (XCOFF) used by IBM AIX on
PowerPC (RS/6000, POWER) systems.  Supported variants:

- XCOFF32  magic 0x01DF  (AIX 4.x / 5.x 32-bit, PPC32, big-endian)
- XCOFF64  magic 0x01F7  (AIX 5.x / 6.x 64-bit, PPC64, big-endian)

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

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Loader symbol names must be valid C/XCOFF identifiers; the loader strtab in
# XCOFF64 shared libraries often starts with a VPD metadata string whose bytes
# can appear as short garbled "names" when l_noff happens to land in that region.
_VALID_LDSYM_NAME = re.compile(r'^[A-Za-z_.@$][A-Za-z0-9_.@$]*$')

XCOFF32_MAGIC = 0x01DF
XCOFF64_MAGIC = 0x01F7

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

_FILE_HDR_FMT32 = '>HHIIIHH'   # magic, nscns, timdat, symptr(4), nsyms, opthdr, flags
_FILE_HDR_SZ    = 20
_FILE_HDR_FMT64 = '>HHIQHHI'   # magic, nscns, timdat, symptr(8), opthdr, flags, nsyms
_FILE_HDR_SZ64  = 24

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

# XCOFF64 .loader section header: 56 bytes (version=2)
# l_version(4) l_nsyms(4) l_nreloc(4) l_istlen(4) l_nimpid(4) l_impoff(4)
# l_stlen(8) l_stoff(8) l_symoff(8) l_rldoff(8)
_LDHDR64_FMT = '>IIIIIIQQQQ'
_LDHDR64_SZ  = 56


# XCOFF32 symbol table entry: 18 bytes
_SYMENT32_FMT = '>8sIhHBB'   # name(8B), value(4B), scnum(2B sn), type(2B), sclass(1B), numaux(1B)
_SYMENT32_SZ  = 18
# Storage classes for function code entry points
_C_EXT    = 2    # exported function descriptor
_C_HIDEXT = 107  # hidden external (code entry — dotted name)


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


def _parse_loader64(ldr: bytes, sections: List[XcoffSection]) -> tuple:
    """Parse XCOFF64 .loader section (56-byte LDHDR64, version 1 or 2); return (exports, imports).

    LDHDR64 field layout (empirically verified against AIX 5.x shr_64.o):
      I×6: l_version, l_nsyms, l_nreloc, l_istlen, l_nimpid, l_stlen(compat-4B)
      Q×4: l_impoff(import-IDs start), l_stoff(sym-name-strtab start), l_symoff, l_rldoff
    Symbols remain 24 bytes (XCOFF32 ldsym format); only LDHDR addresses are widened.
    """
    if len(ldr) < _LDHDR64_SZ:
        return [], []

    (l_version, l_nsyms, l_nreloc, l_istlen,
     l_nimpid, l_stlen, l_impoff, l_stoff,
     l_symoff, l_rldoff) = struct.unpack_from(_LDHDR64_FMT, ldr, 0)

    stab = ldr[l_stoff:l_stoff + l_stlen] if l_stoff + l_stlen <= len(ldr) else ldr[l_stoff:]
    imp_ids = _parse_import_table(ldr, l_impoff, l_nimpid)

    exports: List[XcoffSymbol] = []
    imports: List[XcoffSymbol] = []

    sym_base = l_symoff
    for i in range(l_nsyms):
        off = sym_base + i * _LDSYM32_SZ
        if off + _LDSYM32_SZ > len(ldr):
            break

        name8    = ldr[off:off + 8]
        l_zeroes = struct.unpack_from('>I', name8, 0)[0]
        l_noff   = struct.unpack_from('>I', name8, 4)[0]

        if l_zeroes != 0:
            sym_name = name8.rstrip(b'\x00').decode('ascii', errors='replace')
        elif l_noff < len(stab):
            try:
                null_pos = stab.index(b'\x00', l_noff)
                sym_name = stab[l_noff:null_pos].decode('utf-8', errors='replace')
            except ValueError:
                sym_name = stab[l_noff:].decode('utf-8', errors='replace')
            if not _VALID_LDSYM_NAME.match(sym_name):
                sym_name = f'_sym_{i}'
        else:
            sym_name = f'_sym_{i}'

        l_value, l_scnum, l_smtype, l_smclas, l_ifile = struct.unpack_from(
            _LDSYM32_TAIL_FMT, ldr, off + 8
        )

        if l_ifile > 0:
            lib = imp_ids[l_ifile] if l_ifile < len(imp_ids) else f'ifile_{l_ifile}'
            imports.append(XcoffSymbol(name=sym_name, va=0, lib=lib, smclas=l_smclas))
        else:
            exports.append(XcoffSymbol(name=sym_name, va=l_value, lib='', smclas=l_smclas))

    return exports, imports


def _resolve_descriptors(binary: XcoffBinary) -> None:
    """For PPC32/PPC64 function descriptors in .data, resolve to code VAs.

    PPC32: descriptor = {code_va(4), toc_va(4)} → 8-byte, read as '>I'
    PPC64: descriptor = {code_va(8), toc_va(8)} → 16-byte, read as '>Q'
    Sets ``sym.code_va`` on each export symbol that has a descriptor.
    """
    dsec = binary.data
    if dsec is None or not dsec.data:
        return
    tsec = binary.text
    if tsec is None:
        return

    is64 = binary.arch == 'ppc64'
    va_fmt, va_sz = ('>Q', 8) if is64 else ('>I', 4)

    for sym in binary.exports:
        if sym.va == 0:
            continue
        if not dsec.contains_va(sym.va):
            continue
        off = sym.va - dsec.vaddr
        if off + va_sz > len(dsec.data):
            continue
        code_va = struct.unpack_from(va_fmt, dsec.data, off)[0]
        if code_va != 0 and tsec.contains_va(code_va):
            sym.code_va = code_va


def _parse_symtab32(
    data: bytes, symptr: int, nsyms: int, sections: List[XcoffSection]
) -> List[XcoffSymbol]:
    """Parse XCOFF32 symbol table for C_HIDEXT code-entry symbols.

    Used as a fallback when no .loader section is present (e.g. relocatable .o
    files from AIX ar archives).  C_HIDEXT symbols in .text are the actual
    function code entry points; their name is the user-visible name with a
    leading '.' (e.g. '.frexp' for the frexp function).  Returns one
    XcoffSymbol per code entry with code_va == va == section_vaddr + sym_value.
    """
    if symptr == 0 or nsyms == 0:
        return []

    # String table immediately follows the symbol table entries
    strtab_off = symptr + nsyms * _SYMENT32_SZ
    strtab: bytes = b''
    if strtab_off + 4 <= len(data):
        stlen = struct.unpack_from('>I', data, strtab_off)[0]
        strtab = data[strtab_off: strtab_off + stlen]

    # 1-based section number → vaddr; only for .text sections (code entry points only)
    sec_va: Dict[int, int] = {
        i + 1: s.vaddr for i, s in enumerate(sections) if s.flags & STYP_TEXT
    }

    result: List[XcoffSymbol] = []
    seen: set = set()   # (name, va) dedup — both C_EXT and C_HIDEXT can emit the same dotted name
    i = 0
    while i < nsyms:
        off = symptr + i * _SYMENT32_SZ
        if off + _SYMENT32_SZ > len(data):
            break

        name_bytes, value, scnum, _, sclass, numaux = struct.unpack_from(
            _SYMENT32_FMT, data, off
        )

        # Decode name (inline or string-table offset)
        if name_bytes[:4] == b'\x00\x00\x00\x00':
            stoff = struct.unpack_from('>I', name_bytes, 4)[0]
            raw = strtab[stoff: stoff + 64].split(b'\x00')[0] if stoff < len(strtab) else b''
        else:
            raw = name_bytes.rstrip(b'\x00')
        sym_name = raw.decode('ascii', errors='replace')

        if sclass in (_C_EXT, _C_HIDEXT) and scnum > 0 and scnum in sec_va and sym_name.startswith('.'):
            # Code entry in .text: dotted-name convention (.frexp → frexp)
            clean = sym_name[1:]   # strip leading '.' only
            if clean:
                va = sec_va[scnum] + value
                key = (clean, va)
                if key not in seen:
                    seen.add(key)
                    result.append(XcoffSymbol(name=clean, va=va, lib='', smclas=XMC_PR, code_va=va))

        i += 1 + numaux   # skip auxiliary entries

    return result


_XCOFF64_SENTINEL_VA = 0x1D4C   # n_value used by C_HIDEXT XTY_SD entries with no resolved code VA


def _parse_symtab64(
    data: bytes, symptr: int, nsyms: int, sections: List[XcoffSection]
) -> List[XcoffSymbol]:
    """Parse XCOFF64 main symbol table for named code-entry symbols.

    Despite being 64-bit, XCOFF64 uses 18-byte syment entries (same layout as
    XCOFF32; n_value stays 4 bytes holding a section-relative offset).  C_EXT
    (sclass=2) symbols with scnum=1 (.text) carry direct code VAs for shared-
    library exports, while C_HIDEXT (sclass=107) entries mostly hold a sentinel
    value 0x1D4C and are skipped.

    The strtab uses AIX suffix-compression: n_offset may point into the MIDDLE
    of a longer existing string, so a forward position-map is built first to
    recover the full containing string for any given offset.
    """
    if symptr == 0 or nsyms == 0:
        return []

    strtab_off = symptr + nsyms * _SYMENT32_SZ
    strtab: bytes = b''
    if strtab_off + 4 <= len(data):
        stlen = struct.unpack_from('>I', data, strtab_off)[0]
        strtab = data[strtab_off: strtab_off + stlen]

    # Forward-scan strtab to build offset → string_start map.
    # Every byte of each null-terminated string maps back to that string's start.
    # This recovers full names when n_offset lands in the middle of a suffix-
    # compressed entry (AIX linker reuses string tails rather than duplicating them).
    string_start: Dict[int, int] = {}
    pos = 4   # skip 4-byte length prefix
    while pos < len(strtab):
        start = pos
        end = strtab.find(b'\x00', pos)
        if end < 0:
            end = len(strtab)
        for p in range(start, end + 1):
            string_start[p] = start
        pos = end + 1

    def _full_name(n_offset: int) -> str:
        s = string_start.get(n_offset)
        if s is None:
            return ''
        end = strtab.find(b'\x00', s)
        raw = strtab[s: end if end >= 0 else len(strtab)]
        return raw.decode('utf-8', errors='replace')

    text_scnums: set = {i + 1 for i, s in enumerate(sections) if s.flags & STYP_TEXT}

    result: List[XcoffSymbol] = []
    seen: set = set()
    i = 0
    while i < nsyms:
        off = symptr + i * _SYMENT32_SZ
        if off + _SYMENT32_SZ > len(data):
            break

        name_bytes, value, scnum, _, sclass, numaux = struct.unpack_from(
            _SYMENT32_FMT, data, off
        )

        if sclass in (_C_EXT, _C_HIDEXT) and scnum in text_scnums and value != _XCOFF64_SENTINEL_VA and value != 0:
            if name_bytes[:4] == b'\x00\x00\x00\x00':
                n_offset = struct.unpack_from('>I', name_bytes, 4)[0]
                sym_name = _full_name(n_offset) if n_offset >= 4 else ''
            else:
                sym_name = name_bytes.rstrip(b'\x00').decode('ascii', errors='replace')

            if sym_name and _VALID_LDSYM_NAME.match(sym_name):
                sec_va = sections[scnum - 1].vaddr if scnum - 1 < len(sections) else 0
                code_va = sec_va + value
                key = (sym_name, code_va)
                if key not in seen:
                    seen.add(key)
                    result.append(XcoffSymbol(
                        name=sym_name, va=code_va, lib='', smclas=XMC_PR, code_va=code_va
                    ))

        i += 1 + numaux

    return result


def _merge_symtab64(
    loader_exports: List[XcoffSymbol], syms64: List[XcoffSymbol]
) -> None:
    """Merge main-symtab names into loader-section export list in-place.

    Matches by code_va.  Renames anonymous _sym_N loader entries when a
    matching symtab entry is found.  Appends symtab entries for code VAs
    not tracked by the loader section (internal non-exported functions).
    """
    smap: Dict[int, str] = {s.code_va: s.name for s in syms64 if s.code_va != 0}
    covered: set = {sym.code_va for sym in loader_exports if sym.code_va != 0}

    for sym in loader_exports:
        if sym.code_va != 0 and sym.name.startswith('_sym_') and sym.code_va in smap:
            sym.name = smap[sym.code_va]

    for sym in syms64:
        if sym.code_va not in covered:
            loader_exports.append(sym)


def parse(path: str | Path, data: Optional[bytes] = None) -> XcoffBinary:
    """Parse an XCOFF32 or XCOFF64 binary.

    Args:
        path : path to the XCOFF file (used for error messages and in result)
        data : raw bytes if already read; if None, the file is read from path

    Raises:
        ValueError: if the magic bytes are not 0x01DF or 0x01F7
        struct.error: if the file is truncated
    """
    if data is None:
        data = Path(path).read_bytes()

    if len(data) < _FILE_HDR_SZ:
        raise ValueError(f"file too short ({len(data)} bytes) for XCOFF header")

    magic_raw = struct.unpack_from('>H', data, 0)[0]

    if magic_raw == XCOFF32_MAGIC:
        arch = 'ppc32'
        scnhdr_fmt, scnhdr_sz = _SCNHDR32_FMT, _SCNHDR32_SZ
        file_hdr_sz = _FILE_HDR_SZ
        magic, nscns, timdat, symptr, nsyms, opthdr_sz, flags = struct.unpack_from(
            _FILE_HDR_FMT32, data, 0
        )
    elif magic_raw == XCOFF64_MAGIC:
        arch = 'ppc64'
        scnhdr_fmt, scnhdr_sz = _SCNHDR64_FMT, _SCNHDR64_SZ
        file_hdr_sz = _FILE_HDR_SZ64
        if len(data) < _FILE_HDR_SZ64:
            raise ValueError(f"XCOFF64 file too short ({len(data)} bytes)")
        magic, nscns, timdat, symptr, opthdr_sz, flags, nsyms = struct.unpack_from(
            _FILE_HDR_FMT64, data, 0
        )
    else:
        raise ValueError(f"not an XCOFF binary: magic={magic_raw:#06x} (expected 0x01df or 0x01f7)")

    # Optional header — parse entry, text_start, data_start, toc (XCOFF32 only; .o files skip)
    entry = text_start = data_start = toc_va = 0
    if opthdr_sz >= 28 and len(data) >= file_hdr_sz + 28:
        _, _, _, _, _, entry, text_start, data_start = struct.unpack_from(
            _OPT_HDR32_FMT, data, file_hdr_sz
        )
    if opthdr_sz >= 32 and len(data) >= file_hdr_sz + 32:
        toc_va = struct.unpack_from('>I', data, file_hdr_sz + _OPT_HDR32_TOC_OFF)[0]

    # Section headers
    scn_base = file_hdr_sz + opthdr_sz
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
        if arch == 'ppc64':
            exports, imports = _parse_loader64(loader_data, sections)
        else:
            exports, imports = _parse_loader32(loader_data, sections)
        binary.exports = exports
        binary.imports = imports
        _resolve_descriptors(binary)
    elif arch == 'ppc32' and symptr > 0 and nsyms > 0:
        # Relocatable .o files have no .loader section; fall back to symbol table.
        # C_HIDEXT symbols in .text are code entry points (dotted-name convention).
        binary.exports = _parse_symtab32(data, symptr, nsyms, sections)

    # Supplement XCOFF64 exports with main symbol table names.
    # The loader section names most exports anonymously (_sym_N); C_EXT scnum=1
    # entries in the main symtab carry the real names with direct .text code VAs.
    # After _resolve_descriptors we can match loader exports by code_va.
    if arch == 'ppc64' and symptr > 0 and nsyms > 0:
        syms64 = _parse_symtab64(data, symptr, nsyms, sections)
        if syms64:
            if binary.exports:
                _merge_symtab64(binary.exports, syms64)
            else:
                binary.exports = syms64

    return binary
