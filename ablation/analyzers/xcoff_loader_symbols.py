"""XCOFF32/64 loader symbol standalone resolver.

Provides a quick loader-symbol lookup without requiring BinaryContext or a
full xcoff_parser.parse() call. Useful for ad-hoc session scripts and for
resolving a single binary in isolation.

Why this exists
---------------
1. The VIOS ioscli analysis required two attempts to parse loader symbols
   correctly because the XCOFF32 LDSYM struct has the name field first
   (8 bytes), then l_value, not the other way around. A standalone resolver
   with the correct layout documented prevents this mistake on every new
   AIX target.
2. xcoff_parser.parse() loads the entire binary including descriptor
   resolution and symbol table merging. For a quick "what does this symbol
   map to" check during a session, the overhead is unnecessary.
3. XCOFF64 loader symbols use a different struct layout (name strtab index
   is 4 bytes, not 8 inline bytes). Both formats are handled by one function
   with explicit layout comments so the caller does not need to remember which
   format applies.

Usage::

    from ablation.analyzers.xcoff_loader_symbols import loader_symbols, loader_imports

    # Quick symbol lookup from raw binary bytes
    with open('/path/to/ioscli', 'rb') as f:
        data = f.read()
    syms = loader_symbols(data)
    for name, va in sorted(syms.items()):
        print(f'{name}  {va:#010x}')

    # Imports only
    imps = loader_imports(data)  # {lib_name: [symbol_name, ...]}
"""
from __future__ import annotations

import re
import struct
from typing import Dict, List, Optional, Tuple

# XCOFF32 magic bytes
_XCOFF32_MAGIC = 0x01DF

# XCOFF64 magic bytes
_XCOFF64_MAGIC     = 0x01F7
_XCOFF64_MAGIC_ALT = 0x01EF

# XCOFF32 LDSYM entry is 24 bytes:
#   name[8]      -- inline if len<=8, else (0x00000000, strtab_offset) in bytes 4-7
#   l_value  [4] -- descriptor VA (exports) or 0 (imports)
#   l_scnum  [2] -- section number
#   l_smtype [1]
#   l_smclas [1]
#   l_ifile  [4] -- import library index
#   l_parm   [4]
_LDSYM32_SZ = 24

# XCOFF64 LDSYM entry is 32 bytes:
#   l_value  [8] -- VA
#   l_scnum  [2]
#   l_smtype [1]
#   l_smclas [1]
#   l_ifile  [4]
#   l_parm   [4]
#   l_name   [4] -- offset into loader strtab (always uses strtab)
#   pad      [8]
_LDSYM64_SZ = 32

_VALID_NAME = re.compile(r'^[A-Za-z_.@$][A-Za-z0-9_.@$]*$')


def _read_u32be(data: bytes, off: int) -> int:
    return struct.unpack_from('>I', data, off)[0]


def _read_u64be(data: bytes, off: int) -> int:
    return struct.unpack_from('>Q', data, off)[0]


def _read_u16be(data: bytes, off: int) -> int:
    return struct.unpack_from('>H', data, off)[0]


def _read_u16le(data: bytes, off: int) -> int:
    return struct.unpack_from('<H', data, off)[0]


def _loader_section_offset(data: bytes) -> Optional[int]:
    """Return the file offset of the .loader section, or None."""
    if len(data) < 20:
        return None
    magic = _read_u16be(data, 0)
    if magic not in (_XCOFF32_MAGIC, _XCOFF64_MAGIC, _XCOFF64_MAGIC_ALT):
        return None

    is64 = (magic != _XCOFF32_MAGIC)

    nscns   = _read_u16be(data, 2)
    opthdr  = _read_u16be(data, 16 if not is64 else 16)

    # XCOFF32 file header: 20 bytes; XCOFF64 file header: 24 bytes
    fhdr_sz = 20 if not is64 else 24
    scn_off = fhdr_sz + opthdr
    scn_ent = 40 if not is64 else 72

    # STYP_LOADER = 0x1000
    STYP_LOADER = 0x1000

    for i in range(nscns):
        base = scn_off + i * scn_ent
        if not is64:
            flags   = _read_u32be(data, base + 36)
            sec_off = _read_u32be(data, base + 16)
        else:
            flags   = _read_u32be(data, base + 68)
            sec_off = _read_u64be(data, base + 24)

        if flags & STYP_LOADER:
            return int(sec_off)

    return None


def loader_symbols(data: bytes) -> Dict[str, int]:
    """Return a dict mapping export symbol name to code VA.

    Reads the loader section from raw XCOFF32 or XCOFF64 binary bytes.
    Skips symbols with invalid names or zero VA.

    Args:
        data: Raw bytes of the XCOFF binary.

    Returns:
        Dict of {symbol_name: va}. VA is the descriptor VA for ppc32 (use
        xcoff_parser if you need code_va after descriptor resolution).
    """
    ldr_off = _loader_section_offset(data)
    if ldr_off is None:
        return {}

    magic = _read_u16be(data, 0)
    is64  = (magic != _XCOFF32_MAGIC)

    ldr = data[ldr_off:]
    if len(ldr) < 32:
        return {}

    # Loader section header (same layout for 32 and 64):
    # l_version(4) l_nsyms(4) l_nreloc(4) l_istlen(4) l_nimpid(4) l_impoff(4) l_stlen(4) l_stoff(4)
    (l_version, l_nsyms, _l_nreloc, _l_istlen,
     _l_nimpid, _l_impoff, l_stlen, l_stoff) = struct.unpack_from('>IIIIIIII', ldr, 0)

    strtab = ldr[l_stoff:l_stoff + l_stlen] if l_stlen else b''
    sym_base = 32  # loader header is 32 bytes

    result: Dict[str, int] = {}

    for i in range(l_nsyms):
        soff = sym_base + i * (_LDSYM64_SZ if is64 else _LDSYM32_SZ)
        if soff + _LDSYM32_SZ > len(ldr):
            break

        if not is64:
            # XCOFF32: name[8] then l_value[4]
            name8 = ldr[soff:soff + 8]
            l_value = _read_u32be(ldr, soff + 8)
            l_ifile = _read_u32be(ldr, soff + 16)

            if name8[:4] == b'\x00\x00\x00\x00':
                noff = _read_u32be(name8, 4)
                try:
                    end = strtab.index(b'\x00', noff)
                    sname = strtab[noff:end].decode('ascii', errors='replace')
                except (ValueError, IndexError):
                    continue
            else:
                try:
                    end = name8.index(b'\x00')
                    sname = name8[:end].decode('ascii', errors='replace')
                except ValueError:
                    sname = name8.rstrip(b'\x00').decode('ascii', errors='replace')
        else:
            # XCOFF64: l_value[8] then l_scnum[2] l_smtype[1] l_smclas[1] l_ifile[4] l_parm[4] l_name[4]
            l_value = _read_u64be(ldr, soff)
            l_ifile = _read_u32be(ldr, soff + 16)
            noff    = _read_u32be(ldr, soff + 24)
            try:
                end = strtab.index(b'\x00', noff)
                sname = strtab[noff:end].decode('ascii', errors='replace')
            except (ValueError, IndexError):
                continue

        if not sname or not _VALID_NAME.match(sname):
            continue
        if l_ifile > 0:
            # import: l_ifile points into import strtab, l_value is 0
            continue
        if l_value == 0:
            continue

        result[sname] = l_value

    return result


def loader_imports(data: bytes) -> Dict[str, List[str]]:
    """Return a dict mapping library name to list of imported symbol names.

    Args:
        data: Raw bytes of the XCOFF binary.

    Returns:
        Dict of {lib_name: [symbol_name, ...]}.
    """
    ldr_off = _loader_section_offset(data)
    if ldr_off is None:
        return {}

    magic = _read_u16be(data, 0)
    is64  = (magic != _XCOFF32_MAGIC)

    ldr = data[ldr_off:]
    if len(ldr) < 32:
        return {}

    (l_version, l_nsyms, _l_nreloc, l_istlen,
     l_nimpid, l_impoff, l_stlen, l_stoff) = struct.unpack_from('>IIIIIIII', ldr, 0)

    strtab = ldr[l_stoff:l_stoff + l_stlen] if l_stlen else b''
    sym_base = 32

    # Parse import file table: null-separated strings at l_impoff, l_istlen bytes.
    # Each "import file" is a triplet: base-lib-name, path, member.
    imp_strtab = ldr[l_impoff:l_impoff + l_istlen]
    lib_names: List[str] = ['']   # index 0 = this file itself
    pos = 0
    while pos < len(imp_strtab):
        parts: List[str] = []
        for _ in range(3):
            end = imp_strtab.find(b'\x00', pos)
            if end == -1:
                break
            parts.append(imp_strtab[pos:end].decode('ascii', errors='replace'))
            pos = end + 1
        if len(parts) == 3:
            lib_names.append(parts[0] or parts[2] or '<unknown>')
        elif parts:
            lib_names.append(parts[0] or '<unknown>')

    result: Dict[str, List[str]] = {}

    for i in range(l_nsyms):
        soff = sym_base + i * (_LDSYM64_SZ if is64 else _LDSYM32_SZ)
        if soff + _LDSYM32_SZ > len(ldr):
            break

        if not is64:
            name8 = ldr[soff:soff + 8]
            l_value = _read_u32be(ldr, soff + 8)
            l_ifile = _read_u32be(ldr, soff + 16)

            if name8[:4] == b'\x00\x00\x00\x00':
                noff = _read_u32be(name8, 4)
                try:
                    end = strtab.index(b'\x00', noff)
                    sname = strtab[noff:end].decode('ascii', errors='replace')
                except (ValueError, IndexError):
                    continue
            else:
                sname = name8.rstrip(b'\x00').decode('ascii', errors='replace')
        else:
            l_ifile = _read_u32be(ldr, soff + 16)
            noff    = _read_u32be(ldr, soff + 24)
            try:
                end = strtab.index(b'\x00', noff)
                sname = strtab[noff:end].decode('ascii', errors='replace')
            except (ValueError, IndexError):
                continue

        if l_ifile == 0:
            continue   # skip exports
        if not sname or not _VALID_NAME.match(sname):
            continue

        lib = lib_names[l_ifile] if l_ifile < len(lib_names) else f'lib#{l_ifile}'
        result.setdefault(lib, []).append(sname)

    return result
