"""XCOFF32 symbol table parser — populates BinaryContext with function names.

Why this exists
---------------
1. BinaryContext uses xcoff_parser internally, but its symbol-name feed is
   gated on the .loader section being present and populated.  Many AIX
   firmware binaries (especially executables and stripped shared objects) have
   a full .symtab but an absent, minimal, or incomplete .loader section.
   Without this module, ctx.names_count() returns 0 for those binaries and
   every ctx.name(va) call returns the raw VA address.
2. The RE workflow's "Name everything" requirement (CLAUDE.md) cannot be met
   for XCOFF32 binaries unless a symtab → BinaryContext bridge exists.
3. xcoff_parser._parse_symtab32/_parse_symtab32_exe are parse helpers, not
   analyzers.  They are not exposed through the standard from_context(ctx)
   interface that the RE workflow expects.

What this module adds
---------------------
- Parses the XCOFF32 .symtab for both archive (.o) and executable entry
  points.
- Resolves C_EXT / C_HIDEXT dotted names (.frexp → frexp).
- Calls ctx.set_names_bulk() to populate BinaryContext with all discovered
  function VAs and names.
- Reports how many new names were added and lists the top-VA entries for
  triage.

Gap filled
----------
Gap: stripped XCOFF32 binaries with .symtab but no .loader section returned
SAC=0 function names.  Affects: AIX base executables (automountd, rlogind,
ksh93, etc.) extracted from BFF archives where the loader section was not
included in the compressed entry.

Usage::

    from ablation.analyzers.xcoff_symtab_parser import XcoffSymtabParser
    from ablation.analyzers.binary_context import BinaryContext

    ctx = BinaryContext.load_or_build('/path/to/automountd')
    parser = XcoffSymtabParser.from_context(ctx)
    result = parser.scan()
    print(XcoffSymtabParser.report(result))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ablation.analyzers.binary_context import BinaryContext


# ──────────────────────────────────────────────────────────────
# XCOFF32 symbol table constants (mirrors xcoff_parser.py values)
# ──────────────────────────────────────────────────────────────
_SYMENT32_FMT = '>8sIhHBB'
_SYMENT32_SZ  = 18
_C_EXT        = 2
_C_HIDEXT     = 107
_C_FUN        = 142
_STYP_TEXT    = 0x0020


@dataclass
class XcoffSymtabResult:
    """Output of XcoffSymtabParser.scan()."""
    names_added: int
    """Number of new names populated into BinaryContext."""

    names_already_present: int
    """Number of symbols where ctx already had a name at that VA."""

    symbols: list[tuple[int, str]]
    """All (va, name) pairs found in the symbol table (sorted by va)."""

    error: str = ""
    """Non-empty if parsing failed (e.g. no symbol table in binary)."""


class XcoffSymtabParser:
    """Parse XCOFF32 symbol table and populate BinaryContext with function names.

    Handles both archive-member semantics (symbol value = section-relative offset,
    section base added) and executable semantics (symbol value = absolute VA).
    """

    def __init__(self, ctx: BinaryContext) -> None:
        self._ctx = ctx

    @classmethod
    def from_context(cls, ctx: BinaryContext) -> XcoffSymtabParser:
        """Construct from a loaded BinaryContext."""
        return cls(ctx)

    def scan(self) -> XcoffSymtabResult:
        """Parse the XCOFF32 .symtab and populate BinaryContext.

        Reads the binary from ctx.path, locates the symbol table via the
        XCOFF32 file header (f_symptr, f_nsyms), resolves dotted names and
        code entry VAs, and calls ctx.set_names_bulk().

        Returns
        -------
        XcoffSymtabResult
            Summary of names added and the full symbol list.
        """
        path = getattr(self._ctx, 'path', None)
        if path is None:
            return XcoffSymtabResult(0, 0, [], error="BinaryContext has no path")
        try:
            data = Path(path).read_bytes()
        except OSError as e:
            return XcoffSymtabResult(0, 0, [], error=f"Cannot read {path}: {e}")

        if len(data) < 20:
            return XcoffSymtabResult(0, 0, [], error="File too short for XCOFF32 header")

        magic = struct.unpack_from('>H', data, 0)[0]
        if magic == 0x01df:
            symbols = self._parse_xcoff32(data)
        elif magic == 0x01f7:
            symbols = self._parse_xcoff64(data)
        else:
            return XcoffSymtabResult(
                0, 0, [],
                error=f"Unknown XCOFF magic 0x{magic:04x}; expected 0x01df (32) or 0x01f7 (64)"
            )

        if not symbols:
            return XcoffSymtabResult(0, 0, [], error="No code-entry symbols found in .symtab")

        symbols.sort(key=lambda t: t[0])

        bulk: dict[int, tuple[str, str]] = {}
        already = 0
        for va, name in symbols:
            existing = self._ctx.name(va)
            if existing and not existing.startswith('sub_') and not existing.startswith('0x'):
                already += 1
            else:
                bulk[va] = (name, "xcoff_symtab")

        added = self._ctx.set_names_bulk(bulk)
        return XcoffSymtabResult(
            names_added=added,
            names_already_present=already,
            symbols=symbols,
        )

    def _parse_xcoff32(self, data: bytes) -> list[tuple[int, str]]:
        """Parse XCOFF32 .symtab; return list of (va, name) pairs."""
        if len(data) < 20:
            return []
        _magic, _nscns = struct.unpack_from('>HH', data, 0)
        _timdat, _symptr, _nsyms = struct.unpack_from('>III', data, 4)
        _opthdr, _flags = struct.unpack_from('>HH', data, 16)
        symptr, nsyms = _symptr, _nsyms

        if symptr == 0 or nsyms == 0:
            return []

        # Read string table
        strtab_off = symptr + nsyms * _SYMENT32_SZ
        strtab = b''
        if strtab_off + 4 <= len(data):
            stlen = struct.unpack_from('>I', data, strtab_off)[0]
            strtab = data[strtab_off: strtab_off + stlen]

        # Build section VA map: section_number(1-based) → vaddr
        hdr_size = 20 + _opthdr
        sec_va: dict[int, int] = {}
        for sn in range(_nscns):
            off = hdr_size + sn * 40
            if off + 40 > len(data):
                break
            raw_name = data[off:off+8].rstrip(b'\x00')
            s_vaddr = struct.unpack_from('>I', data, off + 12)[0]
            s_flags = struct.unpack_from('>H', data, off + 36)[0]
            if s_flags & _STYP_TEXT:
                sec_va[sn + 1] = s_vaddr

        result: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()
        i = 0
        while i < nsyms:
            off = symptr + i * _SYMENT32_SZ
            if off + _SYMENT32_SZ > len(data):
                break
            name_bytes, value, scnum, _typ, sclass, numaux = struct.unpack_from(
                _SYMENT32_FMT, data, off
            )
            if name_bytes[:4] == b'\x00\x00\x00\x00':
                stoff = struct.unpack_from('>I', name_bytes, 4)[0]
                raw = strtab[stoff: stoff + 128].split(b'\x00')[0] if stoff < len(strtab) else b''
            else:
                raw = name_bytes.rstrip(b'\x00')
            sym_name = raw.decode('ascii', errors='replace')

            if sclass in (_C_EXT, _C_HIDEXT) and scnum > 0:
                if scnum in sec_va and sym_name.startswith('.'):
                    clean = sym_name[1:]
                    if clean:
                        va = sec_va[scnum] + value
                        key = (va, clean)
                        if key not in seen:
                            seen.add(key)
                            result.append((va, clean))
                elif scnum in sec_va and sym_name:
                    va = sec_va[scnum] + value
                    key = (va, sym_name)
                    if key not in seen:
                        seen.add(key)
                        result.append((va, sym_name))

            i += 1 + numaux

        if not result and sec_va:
            # Executable: all text-section symbols regardless of dotted prefix.
            i = 0
            while i < nsyms:
                off = symptr + i * _SYMENT32_SZ
                if off + _SYMENT32_SZ > len(data):
                    break
                name_bytes, value, scnum, _typ, sclass, numaux = struct.unpack_from(
                    _SYMENT32_FMT, data, off
                )
                if name_bytes[:4] == b'\x00\x00\x00\x00':
                    stoff = struct.unpack_from('>I', name_bytes, 4)[0]
                    raw = strtab[stoff: stoff + 128].split(b'\x00')[0] if stoff < len(strtab) else b''
                else:
                    raw = name_bytes.rstrip(b'\x00')
                sym_name = raw.decode('ascii', errors='replace')
                if sclass in (_C_EXT, _C_HIDEXT) and scnum > 0 and scnum in sec_va and sym_name:
                    va = sec_va[scnum] + value
                    key = (va, sym_name)
                    if key not in seen:
                        seen.add(key)
                        result.append((va, sym_name))
                i += 1 + numaux

        return result

    def _parse_xcoff64(self, data: bytes) -> list[tuple[int, str]]:
        """Parse XCOFF64 .symtab; return list of (va, name) pairs."""
        if len(data) < 24:
            return []
        _magic, _nscns = struct.unpack_from('>HH', data, 0)
        _timdat = struct.unpack_from('>I', data, 4)[0]
        _symptr = struct.unpack_from('>Q', data, 8)[0]
        _nsyms = struct.unpack_from('>I', data, 16)[0]
        _opthdr, _flags = struct.unpack_from('>HH', data, 20)
        if _symptr == 0 or _nsyms == 0:
            return []

        SYMENT64_SZ = 24
        strtab_off = _symptr + _nsyms * SYMENT64_SZ
        strtab = b''
        if strtab_off + 4 <= len(data):
            stlen = struct.unpack_from('>I', data, strtab_off)[0]
            strtab = data[strtab_off: strtab_off + stlen]

        hdr_size = 24 + _opthdr
        sec_va: dict[int, int] = {}
        for sn in range(_nscns):
            off = hdr_size + sn * 72
            if off + 72 > len(data):
                break
            s_vaddr = struct.unpack_from('>Q', data, off + 16)[0]
            # flags at offset 64: name(8)+paddr(8)+vaddr(8)+size(8)+scnptr(8)+relptr(8)+lnnoptr(8)+nreloc(4)+nlnno(4)=64
            s_flags = struct.unpack_from('>I', data, off + 64)[0]
            if s_flags & _STYP_TEXT:
                sec_va[sn + 1] = s_vaddr

        result: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()
        i = 0
        while i < _nsyms:
            off = _symptr + i * SYMENT64_SZ
            if off + SYMENT64_SZ > len(data):
                break
            n_value = struct.unpack_from('>Q', data, off)[0]
            stoff = struct.unpack_from('>I', data, off + 8)[0]
            n_scnum = struct.unpack_from('>h', data, off + 12)[0]
            n_sclass = data[off + 22]
            n_numaux = data[off + 23]

            raw = strtab[stoff: stoff + 128].split(b'\x00')[0] if stoff < len(strtab) else b''
            sym_name = raw.decode('ascii', errors='replace')

            if n_sclass in (_C_EXT, _C_HIDEXT) and n_scnum > 0 and n_scnum in sec_va and sym_name:
                clean = sym_name.lstrip('.')
                if clean:
                    key = (int(n_value), clean)
                    if key not in seen:
                        seen.add(key)
                        result.append((int(n_value), clean))
            i += 1 + n_numaux

        return result

    @staticmethod
    def report(result: XcoffSymtabResult) -> str:
        """Format a human-readable scan summary."""
        if result.error:
            return f"XcoffSymtabParser: ERROR — {result.error}"
        lines = [
            f"XcoffSymtabParser: {result.names_added} names added, "
            f"{result.names_already_present} already present, "
            f"{len(result.symbols)} total symbols in .symtab"
        ]
        if result.symbols:
            lines.append("  Top symbols by VA:")
            for va, name in result.symbols[:20]:
                lines.append(f"    0x{va:08x}  {name}")
            if len(result.symbols) > 20:
                lines.append(f"    ... ({len(result.symbols) - 20} more)")
        return '\n'.join(lines)
