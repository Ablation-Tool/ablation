"""
aix_bff_extractor.py: AIX installp BFF (Backup File Format) XCOFF extractor.

Why this exists (CSMSAMRD-GAP-002 trigger):
  AIX software packages distributed as installp archives embed XCOFF32/XCOFF64
  binaries at arbitrary offsets within the BFF container.  No standard Linux
  tool can extract them: pax(1) requires AIX, restore(8) requires AIX tape
  devices, GNU tar does not understand the BFF container format.

  This module finds every XCOFF binary in a BFF archive (or any arbitrary blob)
  by scanning for XCOFF magic bytes, validating the FILHDR, and computing the
  precise file extent from section headers + symbol table.  It also parses the
  XCOFF32 loader section to enumerate imported library functions, enabling
  dangerous-import triage without an AIX environment.

Relationship to aix_big_ar_extractor.py:
  aix_big_ar_extractor.py handles the AIX <bigaf> library archive format
  (shared libraries like libc.a distributed as big archives).  This module
  handles the AIX installp BFF package format — a different container.
  Both formats embed XCOFF binaries; only the outer envelope differs.

AIX BFF format:
  BFF is the AIX backup/restore stream format used by installp.  The outer
  container has a 512-byte block structure with magic 0x09006bea.  Rather than
  parsing the outer envelope (which requires AIX-specific installp metadata),
  this module uses magic-scan extraction: locate XCOFF magic words at 4-byte-
  aligned offsets, validate the XCOFF FILHDR, compute the binary extent from
  section data + symbol table, and return the raw XCOFF bytes.

XCOFF32 loader section (v1) layout:
  Header (32 bytes):
    l_version  4  l_nsyms   4  l_nreloc  4  l_istlen 4
    l_nimpid   4  l_impoff  4  l_stlen   4  l_stoff  4
  Symbol table:  l_nsyms × 24 bytes  (immediately after header)
  Reloc table:   l_nreloc × 12 bytes
  Import ID table at l_impoff (null-separated path/archive/member strings)
  String table:  l_stlen bytes at l_stoff (from start of loader section)

  Loader symbol name: first 4 bytes (l_zeroes) == 0 → name is at
    loader_string_table[l_offset].  Otherwise the 8-byte field IS the name.

Usage:
    from ablation.analyzers.aix_bff_extractor import AixBffExtractor, XCOFF32Info

    # Scan a .bff file and extract all embedded XCOFF binaries
    for name, xcoff_bytes in AixBffExtractor.from_path('/path/to/pkg.bff'):
        info = XCOFF32Info(xcoff_bytes)
        print(f'{name}: {info.nsyms} symbols, imports={info.dangerous_imports()}')
        info.save(f'/tmp/{name}')

    # Find call-stub VAs for dangerous imports in an already-extracted XCOFF32
    info = XCOFF32Info.from_path('/tmp/IBM.RecoveryRMd.aix')
    stubs = info.import_stubs()         # {'.system': 0x10143d74, ...}
    callers = info.callers_of(stubs['.system'])  # [0x10140e44, ...]
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

# Existing Ablation infrastructure this module builds on:
#   ablation.core.bff_extractor  — proper BFF container parsing (iter_entries)
#   ablation.core.xcoff_parser   — XCOFF32/64 header, sections, imports list
# This module adds the missing pieces:
#   AixBffExtractor — one-shot "BFF → XCOFF binaries" pipeline
#   XCOFF32Info     — import stub VA resolution + caller enumeration
#                     (xcoff_parser gives imports but stub VAs are 0x0)

_BFF_OK = False
try:
    from ablation.core.bff_extractor import iter_entries as _iter_bff_entries
    _BFF_OK = True
except ImportError:
    pass

_XCOFF_PARSER_OK = False
try:
    from ablation.core.xcoff_parser import parse as _xcoff_parse
    _XCOFF_PARSER_OK = True
except ImportError:
    pass

# ── XCOFF magic constants ─────────────────────────────────────────────────────

XCOFF32_MAGIC = 0x01DF
XCOFF64_MAGIC = 0x01F7

# COFF symbol storage classes
_C_EXT     = 2    # external definition
_C_STAT    = 3    # static
_C_WEAKEXT = 111  # weak external

# COFF section numbers
_TEXT_SCNUM = 1

# AIX stub pattern: stw r2, 0x14(r1) — the second instruction of every AIX
# external-call stub.  Paired with lwz r12, N(r2) immediately before it.
_STUB_STW_R2  = struct.pack('>I', 0x90410014)   # stw r2, 0x14(r1)
_LWZ_R12_MASK = 0xFFFF0000
_LWZ_R12_OP   = 0x81820000   # lwz r12, N(r2)  (rD=12=0xC, rA=2)

# Default set of dangerous imported functions to search for
_DEFAULT_DANGEROUS: frozenset = frozenset({
    'system', 'popen', 'execv', 'execve', 'execvp',
    'execl', 'execlp', 'execle',
})

# Dot-prefixed stub names (COFF symbol table entries for external stubs)
_DEFAULT_STUB_NAMES: frozenset = frozenset(
    f'.{fn}' for fn in _DEFAULT_DANGEROUS
)


# ── XCOFF32 section header ────────────────────────────────────────────────────

@dataclass
class XCOFF32Section:
    name:   str
    vaddr:  int
    size:   int
    foff:   int   # file offset within the XCOFF32 binary
    flags:  int

    def contains_va(self, va: int) -> bool:
        return self.vaddr <= va < self.vaddr + self.size

    def va_to_foff(self, va: int) -> int:
        return self.foff + (va - self.vaddr)


# ── XCOFF32 info object ───────────────────────────────────────────────────────

class XCOFF32Info:
    """
    Parse an XCOFF32 (AIX PPC32) binary.

    Provides section layout, loader-section import enumeration, and
    COFF/stub-pattern based import-stub VA resolution.
    """

    def __init__(self, data: bytes) -> None:
        if len(data) < 20:
            raise ValueError('Data too short for XCOFF32 FILHDR')
        magic = struct.unpack('>H', data[0:2])[0]
        if magic != XCOFF32_MAGIC:
            raise ValueError(f'Not XCOFF32: magic=0x{magic:04x}')
        self._data   = data
        self._nscns  = struct.unpack('>H', data[2:4])[0]
        self._symptr = struct.unpack('>I', data[8:12])[0]
        self._nsyms  = struct.unpack('>i', data[12:16])[0]  # signed
        self._opthdr = struct.unpack('>H', data[16:18])[0]
        self._flags  = struct.unpack('>H', data[18:20])[0]
        self._sections: Optional[Dict[str, XCOFF32Section]] = None
        self._stubs_cache: Optional[Dict[str, int]] = None

    @classmethod
    def from_path(cls, path: str) -> 'XCOFF32Info':
        return cls(Path(path).read_bytes())

    # ── identity ──────────────────────────────────────────────────────────────

    @property
    def nsyms(self) -> int:
        return max(0, self._nsyms)

    @property
    def nscns(self) -> int:
        return self._nscns

    @property
    def o_toc(self) -> int:
        """TOC base address (r2 at program start), from AOUTHDR offset 28."""
        if self._opthdr < 32:
            return 0
        return struct.unpack('>I', self._data[48:52])[0]

    # ── sections ──────────────────────────────────────────────────────────────

    @property
    def sections(self) -> Dict[str, XCOFF32Section]:
        if self._sections is None:
            self._sections = self._parse_sections()
        return self._sections

    def _parse_sections(self) -> Dict[str, XCOFF32Section]:
        secs: Dict[str, XCOFF32Section] = {}
        base = 20 + self._opthdr
        for i in range(self._nscns):
            off = base + i * 40
            sh = self._data[off:off + 40]
            if len(sh) < 40:
                break
            name  = sh[:8].rstrip(b'\x00').decode('ascii', errors='replace')
            vaddr = struct.unpack('>I', sh[12:16])[0]
            size  = struct.unpack('>I', sh[16:20])[0]
            foff  = struct.unpack('>I', sh[20:24])[0]
            flags = struct.unpack('>I', sh[36:40])[0]
            secs[name] = XCOFF32Section(name=name, vaddr=vaddr, size=size,
                                        foff=foff, flags=flags)
        return secs

    # ── string table ─────────────────────────────────────────────────────────

    @property
    def _strtab_off(self) -> int:
        """File offset of the COFF string table (follows symbol table)."""
        if self._symptr <= 0 or self._nsyms <= 0:
            return 0
        return self._symptr + self._nsyms * 18

    def _coff_name(self, sym18: bytes) -> str:
        """Resolve an 8-byte COFF symbol name field (inline or string-table)."""
        l_zeroes = struct.unpack('>I', sym18[0:4])[0]
        if l_zeroes:
            return sym18[0:8].rstrip(b'\x00').decode('ascii', errors='replace')
        l_off = struct.unpack('>I', sym18[4:8])[0]
        sto = self._strtab_off
        if sto and sto + l_off < len(self._data):
            return (self._data[sto + l_off:]
                    .split(b'\x00', 1)[0]
                    .decode('ascii', errors='replace'))
        return ''

    # ── loader section imports ────────────────────────────────────────────────

    def dangerous_imports(
        self, targets: Optional[frozenset] = None
    ) -> Dict[str, Dict]:
        """
        Return {func_name: {'ifile': N, 'lib': 'libc.a/shr.o'}} for each
        dangerous function imported from a shared library.

        Delegates to ablation.core.xcoff_parser when available (authoritative).
        Falls back to direct XCOFF32 loader section parsing when xcoff_parser
        is unavailable.
        """
        if targets is None:
            targets = _DEFAULT_DANGEROUS

        # Primary path: xcoff_parser provides the correct import list
        if _XCOFF_PARSER_OK:
            try:
                import tempfile, os
                fd, tmp = tempfile.mkstemp(suffix='.xcoff32')
                try:
                    os.write(fd, self._data)
                    os.close(fd)
                    xb = _xcoff_parse(tmp)
                finally:
                    try: os.unlink(tmp)
                    except OSError: pass
                return {
                    sym.name: {'ifile': -1, 'lib': sym.lib}
                    for sym in xb.imports
                    if sym.name in targets
                }
            except Exception:
                pass  # fall through to manual parse

        # Fallback: manual loader section parse
        found: Dict[str, Dict] = {}
        ls = self.sections.get('.loader')
        if ls and ls.foff and ls.size >= 32:
            found = self._loader_imports(ls, targets)
        return found

    def _loader_imports(
        self, ls: XCOFF32Section, targets: frozenset
    ) -> Dict[str, Dict]:
        lo = ls.foff
        hdr = self._data[lo:lo + 32]
        if len(hdr) < 32:
            return {}
        # XCOFF loader v1 header
        n_lsyms = struct.unpack('>I', hdr[4:8])[0]
        istlen  = struct.unpack('>I', hdr[12:16])[0]
        nimpid  = struct.unpack('>I', hdr[16:20])[0]
        impoff  = struct.unpack('>I', hdr[20:24])[0]
        stlen   = struct.unpack('>I', hdr[24:28])[0]
        stoff   = struct.unpack('>I', hdr[28:32])[0]

        # Import library strings (null-separated: path\0archive\0member\0...)
        imp_raw = self._data[lo + impoff: lo + impoff + istlen]
        libs = [s.decode('ascii', 'replace')
                for s in imp_raw.split(b'\x00') if s]

        # Loader symbol table starts at header_size=32, before reloc table
        lsym_base = lo + 32
        found: Dict[str, Dict] = {}
        for k in range(n_lsyms):
            lsym = self._data[lsym_base + k * 24: lsym_base + k * 24 + 24]
            if len(lsym) < 24:
                break
            l_z = struct.unpack('>I', lsym[0:4])[0]
            lifile = struct.unpack('>I', lsym[16:20])[0]
            if l_z:
                lname = lsym[0:8].rstrip(b'\x00').decode('ascii', 'replace')
            else:
                l_offset = struct.unpack('>I', lsym[4:8])[0]
                str_abs = lo + stoff + l_offset
                if str_abs < len(self._data):
                    lname = (self._data[str_abs:]
                             .split(b'\x00', 1)[0]
                             .decode('ascii', 'replace'))
                else:
                    lname = ''
            if lname in targets:
                lib_str = libs[lifile - 1] if 0 < lifile <= len(libs) else ''
                found[lname] = {'ifile': lifile, 'lib': lib_str}
        return found

    # ── import stub resolution ────────────────────────────────────────────────

    def import_stubs(
        self, targets: Optional[frozenset] = None
    ) -> Dict[str, int]:
        """
        Return {'.system': va, '.popen': va, ...} for each external call stub
        found in the .text section.

        Two complementary methods:
          1. COFF symbol table scan: dot-prefixed entries (.system, .popen)
             with TEXT_SCNUM and C_EXT/C_WEAKEXT storage class.
          2. AIX stub pattern scan: lwz r12, N(r2) immediately before
             stw r2, 0x14(r1) — the canonical AIX external-call stub header.
             Cross-referenced against loader imports to assign names.
        """
        if self._stubs_cache is not None:
            return self._stubs_cache

        if targets is None:
            targets = _DEFAULT_STUB_NAMES

        stubs: Dict[str, int] = {}

        # Method 1: COFF symbol table
        stubs.update(self._stubs_from_symtab(targets))

        # Method 2: stub pattern scan (fills gaps when symbol names are long
        # and stored only in the string table, which may be truncated)
        if len(stubs) < len(targets):
            stubs.update(self._stubs_from_pattern(targets, stubs))

        self._stubs_cache = stubs
        return stubs

    def _stubs_from_symtab(self, targets: frozenset) -> Dict[str, int]:
        if self._symptr <= 0 or self._nsyms <= 0:
            return {}
        found: Dict[str, int] = {}
        i = 0
        soff = self._symptr
        while i < self._nsyms and soff + 18 <= len(self._data):
            sym18 = self._data[soff: soff + 18]
            name   = self._coff_name(sym18)
            value  = struct.unpack('>I', sym18[8:12])[0]
            scnum  = struct.unpack('>h', sym18[12:14])[0]
            sclass = sym18[16]
            numaux = sym18[17]
            if (scnum == _TEXT_SCNUM
                    and sclass in (_C_EXT, _C_WEAKEXT, _C_STAT)
                    and name in targets):
                found[name] = value
            i += 1 + numaux
            soff += 18 * (1 + numaux)
        return found

    def _stubs_from_pattern(
        self, targets: frozenset, already_found: Dict[str, int]
    ) -> Dict[str, int]:
        """
        Find AIX external-call stubs by pattern, then match to loader imports
        via TOC slot lookup.

        AIX PPC32 external-call stub layout (24 bytes):
          lwz  r12, N(r2)      ; load function descriptor pointer from TOC
          stw  r2,  0x14(r1)   ; save caller's TOC (r2) on stack
          lwz  r0,  0(r12)     ; load entry point from descriptor
          lwz  r2,  4(r12)     ; load callee's TOC from descriptor
          mtctr r0
          bctr

        The TOC slot offset N encodes which function is being called.
        Cross-referenced against the XCOFF loader symbol table.
        """
        txt = self.sections.get('.text')
        if not txt or not txt.foff:
            return {}
        text_data = self._data[txt.foff: txt.foff + txt.size]
        text_va   = txt.vaddr

        # Collect all stubs: (stub_va, toc_signed_offset)
        all_stubs: List[Tuple[int, int]] = []
        for i in range(4, len(text_data) - 4, 4):
            if text_data[i: i + 4] == _STUB_STW_R2:
                prev = struct.unpack('>I', text_data[i - 4: i])[0]
                if (prev & _LWZ_R12_MASK) == _LWZ_R12_OP:
                    toc_disp = prev & 0xFFFF
                    # Sign-extend 16-bit displacement
                    if toc_disp >= 0x8000:
                        toc_disp -= 0x10000
                    stub_va = text_va + i - 4
                    all_stubs.append((stub_va, toc_disp))

        if not all_stubs:
            return {}

        # Build TOC-slot-VA → loader symbol name mapping
        o_toc = self.o_toc
        ls = self.sections.get('.loader')
        if not ls or not ls.foff or not o_toc:
            return {}

        lo = ls.foff
        hdr = self._data[lo: lo + 32]
        if len(hdr) < 32:
            return {}
        n_lsyms = struct.unpack('>I', hdr[4:8])[0]
        n_lrel  = struct.unpack('>I', hdr[8:12])[0]
        istlen  = struct.unpack('>I', hdr[12:16])[0]
        impoff  = struct.unpack('>I', hdr[20:24])[0]
        stoff   = struct.unpack('>I', hdr[28:32])[0]

        imp_raw = self._data[lo + impoff: lo + impoff + istlen]
        libs = [s.decode('ascii', 'replace') for s in imp_raw.split(b'\x00') if s]

        # TOC slot VA → loader sym name (for linked binaries where lval != 0)
        toc_slot_to_name: Dict[int, str] = {}
        lsym_base = lo + 32
        for k in range(n_lsyms):
            lsym = self._data[lsym_base + k * 24: lsym_base + k * 24 + 24]
            if len(lsym) < 24:
                break
            l_z    = struct.unpack('>I', lsym[0:4])[0]
            lval   = struct.unpack('>I', lsym[8:12])[0]   # TOC slot VA (0 = unresolved)
            if l_z:
                lname = lsym[0:8].rstrip(b'\x00').decode('ascii', 'replace')
            else:
                l_offset = struct.unpack('>I', lsym[4:8])[0]
                str_abs = lo + stoff + l_offset
                lname = (self._data[str_abs:].split(b'\x00', 1)[0]
                         .decode('ascii', 'replace') if str_abs < len(self._data) else '')
            if lval:
                toc_slot_to_name[lval] = lname

        # Count leading non-function (non-XMC_GL) LDSYM entries.  In XCOFF32
        # static binaries the table begins with runtime symbols (___bzero,
        # ___memmove, errno, …) whose l_smclas != XMC_GL (0x0a).  The LDREL
        # l_symndx is absolute from the start of LDSYM (including those), so we
        # subtract n_prefix before the name lookup to get the true import index.
        _XMC_GL = 0x0a
        n_prefix = 0
        for k in range(n_lsyms):
            lsym_k = self._data[lsym_base + k * 24: lsym_base + k * 24 + 24]
            if len(lsym_k) < 24:
                break
            if lsym_k[15] == _XMC_GL:
                break
            n_prefix += 1

        # LDREL-based TOC disp → name mapping (XCOFF32-GAP-001 fix).
        # Each loader relocation record maps a .data VA (= the TOC slot) to the
        # loader symbol that fills it.  When lval=0 for all LDSYM entries (static
        # XCOFF32), this is the only authoritative source for toc_disp→name.
        # l_symndx is absolute (includes the n_prefix runtime/data entries), so
        # subtract n_prefix to get the true import-function index.
        ldrel_toc_to_name: Dict[int, str] = {}
        lrel_base = lo + 32 + n_lsyms * 24
        for k in range(n_lrel):
            lrel = self._data[lrel_base + k * 12: lrel_base + k * 12 + 12]
            if len(lrel) < 12:
                break
            l_vaddr  = struct.unpack('>I', lrel[0:4])[0]
            l_symndx = struct.unpack('>i', lrel[4:8])[0]
            true_idx = l_symndx - n_prefix
            if 0 <= true_idx < n_lsyms:
                lsym2 = self._data[lsym_base + true_idx * 24: lsym_base + true_idx * 24 + 24]
                if len(lsym2) < 24:
                    continue
                if lsym2[15] != _XMC_GL:          # skip data/runtime entries
                    continue
                l_z2 = struct.unpack('>I', lsym2[0:4])[0]
                if l_z2:
                    lname2 = lsym2[0:8].rstrip(b'\x00').decode('ascii', 'replace')
                else:
                    l_off2 = struct.unpack('>I', lsym2[4:8])[0]
                    str_abs2 = lo + stoff + l_off2
                    lname2 = (self._data[str_abs2:].split(b'\x00', 1)[0]
                              .decode('ascii', 'replace') if str_abs2 < len(self._data) else '')
                toc_disp_ldrel = l_vaddr - o_toc
                ldrel_toc_to_name[toc_disp_ldrel] = lname2

        # Match stubs to names: lval-based first, LDREL-based as fallback.
        found: Dict[str, int] = {}
        for stub_va, toc_disp in all_stubs:
            slot_va = o_toc + toc_disp
            lname = toc_slot_to_name.get(slot_va) or ldrel_toc_to_name.get(toc_disp, '')
            dot_name = f'.{lname}' if lname else ''
            if dot_name in targets and dot_name not in already_found:
                found[dot_name] = stub_va

        return found

    # ── caller enumeration ────────────────────────────────────────────────────

    def callers_of(self, stub_va: int) -> List[int]:
        """
        Return all VAs of bl instructions in .text that call stub_va.

        Uses the PPC32 BL (branch-and-link) instruction encoding:
          [26:31] = 18 (opcode), [1] = AA=0 (relative), [0] = LK=1 (link)
          li field [2:25] = signed 24-bit offset >> 2
        """
        txt = self.sections.get('.text')
        if not txt or not txt.foff:
            return []
        text_data = self._data[txt.foff: txt.foff + txt.size]
        text_va   = txt.vaddr
        callers: List[int] = []
        for off in range(0, len(text_data) - 3, 4):
            word = struct.unpack('>I', text_data[off: off + 4])[0]
            if (word >> 26) == 18 and (word & 3) == 1:  # bl, AA=0, LK=1
                li = word & 0x3FFFFFC
                if li & 0x2000000:
                    li -= 0x4000000
                if text_va + off + li == stub_va:
                    callers.append(text_va + off)
        return callers

    # ── save ──────────────────────────────────────────────────────────────────

    def save(self, path: str) -> None:
        """Write XCOFF32 bytes to path."""
        Path(path).write_bytes(self._data)

    # ── summary ───────────────────────────────────────────────────────────────

    def summary(self) -> str:
        sec_names = ', '.join(self.sections.keys())
        imports = self.dangerous_imports()
        stubs   = self.import_stubs()
        lines = [
            f'XCOFF32: {len(self._data)//1024}KB  nscns={self._nscns}  nsyms={self.nsyms}',
            f'  sections: {sec_names}',
            f'  o_toc: 0x{self.o_toc:x}',
            f'  dangerous imports: {list(imports.keys()) or "none"}',
        ]
        for fn, va in sorted(stubs.items()):
            callers = self.callers_of(va)
            lines.append(f'  stub {fn!r} @ 0x{va:x}: {len(callers)} caller(s)')
        return '\n'.join(lines)


# ── BFF extractor ─────────────────────────────────────────────────────────────

class AixBffExtractor:
    """
    Extract XCOFF32 and XCOFF64 binaries from AIX installp BFF archives.

    Uses magic-byte scanning rather than parsing the BFF container structure,
    which requires AIX-specific metadata tables not present on Linux.

    The extractor finds every XCOFF binary at a 4-byte-aligned offset in the
    archive, validates its file header, and computes the correct byte extent
    from the XCOFF section map and symbol table.  This approach handles all
    known IBM package layouts including multi-component BFF archives that
    contain several XCOFF binaries at different offsets.

    Also useful as a general XCOFF scanner for arbitrary blobs: firmware
    images, filesystem dumps, and memory captures that embed XCOFF objects.
    """

    def __init__(self, data: bytes, *, include_debug: bool = True,
                 min_size: int = 256) -> None:
        """
        Parameters
        ----------
        data          Raw bytes of the BFF archive (or any binary blob).
        include_debug Include XCOFF .debug section in extracted bytes.
                      Pass False to strip DWARF and reduce output size; the
                      extracted binary will be structurally valid but cannot
                      be debugged.  Default True.
        min_size      Minimum extracted binary size in bytes.  Smaller
                      candidates are discarded as false positives.
        """
        self._data          = data
        self._include_debug = include_debug
        self._min_size      = min_size

    @classmethod
    def from_path(
        cls,
        path: str,
        *,
        include_debug: bool = True,
        min_size: int = 256,
    ) -> List[Tuple[str, bytes]]:
        """
        Extract all XCOFF binaries from the file at path.

        Returns a list of (name_hint, xcoff_bytes) tuples.  name_hint is
        derived from nearby ASCII strings in the archive (typically the
        binary's path within the package) or falls back to 'xcoff_at_0xNNN'.
        """
        data = Path(path).read_bytes()
        extractor = cls(data, include_debug=include_debug, min_size=min_size)
        return list(extractor.extract())

    # ── core extraction ───────────────────────────────────────────────────────

    def extract(self) -> Iterator[Tuple[str, bytes]]:
        """
        Yield (name_hint, xcoff_bytes) for each embedded XCOFF binary.

        Uses ablation.core.bff_extractor.iter_entries when available — this is
        the correct structured path that respects the BFF container layout.
        Falls back to magic-byte scanning for compressed or non-standard archives
        where the structured parser raises ValueError.
        """
        if _BFF_OK:
            try:
                xcoff_magic = (b'\x01\xdf', b'\x01\xf7')
                for entry in _iter_bff_entries(self._data):
                    if (not entry.is_dir
                            and len(entry.data) >= self._min_size
                            and entry.data[:2] in xcoff_magic):
                        name = entry.rel_path.split('/')[-1] or 'xcoff'
                        yield name, entry.data
                return
            except (ValueError, Exception):
                pass  # fall through to magic scan

        # Fallback: magic-byte scan (handles compressed / non-standard BFF)
        pos = 0
        while pos < len(self._data) - 20:
            magic_off = self._find_xcoff_magic(pos)
            if magic_off == -1:
                break

            xcoff_bytes = self._extract_one(magic_off)
            if xcoff_bytes and len(xcoff_bytes) >= self._min_size:
                name = self._name_hint(magic_off)
                yield name, xcoff_bytes
                pos = magic_off + len(xcoff_bytes)
            else:
                pos = magic_off + 4

    def _find_xcoff_magic(self, start: int) -> int:
        """Return next 4-byte-aligned XCOFF32/64 magic offset, or -1."""
        # Align start to 4 bytes
        if start % 4:
            start += 4 - (start % 4)
        pos = start
        while pos <= len(self._data) - 20:
            word = struct.unpack('>H', self._data[pos: pos + 2])[0]
            if word in (XCOFF32_MAGIC, XCOFF64_MAGIC):
                return pos
            pos += 4
        return -1

    def _extract_one(self, off: int) -> Optional[bytes]:
        """Attempt to extract a single XCOFF binary starting at off."""
        magic = struct.unpack('>H', self._data[off: off + 2])[0]
        if magic == XCOFF32_MAGIC:
            return self._extract_xcoff32(off)
        return None  # XCOFF64 support is future work

    def _extract_xcoff32(self, off: int) -> Optional[bytes]:
        """
        Extract XCOFF32 binary at off.  Returns bytes or None on failure.

        The extent is the maximum of:
          - Section data ends (section file offset + size)
          - Symbol table end (symptr + nsyms × 18)
          - String table end (above + strtab_size)
        XCOFF .debug section (DWARF) may be excluded; see include_debug.
        """
        d = self._data
        blob_limit = len(d) - off

        try:
            nscns  = struct.unpack('>H', d[off + 2: off + 4])[0]
            symptr = struct.unpack('>I', d[off + 8: off + 12])[0]
            nsyms  = struct.unpack('>i', d[off + 12: off + 16])[0]
            opthdr = struct.unpack('>H', d[off + 16: off + 18])[0]
        except struct.error:
            return None

        if not (1 <= nscns <= 100 and 0 <= opthdr <= 256):
            return None

        max_end = off   # will grow as we find section extents

        sec_base = off + 20 + opthdr
        for i in range(nscns):
            sh_off = sec_base + i * 40
            if sh_off + 40 > len(d):
                break
            sh = d[sh_off: sh_off + 40]
            name  = sh[:8].rstrip(b'\x00').decode('ascii', errors='replace')
            foff  = struct.unpack('>I', sh[20:24])[0]
            size  = struct.unpack('>I', sh[16:20])[0]

            if not self._include_debug and name in ('.debug', '.zdebug'):
                continue
            if foff > 0 and size > 0 and foff < blob_limit:
                max_end = max(max_end, off + foff + size)

        if symptr > 0 and nsyms > 0 and symptr < blob_limit:
            sym_end = off + symptr + nsyms * 18
            # String table immediately follows symbol table
            st_off = sym_end
            if st_off + 4 <= len(d):
                st_size = struct.unpack('>I', d[st_off: st_off + 4])[0]
                if 4 <= st_size < 0x2000000:
                    sym_end += st_size
            max_end = max(max_end, sym_end)

        size = max_end - off
        if size < self._min_size or size > blob_limit:
            return None
        return d[off: max_end]

    # ── name hint ─────────────────────────────────────────────────────────────

    def _name_hint(self, xcoff_off: int, *, window: int = 512) -> str:
        """
        Derive a name for the XCOFF binary from ASCII context before it.

        Scans window bytes before xcoff_off for a null-terminated printable
        ASCII string that looks like a Unix path or filename.  Falls back to
        'xcoff_at_0xNNN'.
        """
        start = max(0, xcoff_off - window)
        ctx   = self._data[start: xcoff_off]
        # Find the last null byte and take the text after it
        last_null = ctx.rfind(b'\x00')
        if last_null >= 0:
            candidate = ctx[last_null + 1:]
        else:
            candidate = ctx
        try:
            s = candidate.decode('ascii').strip()
        except UnicodeDecodeError:
            s = ''
        # Keep only if it looks like a path component (alphanum + /_-.)
        filtered = ''.join(c for c in s if c.isalnum() or c in '/._-')
        if 4 <= len(filtered) <= 128:
            # Return only the last component if it's a full path
            return filtered.split('/')[-1] or filtered
        return f'xcoff_at_{xcoff_off:#x}'
