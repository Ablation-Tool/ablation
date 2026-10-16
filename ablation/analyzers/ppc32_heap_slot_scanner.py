"""PPC32 heap slot overflow pattern scanner.

Detects the pattern where a heap buffer is allocated as N copies of a fixed
slot size (via mulli), then each slot is filled with an unbounded copy
(strcpy, strcat) with no bounds check between the allocation and the copy.

Why this exists
---------------
1. The VIOS ioscli IZ22147 analysis (VIOS-VTD-001) found a heap overflow
   in getBackingDevices() where mulli r3,r3,0x44 computes total malloc size
   and bl .strcpy at 0x10001668 copies into each 68-byte slot without a
   size check. This pattern is not detected by TaintTracker or SinkArgClassifier
   because the slot boundary is arithmetic, not a static buffer size.
2. PPC32 XCOFF executables (AIX ioscli, VIOS utilities, IBM network daemons)
   share this coding pattern in ODM / ODM attribute reader code. A dedicated
   scanner prevents per-target manual disassembly for a known class.
3. The scanner produces byte-verifiable findings: it records the exact VA,
   expected encoding, and the slot size N, ready for byte-verification.

Pattern
-------
In the function being scanned:

  1. mulli rD, rS, N         -- slot size N (0x10 <= N <= 0x400)
  2. bl <malloc>             -- within 6 instructions of mulli
  3. (loop body) bl <strcpy> -- within 512 instructions of malloc
     without any intervening cmpwi/cmplwi that bounds-checks the source

Limitations
-----------
The scanner matches intra-function patterns within a single ELF or XCOFF32
executable. It does not trace the source operand of strcpy (determining
whether the source is attacker-controlled is left to the analyst).

Usage::

    from ablation.analyzers.ppc32_heap_slot_scanner import PPC32HeapSlotScanner

    scanner = PPC32HeapSlotScanner('/path/to/ioscli')
    findings = scanner.scan()
    for f in findings:
        print(PPC32HeapSlotScanner.report([f]))
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class HeapSlotFinding:
    """A heap slot overflow candidate site."""

    func_name:     str       # enclosing function name (if known)
    func_va:       int       # function start VA
    mulli_va:      int       # VA of the mulli instruction
    slot_size:     int       # N (bytes per slot)
    malloc_va:     int       # VA of the bl malloc instruction
    strcpy_va:     int       # VA of the bl strcpy instruction
    strcpy_target: str       # resolved callee name
    has_size_check: bool     # True if a cmpwi/cmplwi was found between malloc and strcpy
    mulli_bytes:   bytes     # raw instruction bytes at mulli_va (for byte-verify)
    strcpy_bytes:  bytes     # raw instruction bytes at strcpy_va (for byte-verify)


def _read_u32be(data: bytes, off: int) -> int:
    return struct.unpack_from('>I', data, off)[0]


def _read_u16be(data: bytes, off: int) -> int:
    return struct.unpack_from('>H', data, off)[0]


def _get_text_and_syms(path: str):
    """Extract .text data, symbols, and .rela.text from an ELF32 or XCOFF32 file.

    Returns (text_data, text_va_base, syms, relas) or None.
      syms  = list of (name, va, size)
      relas = {va: callee_name}
    """
    with open(path, 'rb') as f:
        raw = f.read()

    if raw[:4] == b'\x7fELF':
        return _parse_elf32(raw)
    if len(raw) >= 2:
        magic = _read_u16be(raw, 0)
        if magic == 0x01DF:        # XCOFF32
            return _parse_xcoff32(raw)
    return None


def _parse_elf32(raw: bytes):
    if len(raw) < 52 or raw[4] != 1 or raw[5] != 2:
        return None
    if _read_u16be(raw, 18) != 20:    # EM_PPC
        return None

    e_shoff     = _read_u32be(raw, 32)
    e_shentsize = _read_u16be(raw, 46)
    e_shnum     = _read_u16be(raw, 48)
    e_shstrndx  = _read_u16be(raw, 50)

    shstr_sh = e_shoff + e_shstrndx * e_shentsize
    shstr_off = _read_u32be(raw, shstr_sh + 16)
    shstrtab  = raw[shstr_off:shstr_off + 4096]

    def sh_name(i):
        off = _read_u32be(raw, e_shoff + i * e_shentsize)
        end = shstrtab.index(b'\x00', off)
        return shstrtab[off:end].decode('ascii', errors='replace')

    text_data = b''
    text_va_base = 0
    sym_off = sym_size = str_off = str_size = 0
    rela_off = rela_size = 0

    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        name  = sh_name(i)
        addr  = _read_u32be(raw, base + 12)
        off   = _read_u32be(raw, base + 16)
        sz    = _read_u32be(raw, base + 20)
        if name == '.text':
            text_data = raw[off:off + sz]
            text_va_base = addr
        elif name == '.symtab':
            sym_off, sym_size = off, sz
        elif name == '.strtab':
            str_off, str_size = off, sz
        elif name in ('.rela.text', '.rel.text'):
            rela_off, rela_size = off, sz

    if not text_data:
        return None

    sym_data = raw[sym_off:sym_off + sym_size]
    str_data = raw[str_off:str_off + str_size]
    syms, relas = _build_syms_relas(sym_data, str_data, raw, rela_off, rela_size)
    return text_data, text_va_base, syms, relas


def _parse_xcoff32(raw: bytes):
    """Parse XCOFF32 executable .text, loader symbols, and main symtab."""
    try:
        from ablation.core.xcoff_parser import parse as xcoff_parse
    except ImportError:
        return None

    try:
        # parse() requires a path even when data is provided; use a dummy sentinel
        binary = xcoff_parse(path='<inline>', data=raw)
    except Exception:
        return None

    if not binary.sections:
        return None

    # Find .text section (STYP_TEXT = 0x0020)
    text_sec = next((s for s in binary.sections if s.flags & 0x0020), None)
    if text_sec is None:
        return None

    text_data = text_sec.data   # XcoffSection carries the raw bytes directly
    text_va_base = text_sec.vaddr

    # Use size=4 (minimum instruction) so sym_map construction includes all exports.
    # XCOFF32 executables don't carry symbol sizes; 4 is enough to satisfy sz > 0.
    syms = [(sym.name, sym.code_va, 4) for sym in binary.exports if sym.code_va]
    relas: dict[int, str] = {}
    return text_data, text_va_base, syms, relas


def _build_syms_relas(sym_data, str_data, raw, rela_off, rela_size):
    """Build symbol list and relocation map from ELF tables."""
    sym_idx_to_name: dict[int, str] = {}
    syms = []
    entry_sz = 16

    for i in range(len(sym_data) // entry_sz):
        s = sym_data[i * entry_sz:(i + 1) * entry_sz]
        st_name, st_value, st_size, st_info, _st_other, st_shndx = struct.unpack_from('>IIIBBH', s)
        st_bind = st_info >> 4
        st_type = st_info & 0xf
        try:
            end = str_data.index(b'\x00', st_name)
            sname = str_data[st_name:end].decode('ascii', errors='replace')
        except (ValueError, IndexError):
            sname = ''
        sym_idx_to_name[i] = sname
        if st_size > 0 and st_shndx == 1:
            syms.append((sname, st_value, st_size))

    relas: dict[int, str] = {}
    if rela_off:
        for j in range(rela_size // 12):
            roff = rela_off + j * 12
            r_offset = _read_u32be(raw, roff)
            r_info   = _read_u32be(raw, roff + 4)
            sym_idx  = r_info >> 8
            relas[r_offset] = sym_idx_to_name.get(sym_idx, '')

    return syms, relas


_COPY_TARGETS = frozenset({'.strcpy', 'strcpy', 'strcat', '.strcat', 'sprintf', '.sprintf'})
_MALLOC_TARGETS = frozenset({'malloc', '.malloc', 'SsMemAlloc', 'SsMemCalloc'})

_SLOT_MIN = 0x10
_SLOT_MAX = 0x400
_MALLOC_WINDOW = 6     # mulli must be within this many instructions of malloc
_STRCPY_WINDOW = 512   # malloc must be within this many instructions of strcpy


class PPC32HeapSlotScanner:
    """Scans a PPC32 binary for heap slot overflow patterns.

    Args:
        binary_path: Path to the ELF32 PPC binary or XCOFF32 executable.
    """

    def __init__(self, binary_path: str | Path):
        self.binary_path = str(binary_path)

    @classmethod
    def from_context(cls, ctx) -> 'PPC32HeapSlotScanner':
        return cls(ctx.path)

    def scan(self) -> List[HeapSlotFinding]:
        """Scan the binary for heap slot overflow candidates.

        Returns a list of HeapSlotFinding records, one per candidate site.
        """
        try:
            from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
        except ImportError:
            return []

        parsed = _get_text_and_syms(self.binary_path)
        if parsed is None:
            return []

        text_data, text_va_base, syms, relas = parsed

        with open(self.binary_path, 'rb') as fh:
            raw_full = fh.read()

        cs = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
        cs.skipdata = True   # skip invalid/padding bytes so all functions are reached

        # Collect all instructions as a flat list with metadata
        instrs = list(cs.disasm(text_data, text_va_base))
        if not instrs:
            return []

        sym_map: dict[int, tuple[str, int]] = {}  # va -> (name, end_va)
        for name, va, sz in syms:
            if sz > 0:
                sym_map[va] = (name, va + sz)

        # va_to_name: flat VA -> name lookup for callee resolution (XCOFF32 exports
        # have real sizes so this covers malloc/strcpy/etc. with exact VA match)
        va_to_name: dict[int, str] = {va: name for name, va, _sz in syms}

        # For func_for_va, use sorted predecessor when sizes are unavailable
        # (XCOFF32 exports are listed with size=4 placeholder)
        _sorted_vas = sorted(va for va, _sz in [(va, sz) for _, va, sz in syms] if _sz > 0)

        def func_for_va(va: int) -> str:
            # Range-based lookup (works when sizes are known)
            for fva, (fname, fend) in sym_map.items():
                if fva <= va < fend and (fend - fva) > 4:
                    return fname
            # Sorted predecessor fallback for XCOFF32 (sizes unknown)
            best_va = 0
            for fva in _sorted_vas:
                if fva <= va:
                    best_va = fva
                else:
                    break
            return va_to_name.get(best_va, '')

        findings: List[HeapSlotFinding] = []

        for idx, instr in enumerate(instrs):
            # Look for mulli rD, rS, N (slot size multiplier)
            if instr.mnemonic != 'mulli':
                continue
            # mulli rD, rS, N: extract N from op_str "r3, r3, 0x44"
            parts = instr.op_str.split(',')
            if len(parts) < 3:
                continue
            try:
                slot_size = int(parts[2].strip(), 0)
            except ValueError:
                continue
            if not (_SLOT_MIN <= slot_size <= _SLOT_MAX):
                continue

            mulli_va = instr.address
            mulli_bytes = text_data[mulli_va - text_va_base:mulli_va - text_va_base + 4]

            # Search forward for malloc call within MALLOC_WINDOW instructions
            malloc_va = 0
            for j in range(idx + 1, min(idx + 1 + _MALLOC_WINDOW, len(instrs))):
                ni = instrs[j]
                if ni.mnemonic == 'bl':
                    callee = relas.get(ni.address, '')
                    if not callee:
                        try:
                            target = int(ni.op_str.strip(), 0)
                            callee = va_to_name.get(target, '')
                        except ValueError:
                            callee = ''
                    if callee in _MALLOC_TARGETS:
                        malloc_va = ni.address
                        break

            if not malloc_va:
                continue

            # Search forward for strcpy call within STRCPY_WINDOW instructions
            # Track whether any cmpwi/cmplwi appears between malloc and strcpy
            has_check = False
            strcpy_va = 0
            strcpy_target = ''

            for k in range(j + 1, min(idx + 1 + _STRCPY_WINDOW, len(instrs))):
                ni = instrs[k]
                if ni.mnemonic in ('cmpwi', 'cmplwi', 'cmpw', 'cmp'):
                    has_check = True
                if ni.mnemonic == 'bl':
                    callee = relas.get(ni.address, '')
                    if not callee:
                        try:
                            target = int(ni.op_str.strip(), 0)
                            callee = va_to_name.get(target, '')
                        except ValueError:
                            callee = ''
                    if callee in _COPY_TARGETS:
                        strcpy_va = ni.address
                        strcpy_target = callee
                        break

            if not strcpy_va:
                continue

            strcpy_text_off = strcpy_va - text_va_base
            strcpy_bytes = text_data[strcpy_text_off:strcpy_text_off + 4]

            findings.append(HeapSlotFinding(
                func_name=func_for_va(mulli_va),
                func_va=mulli_va,
                mulli_va=mulli_va,
                slot_size=slot_size,
                malloc_va=malloc_va,
                strcpy_va=strcpy_va,
                strcpy_target=strcpy_target,
                has_size_check=has_check,
                mulli_bytes=mulli_bytes,
                strcpy_bytes=strcpy_bytes,
            ))

        return findings

    @staticmethod
    def report(findings: List[HeapSlotFinding]) -> str:
        if not findings:
            return 'PPC32HeapSlotScanner: no heap slot overflow patterns found.\n'
        lines = [f'PPC32HeapSlotScanner: {len(findings)} candidate(s)']
        for f in findings:
            check_str = 'SIZE-CHECKED' if f.has_size_check else 'NO-CHECK'
            lines.append(
                f'  {f.func_name or "?"}'
                f'  mulli_va={f.mulli_va:#010x}  slot={f.slot_size:#x}B'
                f'  malloc_va={f.malloc_va:#010x}'
                f'  strcpy_va={f.strcpy_va:#010x}  callee={f.strcpy_target!r}'
                f'  [{check_str}]'
            )
            lines.append(
                f'    mulli_bytes={f.mulli_bytes.hex()}'
                f'  strcpy_bytes={f.strcpy_bytes.hex()}'
            )
        return '\n'.join(lines) + '\n'
