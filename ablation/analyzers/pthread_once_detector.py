"""
PthreadOnceDetector — identifies pthread_once(3) lazy-init wrappers misidentified as auth checks.

Background
----------
Gap this fills: stripped server binaries often have small wrapper functions that call
pthread_once() to lazily initialize global state, then return 0.  During manual RE of IBM
Storage Defender Sentinel dispatch (session 12), a suspected auth check at 0x7781ac (called as
"authentication" in Q-shell session init func@0xce3be2) was identified as a pthread_once() lazy
initializer only after full disassembly.  The pattern:

  sub  rsp, N
  lea  rdi, [rip+X]    ; once_control global
  lea  rsi, [rip+Y]    ; init callback
  call pthread_once_plt
  xor  eax, eax        ; return 0 ALWAYS
  ret

...is not an authentication check but is indistinguishable from one without examining the PLT
and the return path.  This module automates that classification for all callers of pthread_once
in a binary, producing an LAZY_INIT / POSSIBLE_AUTH verdict for each caller.

Algorithm
---------
1. Locate pthread_once PLT via .rela.plt relocations.
2. Scan executable sections for `call <pthread_once_plt>` (E8 rel32 or FF /2 encodings).
3. For each call site, walk backward to find the function prologue, then forward through
   the function body (bounded to _MAX_FUNC_BYTES):
   a. Count all `call` instructions in the function.
   b. Check whether the function ends with `xor eax, eax` (or `xor rax, rax`) followed
      (possibly with a few stack-restore instructions) by `ret`.
4. Verdict:
   - LAZY_INIT:    function has 0-1 calls (pthread_once only), return value is always 0.
   - POSSIBLE_AUTH: function has ≥2 calls, or the return path is conditional / non-zero.
5. Flag all LAZY_INIT functions so callers that test their return value for auth can be
   corrected.

Usage
-----
    from ablation.analyzers.pthread_once_detector import PthreadOnceDetector

    det     = PthreadOnceDetector.from_context(ctx)
    results = det.detect()
    print(PthreadOnceDetector.report(results))

    # Filter confirmed lazy inits:
    lazy = [r for r in results if r.verdict == 'LAZY_INIT']
    for r in lazy:
        print(f'  func@{r.func_va:#010x}  called from {len(r.caller_vas)} site(s)')
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_CS_OK = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import (
        X86_INS_CALL, X86_INS_RET, X86_INS_XOR, X86_INS_MOV,
        X86_INS_ADD, X86_INS_POP, X86_INS_LEAVE,
        X86_OP_REG, X86_OP_IMM,
        X86_REG_EAX, X86_REG_RAX,
    )
    _CS_OK = True
except ImportError:
    pass

# Maximum bytes to disassemble per function body
_MAX_FUNC_BYTES = 512
# Instruction window to scan backward from call site looking for function prologue
_BACK_SCAN_BYTES = 256
# Minimum instruction count in a "possible auth" function (vs. tiny lazy-init wrapper)
_MIN_AUTH_INSNS = 6


LAZY_INIT     = 'LAZY_INIT'
POSSIBLE_AUTH = 'POSSIBLE_AUTH'
UNKNOWN       = 'UNKNOWN'


@dataclass
class PthreadOnceResult:
    """Classification result for one pthread_once() call site / wrapping function."""
    call_va:      int           # VA of the `call pthread_once` instruction
    func_va:      int           # estimated function start VA
    verdict:      str           # LAZY_INIT | POSSIBLE_AUTH | UNKNOWN
    returns_zero: bool  = False # True if function unconditionally returns 0
    call_count:   int   = 0     # total call instructions in the function
    caller_vas:   List[int] = field(default_factory=list)  # VAs that call this wrapper
    detail:       str   = ''

    def fmt(self) -> str:
        callers_str = ''
        if self.caller_vas:
            callers_str = '  callers=[' + ', '.join(f'{v:#010x}' for v in self.caller_vas[:4])
            if len(self.caller_vas) > 4:
                callers_str += f', +{len(self.caller_vas) - 4}'
            callers_str += ']'
        return (
            f'  {self.verdict:14s}  call@{self.call_va:#010x}'
            f'  func@{self.func_va:#010x}'
            f'  calls={self.call_count}  zero_ret={self.returns_zero}'
            f'{callers_str}'
            f'  {self.detail}'
        )


class PthreadOnceDetector:
    """
    Find all pthread_once() call sites in a stripped x86-64 ELF and determine
    whether the wrapping function is a lazy initializer (LAZY_INIT) or a real
    auth/init function with additional logic (POSSIBLE_AUTH).
    """

    def __init__(self, binary_path: str):
        self._path = binary_path
        self._data: bytes = Path(binary_path).read_bytes()
        self._exec_regions: List[Tuple[int, int, int]] = []  # (va, va_end, file_off)
        self._plt_va:  Optional[int] = None   # VA of pthread_once PLT stub
        self._once_va_map: Dict[int, int] = {}  # func_va → call_va (for dedup)
        self._func_call_map: Dict[int, List[int]] = {}  # func_va → [call_va, ...]
        self._md: Optional[Cs] = None
        if _CS_OK:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True
        self._parse_elf()
        self._find_pthread_once_plt()

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_path(cls, path: str) -> 'PthreadOnceDetector':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'PthreadOnceDetector':
        path = getattr(ctx, 'binary_path', None) or getattr(ctx, 'path', None)
        obj  = cls(path)
        return obj

    # ------------------------------------------------------------------
    # ELF helpers
    # ------------------------------------------------------------------

    def _parse_elf(self) -> None:
        data = self._data
        if len(data) < 64 or data[:4] != b'\x7fELF':
            return
        e_shoff     = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum     = struct.unpack_from('<H', data, 60)[0]
        e_shstrndx  = struct.unpack_from('<H', data, 62)[0]
        if e_shoff == 0 or e_shstrndx >= e_shnum:
            return
        shstr_sh  = e_shoff + e_shstrndx * e_shentsize
        shstr_off = struct.unpack_from('<Q', data, shstr_sh + 24)[0]
        SHF_EXECINSTR = 0x4
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            sh_flags = struct.unpack_from('<Q', data, sh + 8)[0]
            sh_addr  = struct.unpack_from('<Q', data, sh + 16)[0]
            sh_off   = struct.unpack_from('<Q', data, sh + 24)[0]
            sh_size  = struct.unpack_from('<Q', data, sh + 32)[0]
            if sh_flags & SHF_EXECINSTR and sh_size > 0:
                self._exec_regions.append((sh_addr, sh_addr + sh_size, sh_off))

    def _find_pthread_once_plt(self) -> None:
        """Locate pthread_once PLT VA via .rela.plt / .plt.sec / .plt."""
        data = self._data
        if len(data) < 64:
            return
        e_shoff     = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum     = struct.unpack_from('<H', data, 60)[0]
        e_shstrndx  = struct.unpack_from('<H', data, 62)[0]
        if e_shoff == 0 or e_shstrndx >= e_shnum:
            return
        shstr_sh  = e_shoff + e_shstrndx * e_shentsize
        shstr_off = struct.unpack_from('<Q', data, shstr_sh + 24)[0]

        SHT_RELA    = 4
        SHT_DYNSYM  = 11
        SHT_STRTAB  = 3

        sections: Dict[str, Tuple[int, int, int, int]] = {}  # name → (type, addr, off, size, link, entsize)
        all_sections: List[Tuple[int, str, int, int, int, int, int]] = []
        for i in range(e_shnum):
            sh     = e_shoff + i * e_shentsize
            sh_name_idx = struct.unpack_from('<I', data, sh)[0]
            sh_type     = struct.unpack_from('<I', data, sh + 4)[0]
            sh_addr     = struct.unpack_from('<Q', data, sh + 16)[0]
            sh_off      = struct.unpack_from('<Q', data, sh + 24)[0]
            sh_size     = struct.unpack_from('<Q', data, sh + 32)[0]
            sh_link     = struct.unpack_from('<I', data, sh + 40)[0]
            sh_entsize  = struct.unpack_from('<Q', data, sh + 56)[0]
            nm_end = data.find(b'\x00', shstr_off + sh_name_idx)
            nm     = data[shstr_off + sh_name_idx:nm_end].decode('ascii', errors='replace')
            all_sections.append((i, nm, sh_type, sh_addr, sh_off, sh_size, sh_link))
            sections[nm] = (sh_type, sh_addr, sh_off, sh_size, sh_link, sh_entsize)

        # Find .rela.plt
        rela_plt = sections.get('.rela.plt') or sections.get('.rela.plt.sec')
        if not rela_plt:
            return
        rela_type, rela_addr, rela_off, rela_size, rela_link, rela_ent = rela_plt
        if rela_ent == 0:
            rela_ent = 24  # standard RELA entry size

        # Find .dynsym and its strtab
        dynsym = sections.get('.dynsym')
        if not dynsym:
            return
        _, dynsym_addr, dynsym_off, dynsym_size, dynsym_link, dynsym_ent = dynsym
        if dynsym_ent == 0:
            dynsym_ent = 24

        # Find strtab for dynsym
        strtab_sec = None
        for i, nm, stype, saddr, soff, ssize, slink in all_sections:
            if i == dynsym_link and stype == SHT_STRTAB:
                strtab_sec = (saddr, soff, ssize)
                break
        if strtab_sec is None:
            strtab_sec = sections.get('.dynstr')
            if strtab_sec:
                _, st_addr, st_off, st_size, *_ = strtab_sec
                strtab_sec = (st_addr, st_off, st_size)
        if strtab_sec is None:
            return
        _, strtab_off, strtab_size = strtab_sec

        # Find .plt section VA for PLT entry address calculation
        plt_info = sections.get('.plt')
        if plt_info is None:
            return
        _, plt_va, plt_off, plt_size, *_ = plt_info
        # Each PLT stub is 16 bytes; slot 0 is the resolver, entries start at slot 1
        PLT_STUB_SIZE = 16

        # Walk .rela.plt entries
        n_relocs = rela_size // rela_ent
        for j in range(n_relocs):
            rela = rela_off + j * rela_ent
            r_offset = struct.unpack_from('<Q', data, rela)[0]
            r_info   = struct.unpack_from('<Q', data, rela + 8)[0]
            r_sym    = r_info >> 32
            # Get symbol name
            sym_off = dynsym_off + r_sym * dynsym_ent
            if sym_off + 4 > len(data):
                continue
            sym_name_idx = struct.unpack_from('<I', data, sym_off)[0]
            nm_end = data.find(b'\x00', strtab_off + sym_name_idx)
            sym_name = data[strtab_off + sym_name_idx:nm_end].decode('ascii', errors='replace')
            if 'pthread_once' not in sym_name:
                continue
            # PLT stub VA: plt_va + (j + 1) * PLT_STUB_SIZE
            stub_va = plt_va + (j + 1) * PLT_STUB_SIZE
            self._plt_va = stub_va
            return

    # ------------------------------------------------------------------
    # Function VA estimation (backward prologue scan)
    # ------------------------------------------------------------------

    def _file_off_for_exec_va(self, va: int) -> Optional[int]:
        for lo, hi, foff in self._exec_regions:
            if lo <= va < hi:
                return foff + (va - lo)
        return None

    def _exec_va_for_file_off(self, foff: int) -> Optional[int]:
        for lo, hi, soff in self._exec_regions:
            size = hi - lo
            if soff <= foff < soff + size:
                return lo + (foff - soff)
        return None

    def _find_func_start(self, call_site_va: int) -> int:
        """
        Walk backward from call_site_va looking for a push rbp or endbr64 prologue.
        Falls back to _BACK_SCAN_BYTES before call_site_va if no prologue found.
        """
        off = self._file_off_for_exec_va(call_site_va)
        if off is None:
            return call_site_va - _BACK_SCAN_BYTES

        back = min(off, _BACK_SCAN_BYTES)
        search_start = off - back

        # endbr64 = f3 0f 1e fa
        # push rbp = 55
        # sub rsp, N = 48 83 ec XX  (frameless leaf functions; accept only when
        #   preceded by a function-boundary byte: ret/nop/int3/zero-fill)
        # Scan nearest-first (backward from the call site) so the first hit is the
        # prologue of the function that *contains* the call, not a preceding function.
        endbr = b'\xf3\x0f\x1e\xfa'
        _BOUNDARY = frozenset((0x90, 0xcc, 0xc3, 0x00))  # nop, int3, ret, zero-fill
        best = search_start
        for i in range(1, back + 1):
            pos = off - i
            if self._data[pos:pos+4] == endbr:
                best = pos
                break
            if self._data[pos] == 0x55:  # push rbp
                best = pos
                break
            if (self._data[pos:pos+3] == b'\x48\x83\xec'  # sub rsp, imm8
                    and pos > 0
                    and self._data[pos - 1] in _BOUNDARY):
                best = pos
                break

        va = self._exec_va_for_file_off(best)
        return va if va is not None else call_site_va - back

    # ------------------------------------------------------------------
    # Function body analysis
    # ------------------------------------------------------------------

    def _analyze_func(self, func_va: int) -> Tuple[int, bool, str]:
        """
        Disassemble from func_va for up to _MAX_FUNC_BYTES.
        Returns: (call_count, returns_zero_unconditionally, detail_str)
        """
        if not _CS_OK or self._md is None:
            return 0, False, 'capstone not available'

        off = self._file_off_for_exec_va(func_va)
        if off is None:
            return 0, False, 'func VA not in exec region'

        code = self._data[off:off + _MAX_FUNC_BYTES]
        insns = list(self._md.disasm(code, func_va))

        call_count    = 0
        last_was_zero = False
        saw_ret       = False
        detail_parts: List[str] = []

        for insn in insns:
            if insn.id == X86_INS_CALL:
                call_count += 1
                last_was_zero = False
            elif insn.id == X86_INS_XOR:
                ops = insn.operands
                if len(ops) == 2:
                    if (ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG
                            and ops[0].reg == ops[1].reg
                            and ops[0].reg in (X86_REG_EAX, X86_REG_RAX)):
                        last_was_zero = True
            elif insn.id in (X86_INS_ADD, X86_INS_POP, X86_INS_LEAVE, X86_INS_MOV):
                pass  # stack cleanup; preserve last_was_zero
            elif insn.id == X86_INS_RET:
                saw_ret = True
                break
            else:
                last_was_zero = False  # intervening instruction after xor eax,eax

        returns_zero = saw_ret and last_was_zero
        return call_count, returns_zero, ''

    # ------------------------------------------------------------------
    # Call site scanner
    # ------------------------------------------------------------------

    def _find_call_sites(self) -> List[Tuple[int, int]]:
        """
        Scan for `call <pthread_once_plt>` in all executable sections.
        Returns list of (call_site_va, func_start_va).
        """
        if self._plt_va is None:
            return []
        results: List[Tuple[int, int]] = []
        for lo, hi, foff in self._exec_regions:
            size = hi - lo
            text = self._data[foff:foff + size]
            pos  = 0
            while pos < len(text) - 4:
                if text[pos] == 0xe8:  # CALL rel32
                    rel32  = struct.unpack_from('<i', text, pos + 1)[0]
                    call_va = lo + pos
                    target  = call_va + 5 + rel32
                    if target == self._plt_va:
                        func_va = self._find_func_start(call_va)
                        results.append((call_va, func_va))
                pos += 1
        return results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self) -> List[PthreadOnceResult]:
        """
        Detect all pthread_once call sites and classify wrapping functions.
        Returns one PthreadOnceResult per unique wrapping function.
        """
        if self._plt_va is None:
            return []

        call_sites = self._find_call_sites()
        if not call_sites:
            return []

        # Group by func_va
        func_to_calls: Dict[int, List[int]] = {}
        for call_va, func_va in call_sites:
            func_to_calls.setdefault(func_va, []).append(call_va)

        results: List[PthreadOnceResult] = []
        for func_va, call_vas in sorted(func_to_calls.items()):
            # Use the most-common call_va (first) as the representative
            call_va = call_vas[0]
            call_count, returns_zero, detail = self._analyze_func(func_va)

            if call_count <= 1 and returns_zero:
                verdict = LAZY_INIT
                if not detail:
                    detail = 'single pthread_once call + unconditional zero return'
            elif call_count > 1:
                verdict = POSSIBLE_AUTH
                if not detail:
                    detail = f'{call_count} calls in function — may have real logic'
            else:
                verdict = UNKNOWN
                if not detail:
                    detail = 'disassembly inconclusive'

            # Find callers of this wrapper function (scan for call <func_va>)
            callers = self._find_direct_callers(func_va)

            results.append(PthreadOnceResult(
                call_va      = call_va,
                func_va      = func_va,
                verdict      = verdict,
                returns_zero = returns_zero,
                call_count   = call_count,
                caller_vas   = callers,
                detail       = detail,
            ))

        return results

    def _find_direct_callers(self, target_va: int) -> List[int]:
        """Find `call <target_va>` sites in executable sections (E8 rel32 only)."""
        callers: List[int] = []
        for lo, hi, foff in self._exec_regions:
            size = hi - lo
            text = self._data[foff:foff + size]
            pos  = 0
            while pos < len(text) - 4:
                if text[pos] == 0xe8:
                    rel32   = struct.unpack_from('<i', text, pos + 1)[0]
                    call_va = lo + pos
                    tgt     = call_va + 5 + rel32
                    if tgt == target_va:
                        callers.append(call_va)
                pos += 1
        return sorted(callers)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @staticmethod
    def report(results: List[PthreadOnceResult]) -> str:
        if not results:
            return 'PthreadOnceDetector: no pthread_once call sites found'
        lazy    = [r for r in results if r.verdict == LAZY_INIT]
        authish = [r for r in results if r.verdict == POSSIBLE_AUTH]
        unknown = [r for r in results if r.verdict == UNKNOWN]
        lines   = [
            f'PthreadOnceDetector: {len(results)} site(s)  '
            f'LAZY_INIT={len(lazy)}  POSSIBLE_AUTH={len(authish)}  UNKNOWN={len(unknown)}'
        ]
        if lazy:
            lines.append(f'\nLAZY_INIT (safe to eliminate as auth barriers):')
            for r in lazy:
                lines.append(r.fmt())
        if authish:
            lines.append(f'\nPOSSIBLE_AUTH (investigate further):')
            for r in authish:
                lines.append(r.fmt())
        if unknown:
            lines.append(f'\nUNKNOWN:')
            for r in unknown:
                lines.append(r.fmt())
        return '\n'.join(lines)
