"""
uefi_sink_classifier_la64.py — GCC max-not-min bug detector for UEFI Boot Services
allocations in LA64 PE32+ firmware images.

Why this exists
---------------
1.  UEFI code calls memory allocation through a function pointer table
    (EFI_BOOT_SERVICES) — there is no PLT.  LA64MaxNotMinScanner.from_pe32plus()
    with `pe32plus=True` reports any JIRL where the max-not-min result is live in
    ANY argument register, but does not distinguish AllocatePool(size=$a1) from
    AllocatePages(pages=$a2) and cannot suppress hits where the result flows into
    a non-size argument (e.g. the PoolType=$a0 of AllocatePool).

2.  This module resolves dispatch sites by scanning for the standard two-instruction
    sequence that appears at every Boot Services call site in EDK2-compiled LA64 code:

        ld.d  $rx, $ry, <gbs_offset>    ← load function pointer from gBS table
        jirl  $ra, $rx, 0               ← indirect call

    and maps the JIRL's VA to the corresponding EFI_BOOT_SERVICES function name
    and the argument register that carries the dangerous size.

Architecture — LA64 lp64d ABI
-------------------------------
    $a0 = r4 = 4
    $a1 = r5 = 5
    $a2 = r6 = 6
    $a3 = r7 = 7

EFI_BOOT_SERVICES table offsets (EDK2 MdePkg/Include/Uefi/UefiSpec.h)
-----------------------------------------------------------------------
    0x18  AllocatePages(Type, MemoryType, Pages, *Memory)   Pages  = $a2 (arg_pos 2)
    0x20  FreePages(Memory, Pages)
    0x28  GetMemoryMap(*MapSize, ...)                        MapSize = $a0 (arg_pos 0)
    0x30  AllocatePool(PoolType, Size, **Buffer)             Size   = $a1 (arg_pos 1)
    0x38  FreePool(*Buffer)

Instruction encodings used (LoongArch32/64 ISA)
-----------------------------------------------
    ld.d Rd, Rj, si12    — 3R+si12: bits[31:22]=0b0010100011, bits[21:10]=si12
    jirl Rd, Rj, si16    — 2RI16:   bits[31:26]=0b010011=19, bits[25:10]=si16,
                                     bits[ 9: 5]=Rj, bits[4:0]=Rd
    sltu/slt/masknez/maskeqz/or — imported from LA64MaxNotMinScanner

Usage
------
    from ablation.analyzers.uefi_sink_classifier_la64 import UEFISinkClassifierLA64

    scanner = UEFISinkClassifierLA64.from_path('/path/to/module.efi')
    findings = scanner.scan()
    print(scanner.report(findings))

Module gap history
-------------------
    Session 3532 (TencentOS RE): PE32+ UEFI analysis tooling identified as gap #3.
    This module closes gap #3B: gBS-dispatch sink detection for LA64 UEFI images.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from ablation.analyzers.loongarch64_max_not_min_scanner import (
    _MATCH_SLTU, _MATCH_SLT,
    _MATCH_MASKNEZ, _MATCH_MASKEQZ,
    _MATCH_OR, _MASK_3R,
    _MATCH_JIRL, _MASK_JIRL,
    _rd, _rj, _rk,
    _ARG_REGS,
)


# ---------------------------------------------------------------------------
# EFI_BOOT_SERVICES table offsets → (function_name, arg_pos, arg_label)
#   arg_pos: 0-based index into lp64d argument registers ($a0=0, $a1=1, ...)
# ---------------------------------------------------------------------------

_GBS_SINKS: Dict[int, Tuple[str, int, str]] = {
    0x18: ('AllocatePages', 2, 'pages'),   # Pages = $a2
    0x28: ('GetMemoryMap',  0, 'map_size'),# MapSize = $a0
    0x30: ('AllocatePool',  1, 'size'),    # Size = $a1
}

# Argument register numbers for the expected size arguments
_A0, _A1, _A2 = 4, 5, 6


# ---------------------------------------------------------------------------
# Instruction masks for ld.d and jirl
# ---------------------------------------------------------------------------

# ld.d Rd, Rj, si12  — 2RI12+3R hybrid: bits[31:22] = 0b0010100011 = 163
_MATCH_LDD  = 0x28C00000   # 163 << 22
_MASK_LDD   = 0xFFC00000   # bits[31:22]

def _ldd_si12(word: int) -> int:
    """Extract signed 12-bit immediate from ld.d instruction."""
    raw = (word >> 10) & 0xFFF
    if raw & 0x800:
        raw |= -0x1000
    return raw

# jirl Rd, Rj, si16  — 2RI16: bits[31:26] = 0b010011 = 19
_MATCH_JIRL_TOP6 = 0x4C000000  # 19 << 26
_MASK_JIRL_TOP6  = 0xFC000000

# Maximum instructions to look backwards from a JIRL to find its ld.d loader
_DISPATCH_LOOKBACK = 4

# Maximum instructions to look ahead after the max-not-min OR instruction
_LOOKAHEAD = 20

# Branches use bits[4:0] as source, not destination — excluded from liveness kill
_BRANCH_TOP6: frozenset = frozenset({0x10, 0x11, 0x14, 0x15, 0x16, 0x17,
                                      0x18, 0x19, 0x1a, 0x1b})

# 2RI12-format stores: bits[31:22] opcode
_STORE_OP22: frozenset = frozenset({
    0x29c00000 >> 22, 0x2a000000 >> 22,
    0x2a400000 >> 22, 0x2a800000 >> 22,
})

# mul.d Rd, Rj, Rk (max-not-min through multiply → PLAUSIBLE_LOW)
_MATCH_MULD = 0x001D8000


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class UEFIFinding:
    pattern_va:  int        # VA of the sltu/slt instruction (start of 4-insn sequence)
    result_reg:  int        # register number carrying the max-not-min result
    sink_va:     int        # VA of the jirl call instruction
    gbs_func:    str        # EFI_BOOT_SERVICES function name (e.g. 'AllocatePool')
    gbs_offset:  int        # offset in gBS table (e.g. 0x30)
    sink_arg:    str        # argument label (e.g. 'size')
    compare_op:  str        # 'sltu' or 'slt'
    fp_class:    str = ''   # '' = real finding; 'copy_limit' = mul.d in chain

    def __str__(self) -> str:
        tag = f'  [{self.fp_class.upper()}]' if self.fp_class else ''
        arg_reg = f'$a{self.result_reg - 4}'
        return (
            f'UEFI_MAX_NOT_MIN  pattern@0x{self.pattern_va:x}'
            f'  {arg_reg} -> {self.gbs_func}(gBS+0x{self.gbs_offset:x},{self.sink_arg})'
            f'@0x{self.sink_va:x}' + tag
        )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class UEFISinkClassifierLA64:
    """
    Detect GCC 12.3.1.7 max-not-min bug findings reaching EFI_BOOT_SERVICES
    allocation calls in LA64 UEFI PE32+ images.

    Call flow:
        from_path(path) / from_pe32plus(data)
            → _find_dispatch_sites()   : maps JIRL VA → (gbs_func, arg_reg, label)
            → scan()                   : finds 4-insn max-not-min pattern, checks
                                         whether rout flows into the correct arg
                                         register at a known gBS JIRL
            → report(findings)
    """

    def __init__(self, data: bytes, text_va: int, text_sz: int, base: int = 0):
        self._data    = data
        self._text_va = text_va
        self._text_sz = text_sz
        self._base    = base

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_pe32plus(cls, data: bytes, image_base: int = 0) -> 'UEFISinkClassifierLA64':
        """Load a PE32+ UEFI image from raw bytes."""
        text_va = 0
        text_sz = len(data)
        base    = 0

        if len(data) >= 0x40:
            pe_off = struct.unpack_from('<I', data, 0x3c)[0]
            if pe_off + 24 <= len(data) and data[pe_off:pe_off + 4] == b'PE\x00\x00':
                num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
                opt_size     = struct.unpack_from('<H', data, pe_off + 20)[0]
                sect_off     = pe_off + 24 + opt_size
                for i in range(num_sections):
                    s = sect_off + i * 40
                    if s + 40 > len(data):
                        break
                    chars = struct.unpack_from('<I', data, s + 36)[0]
                    if chars & 0x20:  # IMAGE_SCN_CNT_CODE
                        vsize   = struct.unpack_from('<I', data, s + 8)[0]
                        vaddr   = struct.unpack_from('<I', data, s + 12)[0]
                        raw_sz  = struct.unpack_from('<I', data, s + 16)[0]
                        raw_off = struct.unpack_from('<I', data, s + 20)[0]
                        text_va = image_base + vaddr
                        text_sz = min(vsize, raw_sz)
                        base    = text_va - raw_off
                        break

        return cls(data, text_va, text_sz, base)

    @classmethod
    def from_path(cls, path: str) -> 'UEFISinkClassifierLA64':
        data = open(path, 'rb').read()
        return cls.from_pe32plus(data)

    # ------------------------------------------------------------------
    # Dispatch site detection
    # ------------------------------------------------------------------

    def _word_at(self, va: int) -> Optional[int]:
        off = va - self._base
        if off < 0 or off + 4 > len(self._data):
            return None
        return struct.unpack_from('<I', self._data, off)[0]

    def _find_dispatch_sites(self) -> Dict[int, Tuple[str, int, str]]:
        """
        Scan .text for gBS dispatch site pairs:
            ld.d  $rx, $ry, <gbs_offset>      ← load function pointer from gBS table
            jirl  $ra, $rx, 0                  ← indirect call (rd=$ra=1)

        The ld.d must appear within _DISPATCH_LOOKBACK instructions before the JIRL.
        The ld.d si12 immediate must be one of the _GBS_SINKS offsets.

        Returns {jirl_va: (func_name, arg_reg_number, arg_label)}.
        """
        sites: Dict[int, Tuple[str, int, str]] = {}
        va  = self._text_va
        end = self._text_va + self._text_sz

        while va < end:
            word = self._word_at(va)
            if word is None:
                break

            # Detect JIRL $ra, $rx, 0  (Rd=$ra=1, si16=0)
            is_jirl = (
                (word & _MASK_JIRL_TOP6) == _MATCH_JIRL_TOP6
                and _rd(word) == 1          # rd = $ra
                and (word >> 10) & 0xFFFF == 0  # si16 = 0
            )
            if is_jirl:
                rx = _rj(word)  # the register holding the function pointer
                # Look backwards for ld.d $rx, $ry, gbs_offset
                for back in range(1, _DISPATCH_LOOKBACK + 1):
                    prev_va   = va - back * 4
                    prev_word = self._word_at(prev_va)
                    if prev_word is None:
                        break
                    if (prev_word & _MASK_LDD) == _MATCH_LDD and _rd(prev_word) == rx:
                        offset = _ldd_si12(prev_word)
                        if offset in _GBS_SINKS:
                            sites[va] = _GBS_SINKS[offset]
                        break  # stop on first ld.d that writes rx

            va += 4

        return sites

    # ------------------------------------------------------------------
    # Max-not-min pattern scan
    # ------------------------------------------------------------------

    def scan(self) -> List[UEFIFinding]:
        """
        Find 4-instruction max-not-min patterns whose result flows into the
        correct argument register at a known gBS dispatch site within LOOKAHEAD
        instructions.
        """
        dispatch = self._find_dispatch_sites()
        if not dispatch:
            return []

        findings: List[UEFIFinding] = []
        va  = self._text_va
        end = self._text_va + self._text_sz - 12  # need at least 4 words

        while va < end:
            w0 = self._word_at(va)
            if w0 is None:
                break

            if (w0 & _MASK_3R) not in (_MATCH_SLTU, _MATCH_SLT):
                va += 4
                continue

            rcond = _rd(w0)
            ra    = _rj(w0)
            rb    = _rk(w0)

            w1 = self._word_at(va + 4)
            w2 = self._word_at(va + 8)
            w3 = self._word_at(va + 12)
            if w1 is None or w2 is None or w3 is None:
                break

            # masknez Rtmp1, Rb, Rcond
            if (w1 & _MASK_3R) != _MATCH_MASKNEZ or _rj(w1) != rb or _rk(w1) != rcond:
                va += 4
                continue
            rtmp1 = _rd(w1)

            # maskeqz Rtmp2, Ra, Rcond
            if (w2 & _MASK_3R) != _MATCH_MASKEQZ or _rj(w2) != ra or _rk(w2) != rcond:
                va += 4
                continue
            rtmp2 = _rd(w2)

            # or Rout, Rtmp2, Rtmp1 (commutative)
            if (w3 & _MASK_3R) != _MATCH_OR or {_rj(w3), _rk(w3)} != {rtmp1, rtmp2}:
                va += 4
                continue
            rout = _rd(w3)

            compare_op = 'slt' if (w0 & _MASK_3R) == _MATCH_SLT else 'sltu'

            # Lookahead for a gBS JIRL where rout is in the correct arg register
            hit = self._check_lookahead(va + 16, rout, dispatch)
            if hit:
                sink_va, func_name, gbs_offset, arg_label, fp_class = hit
                findings.append(UEFIFinding(
                    pattern_va = va,
                    result_reg = rout,
                    sink_va    = sink_va,
                    gbs_func   = func_name,
                    gbs_offset = gbs_offset,
                    sink_arg   = arg_label,
                    compare_op = compare_op,
                    fp_class   = fp_class,
                ))

            va += 4

        return findings

    def _check_lookahead(
        self,
        start_va: int,
        rout: int,
        dispatch: Dict[int, Tuple[str, int, str]],
    ) -> Optional[Tuple[int, str, int, str, str]]:
        """
        Walk up to _LOOKAHEAD instructions from start_va tracking rout.
        Return (sink_va, func_name, gbs_offset, arg_label, fp_class) on hit, else None.
        """
        live: Set[int] = {rout}
        is_copy_limit = False

        for i in range(_LOOKAHEAD):
            va   = start_va + i * 4
            word = self._word_at(va)
            if word is None:
                break

            # JIRL $ra, $rx, 0 at a known dispatch site
            if (
                (word & _MASK_JIRL_TOP6) == _MATCH_JIRL_TOP6
                and _rd(word) == 1
                and (word >> 10) & 0xFFFF == 0
            ):
                if va in dispatch:
                    func_name, expected_arg_pos, arg_label = dispatch[va]
                    expected_reg = _A0 + expected_arg_pos  # $a0=4, $a1=5, $a2=6
                    if expected_reg in live:
                        fp_class = 'copy_limit' if is_copy_limit else ''
                        # Reverse-lookup gbs_offset from func_name
                        gbs_off = next(
                            (k for k, v in _GBS_SINKS.items() if v[0] == func_name),
                            0
                        )
                        return (va, func_name, gbs_off, arg_label, fp_class)
                # Unknown JIRL: clobbers arg registers
                live -= _ARG_REGS
                continue

            # or Rd, Rj, $zero (register move): propagate liveness
            if (word & _MASK_3R) == _MATCH_OR and _rk(word) == 0:
                if _rj(word) in live:
                    live.add(_rd(word))
                continue

            # mul.d: tag copy_limit (max-not-min through multiply)
            if (word & _MASK_3R) == _MATCH_MULD:
                if _rj(word) in live or _rk(word) in live:
                    live.add(_rd(word))
                    is_copy_limit = True
                continue

            # Dead-register kill: any instruction writing live register
            rd = _rd(word)
            if rd != 0 and rd in live:
                top6  = word >> 26
                op22  = word >> 22
                if top6 not in _BRANCH_TOP6 and op22 not in _STORE_OP22:
                    live.discard(rd)

        return None

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def report(self, findings: List[UEFIFinding]) -> str:
        if not findings:
            return '[UEFISinkClassifierLA64] 0 findings (no gBS allocation sinks reached)\n'
        lines = [f'[UEFISinkClassifierLA64] {len(findings)} finding(s)']
        for f in findings:
            tag = f'  [{f.fp_class.upper()}]' if f.fp_class else ''
            lines.append(f'  {str(f)}{tag}')
        return '\n'.join(lines) + '\n'
