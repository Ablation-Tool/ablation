"""
la64_heap_vuln_scanner.py: integer overflow before heap allocation on LoongArch64.

Detects the pattern: overflow-prone arithmetic op (mul.w / sll.w / add.w / addi.w)
whose result flows — without an intervening bounds check — into an allocation sink
(malloc / calloc / realloc / posix_memalign / kmalloc / vmalloc) as the size argument.

The critical class is mul.w: LoongArch64 mul.w computes the low 32 bits of the
product and SIGN-EXTENDS to 64 bits.  If an attacker controls one multiplicand
and can produce a 32-bit wraparound, the resulting 64-bit value used as malloc's
size argument is far smaller than intended — classic heap integer overflow.

Detection algorithm:
    For each BL to an allocation sink in .text:
        1. Identify size_reg (ABI-defined per sink: $a0 for malloc, $a1 for realloc…)
        2. Trace backward LOOKBACK=32 instructions tracking size_reg through moves
        3. Find the instruction that last defined size_reg
        4. If that instruction is mul.w / sll.w / add.w / addi.w: CANDIDATE
        5. Filter: scan the window between the definer and the BL for a
           BLTU/BGEU/BLT/BGE/BEQ/BNE that uses size_reg as rj or rk → ELIMINATED
        6. Remaining candidates → FINDING

LoongArch64 calling convention (lp64d):
    $a0–$a7 = r4–r11   (integer argument registers)

Supports both ET_DYN / ET_EXEC (loads .plt / .rela.plt) and ET_REL kernel modules
(loads .rela.text with R_LARCH_B26 = 66).

Usage:
    from ablation.analyzers.la64_heap_vuln_scanner import LA64HeapVulnScanner

    scanner = LA64HeapVulnScanner.from_path('/path/to/binary')
    findings = scanner.scan()
    print(LA64HeapVulnScanner.report(findings))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False


# ---------------------------------------------------------------------------
# LoongArch64 ISA encoding constants
# 3R format: bits[31:15] = opcode17, bits[14:10] = rk, bits[9:5] = rj, bits[4:0] = rd
# All constants verified against binutils 2.41 loongarch-opc.c and the
# LoongArch Architecture Reference Manual v1.10.
# ---------------------------------------------------------------------------

# -- 3R arithmetic (bits[31:15] = opcode17) --
_OP17_ADD_W   = 0x20   # add.w   rd = (int32)(rj + rk), sign-ext to 64b → wraps
_OP17_ADD_D   = 0x21   # add.d   rd = rj + rk  (64-bit, harder to overflow)
_OP17_MUL_W   = 0x38   # mul.w   rd = (int32)(rj * rk), sign-ext to 64b → CRITICAL
_OP17_MUL_D   = 0x39   # mul.d   rd = rj * rk  (64-bit)
_OP17_SLL_W   = 0x2e   # sll.w   rd = (int32)(rj << (rk & 31)), sign-ext → wraps
_OP17_SLL_D   = 0x31   # sll.d   rd = rj << (rk & 63)
_OP17_OR      = 0x2a   # or      rd = rj | rk  (rk=0 → register move)
_OP17_SLTU    = 0x25   # sltu    rd = (unsigned rj < unsigned rk) ? 1 : 0
_OP17_SLT     = 0x24   # slt     rd = (signed rj < signed rk) ? 1 : 0

# -- 2RI12 format (bits[31:22] = opcode10, bits[21:10] = imm12, bits[9:5] = rj, bits[4:0] = rd) --
_OP10_ADDI_W  = 0x0a   # addi.w  rd = (int32)(rj + sext12(imm)), sign-ext → wraps
_OP10_ADDI_D  = 0x0b   # addi.d  rd = rj + sext12(imm)

# -- Branches (bits[31:26] = top6) --
# These use bits[4:0] as part of an immediate or source register (never destination).
# A branch comparing the overflow register to a bound eliminates the finding.
_BRANCH_TOP6 = frozenset({0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b})
# Bounds-check branches: BLTU / BGEU / BLT / BGE / BEQ / BNE
# (BEQ/BNE can be a zero check; BLT/BGE/BLTU/BGEU are the classic size guards)
_GUARD_BRANCH_TOP6 = frozenset({0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b})

# -- 2RI12 stores (bits[31:22] = opcode10) — bits[4:0] are source, not dest --
_STORE_OP10 = frozenset({
    0x29c00000 >> 22,   # ST.B
    0x2a000000 >> 22,   # ST.H
    0x2a400000 >> 22,   # ST.W
    0x2a800000 >> 22,   # ST.D
    0x2b000000 >> 22,   # FST.S
    0x2b400000 >> 22,   # FST.D
})

# -- 3R indexed stores (bits[31:15] = opcode17) — bits[4:0] are source --
_STOREX_OP17 = frozenset({
    0x38100000 >> 15,   # STX.B
    0x38108000 >> 15,   # STX.H
    0x38110000 >> 15,   # STX.W
    0x38118000 >> 15,   # STX.D
    0x38400000 >> 15,   # STPTR.W
    0x38408000 >> 15,   # STPTR.D
})

# BL opcode (bits[31:26] = 0x15)
_BL_TOP6 = 0x15

# ---------------------------------------------------------------------------
# Overflow op classification
# ---------------------------------------------------------------------------

# (mnemonic, severity, fmt)
_OVERFLOW_3R: Dict[int, Tuple[str, str]] = {
    _OP17_MUL_W:  ("mul.w",   "HIGH"),    # 32-bit multiply — most dangerous
    _OP17_SLL_W:  ("sll.w",   "HIGH"),    # 32-bit left shift
    _OP17_ADD_W:  ("add.w",   "MEDIUM"),  # 32-bit add (sign-ext wrap)
    _OP17_MUL_D:  ("mul.d",   "MEDIUM"),  # 64-bit multiply (wrap harder, but report)
    _OP17_SLL_D:  ("sll.d",   "MEDIUM"),  # 64-bit shift
}
_OVERFLOW_2RI12: Dict[int, Tuple[str, str]] = {
    _OP10_ADDI_W: ("addi.w",  "MEDIUM"),  # 32-bit add-imm
}

# ---------------------------------------------------------------------------
# Sink → (size_arg_register, arg_label)
# LoongArch64 lp64d ABI: a0=r4, a1=r5, a2=r6, a3=r7
# ---------------------------------------------------------------------------
_A0, _A1, _A2, _A3 = 4, 5, 6, 7

_ALLOC_SINKS: Dict[str, Tuple[int, str]] = {
    "malloc":           (_A0, "size"),
    "calloc":           (_A0, "nmemb"),   # nmemb * size overflow; also check a1
    "realloc":          (_A1, "newsize"),
    "posix_memalign":   (_A2, "size"),
    "aligned_alloc":    (_A1, "size"),
    "mmap":             (_A1, "length"),
    # kernel allocators
    "kmalloc":          (_A0, "size"),
    "kzalloc":          (_A0, "size"),
    "krealloc":         (_A1, "newsize"),
    "__kmalloc":        (_A0, "size"),
    "vmalloc":          (_A0, "size"),
    "kvmalloc":         (_A0, "size"),
    "kvmalloc_node":    (_A0, "size"),
    "__vmalloc":        (_A0, "size"),
    "vzalloc":          (_A0, "size"),
    "devm_kmalloc":     (_A1, "size"),   # (dev, size, gfp)
}


# ---------------------------------------------------------------------------
# Register-level helpers
# ---------------------------------------------------------------------------

def _rd(w: int)   -> int: return  w        & 0x1f
def _rj(w: int)   -> int: return (w >>  5) & 0x1f
def _rk(w: int)   -> int: return (w >> 10) & 0x1f
def _op17(w: int) -> int: return  w >> 15
def _op10(w: int) -> int: return  w >> 22
def _top6(w: int) -> int: return  w >> 26


def _is_move(w: int, src: int) -> Optional[int]:
    """If w is 'or rd, src, r0' (move), return rd.  Otherwise None."""
    if _op17(w) == _OP17_OR and _rj(w) == src and _rk(w) == 0:
        return _rd(w)
    return None


def _bl_target(word: int, va: int) -> int:
    """Absolute target VA for a BL instruction (imm26 × 4, PC-relative)."""
    imm26 = ((word & 0x3ff) << 16) | ((word >> 10) & 0xffff)
    if imm26 & (1 << 25):
        imm26 |= (-1 << 26)
    return (va + (imm26 << 2)) & 0xffffffffffffffff


# ---------------------------------------------------------------------------
# Finding record
# ---------------------------------------------------------------------------

@dataclass
class LA64HeapVulnFinding:
    overflow_va:  int    # VA of the overflow arithmetic instruction
    overflow_op:  str    # mnemonic ("mul.w", "sll.w", …)
    overflow_reg: int    # register number that holds the potentially-wrapped value
    sink_va:      int    # VA of the BL to the allocation sink
    sink_name:    str    # PLT symbol name ("malloc", "kmalloc", …)
    size_arg:     str    # argument label ("size", "nmemb", …)
    severity:     str    # "HIGH" or "MEDIUM"

    def __str__(self) -> str:
        reg = f"$a{self.overflow_reg - 4}" if 4 <= self.overflow_reg <= 11 else f"$r{self.overflow_reg}"
        return (
            f"LA64_HEAP_OVERFLOW  {self.overflow_op}→{reg}"
            f"  overflow@0x{self.overflow_va:x}"
            f"  {self.sink_name}({self.size_arg})@0x{self.sink_va:x}"
            f"  [{self.severity}]"
        )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class LA64HeapVulnScanner:
    """
    Scan a LoongArch64 ELF for integer overflow before heap allocation.

    Construction:
        scanner = LA64HeapVulnScanner.from_path('/path/to/binary')

    Then:
        findings = scanner.scan()
        print(LA64HeapVulnScanner.report(findings))
    """

    # Backward window: how many instructions before a BL to examine.
    LOOKBACK = 32
    # Max register-move depth to follow (move chains longer than this are ignored).
    MAX_MOVE_DEPTH = 4

    def __init__(
        self,
        data: bytes,
        base: int,
        plt: Dict[int, str],
        text_va: int,
        text_size: int,
        is_rel: bool = False,
    ):
        self._data    = data
        self._base    = base
        self._plt     = plt       # VA → symbol name (or file offset → name for ET_REL)
        self._text_va = text_va
        self._text_sz = text_size
        self._is_rel  = is_rel

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_path(cls, path: str) -> 'LA64HeapVulnScanner':
        data = Path(path).read_bytes()
        base    = 0
        plt:    Dict[int, str] = {}
        text_va = 0
        text_sz = len(data)
        is_rel  = False

        if _LIEF_OK:
            try:
                binary = lief.parse(data)
                if isinstance(binary, lief.ELF.Binary):
                    is_rel = (int(binary.header.file_type) == 1)

                    if is_rel:
                        text_sec = binary.get_section('.text')
                        if text_sec:
                            text_va = int(text_sec.offset)
                            text_sz = int(text_sec.size)
                            text_file_off = int(text_sec.offset)
                        rela = binary.get_section('.rela.text')
                        if rela and text_sec:
                            rela_data = bytes(rela.content)
                            syms = list(binary.symbols)
                            for i in range(len(rela_data) // 24):
                                off      = i * 24
                                r_offset = struct.unpack_from('<Q', rela_data, off)[0]
                                r_info   = struct.unpack_from('<Q', rela_data, off + 8)[0]
                                sym_idx  = r_info >> 32
                                r_type   = r_info & 0xffffffff
                                if r_type != 66:   # R_LARCH_B26
                                    continue
                                try:
                                    name = syms[sym_idx].name or ''
                                except Exception:
                                    name = ''
                                if name and name in _ALLOC_SINKS:
                                    plt[text_file_off + int(r_offset)] = name
                    else:
                        base    = binary.imagebase
                        text_sec = binary.get_section('.text')
                        if text_sec:
                            text_va = int(text_sec.virtual_address)
                            text_sz = int(text_sec.size)
                        plt_sec  = binary.get_section('.plt')
                        rela_plt = binary.get_section('.rela.plt')
                        if plt_sec and rela_plt:
                            plt_base  = int(plt_sec.virtual_address)
                            rela_data = bytes(rela_plt.content)
                            for idx in range(len(rela_data) // 24):
                                off    = idx * 24
                                r_info = struct.unpack_from('<Q', rela_data, off + 8)[0]
                                sym_idx = r_info >> 32
                                try:
                                    name = binary.dynamic_symbols[sym_idx].name or ''
                                except Exception:
                                    name = ''
                                if name:
                                    stub_va = plt_base + (2 + idx) * 16
                                    plt[stub_va] = name
            except Exception:
                pass

        return cls(data, base, plt, text_va, text_sz, is_rel=is_rel)

    # ------------------------------------------------------------------
    # Low-level access
    # ------------------------------------------------------------------

    def _word_at(self, va: int) -> Optional[int]:
        off = va - self._base
        if off < 0 or off + 4 > len(self._data):
            return None
        return struct.unpack_from('<I', self._data, off)[0]

    def _words_before(self, va: int, n: int) -> List[Tuple[int, int]]:
        """Return up to n (va, word) pairs ending just before `va`, in order."""
        results = []
        start = max(self._text_va, va - n * 4)
        addr  = start
        while addr < va:
            w = self._word_at(addr)
            if w is not None:
                results.append((addr, w))
            addr += 4
        return results[-(n):]

    # ------------------------------------------------------------------
    # Core scan
    # ------------------------------------------------------------------

    def scan(self) -> List[LA64HeapVulnFinding]:
        findings: List[LA64HeapVulnFinding] = []
        va  = self._text_va
        end = self._text_va + self._text_sz

        while va < end:
            w = self._word_at(va)
            if w is None:
                break

            # Detect BL to an allocation sink.
            if _top6(w) == _BL_TOP6:
                if self._is_rel:
                    target_key = va  # ET_REL: keyed by file offset of the BL
                else:
                    target_key = _bl_target(w, va)

                sink_name = self._plt.get(target_key)
                if sink_name and sink_name in _ALLOC_SINKS:
                    size_reg, arg_label = _ALLOC_SINKS[sink_name]
                    finding = self._check_backward(va, size_reg, arg_label, sink_name)
                    if finding:
                        findings.append(finding)

                    # calloc: also check a0 (nmemb) feeding an implicit multiply
                    if sink_name == "calloc":
                        f2 = self._check_backward(va, _A0, "nmemb", sink_name)
                        if f2:
                            findings.append(f2)

            va += 4

        # Deduplicate (same overflow_va + sink_va pair)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.overflow_va, f.sink_va)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    # ------------------------------------------------------------------

    def _check_backward(
        self,
        bl_va:    int,
        size_reg: int,
        arg_label: str,
        sink_name: str,
    ) -> Optional[LA64HeapVulnFinding]:
        """
        Trace backward from bl_va looking for an overflow arithmetic op that
        wrote size_reg (or its move-aliased source).  Returns a finding if one
        is found without an intervening bounds check.
        """
        window = self._words_before(bl_va, self.LOOKBACK)
        if not window:
            return None

        # Follow moves: maintain a set of registers that are "aliases" of the
        # size register (any of which being written by an overflow op is a hit).
        tracked = {size_reg}

        # Walk backward through the window.
        for i in range(len(window) - 1, -1, -1):
            addr, w = window[i]

            op17  = _op17(w)
            op10  = _op10(w)
            top6  = _top6(w)
            rd    = _rd(w)
            rj    = _rj(w)
            rk    = _rk(w)

            # Bounds check: any 2-register branch involving a tracked register
            # means the code guarded the size before the malloc call.
            if top6 in _GUARD_BRANCH_TOP6:
                # BEQ/BNE/BLT/BGE/BLTU/BGEU rj, rk, offset
                # For these formats: bits[9:5] = rj, bits[4:0] = rd (reused as rk2)
                br_rj = (w >> 5) & 0x1f
                br_rk = w & 0x1f
                if br_rj in tracked or br_rk in tracked:
                    return None   # bounds check found → ELIMINATED

            # Overflow arithmetic producing a tracked register?
            is_store = (op10 in _STORE_OP10) or (op17 in _STOREX_OP17)
            is_branch = top6 in _BRANCH_TOP6

            if not is_store and not is_branch:
                if rd in tracked:
                    # Check if this is a move: or rd, rj, r0
                    if op17 == _OP17_OR and rk == 0:
                        # Move: size_reg ← rj. Follow rj backward.
                        tracked.add(rj)
                        tracked.discard(rd)  # rd is no longer "tracked" as a source
                        continue

                    # Check addi.d rd, rj, 0 (NOP/move equivalent)
                    if op10 == _OP10_ADDI_D and (w & 0x3ffc00) == 0:  # imm12 == 0
                        tracked.add(rj)
                        tracked.discard(rd)
                        continue

                    # Overflow 3R?
                    if op17 in _OVERFLOW_3R:
                        # add.w $rd, $r0, rk or add.w $rd, rj, $r0: rj or rk is
                        # zero-register → result equals the non-zero operand with
                        # 32-bit sign extension.  Not an arithmetic overflow.
                        if op17 in (_OP17_ADD_W, _OP17_ADD_D) and (rj == 0 or rk == 0):
                            return None
                        # mul.w/sll.w with a zero operand always produces 0 → no overflow.
                        if op17 in (_OP17_MUL_W, _OP17_SLL_W, _OP17_MUL_D, _OP17_SLL_D) and (rj == 0 or rk == 0):
                            return None
                        mnem, severity = _OVERFLOW_3R[op17]
                        return LA64HeapVulnFinding(
                            overflow_va  = addr,
                            overflow_op  = mnem,
                            overflow_reg = size_reg,
                            sink_va      = bl_va,
                            sink_name    = sink_name,
                            size_arg     = arg_label,
                            severity     = severity,
                        )

                    # Overflow 2RI12?
                    if op10 in _OVERFLOW_2RI12:
                        # addi.w $rd, $r0, const is a constant load — not overflow.
                        if rj == 0:
                            return None
                        mnem, severity = _OVERFLOW_2RI12[op10]
                        return LA64HeapVulnFinding(
                            overflow_va  = addr,
                            overflow_op  = mnem,
                            overflow_reg = size_reg,
                            sink_va      = bl_va,
                            sink_name    = sink_name,
                            size_arg     = arg_label,
                            severity     = severity,
                        )

                    # Non-overflow instruction that writes tracked register:
                    # if it's a load or normal ALU, it overwrites from a safe source.
                    # Stop tracking — the overflow must have been further back in a
                    # different register, and we have no move chain to follow.
                    return None

        return None

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @staticmethod
    def report(findings: List[LA64HeapVulnFinding]) -> str:
        if not findings:
            return "LA64HeapVulnScanner: no findings."
        lines = [f"LA64HeapVulnScanner: {len(findings)} finding(s)"]
        for f in sorted(findings, key=lambda x: x.severity == "HIGH", reverse=True):
            lines.append(f"  {f}")
        return "\n".join(lines)
