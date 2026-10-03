"""
loongarch64_max_not_min_scanner.py: detects the GCC 12.3.1.7 LoongArch64 min-to-max
code-generation bug and checks whether the wrong value flows into a memory sink.

GCC for LoongArch64 branchless min/max uses a four-instruction sequence:

    sltu   Rcond, Ra, Rb      # Rcond = (Ra < Rb) unsigned
    masknez Rtmp1, Rb, Rcond  # Rtmp1 = (Rcond != 0) ? Rb : 0   -- selects Rb when Ra<Rb
    maskeqz Rtmp2, Ra, Rcond  # Rtmp2 = (Rcond == 0) ? Ra : 0   -- selects Ra when Ra>=Rb
    or     Rout, Rtmp2, Rtmp1 # Rout  = Rtmp1 | Rtmp2

That implements max(Ra, Rb). Correct min(Ra, Rb) swaps the masknez/maskeqz order.
In GCC 12.3.1.7-1.tl4 the swap is missing, so every branchless min emits max.

The scanner finds the four-instruction MAX sequence and checks whether Rout reaches
a memory-sizing sink (memcpy/memmove count, read/fread count, malloc size) within a
configurable lookahead window without being clobbered. A hit means the operation
uses max(Ra,Rb) as a size where min(Ra,Rb) was intended -- a classic heap overread
or heap overflow depending on which argument is the allocation size.

Affected corpus: TencentOS Server 4.6 LoongArch64, GCC 12.3.1.7-1.tl4.
Root CVE class: CWE-122 (heap-based buffer overflow) / CWE-125 (out-of-bounds read).

Usage:
    from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner

    scanner = LA64MaxNotMinScanner.from_path('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False


# ---------------------------------------------------------------------------
# Instruction encoding constants (from binutils 2.41 loongarch-opc.c)
# All 3R format: bits[31:15] = opcode, bits[14:10] = rk, bits[9:5] = rj, bits[4:0] = rd
# ---------------------------------------------------------------------------

_MATCH_SLTU    = 0x00128000
_MATCH_MASKEQZ = 0x00130000
_MATCH_MASKNEZ = 0x00138000
_MATCH_OR      = 0x00150000
_MASK_3R       = 0xffff8000   # bits[31:15]

_MATCH_BL      = 0x54000000
_MASK_BL       = 0xfc000000   # bl offs26

_MATCH_JIRL    = 0x4c000000
_MASK_JIRL     = 0xfc000000

_MATCH_MULD    = 0x001d8000   # mul.d Rd, Rj, Rk (3R format)

# Comparison branches used as capacity guards in Rust Vec-growth: blt/bge/bltu/bgeu.
# When >= 2 of these appear in the lookahead window before a memset sink the pattern
# is Rust Vec-resize (intentional max(cap*2, len+needed) → memset), not an overflow.
_VEC_GUARD_TOP6: frozenset = frozenset({0x18, 0x19, 0x1a, 0x1b})  # BLT BGE BLTU BGEU
_VEC_GUARD_THRESHOLD = 2

# ---------------------------------------------------------------------------
# Dead-register kill tables (Cifuentes §5.4.1 liveness analysis).
# LoongArch64 stores and conditional branches use bits[4:0] as a SOURCE
# register, NOT a destination.  Every other instruction class writes rd.
# ---------------------------------------------------------------------------

# 2RI12-format stores: bits[31:22] opcode  (ST.B / ST.H / ST.W / ST.D)
_STORE_OP22: frozenset = frozenset({
    0x29c00000 >> 22,   # ST.B
    0x2a000000 >> 22,   # ST.H
    0x2a400000 >> 22,   # ST.W
    0x2a800000 >> 22,   # ST.D
    0x2b000000 >> 22,   # FST.S
    0x2b400000 >> 22,   # FST.D
})

# 3R-format indexed stores: bits[31:15] opcode  (STX.B / STX.H / STX.W / STX.D)
_STOREX_OP15: frozenset = frozenset({
    0x38100000 >> 15,   # STX.B
    0x38108000 >> 15,   # STX.H
    0x38110000 >> 15,   # STX.W
    0x38118000 >> 15,   # STX.D
    0x38400000 >> 15,   # STPTR.W
    0x38408000 >> 15,   # STPTR.D
})

# Conditional branches: bits[31:26] opcode — bits[4:0] are part of the
# offset immediate or a source register, never a destination.
_BRANCH_TOP6: frozenset = frozenset({
    0x10,  # BEQZ
    0x11,  # BNEZ
    0x14,  # B
    0x15,  # BL   (handled before we reach the kill check, but included for safety)
    0x16,  # BEQ
    0x17,  # BNE
    0x18,  # BLT
    0x19,  # BGE
    0x1a,  # BLTU
    0x1b,  # BGEU
})

# OR instruction used as a register move: or Rd, Rj, $zero (rk=0)
_MASK_OR_MOVE  = 0xffff83e0   # bits[31:15] + bits[14:10] (rk forced to 0)
_MATCH_OR_MOVE = 0x00150000   # rk=0 encodes as bits[14:10]=00000

# Argument registers (lp64 ABI)
_ARG_REGS: Set[int] = {4, 5, 6, 7, 8, 9, 10, 11}  # $a0-$a7 (r4-r11)
_A0, _A1, _A2 = 4, 5, 6  # memcpy(dst=$a0, src=$a1, count=$a2); read(fd=$a0, buf=$a1, n=$a2)


def _rd(word: int) -> int:  return  word        & 0x1f
def _rj(word: int) -> int:  return (word >>  5) & 0x1f
def _rk(word: int) -> int:  return (word >> 10) & 0x1f


def _bl_target(word: int, va: int) -> int:
    """Resolve absolute target VA for a bl instruction."""
    # imm26: upper 10 bits are word[9:0], lower 16 bits are word[25:10]
    imm26 = ((word & 0x3ff) << 16) | ((word >> 10) & 0xffff)
    if imm26 & (1 << 25):
        imm26 |= (-1 << 26)
    return (va + (imm26 << 2)) & 0xffffffffffffffff


# ---------------------------------------------------------------------------
# Sink descriptors
# Keyed by canonical PLT symbol name; value is the argument register index
# (0-based into the lp64 integer argument registers $a0-$a7) that carries
# the dangerous size value produced by the max-not-min bug.
# ---------------------------------------------------------------------------

_SINKS: Dict[str, Tuple[int, str]] = {
    # (arg_reg_number, human label)
    "memcpy":          (_A2, "count"),
    "memmove":         (_A2, "count"),
    "memset":          (_A2, "count"),
    "__memcpy":        (_A2, "count"),
    "__memmove":       (_A2, "count"),
    "read":            (_A2, "nbytes"),
    "pread":           (_A2, "nbytes"),
    "pread64":         (_A2, "nbytes"),
    "fread":           (_A2, "nmemb"),
    "fgets":           (_A1, "size"),
    "recv":            (_A2, "len"),
    "recvfrom":        (_A2, "len"),
    "malloc":          (_A0, "size"),
    "calloc":          (_A0, "nmemb"),
    "realloc":         (_A1, "size"),
    "posix_memalign":  (_A2, "size"),
    "kmalloc":         (_A0, "size"),
    "vmalloc":         (_A0, "size"),
    "kzalloc":         (_A0, "size"),
    "__kmalloc":       (_A0, "size"),
}


# ---------------------------------------------------------------------------
# Finding record
# ---------------------------------------------------------------------------

@dataclass
class LA64MaxNotMinFinding:
    func_va:    int         # VA of the enclosing function (0 if unknown)
    pattern_va: int         # VA of the sltu instruction (start of 4-insn sequence)
    result_reg: int         # register number of the or result
    result_name: str        # ABI name of result_reg
    sink_va:    int         # VA of the bl to the sink
    sink_name:  str         # PLT symbol name
    sink_arg:   str         # argument label ("count", "size", etc.)
    context:    str = ""    # disassembly snippet
    fp_class:   str = ""    # "": real finding; "vec_growth": ELIMINATED (Rust Vec-resize);
                            # "copy_limit": PLAUSIBLE_LOW (max*elem_size via mul.d)

    def __str__(self) -> str:
        tag = f"  [{self.fp_class.upper()}]" if self.fp_class else ""
        return (f"LA64_MAX_NOT_MIN  pattern@0x{self.pattern_va:x}"
                f"  {self.result_name} -> {self.sink_name}({self.sink_arg})"
                f"@0x{self.sink_va:x}"
                + (f"  [{self.context}]" if self.context else "")
                + tag)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class LA64MaxNotMinScanner:
    """
    Scans a LoongArch64 ELF or PE32+ (UEFI DXE) binary for the GCC 12.3.1.7
    max-not-min sequence and confirms whether the result reaches a sink.

    ELF mode  : from_path(elf)     -> scan() -> report(findings)
    PE32+ mode: from_pe32plus(data) -> scan() -> report(findings)

    In PE32+ mode, PLT resolution is impossible (no GOT/PLT; external calls go
    through EFI Boot Services Table pointers via JIRL).  Instead, any BL or JIRL
    where the max-not-min result is live in an argument register ($a0-$a7) at
    call time is reported with sink_name "<direct>" or "<indirect>".
    """

    # How far to look past the `or` instruction for a sink call.
    LOOKAHEAD = 20

    def __init__(self, data: bytes, base: int, plt: Dict[int, str],
                 text_va: int, text_size: int, is_rel: bool = False,
                 pe32plus: bool = False):
        self._data     = data
        self._base     = base
        self._plt      = plt
        self._text_va  = text_va
        self._text_sz  = text_size
        self._is_rel   = is_rel    # True for ET_REL (kernel modules): plt keyed by file offset
        self._pe32plus = pe32plus  # True for UEFI PE32+: arg-register feed detection only

    @classmethod
    def from_path(cls, path: str) -> 'LA64MaxNotMinScanner':
        data = Path(path).read_bytes()
        base     = 0
        plt:     Dict[int, str] = {}
        text_va  = 0
        text_sz  = len(data)

        _is_rel_flag = False
        if _LIEF_OK:
            try:
                binary = lief.parse(data)
                if isinstance(binary, lief.ELF.Binary):
                    _is_rel_flag = (int(binary.header.file_type) == 1)  # ET_REL = 1
                    is_rel = _is_rel_flag

                    if is_rel:
                        # ET_REL (kernel module): sections have no load VA.
                        # Use file offset as the "VA" so that _words_at(offset, n)
                        # computes off = offset - base = offset - offset = 0 from section start.
                        # base stays 0; text_va = section file offset.
                        text_sec = binary.get_section('.text')
                        if text_sec:
                            text_va = int(text_sec.offset)
                            text_sz = int(text_sec.size)

                        # Build sink map from .rela.text: relocations that target external
                        # symbols (UND) are calls to kernel exports like kmalloc/memcpy.
                        # RELA entry for a BL is placed at the BL instruction's file offset.
                        rela_text = binary.get_section('.rela.text')
                        if rela_text:
                            rela_data = bytes(rela_text.content)
                            entry_size = 24  # Rela64
                            text_file_off = int(text_sec.offset) if text_sec else 0
                            syms = list(binary.symbols)
                            for i in range(len(rela_data) // entry_size):
                                off = i * entry_size
                                r_offset = struct.unpack_from('<Q', rela_data, off)[0]
                                r_info   = struct.unpack_from('<Q', rela_data, off + 8)[0]
                                sym_idx  = r_info >> 32
                                r_type   = r_info & 0xffffffff
                                # R_LARCH_B26 = 66 (0x42) — BL relocation type for function calls
                                if r_type != 66:
                                    continue
                                try:
                                    sym = syms[sym_idx]
                                    name = sym.name or ''
                                except Exception:
                                    name = ''
                                if name and name in _SINKS:
                                    # r_offset is the offset within .text where the BL lives
                                    call_file_off = text_file_off + r_offset
                                    plt[call_file_off] = name
                    else:
                        base = binary.imagebase
                        text_sec = binary.get_section('.text')
                        if text_sec:
                            text_va = int(text_sec.virtual_address)
                            text_sz = int(text_sec.size)

                        # LoongArch64 PLT uses 2-slot (32-byte) header; stubs start at index 2.
                        # Each PLT stub is 16 bytes (4 instructions: pcaddu12i + ld.d + jirl + nop).
                        plt_sec  = binary.get_section('.plt')
                        rela_plt = binary.get_section('.rela.plt')
                        if plt_sec and rela_plt:
                            plt_base = int(plt_sec.virtual_address)
                            rela_data = bytes(rela_plt.content)
                            entry_size = 24
                            for idx in range(len(rela_data) // entry_size):
                                off = idx * entry_size
                                r_info = struct.unpack_from('<Q', rela_data, off + 8)[0]
                                sym_idx = r_info >> 32
                                try:
                                    sym = binary.dynamic_symbols[sym_idx]
                                    name = sym.name or ''
                                except Exception:
                                    name = ''
                                if name:
                                    stub_va = plt_base + (2 + idx) * 16
                                    plt[stub_va] = name
            except Exception:
                pass

        return cls(data, base, plt, text_va, text_sz, is_rel=_is_rel_flag)

    @classmethod
    def from_pe32plus(cls, data: bytes, image_base: int = 0) -> 'LA64MaxNotMinScanner':
        """
        Load a PE32+ (UEFI DXE/PEIM) binary for scanning.

        Parses the PE32+ section table to find the first code section (.text),
        then sets up the VA→file-offset bias so the standard _words_at() path
        works without modification.

        Because PE32+ has no PLT/GOT, sink names cannot be resolved.  The
        scanner instead reports any BL/JIRL call site where the max-not-min
        result is live in an argument register at call time.  Confirm sinks
        manually: AllocatePool is always JIRL through the Boot Services Table;
        CopyMem/SetMem are similar.

        Parameters
        ----------
        data        : raw file bytes of the .efi module
        image_base  : preferred load address reported in the optional header
                      (pass 0 to use the on-disk section layout directly)
        """
        text_va  = 0
        text_sz  = 0
        # bias = image_base + vaddr - raw_off  so that off = va - bias = raw_off + delta
        base     = 0

        found_text = False
        if len(data) >= 0x40:
            pe_off = struct.unpack_from('<I', data, 0x3c)[0]
            if pe_off + 24 <= len(data) and data[pe_off:pe_off+4] == b'PE\x00\x00':
                num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
                opt_size     = struct.unpack_from('<H', data, pe_off + 20)[0]
                sect_off     = pe_off + 24 + opt_size
                for i in range(num_sections):
                    s = sect_off + i * 40
                    if s + 40 > len(data):
                        break
                    chars   = struct.unpack_from('<I', data, s + 36)[0]
                    # IMAGE_SCN_CNT_CODE (0x20) marks executable sections
                    if chars & 0x20:
                        vsize   = struct.unpack_from('<I', data, s + 8)[0]
                        vaddr   = struct.unpack_from('<I', data, s + 12)[0]
                        raw_sz  = struct.unpack_from('<I', data, s + 16)[0]
                        raw_off = struct.unpack_from('<I', data, s + 20)[0]
                        text_va  = image_base + vaddr
                        text_sz  = min(vsize, raw_sz)
                        # bias: _words_at(va) computes off = va - base
                        # we want off = raw_off when va = text_va
                        base     = text_va - raw_off
                        found_text = True
                        break

        if not found_text:
            # Fallback: treat the whole file as a flat .text region at VA 0
            text_va = 0
            text_sz = len(data)
            base    = 0

        return cls(data, base, {}, text_va, text_sz, is_rel=False, pe32plus=True)

    # ------------------------------------------------------------------

    def _words_at(self, va: int, count: int) -> Optional[List[int]]:
        """Read `count` 32-bit LE words starting at VA. Returns None on bounds error."""
        off = va - self._base
        need = count * 4
        if off < 0 or off + need > len(self._data):
            return None
        return list(struct.unpack_from(f'<{count}I', self._data, off))

    def _word_at(self, va: int) -> Optional[int]:
        words = self._words_at(va, 1)
        return words[0] if words else None

    # ------------------------------------------------------------------

    def scan(self) -> List[LA64MaxNotMinFinding]:
        """
        Slide a 4-word window over .text looking for the MAX sequence, then
        confirm the or-result reaches a sink within LOOKAHEAD instructions.
        """
        findings: List[LA64MaxNotMinFinding] = []
        va = self._text_va
        end_va = self._text_va + self._text_sz - 12  # need at least 4 words

        while va < end_va:
            words = self._words_at(va, 4)
            if words is None:
                break

            w0, w1, w2, w3 = words

            # Instruction 0: sltu Rcond, Ra, Rb
            if (w0 & _MASK_3R) != _MATCH_SLTU:
                va += 4
                continue

            rcond = _rd(w0)
            ra    = _rj(w0)
            rb    = _rk(w0)

            # Instruction 1: masknez Rtmp1, Rb, Rcond   (MAX path: selects Rb when Ra<Rb)
            if (w1 & _MASK_3R) != _MATCH_MASKNEZ:
                va += 4
                continue
            if _rj(w1) != rb or _rk(w1) != rcond:
                va += 4
                continue
            rtmp1 = _rd(w1)

            # Instruction 2: maskeqz Rtmp2, Ra, Rcond   (MAX path: selects Ra when Ra>=Rb)
            if (w2 & _MASK_3R) != _MATCH_MASKEQZ:
                va += 4
                continue
            if _rj(w2) != ra or _rk(w2) != rcond:
                va += 4
                continue
            rtmp2 = _rd(w2)

            # Instruction 3: or Rout, Rtmp2, Rtmp1  (or commuted: Rtmp1, Rtmp2)
            # OR is commutative; GCC may emit either operand order depending on
            # register allocation.  Use set equality to accept both.
            if (w3 & _MASK_3R) != _MATCH_OR:
                va += 4
                continue
            if {_rj(w3), _rk(w3)} != {rtmp1, rtmp2}:
                va += 4
                continue
            rout = _rd(w3)

            # Found the MAX sequence. Now check the lookahead window for a sink.
            hit = self._check_lookahead(va + 16, rout)
            if hit:
                sink_va, sink_name, sink_arg, fp_class = hit
                ctx = self._context_snippet(va)
                findings.append(LA64MaxNotMinFinding(
                    func_va    = 0,  # not needed for triage; callers can fill in
                    pattern_va = va,
                    result_reg = rout,
                    result_name = self._reg_name(rout),
                    sink_va    = sink_va,
                    sink_name  = sink_name,
                    sink_arg   = sink_arg,
                    context    = ctx,
                    fp_class   = fp_class,
                ))

            va += 4

        return findings

    def _check_lookahead(
        self, start_va: int, rout: int
    ) -> Optional[Tuple[int, str, str, str]]:
        """
        Walk up to LOOKAHEAD instructions from start_va. Track register rout.
        Return (sink_va, sym, arg_label) if rout flows into a sink arg, else None.

        ELF mode:
          - rout already in a sink arg position when bl fires
          - or Rx, rout, $zero (move rout -> Rx)
          - addi.d Rx, rout, 0  (zero-offset add = move; mask 0xffc003ff)

        PE32+ mode (self._pe32plus):
          - No PLT. Any BL or JIRL where a live register is in $a0-$a7 is
            reported as sink_name="<direct>" or "<indirect>".
        """
        # current_reg tracks which register currently holds the max-not-min value
        live: Set[int] = {rout}

        for i in range(self.LOOKAHEAD):
            va = start_va + i * 4
            word = self._word_at(va)
            if word is None:
                break

            # BL instruction
            if (word & _MASK_BL) == _MATCH_BL:
                if self._pe32plus:
                    # PE32+: no PLT — report if any live reg is an argument register
                    live_args = live & _ARG_REGS
                    if live_args:
                        arg_reg = min(live_args)
                        return (va, "<direct>", self._reg_name(arg_reg), "")
                else:
                    # ET_REL: plt is keyed by call-site file offset (= va in rel mode)
                    # ET_DYN/EXEC: plt is keyed by PLT stub VA (= resolved BL target)
                    target = va if self._is_rel else _bl_target(word, va)
                    sym = self._plt.get(target)
                    if sym and sym in _SINKS:
                        expected_reg, arg_label = _SINKS[sym]
                        if expected_reg in live:
                            return (va, sym, arg_label, "")
                # Calls to unknown functions clobber $a0-$a7; reset argument registers
                live -= _ARG_REGS
                continue

            # JIRL indirect call (rd != $zero means return address is saved -> it is a call)
            if (word & _MASK_JIRL) == _MATCH_JIRL and _rd(word) != 0:
                if self._pe32plus:
                    live_args = live & _ARG_REGS
                    if live_args:
                        arg_reg = min(live_args)
                        return (va, "<indirect>", self._reg_name(arg_reg), "")
                live -= _ARG_REGS
                continue

            # or Rdst, Rsrc, $zero  (register move)
            if (word & _MASK_3R) == _MATCH_OR and _rk(word) == 0:
                if _rj(word) in live:
                    live.add(_rd(word))
                continue

            # addi.d Rdst, Rsrc, 0  (zero-immediate add = move)
            # addi.d: match=0x02c00000 mask=0xffc00000; bits[21:10] = si12; format r0:5,r5:5,si10:12
            if (word & 0xffc00000) == 0x02c00000:
                si12 = (word >> 10) & 0xfff
                if si12 == 0 and _rj(word) in live:
                    live.add(_rd(word))
                continue

            # Dead-register kill (Cifuentes §5.4.1): if this instruction
            # defines bits[4:0] as a destination register, the or-result value
            # is no longer live in that register.
            # Stores (2RI12 and 3R indexed) use bits[4:0] as a SOURCE.
            # Conditional branches use bits[4:0] as part of an immediate.
            # Every other instruction class (ALU, loads, pcaddu*, etc.) writes rd.
            rd = _rd(word)
            if rd != 0 and rd in live:
                top6  = word >> 26
                op22  = word >> 22
                op15  = word >> 15
                if top6 not in _BRANCH_TOP6 and op22 not in _STORE_OP22 and op15 not in _STOREX_OP15:
                    live.discard(rd)

        return None

    # ------------------------------------------------------------------

    @staticmethod
    def _reg_name(reg: int) -> str:
        _NAMES = (
            "$zero", "$ra",  "$tp",  "$sp",  "$a0",  "$a1",  "$a2",  "$a3",
            "$a4",   "$a5",  "$a6",  "$a7",  "$t0",  "$t1",  "$t2",  "$t3",
            "$t4",   "$t5",  "$t6",  "$t7",  "$t8",  "$r21", "$fp",  "$s0",
            "$s1",   "$s2",  "$s3",  "$s4",  "$s5",  "$s6",  "$s7",  "$s8",
        )
        return _NAMES[reg] if 0 <= reg < 32 else f"$r{reg}"

    def _context_snippet(self, va: int) -> str:
        """Return a compact hex representation of the 4-instruction sequence."""
        words = self._words_at(va, 4)
        if not words:
            return ""
        return " ".join(f"{w:08x}" for w in words)

    # ------------------------------------------------------------------

    def report(self, findings: List[LA64MaxNotMinFinding]) -> str:
        if not findings:
            return "LA64 max-not-min scan: no sink-proximate patterns found."
        lines = [
            f"LA64 max-not-min scan: {len(findings)} finding(s)",
            "=" * 72,
        ]
        for f in findings:
            lines.append(str(f))
        return "\n".join(lines)
