"""
sanitizer_detector.py: detect allowlist-style byte-validator functions in x86-64
ELF binaries and determine whether they block shell metacharacters.

Background
----------
Stripped firmware binaries contain validator functions (e.g., Fortinet's
is_valid_host_name in libcmdb_plugin.so) that enforce character allowlists on
user-supplied strings before those strings reach exec-class sinks. When an
argument passes through a function that enforces [A-Za-z0-9_-], shell
metacharacter injection is structurally impossible regardless of the sink type.

This module detects such functions by behavioral signature without requiring
symbol names, then determines what charset they enforce.

Detection signature
-------------------
An allowlist byte-validator has all of these:
  1. Short function (< 128 instructions): allowlist checks are compact.
  2. Byte-load loop: movzx eX, byte ptr [...] inside a backward-edge loop.
  3. Range/equality comparisons: cmp + ja/jb/je/jne against specific immediates.
  4. Dual return values: one path returns 0 (reject), another returns 1 (accept).
  5. No calls to printf-family, malloc, or other heavy functions (it's a pure
     character-classification function).

Charset extraction
------------------
From the comparison immediates we reconstruct the allowed character set. Then:
  SHELL_SAFE   — allowed chars ∩ SHELL_METACHARACTERS = ∅
  SHELL_UNSAFE — shell metacharacters can pass through
  UNKNOWN      — insufficient comparison data to determine charset

Shell metacharacters checked:
  ; | & $ ` ' " ( ) < > ! \\ newline space tab

Usage:
    from ablation.analyzers.sanitizer_detector import SanitizerDetector

    det = SanitizerDetector.from_path('/path/to/binary')
    profiles = det.detect()
    for p in profiles:
        print(p.fmt())

    # Check if a specific function VA is a known sanitizer
    p = det.lookup(0x84f00)
    if p and p.shell_safe:
        print('argument is safe for shell use')

    # Integration with SinkArgClassifier: after getting ARG_PROPAGATED or
    # SNPRINTF_RODATA findings, check if the argument passed through a sanitizer
    # on its way to the sink.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

_CS_OK = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import (
        X86_OP_REG, X86_OP_MEM, X86_OP_IMM,
        X86_REG_RAX, X86_REG_RDI, X86_REG_RSI,
        X86_REG_RBP, X86_REG_RSP, X86_REG_RIP,
        X86_INS_MOVZX, X86_INS_RET, X86_INS_CALL,
        X86_INS_CMP, X86_INS_TEST,
        X86_INS_JA, X86_INS_JB, X86_INS_JAE, X86_INS_JBE,
        X86_INS_JE, X86_INS_JNE,
    )
    _CS_OK = True
except ImportError:
    pass

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# Re-use the shared PLT/func-start helpers from sink_arg_classifier
try:
    from .sink_arg_classifier import _extract_plt_x86, _extract_func_starts
except ImportError:
    from sink_arg_classifier import _extract_plt_x86, _extract_func_starts

# ── Shell metacharacter set ───────────────────────────────────────────────────
# Bytes whose presence in an allowed charset indicates shell injection is possible.
SHELL_METACHARACTERS: FrozenSet[int] = frozenset([
    0x3b,  # ;
    0x7c,  # |
    0x26,  # &
    0x24,  # $
    0x60,  # `
    0x27,  # '
    0x22,  # "
    0x28,  # (
    0x29,  # )
    0x3c,  # <
    0x3e,  # >
    0x21,  # !
    0x5c,  # backslash
    0x0a,  # newline
    0x20,  # space
    0x09,  # tab
    0x2a,  # *  (glob)
    0x3f,  # ?  (glob)
    0x5b,  # [  (glob)
    0x7e,  # ~  (tilde expansion)
])

# Bytes that are explicitly safe (common in [A-Za-z0-9_-] allowlists)
_ALPHANUM_HYPHEN_UNDERSCORE: FrozenSet[int] = frozenset(
    list(range(0x41, 0x5b)) +   # A-Z
    list(range(0x61, 0x7b)) +   # a-z
    list(range(0x30, 0x3a)) +   # 0-9
    [0x5f, 0x2d, 0x00]          # _ - NUL (null terminator)
)

# Detection thresholds
_MAX_VALIDATOR_INSNS  = 120   # validators are compact; reject large functions
_MIN_BYTE_LOADS       = 1     # need at least one movzx byte load in a loop
_MIN_COMPARISONS      = 2     # need at least 2 comparison immediates
_MIN_SCORE            = 4     # minimum detection score (0-10)

# Score weights
_W_BYTE_LOAD     = 3   # has movzx byte loads
_W_RANGE_CMP     = 2   # has ja/jb range comparisons
_W_DUAL_RETURN   = 2   # has both xor eax,eax and mov eax,1 (or eax,eax / ret 0/1)
_W_NO_CALLS      = 2   # no CALL instructions (pure classifier)
_W_BACKWARD_EDGE = 1   # has a backward jump (loop)


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class SanitizerProfile:
    """Behavioral profile of a detected byte-validator function."""
    func_va:          int
    score:            int               # 0–10 detection confidence
    allowed_bytes:    FrozenSet[int]    # reconstructed allowed charset
    blocked_bytes:    FrozenSet[int]    # reconstructed blocked charset
    shell_safe:       bool              # allowed ∩ SHELL_METACHARACTERS = ∅
    verdict:          str               # SHELL_SAFE | SHELL_UNSAFE | PARTIAL | UNKNOWN
    comparison_imms:  List[int]         # raw comparison immediates observed
    n_byte_loads:     int
    n_comparisons:    int
    detail:           str

    def fmt(self) -> str:
        meta_in_allowed = sorted(
            chr(b) for b in self.allowed_bytes & SHELL_METACHARACTERS
        )
        return (
            f"  0x{self.func_va:x}  score={self.score}  {self.verdict:12s}  "
            f"byte_loads={self.n_byte_loads}  cmps={self.n_comparisons}  "
            f"metachar_allowed={meta_in_allowed or 'none'}  {self.detail}"
        )

    def as_dict(self) -> dict:
        return {
            'func_va':       hex(self.func_va),
            'score':         self.score,
            'verdict':       self.verdict,
            'shell_safe':    self.shell_safe,
            'allowed_chars': sorted(chr(b) for b in self.allowed_bytes if 0x20 <= b < 0x7f),
            'detail':        self.detail,
        }


# ── Detector ──────────────────────────────────────────────────────────────────

class SanitizerDetector:
    """
    Detect allowlist byte-validator functions in stripped x86-64 ELF binaries.

    For each function:
      1. Disassemble up to _MAX_VALIDATOR_INSNS instructions.
      2. Score against behavioral signals (byte loads, range cmps, dual return,
         no calls, backward edge).
      3. Extract comparison immediates to reconstruct the charset model.
      4. Classify as SHELL_SAFE, SHELL_UNSAFE, or UNKNOWN.

    Fortinet is_valid_host_name pattern (libcmdb_plugin.so 0x84f00):
      movzx edx, byte ptr [rdi]     ← byte load
      test dl, dl
      je   <null_terminator_exit>
      lea ecx, [rdx - 0x41]         ← range: A-Z
      cmp cl, 0x19
      jbe  <ok>
      lea ecx, [rdx - 0x61]         ← range: a-z
      cmp cl, 0x19
      jbe  <ok>
      ... (0-9, _, -)
      xor eax, eax                  ← return 0 (invalid)
      ret
      ...
      mov eax, 1                    ← return 1 (valid)
      ret
    """

    def __init__(self, binary_path: str):
        self._path = binary_path
        self._data: bytes = Path(binary_path).read_bytes()
        self._func_starts: List[int] = []
        self._md: Optional[Cs] = None
        self._bin = None
        self._known: Dict[int, SanitizerProfile] = {}  # func_va → profile
        if _CS_OK:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(binary_path)
        self._init()

    @classmethod
    def from_path(cls, path: str) -> 'SanitizerDetector':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'SanitizerDetector':
        obj = cls(ctx.path)
        obj._func_starts = list(ctx.func_starts)
        return obj

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        if not self._func_starts:
            self._func_starts = _extract_func_starts(self._bin, self._data)

    def _va_to_bytes(self, va: int, size: int) -> bytes:
        if self._bin is None:
            return b''
        try:
            off = self._bin.virtual_address_to_offset(va)
            return self._data[off:off + size]
        except Exception:
            return b''

    # ── detection ─────────────────────────────────────────────────────────────

    def detect(self, min_score: int = _MIN_SCORE) -> List[SanitizerProfile]:
        """Run detection across all known function starts. Returns profiles above min_score."""
        if not _CS_OK or self._md is None:
            return []
        results: List[SanitizerProfile] = []
        for func_va in self._func_starts:
            p = self._analyze_function(func_va)
            if p is not None and p.score >= min_score:
                self._known[func_va] = p
                results.append(p)
        return sorted(results, key=lambda x: -x.score)

    def lookup(self, func_va: int) -> Optional[SanitizerProfile]:
        """Return profile for a specific function VA (only if detect() was run first)."""
        return self._known.get(func_va)

    def analyze_function(self, func_va: int) -> Optional[SanitizerProfile]:
        """Analyze a single function by VA. Does not require detect() to have run first."""
        if not _CS_OK or self._md is None:
            return None
        return self._analyze_function(func_va)

    def _analyze_function(self, func_va: int) -> Optional[SanitizerProfile]:
        # Disassemble up to _MAX_VALIDATOR_INSNS * 6 bytes (avg 4 bytes/insn + margin)
        raw = self._va_to_bytes(func_va, _MAX_VALIDATOR_INSNS * 6)
        if not raw:
            return None

        insns = list(self._md.disasm(raw, func_va))
        if not insns or len(insns) > _MAX_VALIDATOR_INSNS:
            return None

        # ── signal collection ─────────────────────────────────────────────────
        n_byte_loads  = 0
        n_calls       = 0
        n_ret         = 0
        has_zero_ret  = False    # xor eax,eax / mov eax,0 before ret
        has_one_ret   = False    # mov eax,1 / eax=1 before ret
        has_back_edge = False
        comparison_imms: List[int] = []
        range_cmps = 0
        eax_before_ret = -1      # last value assigned to eax/rax before a ret

        # Char-register tracking: the register receiving byte loads should also
        # be the LHS of ASCII-range comparisons. This cuts FPs from math/crypto
        # functions that happen to have movzx + unrelated cmps.
        char_reg_loads: Dict[str, int] = {}   # reg_name → count of byte loads
        char_reg_cmps:  Dict[str, int] = {}   # reg_name → count of ASCII cmps on that reg
        last_byte_load_reg: str = ''

        min_va = insns[0].address

        for idx, insn in enumerate(insns):
            mnem = insn.mnemonic.lower()

            # Byte loads: movzx Rdst, byte ptr [...]
            if mnem == 'movzx' and insn.operands:
                dst = insn.operands[0]
                src = insn.operands[1] if len(insn.operands) > 1 else None
                if src and src.type == X86_OP_MEM and dst.type == X86_OP_REG:
                    n_byte_loads += 1
                    rname = insn.reg_name(dst.reg)
                    char_reg_loads[rname] = char_reg_loads.get(rname, 0) + 1
                    last_byte_load_reg = rname

            # Calls
            if mnem == 'call':
                n_calls += 1

            # Return value tracking
            if mnem in ('xor', 'mov') and insn.operands and len(insn.operands) == 2:
                dst = insn.operands[0]
                src = insn.operands[1]
                if dst.type == X86_OP_REG:
                    dst_name = insn.reg_name(dst.reg).lower()
                    if dst_name in ('eax', 'rax', 'al'):
                        if mnem == 'xor' and src.type == X86_OP_REG and src.reg == dst.reg:
                            eax_before_ret = 0
                        elif src.type == X86_OP_IMM:
                            eax_before_ret = src.imm & 0xffff

            # cset eax → dual return (compiler replaces mov eax,0/1 with condition set)
            if mnem == 'cset' and insn.operands:
                dst = insn.operands[0]
                if dst.type == X86_OP_REG:
                    dst_name = insn.reg_name(dst.reg).lower()
                    if dst_name in ('eax', 'rax', 'al', 'w0'):
                        # cset sets to 0 or 1 based on condition — counts as both
                        has_zero_ret = True
                        has_one_ret  = True

            # Ret detection — record what eax was set to before this ret
            if mnem in ('ret', 'retq'):
                n_ret += 1
                if eax_before_ret == 0:
                    has_zero_ret = True
                elif eax_before_ret == 1:
                    has_one_ret = True
                eax_before_ret = -1

            # Comparison immediates — track which register is on LHS
            if mnem in ('cmp', 'test') and insn.operands:
                lhs_reg = ''
                for op in insn.operands:
                    if op.type == X86_OP_REG:
                        lhs_reg = insn.reg_name(op.reg)
                    elif op.type == X86_OP_IMM and 0 < op.imm < 256:
                        comparison_imms.append(op.imm & 0xff)
                        if lhs_reg:
                            char_reg_cmps[lhs_reg] = char_reg_cmps.get(lhs_reg, 0) + 1

            # Range checks (cmp + ja/jb/jae/jbe = unsigned range → allowlist structure)
            if mnem in ('ja', 'jb', 'jae', 'jbe'):
                range_cmps += 1

            # Backward edge (loop)
            if mnem.startswith('j') and insn.operands:
                op = insn.operands[0]
                if op.type == X86_OP_IMM and min_va <= op.imm < insn.address:
                    has_back_edge = True

        # RC = C_R * cmp_same_reg_ratio(R) where R is the dominant byte-load register.
        # cmp_same_reg_ratio = C_R / C_total (ASCII cmp on R / all ASCII cmps).
        # High when one register dominates byte-loads AND ASCII comparisons (validator).
        # Low when compares scatter across many registers (math function FP).
        rc_score = 0.0
        if char_reg_loads and char_reg_cmps:
            total_ascii_cmps = sum(char_reg_cmps.values())
            if total_ascii_cmps > 0:
                dominant_load = max(char_reg_loads, key=char_reg_loads.get)
                stem = dominant_load.lstrip('r').lstrip('e')
                c_r = sum(
                    v for k, v in char_reg_cmps.items()
                    if k == dominant_load
                    or k.lstrip('r').lstrip('e') == stem
                    or dominant_load.lstrip('r').lstrip('e') == k.lstrip('r').lstrip('e')
                )
                ratio = c_r / total_ascii_cmps  # cmp_same_reg_ratio
                rc_score = c_r * ratio           # RC: concentration × count

        # Hard gate: a pure byte-validator has NO calls to external functions.
        # Any function with calls is rejected before scoring.
        if n_calls > 0:
            return None

        # ── scoring ───────────────────────────────────────────────────────────
        score = 0
        if n_byte_loads >= _MIN_BYTE_LOADS:
            score += _W_BYTE_LOAD
        # RC-based range score: >0.5 (score 1) and >1.5 (score 2) reward concentration
        if rc_score > 0.5:
            score += 1
        if rc_score > 1.5:
            score += 1   # matches _W_RANGE_CMP total when RC is strong
        if has_zero_ret and has_one_ret:
            score += _W_DUAL_RETURN
        if n_calls == 0:
            score += _W_NO_CALLS
        if has_back_edge:
            score += _W_BACKWARD_EDGE

        if score < _MIN_SCORE:
            return None

        # ── charset reconstruction ────────────────────────────────────────────
        allowed, blocked = self._reconstruct_charset(comparison_imms, insns)

        metachar_in_allowed = allowed & SHELL_METACHARACTERS
        if not comparison_imms or (not allowed and not blocked):
            verdict = 'UNKNOWN'
            shell_safe = False
        elif not metachar_in_allowed:
            verdict = 'SHELL_SAFE'
            shell_safe = True
        elif metachar_in_allowed:
            verdict = 'SHELL_UNSAFE'
            shell_safe = False
        else:
            verdict = 'PARTIAL'
            shell_safe = False

        detail = (
            f'loads={n_byte_loads} rc={rc_score:.2f} range_cmps={range_cmps} '
            f'ret0={has_zero_ret} ret1={has_one_ret} '
            f'calls={n_calls} back_edge={has_back_edge}'
        )

        return SanitizerProfile(
            func_va=func_va,
            score=min(score, 10),
            allowed_bytes=frozenset(allowed),
            blocked_bytes=frozenset(blocked),
            shell_safe=shell_safe,
            verdict=verdict,
            comparison_imms=sorted(set(comparison_imms)),
            n_byte_loads=n_byte_loads,
            n_comparisons=len(comparison_imms),
            detail=detail,
        )

    def _reconstruct_charset(
        self,
        imms: List[int],
        insns: list,
    ) -> Tuple[Set[int], Set[int]]:
        """
        Heuristic charset reconstruction from comparison immediates.

        Two patterns:
          RANGE: lea ecx, [rdx - BASE]; cmp cl, RANGE_SIZE; jbe ok
            → allows bytes [BASE, BASE+RANGE_SIZE]
          EXACT: cmp dl, VALUE; je ok  or  cmp dl, VALUE; jne fail
            → allows or blocks specific VALUE

        Returns (allowed, blocked) byte sets.
        """
        allowed: Set[int] = set()
        blocked: Set[int] = set()

        # Scan for lea-then-cmp range patterns
        for idx, insn in enumerate(insns):
            mnem = insn.mnemonic.lower()
            if mnem == 'lea' and insn.operands and len(insn.operands) == 2:
                src = insn.operands[1]
                if src.type == X86_OP_MEM and src.mem.disp < 0:
                    base = (-src.mem.disp) & 0xff
                    # Look ahead for cmp + jbe
                    for k in range(idx + 1, min(idx + 5, len(insns))):
                        next_mnem = insns[k].mnemonic.lower()
                        if next_mnem == 'cmp' and insns[k].operands:
                            for op in insns[k].operands:
                                if op.type == X86_OP_IMM and 0 < op.imm < 256:
                                    size = op.imm & 0xff
                                    for b in range(base, base + size + 1):
                                        if b < 256:
                                            allowed.add(b)
                        elif next_mnem in ('jbe', 'jb'):
                            break  # consumed range check

        # Scan for exact-byte comparisons with je (allow specific byte)
        for idx, insn in enumerate(insns):
            mnem = insn.mnemonic.lower()
            if mnem == 'cmp' and insn.operands and len(insn.operands) == 2:
                has_imm = False
                imm_val = -1
                for op in insn.operands:
                    if op.type == X86_OP_IMM and 0 < op.imm < 256:
                        has_imm = True
                        imm_val = op.imm & 0xff
                if not has_imm:
                    continue
                # Look at next branch type
                for k in range(idx + 1, min(idx + 3, len(insns))):
                    next_mnem = insns[k].mnemonic.lower()
                    if next_mnem == 'je':
                        allowed.add(imm_val)
                    elif next_mnem == 'jne':
                        blocked.add(imm_val)

        # If we found allowed chars via range but nothing else, fill in common
        # single-char allowances (null terminator, dot for domain names, etc.)
        if not allowed and imms:
            # Fall back: every imm used in je context is probably allowed
            allowed = set(imms)

        return allowed, blocked

    # ── reporting ─────────────────────────────────────────────────────────────

    def report(self, profiles: List[SanitizerProfile]) -> str:
        if not profiles:
            return '[sanitizer_detector] no validator functions detected\n'
        safe   = sum(1 for p in profiles if p.verdict == 'SHELL_SAFE')
        unsafe = sum(1 for p in profiles if p.verdict == 'SHELL_UNSAFE')
        unk    = sum(1 for p in profiles if p.verdict == 'UNKNOWN')
        hdr = (
            f'[sanitizer_detector] {len(profiles)} validator(s)  '
            f'SHELL_SAFE={safe}  SHELL_UNSAFE={unsafe}  UNKNOWN={unk}\n'
        )
        lines = [hdr]
        for p in profiles:
            lines.append(p.fmt())
        return '\n'.join(lines) + '\n'


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='Detect byte-validator/sanitizer functions')
    ap.add_argument('binary')
    ap.add_argument('--min-score', type=int, default=_MIN_SCORE,
                    help=f'Minimum detection score (0-10, default {_MIN_SCORE})')
    ap.add_argument('--shell-safe-only', action='store_true',
                    help='Show only SHELL_SAFE validators')
    ap.add_argument('--va', type=lambda x: int(x, 0),
                    help='Analyze a single function at VA (hex or decimal)')
    args = ap.parse_args()

    det = SanitizerDetector.from_path(args.binary)

    if args.va:
        p = det.analyze_function(args.va)
        if p:
            print(det.report([p]))
        else:
            print(f'[sanitizer_detector] 0x{args.va:x}: score below threshold or not detected')
        return

    profiles = det.detect(min_score=args.min_score)
    if args.shell_safe_only:
        profiles = [p for p in profiles if p.shell_safe]
    print(det.report(profiles))


if __name__ == '__main__':
    _cli()
