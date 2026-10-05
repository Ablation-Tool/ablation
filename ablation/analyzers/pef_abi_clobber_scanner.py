"""
pef_abi_clobber_scanner.py — PPC32 PEF ABI register clobber detector.

Detects call sites where an argument register is clobbered by an intermediate
``bl`` instruction between the time it was last written and the time it is read
by a sink call.  Built on ``encoding_dag.Template`` / ``Field`` for correct
PPC32 bitfield extraction.

Three bugs that affected the hand-written OpenTransport scanner are impossible
in this implementation because the fix is structural:

  1. ori/addi dest-field asymmetry
       D-form arithmetic (addi/lwz/addic): dest = RT = bits[25:21]
       D-form logical   (ori/andi/oris):   dest = RA = bits[20:16]
     Separate ``Template`` definitions per instruction form; each field is
     named at its actual bit position.  One shared field extractor cannot
     exist.

  2. addic (opcode 12) missing from the r4-write detection list
     The dispatch table is keyed on primary opcode.  Adding opcode 12 is one
     dict entry; there is no hidden "other" path that silently skips it.

  3. Unconditional branches (b / ba) not treated as basic-block boundaries
     I-form instructions with LK=0 decode to ``_UNCOND``; the backward walk
     stops immediately.  The decision is in the semantic layer, not in a
     per-opcode check inside the loop.

Usage::

    from ablation.analyzers.pef_abi_clobber_scanner import PEFABIClobberScanner

    # Scan PEF code section for ABI clobber before OTStrCat (checks r4)
    scanner = PEFABIClobberScanner.from_bytes(code_bytes, base_va=0)
    findings = scanner.scan(
        sink_vas=[0x01690, 0x01774],   # VA of each 'bl OTStrCat'
        check_regs=[4],                 # r4 = string source arg
    )
    print(scanner.report(findings))

    # OTMemcpy checks both r4 (source) and r5 (size)
    findings = scanner.scan(
        sink_vas=[0x06e24],
        check_regs=[4, 5],
    )
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Tuple

from ablation.analyzers.encoding_dag import Field, Template


# ── PPC32 instruction form templates ─────────────────────────────────────────
#
# All templates are 32-bit big-endian.  Fields are listed MSB-first; the first
# Field occupies the highest bits.  No fixed-value constraints — these are pure
# structural decoders used only for bitfield extraction, not for validation or
# round-trip encode.
#
# PPC32 bit numbering: bit 0 = MSB, bit 31 = LSB.
# In Template field order: field[0] is at bits[0:width-1] = the top N bits.
# Template.decode() computes: shift starts at total_bits; for each Field,
# shift -= width; value = (raw >> shift) & mask.  For a 32-bit template this
# extracts bits[31:26] first, then bits[25:21], etc.

# D-form arithmetic  [opcode(6) | RT(5) | RA(5) | SI(16)]
# Used by: addi(14), addis(15), addic(12), addic.(13), lwz(32), lwzu(33),
#          lbz(34), lbzu(35), lhz(40), lhzu(41), lha(42), lhau(43), lmw(46)
# Destination register: RT = bits[25:21]
_DFORM_ARITH = Template("dform_arith", [
    Field("opcode", 6), Field("RT", 5), Field("RA", 5), Field("SI", 16),
])

# D-form logical  [opcode(6) | RS(5) | RA(5) | UI(16)]
# Used by: ori(24), oris(25), xori(26), xoris(27), andi.(28), andis.(29)
# CRITICAL: destination is RA = bits[20:16]; RS = bits[25:21] is the SOURCE.
# This is opposite to D-form arithmetic.  Separate template prevents the
# RT-field bug that plagued the hand-written scanner.
_DFORM_LOGICAL = Template("dform_logical", [
    Field("opcode", 6), Field("RS", 5), Field("RA", 5), Field("UI", 16),
])

# M-form (rotate)  [opcode(6) | RS(5) | RA(5) | SH(5) | MB(5) | ME(5) | Rc(1)]
# Used by: rlwimi(20), rlwinm(21)/slwi/srwi, rlwnm(23)
# Destination register: RA = bits[20:16]; RS = bits[25:21] is source.
_MFORM = Template("mform", [
    Field("opcode", 6), Field("RS", 5), Field("RA", 5),
    Field("SH", 5), Field("MB", 5), Field("ME", 5), Field("Rc", 1),
])

# X-form  [opcode(6) | RT(5) | RA(5) | RB(5) | XO(10) | Rc(1)]
# Used by opcode-31 instructions.  Whether the destination is RT or RA depends
# on the specific XO value — see _XO31_DEST below.
_XFORM = Template("xform", [
    Field("opcode", 6), Field("RT", 5), Field("RA", 5),
    Field("RB", 5), Field("XO", 10), Field("Rc", 1),
])

# I-form (unconditional branch)  [opcode(6) | LI(24) | AA(1) | LK(1)]
# opcode 18.  LK=1 → bl/bla (call).  LK=0 → b/ba (unconditional jump).
_IFORM = Template("iform", [
    Field("opcode", 6), Field("LI", 24), Field("AA", 1), Field("LK", 1),
])

# XL-form (branch-to-LR / CTR)  [opcode(6) | BO(5) | BI(5) | pad(5) | XO(10) | LK(1)]
# opcode 19.  XO=16 + BO=20 (0b10100) → unconditional blr.
_XLFORM = Template("xlform", [
    Field("opcode", 6), Field("BO", 5), Field("BI", 5),
    Field("_pad", 5), Field("XO", 10), Field("LK", 1),
])


# ── Dispatch tables ───────────────────────────────────────────────────────────

# Primary opcode → (template, dest_field_name) for single-register write ops.
# Opcodes 18, 19, 31 are absent — handled by special-case logic in classify().
_PRIMARY_WRITE: Dict[int, Tuple[Template, str]] = {
    # D-form arithmetic: destination = RT
    12: (_DFORM_ARITH, "RT"),   # addic
    13: (_DFORM_ARITH, "RT"),   # addic.
    14: (_DFORM_ARITH, "RT"),   # addi / li
    15: (_DFORM_ARITH, "RT"),   # addis / lis
    32: (_DFORM_ARITH, "RT"),   # lwz
    33: (_DFORM_ARITH, "RT"),   # lwzu
    34: (_DFORM_ARITH, "RT"),   # lbz
    35: (_DFORM_ARITH, "RT"),   # lbzu
    40: (_DFORM_ARITH, "RT"),   # lhz
    41: (_DFORM_ARITH, "RT"),   # lhzu
    42: (_DFORM_ARITH, "RT"),   # lha
    43: (_DFORM_ARITH, "RT"),   # lhau
    46: (_DFORM_ARITH, "RT"),   # lmw — range write (RT..r31); see range_write in InsnClass
    # D-form logical: destination = RA (NOT RS)
    24: (_DFORM_LOGICAL, "RA"), # ori / mr
    25: (_DFORM_LOGICAL, "RA"), # oris
    26: (_DFORM_LOGICAL, "RA"), # xori
    27: (_DFORM_LOGICAL, "RA"), # xoris
    28: (_DFORM_LOGICAL, "RA"), # andi.
    29: (_DFORM_LOGICAL, "RA"), # andis.
    # M-form: destination = RA (RS is source)
    20: (_MFORM, "RA"),         # rlwimi
    21: (_MFORM, "RA"),         # rlwinm / slwi / srwi
    23: (_MFORM, "RA"),         # rlwnm
}

# Opcode-31 extended XO → dest_field_name in _XFORM.
# "RT" = bits[25:21] is the destination (arithmetic/load ops).
# "RA" = bits[20:16] is the destination (logic/shift ops where RT field is RS source).
# Stores (stwx, stwux, stbx, etc.) and comparisons (cmpw, cmplw, etc.) are
# intentionally absent — they do not write a GPR destination.
_XO31_DEST: Dict[int, str] = {
    # Arithmetic / multiply / divide (dest = RT)
    8: "RT", 10: "RT", 11: "RT", 40: "RT", 75: "RT",
    104: "RT", 136: "RT", 138: "RT", 200: "RT", 202: "RT",
    232: "RT", 234: "RT", 235: "RT", 266: "RT", 491: "RT", 523: "RT",
    # Special purpose register reads (dest = RT)
    19: "RT",   # mfcr
    339: "RT",  # mfspr (mflr is mfspr with SPR=8)
    # Load X-form (dest = RT)
    20: "RT",   # lwarx
    23: "RT",   # lwzx
    55: "RT",   # lwzux
    87: "RT",   # lbzx
    119: "RT",  # lbzux
    279: "RT",  # lhzx
    311: "RT",  # lhzux
    343: "RT",  # lhax
    375: "RT",  # lhaux
    533: "RT",  # lswx  (range write — also listed in _XO31_RANGE)
    597: "RT",  # lswi  (range write)
    # Logic / shift (dest = RA; bits[25:21] is RS source)
    24: "RA",   # slw
    26: "RA",   # cntlzw
    28: "RA",   # and
    60: "RA",   # andc
    124: "RA",  # nor
    284: "RA",  # eqv
    316: "RA",  # xor
    412: "RA",  # orc
    444: "RA",  # or / mr
    476: "RA",  # nand
    536: "RA",  # srw
    792: "RA",  # sraw
    824: "RA",  # srawi
    922: "RA",  # extsh
    954: "RA",  # extsb
}

# XO values that perform range loads starting from RT (like lmw).
# Conservative: treat as writing RT..r31.
_XO31_RANGE: FrozenSet[int] = frozenset({533, 597})  # lswx, lswi


# ── Instruction classification ────────────────────────────────────────────────

_WRITE = "write"    # writes to a register
_CALL  = "call"     # bl: clobbers all volatile regs (r3-r12)
_UNCOND = "uncond"  # b / ba: unconditional branch — basic-block boundary
_RETURN = "return"  # blr: return — basic-block boundary
_OTHER  = "other"   # everything else (stores, comparisons, conditional branches)


@dataclass
class InsnClass:
    """Classification of one PPC32 instruction word for ABI clobber analysis."""
    kind: str                   # _WRITE | _CALL | _UNCOND | _RETURN | _OTHER
    dst_reg: int = -1           # destination register number (kind == _WRITE only)
    range_write: bool = False   # True for lmw/lswx/lswi: writes dst_reg..r31


def classify(word: int) -> InsnClass:
    """Classify a 32-bit big-endian PPC32 instruction word."""
    opcode = (word >> 26) & 0x3F

    # Primary write opcodes
    if opcode in _PRIMARY_WRITE:
        tmpl, dest_field = _PRIMARY_WRITE[opcode]
        fields = tmpl.decode(word)
        dst = fields[dest_field]
        return InsnClass(_WRITE, dst_reg=dst, range_write=(opcode == 46))

    # I-form: bl (LK=1) or b (LK=0)
    if opcode == 18:
        fields = _IFORM.decode(word)
        return InsnClass(_CALL if fields["LK"] else _UNCOND)

    # XL-form: bclr etc.
    if opcode == 19:
        fields = _XLFORM.decode(word)
        if fields["XO"] == 16 and fields["BO"] == 20:   # unconditional blr
            return InsnClass(_RETURN)
        return InsnClass(_OTHER)

    # X-form (opcode 31): extended dispatch on XO
    if opcode == 31:
        fields = _XFORM.decode(word)
        xo = fields["XO"]
        dest_field = _XO31_DEST.get(xo)
        if dest_field:
            dst = fields[dest_field]
            return InsnClass(_WRITE, dst_reg=dst, range_write=(xo in _XO31_RANGE))
        return InsnClass(_OTHER)

    return InsnClass(_OTHER)


# ── Finding and scanner ───────────────────────────────────────────────────────

@dataclass
class ABIClobberFinding:
    """Result for one (sink_va, check_reg) pair."""
    site_va: int         # VA of the sink BL instruction
    check_reg: int       # register examined (e.g. 4 for r4)
    verdict: str         # "PLAUSIBLE" or "SAFE"
    stop_va: int         # VA where the backward walk stopped
    stop_reason: str     # "reg_written" | "call_clobber" | "uncond_branch" |
                         # "return" | "window_exhausted"

    def fmt(self) -> str:
        tag = f"[{self.verdict}]".ljust(12)
        return (
            f"{tag} 0x{self.site_va:06x}  r{self.check_reg}"
            f"  {self.stop_reason} @ 0x{self.stop_va:06x}"
        )


class PEFABIClobberScanner:
    """Detect ABI register clobber violations in PPC32 PEF code sections.

    Walks backward from each sink call site (a ``bl`` to e.g. OTStrCat or
    OTMemcpy) looking for evidence that the argument register(s) were last
    written *after* any intermediate ``bl`` and *before* the sink.

    Backward walk stops at:
      - An instruction that writes the checked register → SAFE
      - A ``bl`` (clobbers volatile regs r3-r12) → PLAUSIBLE
      - An unconditional ``b`` / ``ba`` (crossed basic-block boundary) → PLAUSIBLE
      - A ``blr`` (crossed function boundary) → PLAUSIBLE
      - Window exhausted without finding a write → PLAUSIBLE
    """

    def __init__(self, code: bytes, base_va: int = 0) -> None:
        self._code = code
        self._base = base_va

    @classmethod
    def from_bytes(cls, code: bytes, base_va: int = 0) -> "PEFABIClobberScanner":
        """Construct from raw PEF code section bytes."""
        return cls(code, base_va)

    def scan(
        self,
        sink_vas: List[int],
        check_regs: Optional[List[int]] = None,
        window: int = 32,
    ) -> List[ABIClobberFinding]:
        """Scan each sink VA for each checked register.

        Args:
            sink_vas:   Virtual addresses of BL-to-sink instructions to examine.
            check_regs: Register numbers to check.  Default [4] (string source arg).
                        Pass [4, 5] for OTMemcpy (source and size).
            window:     Maximum instructions to look backward per site.

        Returns:
            List of ABIClobberFinding, one per (site_va, check_reg) pair.
            Only PLAUSIBLE verdicts require manual verification.
        """
        if check_regs is None:
            check_regs = [4]
        if window < 1:
            raise ValueError("window must be >= 1")
        findings: List[ABIClobberFinding] = []
        for sva in sink_vas:
            for reg in check_regs:
                f = self._check_site(sva, reg, window)
                if f is not None:
                    findings.append(f)
        return findings

    def _check_site(
        self, site_va: int, check_reg: int, window: int
    ) -> Optional[ABIClobberFinding]:
        """Walk backward from site_va to classify one (site, reg) pair."""
        off = site_va - self._base
        if off < 4 or off > len(self._code) - 4:
            return None
        # Verify site_va is word-aligned
        if off & 3:
            return None
        # Verify the instruction at site_va is actually a bl (LK=1)
        sink_word = struct.unpack_from(">I", self._code, off)[0]
        if classify(sink_word).kind != _CALL:
            return None

        for i in range(1, window + 1):
            cur_off = off - (i * 4)
            if cur_off < 0:
                return ABIClobberFinding(
                    site_va, check_reg, "PLAUSIBLE",
                    self._base, "window_exhausted",
                )
            word = struct.unpack_from(">I", self._code, cur_off)[0]
            cur_va = self._base + cur_off
            try:
                ic = classify(word)
            except Exception:
                ic = InsnClass(_OTHER)

            if ic.kind == _WRITE:
                if ic.range_write:
                    written = ic.dst_reg <= check_reg <= 31
                else:
                    written = (ic.dst_reg == check_reg)
                if written:
                    return ABIClobberFinding(
                        site_va, check_reg, "SAFE", cur_va, "reg_written",
                    )

            elif ic.kind == _CALL:
                # PPC ABI: bl clobbers r3-r12 (caller-saved volatile)
                if 3 <= check_reg <= 12:
                    return ABIClobberFinding(
                        site_va, check_reg, "PLAUSIBLE", cur_va, "call_clobber",
                    )

            elif ic.kind == _UNCOND:
                return ABIClobberFinding(
                    site_va, check_reg, "PLAUSIBLE", cur_va, "uncond_branch",
                )

            elif ic.kind == _RETURN:
                return ABIClobberFinding(
                    site_va, check_reg, "PLAUSIBLE", cur_va, "return",
                )

        return ABIClobberFinding(
            site_va, check_reg, "PLAUSIBLE",
            self._base + off - window * 4, "window_exhausted",
        )

    @staticmethod
    def report(findings: List[ABIClobberFinding]) -> str:
        """Format findings as a human-readable report string."""
        if not findings:
            return "PEFABIClobberScanner: no sites found."
        plausible = [f for f in findings if f.verdict == "PLAUSIBLE"]
        safe = [f for f in findings if f.verdict == "SAFE"]
        lines = [
            f"PEFABIClobberScanner: {len(findings)} site(s) — "
            f"PLAUSIBLE={len(plausible)}  SAFE={len(safe)}",
            "",
        ]
        for f in sorted(findings, key=lambda x: (x.site_va, x.check_reg)):
            lines.append(f.fmt())
        return "\n".join(lines)
