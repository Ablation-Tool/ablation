"""RISC-V ISA / ABI utilities shared by the RV32 and RV64 taint trackers.

Facts are sourced from the RISC-V Unprivileged ISA spec and the psABI.
Each function documents the spec section it encodes.
"""
from __future__ import annotations

from typing import Optional

# ---------------------------------------------------------------------------
# Register name canonicalization (psABI §"Register Convention", ISA Ch. 2)
# ---------------------------------------------------------------------------

_ABI_INT = [
    "zero", "ra", "sp", "gp", "tp",
    "t0", "t1", "t2",
    "s0", "s1",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6",
]
_INT_SET = frozenset(_ABI_INT)
_X_TO_ABI = {f"x{i}": n for i, n in enumerate(_ABI_INT)}
_ALIASES = {"fp": "s0"}


def canon_reg(name: str) -> Optional[str]:
    """Return the canonical ABI name for any register spelling.

    Accepts ``x10``, ``a0``, ``fp``. Returns ``None`` for immediates,
    memory expressions, or anything else that is not a register.
    ``fp`` canonicalizes to ``s0`` per the psABI.
    """
    n = name.strip().lower()
    if n in _ALIASES:
        return _ALIASES[n]
    if n in _INT_SET:
        return n
    return _X_TO_ABI.get(n)


def is_reg(name: str) -> bool:
    return canon_reg(name) is not None


# ---------------------------------------------------------------------------
# Immediate normalization (ISA §2.4 — I-type immediates are sign-extended)
# ---------------------------------------------------------------------------

def norm_imm12(raw: int, xlen: int = 64) -> int:
    """Normalize any rendered form of a 12-bit sign-extended immediate.

    Backends render ``andi a0, a0, -16`` as ``-16``, ``0xff0``, ``4080``, or
    the full sign-extended value ``0xfffffffffffffff0``. All encode the same
    12-bit field. Returns a signed integer in [-2048, 2047].
    """
    if -0x800 <= raw <= 0x7FF:
        return raw
    if 0x800 <= raw <= 0xFFF:          # raw unsigned 12-bit (e.g. 0xff0 = 4080)
        return raw - 0x1000
    mask = (1 << xlen) - 1
    v = raw & mask
    low12 = v & 0xFFF
    return low12 - 0x1000 if low12 >= 0x800 else low12


def andi_bound(imm12: int) -> Optional[int]:
    """Upper bound on ``rd`` established by ``andi rd, rs, imm``.

    A non-negative 12-bit immediate zeros every bit above it, bounding rd to
    at most ``imm``.  A negative immediate (bit 11 set) is an alignment mask
    with all high bits set; it bounds nothing, so returns ``None``.
    """
    return imm12 if imm12 >= 0 else None


def andi_propagates(imm_token: str, xlen: int = 64) -> bool:
    """True when an ``andi`` instruction does NOT sanitize taint.

    ``andi`` sanitizes only when the immediate is non-negative (a bounding
    mask). Negative immediates (alignment masks, e.g. -16 = ``sp & ~0xf``)
    have all high bits set and leave the value attacker-controlled.
    ``imm == -1`` is an identity (``rs & ~0 == rs``), so taint must propagate.

    ``imm_token`` is the raw string from the disassembler (``-0x10``, ``0xff0``,
    ``255``, etc.).
    """
    try:
        raw = int(imm_token.strip(), 0)
    except (ValueError, AttributeError):
        return False          # can't parse -> conservative: assume sanitizes
    return andi_bound(norm_imm12(raw, xlen)) is None
