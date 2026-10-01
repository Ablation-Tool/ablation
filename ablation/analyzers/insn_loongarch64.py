"""Instruction model and operand parser for LoongArch64.

All LoongArch instructions are fixed 32-bit little-endian. Operands are already
rendered as ABI-named tokens by loongarch_decoder.py, so parsing here is
straightforward: split on ", " and classify each token.

Operand token grammar (as emitted by loongarch_decoder._render_operands):
  register    $zero  $ra  $sp  $a0  $t3  $fp  $s1  $fa0  $fcc2  $fcsr0
  signed imm  -16    0    256   (decimal, no prefix)
  hex imm     0x1f   0xa0      (0x prefix; always non-negative)

Load/store format: dst_reg, base_reg, offset
  ld.d $a0, $sp, 8   -> [Reg($a0), Reg($sp), Imm(8)]
  st.d $ra, $sp, -8  -> [Reg($ra), Reg($sp), Imm(-8)]

We do NOT synthesise a Mem object at parse time; load/store detection is done
by mnemonic in the taint engine so that indexed loads (ldx.*) work the same way.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Union

from .isa_loongarch64 import canon_reg

_HEX_RE = re.compile(r"^-?0x[0-9a-fA-F]+$")
_DEC_RE = re.compile(r"^-?\d+$")


# ---------------------------------------------------------------------------
# Operand types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Reg:
    name: str
    def __str__(self) -> str: return self.name


@dataclass(frozen=True)
class Imm:
    value: int
    def __str__(self) -> str:
        return hex(self.value) if self.value >= 0x10 else str(self.value)


Operand = Union[Reg, Imm]


def _parse_token(tok: str) -> Operand:
    t = tok.strip()
    if t.startswith("$"):
        return Reg(t)
    if _HEX_RE.match(t):
        return Imm(int(t, 16))
    if _DEC_RE.match(t):
        return Imm(int(t))
    # Fallback: treat as a symbolic label or CSR number
    try:
        return Imm(int(t, 0))
    except ValueError:
        return Reg(t)  # symbolic name


# ---------------------------------------------------------------------------
# Insn
# ---------------------------------------------------------------------------

@dataclass
class Insn:
    address:  int
    mnemonic: str
    ops:      List[Operand] = field(default_factory=list)
    size:     int = 4
    raw:      int = 0   # raw 32-bit word

    def reg(self, i: int) -> Optional[str]:
        """Return canonical lp64 name of the i-th operand if it's a GPR."""
        if i >= len(self.ops) or not isinstance(self.ops[i], Reg):
            return None
        return canon_reg(self.ops[i].name) or self.ops[i].name

    def imm(self, i: int) -> Optional[int]:
        """Return integer value of the i-th operand if it's an immediate."""
        if i >= len(self.ops) or not isinstance(self.ops[i], Imm):
            return None
        return self.ops[i].value

    def any_reg(self, i: int) -> Optional[str]:
        """Return register name (canonical or as-is) for the i-th operand."""
        if i >= len(self.ops) or not isinstance(self.ops[i], Reg):
            return None
        return canon_reg(self.ops[i].name) or self.ops[i].name

    def __repr__(self) -> str:
        ops = ", ".join(str(o) for o in self.ops)
        return f"<Insn {self.address:#x}: {self.mnemonic} {ops}>"


# ---------------------------------------------------------------------------
# Factory: Insn from a LoongArchFrame
# ---------------------------------------------------------------------------

def from_loongarch_frame(va: int, mnemonic: str, op_str: str,
                         size: int = 4, raw: int = 0) -> Insn:
    """Build an Insn from a LoongArchFrame's (va, mnemonic, op_str, width)."""
    if not op_str.strip():
        return Insn(va, mnemonic, [], size, raw)
    tokens = [t.strip() for t in op_str.split(",")]
    ops = [_parse_token(t) for t in tokens if t]
    return Insn(va, mnemonic, ops, size, raw)


def from_loongarch_frames(frames) -> Iterator[Insn]:
    """Yield Insn objects from an iterable of LoongArchFrame objects."""
    for f in frames:
        yield from_loongarch_frame(f.va, f.mnemonic, f.op_str, f.width, f.insn)
