"""Register and BCS ABI constants for the Motorola MC88100 architecture.

Instruction encodings and operand layouts are maintained in ``m88k_opcodes``.
"""
from __future__ import annotations

from typing import FrozenSet, Tuple

ZERO_REG = "r0"
LINK_REG = "r1"
SP_REG = "r31"
FP_REG = "r30"
ARG_REGS: Tuple[str, ...] = tuple(f"r{i}" for i in range(2, 10))
RET_REGS: Tuple[str, ...] = tuple(f"r{i}" for i in range(10, 14))
CALLEE_SAVED: FrozenSet[str] = frozenset(f"r{i}" for i in range(14, 31))
REG_NAMES: Tuple[str, ...] = tuple(f"r{i}" for i in range(32))


def reg_name(n: int) -> str:
    if not 0 <= n <= 31:
        raise ValueError(f"invalid M88k register number: {n}")
    return f"r{n}"


def is_callee_saved(reg: str) -> bool:
    return reg in CALLEE_SAVED or reg in (FP_REG, SP_REG)
