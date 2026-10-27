"""Direct absolute-address candidates from recovered MicroBlaze instructions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .microblaze_cfg import MicroBlazeRecovery


@dataclass(frozen=True)
class MemoryReference:
    address: int
    instruction: int
    mnemonic: str
    register: Optional[int]


@dataclass(frozen=True)
class ReferenceNeighbors:
    lower: Optional[int]
    upper: Optional[int]


def direct_memory_references(
    recovery: MicroBlazeRecovery,
    start: int = 0,
    end: int = 0x1_0000_0000,
) -> dict[int, list[MemoryReference]]:
    if start < 0 or end > 0x1_0000_0000 or start >= end:
        raise ValueError("reference interval must be within the 32-bit address space")
    references: dict[int, list[MemoryReference]] = {}
    for instruction, insn in sorted(recovery.code.items()):
        if (
            insn.flow != "linear"
            or insn.ra != 0
            or insn.imm is None
            or insn.mnemonic == "imm"
        ):
            continue
        address = insn.imm & 0xFFFFFFFF
        if not start <= address < end:
            continue
        if insn.mnemonic in ("addi", "addik", "ori") and insn.rd == 0:
            continue
        references.setdefault(address, []).append(
            MemoryReference(address, instruction, insn.mnemonic, insn.rd)
        )
    return references


def reference_neighbors(
    references: dict[int, list[MemoryReference]],
    address: int,
) -> ReferenceNeighbors:
    lower = max((candidate for candidate in references if candidate < address), default=None)
    upper = min((candidate for candidate in references if candidate > address), default=None)
    return ReferenceNeighbors(lower, upper)
