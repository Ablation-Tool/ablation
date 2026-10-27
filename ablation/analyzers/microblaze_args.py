"""Bounded same-block constant recovery for MicroBlaze direct-call arguments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .microblaze_cfg import MicroBlazeFunction
from .microblaze_decoder import MicroBlazeInsn


MAX_ARGUMENT_INSTRUCTIONS = 256


@dataclass(frozen=True)
class CallArgument:
    register: int
    value: Optional[int]
    definition: Optional[int]


def _constant_write(
    insn: MicroBlazeInsn,
    values: dict[int, Optional[int]],
) -> tuple[bool, Optional[int]]:
    if insn.rd in (None, 0):
        return False, None
    if insn.mnemonic.startswith(("sb", "sh", "sw")):
        return False, None
    ra = values.get(insn.ra or 0)
    rb = values.get(insn.rb or 0)
    if insn.mnemonic in ("addi", "addik"):
        return True, None if ra is None else (ra + (insn.imm or 0)) & 0xFFFFFFFF
    if insn.mnemonic in ("add", "addk"):
        return True, None if ra is None or rb is None else (ra + rb) & 0xFFFFFFFF
    if insn.mnemonic == "ori":
        return True, None if ra is None else (ra | (insn.imm or 0)) & 0xFFFFFFFF
    if insn.mnemonic == "or":
        return True, None if ra is None or rb is None else (ra | rb) & 0xFFFFFFFF
    return True, None


def call_arguments(
    function: MicroBlazeFunction,
    call_address: int,
    registers: Iterable[int] = (5, 6, 7),
    *,
    max_instructions: int = MAX_ARGUMENT_INSTRUCTIONS,
) -> dict[int, CallArgument]:
    if not 1 <= max_instructions <= 4096:
        raise ValueError("max_instructions must be between 1 and 4096")
    requested_list: list[int] = []
    for count, register in enumerate(registers, 1):
        if count > 32:
            raise ValueError("too many argument registers")
        if register < 0 or register > 31:
            raise ValueError("argument registers must be between r0 and r31")
        if register not in requested_list:
            requested_list.append(register)
        if len(requested_list) > 32:
            raise ValueError("too many argument registers")
    requested = tuple(requested_list)
    if not requested:
        raise ValueError("at least one argument register is required")
    if call_address not in function.calls:
        raise ValueError(f"no direct call at {call_address:#x}")

    for block in function:
        addresses = [insn.address for insn in block.insns]
        if call_address not in addresses:
            continue
        position = addresses.index(call_address)
        call = block.insns[position]
        count = position + 2 if call.delay_slot else position + 1
        sequence = block.insns[:count]
        if len(sequence) > max_instructions:
            sequence = sequence[-max_instructions:]
        values: dict[int, Optional[int]] = {0: 0}
        definitions: dict[int, Optional[int]] = {}
        for insn in sequence:
            if insn.address == call_address or insn.mnemonic == "imm":
                continue
            writes, value = _constant_write(insn, values)
            if writes and insn.rd is not None:
                values[insn.rd] = value
                definitions[insn.rd] = insn.address
            values[0] = 0
        return {
            register: CallArgument(register, values.get(register), definitions.get(register))
            for register in requested
        }
    raise ValueError(f"call site {call_address:#x} is absent from function blocks")
