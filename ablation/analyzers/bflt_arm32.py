"""Link-time ARM32 literal and pointer recovery for parsed bFLT images."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CsInsn
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

from ablation.parsers.bflt import BfltImage


@dataclass(frozen=True)
class Arm32LiteralReference:
    """A PC-relative load and the link-time value it references."""

    instruction_address: int
    mnemonic: str
    operands: str
    literal_address: int
    value: int | None


class BfltArm32:
    """Read little-endian ARM32 code with an explicit pointer byte order."""

    _LOAD_MNEMONICS = frozenset({"ldr", "ldrb", "ldrsb", "ldrh", "ldrsh"})

    def __init__(self, image: BfltImage, *, pointer_byteorder: str) -> None:
        if not isinstance(image, BfltImage):
            raise TypeError("image must be a parsed BfltImage")
        if pointer_byteorder not in ("big", "little"):
            raise ValueError("pointer_byteorder must be 'big' or 'little'")
        self.image = image
        self.pointer_byteorder = pointer_byteorder
        self._decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self._decoder.skipdata = True
        self._decoder.detail = True

    def read_pointer(self, address: int) -> int:
        """Read a stored 32-bit pointer without applying a runtime load base."""
        return int.from_bytes(
            self.image.read_memory(address, 4), self.pointer_byteorder
        )

    def instructions(self, start: int = 0x40, end: int | None = None) -> Iterator[CsInsn]:
        """Disassemble a bounded, four-byte-aligned range in the text region."""
        stop = self.image.data_start if end is None else end
        if start < 0x40 or start > stop or stop > self.image.data_start:
            raise ValueError("disassembly range lies outside bFLT text")
        if start % 4 or stop % 4:
            raise ValueError("ARM32 disassembly range must be four-byte aligned")
        yield from self._decoder.disasm(
            self.image.memory_image[start:stop], start
        )

    def pointer_references(
        self, target: int, *, start: int = 0x40, end: int | None = None,
    ) -> list[int]:
        """Return aligned stored-pointer candidates, not proven code references."""
        self._validate_target(target)
        stop = self.image.data_end if end is None else end
        if start < 0x40 or start > stop or stop > self.image.data_end:
            raise ValueError("pointer scan range lies outside initialized bFLT memory")
        if start % 4:
            raise ValueError("pointer scan start must be four-byte aligned")
        return [
            address for address in range(start, stop - 3, 4)
            if self.read_pointer(address) == target
        ]

    def literal_references(
        self, target: int, *, dereference: bool = True,
    ) -> list[Arm32LiteralReference]:
        """Find PC-relative loads of a pointer, or loads from a literal address."""
        self._validate_target(target)
        references = []
        for insn in self.instructions():
            literal = self.literal_address(insn)
            if literal is None:
                continue
            if not dereference:
                if literal == target:
                    references.append(self._reference(insn, literal, None))
                continue
            if literal < 0 or literal + 4 > len(self.image.memory_image):
                continue
            value = self.read_pointer(literal)
            if value == target:
                references.append(self._reference(insn, literal, value))
        return references

    def literal_address(self, insn: CsInsn) -> int | None:
        """Return the flat literal-pool address for a supported PC-relative load."""
        if insn.mnemonic not in self._LOAD_MNEMONICS or len(insn.operands) != 2:
            return None
        memory = insn.operands[1]
        if memory.type != ARM_OP_MEM or memory.mem.base != ARM_REG_PC:
            return None
        if memory.mem.index != 0 or memory.mem.scale != 1:
            return None
        return insn.address + 8 + memory.mem.disp

    @staticmethod
    def _reference(
        insn: CsInsn, literal: int, value: int | None,
    ) -> Arm32LiteralReference:
        return Arm32LiteralReference(
            instruction_address=insn.address,
            mnemonic=insn.mnemonic,
            operands=insn.op_str,
            literal_address=literal,
            value=value,
        )

    @staticmethod
    def _validate_target(target: int) -> None:
        if not 0 <= target <= 0xFFFFFFFF:
            raise ValueError("target must fit a 32-bit pointer")
