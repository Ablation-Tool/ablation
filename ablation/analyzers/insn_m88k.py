"""Table-driven Motorola MC88100 instruction decoder."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterator, Optional, Set

from .m88k_opcodes import OPCODES

try:
    from ablation.core.coff_m88k_parser import M88kCoffBinary, Section
except ImportError:
    M88kCoffBinary = None  # type: ignore
    Section = None  # type: ignore

SFU0 = 0x80000000
SFU1 = 0x84000000
SFU7 = 0x9C000000
RRI10 = 0xF0000000
RRR = 0xF4000000
SFUMASK = 0xFC00FFE0
RRRMASK = 0xFC00FFE0
RRI10MASK = 0xFC00FC00
DEFMASK = 0xFC000000
CTRLMASK = 0xFC00F800


def _opcode_mask(word: int) -> int:
    in_class = word & DEFMASK
    if SFU0 <= in_class <= SFU7:
        return CTRLMASK if word < SFU1 else SFUMASK
    if in_class == RRR:
        return RRRMASK
    if in_class == RRI10:
        return RRI10MASK
    return DEFMASK


def _build_table() -> Dict[int, tuple]:
    table: Dict[int, tuple] = {}
    for opcode, mnemonic, operands in OPCODES:
        table.setdefault(opcode & _opcode_mask(opcode), (mnemonic, operands))
    return table


_OPCODE_TABLE = _build_table()
CONDITION_NAMES = {
    0x1: "gt0", 0x2: "eq0", 0x3: "ge0", 0xC: "lt0", 0xD: "ne0", 0xE: "le0",
}


@dataclass
class M88kInsn:
    address: int
    mnemonic: str
    op_str: str
    raw: int
    is_branch: bool = False
    is_call: bool = False
    is_return: bool = False
    branch_target: Optional[int] = None

    @property
    def known(self) -> bool:
        return self.mnemonic != "word"

    def __str__(self) -> str:
        target = f"  -> {self.branch_target:#010x}" if self.branch_target is not None else ""
        return f"{self.address:#010x}:  {self.raw:08x}  {self.mnemonic:<10} {self.op_str}{target}"


def _signed(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return (value ^ sign) - sign


class M88kDecoder:
    def __init__(self, binary: "M88kCoffBinary") -> None:
        self._bin = binary
        text = binary.text
        if text is None:
            raise ValueError("binary has no .text section")
        self._text: "Section" = text

    def decode_word(self, word: int, va: int) -> M88kInsn:
        opcode = word & _opcode_mask(word)
        entry = _OPCODE_TABLE.get(opcode)
        if entry is None:
            return M88kInsn(va, "word", f"0x{word:08x}", word)
        mnemonic, operands = entry
        rendered = []
        branch_target = None
        for index, (offset, width, kind) in enumerate(operands):
            value = (word >> offset) & ((1 << width) - 1)
            if kind == "CRREG":
                text = f"cr{value}"
            elif kind == "FCRREG":
                text = f"fcr{value}"
            elif kind == "REGSC":
                text = f"[r{value}]"
            elif kind == "REG":
                text = f"r{value}"
            elif kind == "XREG":
                text = f"x{value}"
            elif kind == "HEX":
                text = "0" if value == 0 else f"0x{value:02x}"
            elif kind == "DEC":
                text = str(value)
            elif kind == "CONDMASK":
                text = CONDITION_NAMES.get(value & 0x0F, f"{value:x}")
            elif kind == "PCREL":
                branch_target = va + 4 * _signed(value, width)
                text = f"{branch_target:#010x}"
            elif kind == "CONT":
                other = (word >> (offset + 5)) & 0x1F
                text = f"{value},r{other}"
            elif kind == "BF":
                other = (word >> (offset + 5)) & 0x1F
                text = f"{other}<{value}>"
            else:
                text = f"<{kind}:{value:x}>"
            if index and kind not in ("REGSC", "CONT"):
                rendered.append(",")
            rendered.append(text)
        op_str = " " + "".join(rendered) if rendered else ""
        is_call = mnemonic in ("bsr", "bsr.n", "jsr", "jsr.n")
        is_branch = mnemonic in ("br", "br.n", "bb0", "bb0.n", "bb1", "bb1.n", "bcnd", "bcnd.n")
        is_return = mnemonic in ("jmp", "jmp.n") and operands and operands[0][2] == "REG" and ((word >> operands[0][0]) & 0x1F) == 1
        return M88kInsn(va, mnemonic, op_str, word, is_branch, is_call, is_return, branch_target)

    def disassemble_va(self, start_va: int, max_insns: int = 512) -> Iterator[M88kInsn]:
        section = self._text
        if not section.contains_va(start_va):
            return
        va = start_va
        count = 0
        while count < max_insns and section.contains_va(va):
            insn = self.decode_word(section.read_word(va), va)
            yield insn
            va += 4
            count += 1
            if insn.is_return:
                break

    def disassemble_bytes(self, data: bytes, base_va: int) -> Iterator[M88kInsn]:
        if len(data) % 4:
            raise ValueError("M88K input length must be a multiple of four")
        for offset in range(0, len(data), 4):
            yield self.decode_word(struct.unpack_from(">I", data, offset)[0], base_va + offset)

    def function_starts(self) -> Set[int]:
        targets: Set[int] = set()
        section = self._text
        va = section.vaddr
        while section.contains_va(va):
            word = section.read_word(va)
            op = word >> 26
            if op in (0x32, 0x33):
                displacement = word & 0x3FFFFFF
                if displacement & 0x2000000:
                    displacement -= 0x4000000
                target = va + displacement * 4
                if section.contains_va(target):
                    targets.add(target)
            va += 4
        return targets

    def string_refs(self) -> Dict[int, int]:
        refs: Dict[int, int] = {}
        section = self._text
        data_section = self._bin.data
        if data_section is None:
            return refs
        va = section.vaddr
        previous_word = 0
        previous_va = 0
        while section.contains_va(va):
            word = section.read_word(va)
            if previous_word >> 26 == 0x17 and word >> 26 == 0x16:
                rd1 = (previous_word >> 21) & 0x1F
                source1 = (previous_word >> 16) & 0x1F
                rd2 = (word >> 21) & 0x1F
                source2 = (word >> 16) & 0x1F
                if source1 == 0 and rd1 == rd2 == source2:
                    data_va = ((previous_word & 0xFFFF) << 16) | (word & 0xFFFF)
                    if data_section.contains_va(data_va):
                        refs[previous_va] = data_va
            previous_word = word
            previous_va = va
            va += 4
        return refs
