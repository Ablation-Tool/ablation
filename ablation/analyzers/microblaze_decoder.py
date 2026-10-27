"""MicroBlaze big-endian instruction decoder for raw firmware load segments.

Capstone 5 does not support MicroBlaze. This decoder covers the base integer
ISA and common optional instructions used by Xilinx PLM firmware. Encodings
follow QEMU target/microblaze/insns.decode.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


MAX_IMAGE_BYTES = 256 * 1024 * 1024


def _s16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _s32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def _reg(value: Optional[int]) -> str:
    return f"r{value}" if value is not None else ""


@dataclass(frozen=True)
class MicroBlazeInsn:
    offset: int
    address: int
    word: int
    mnemonic: str
    operands: str = ""
    rd: Optional[int] = None
    ra: Optional[int] = None
    rb: Optional[int] = None
    imm: Optional[int] = None
    target: Optional[int] = None
    flow: str = "linear"
    delay_slot: bool = False
    extended_imm: bool = False
    valid: bool = True

    @property
    def size(self) -> int:
        return 4

    def __str__(self) -> str:
        text = f"{self.address:08x}: {self.word:08x}  {self.mnemonic}"
        if self.operands:
            text += f" {self.operands}"
        return text


_TYPEA = (
    (0x00, "add"), (0x02, "addc"), (0x04, "addk"), (0x06, "addkc"),
    (0x01, "rsub"), (0x03, "rsubc"), (0x05, "rsubk"), (0x07, "rsubkc"),
    (0x10, "mul"), (0x12, "idiv"),
    (0x20, "or"), (0x21, "and"), (0x22, "xor"), (0x23, "andn"),
)

_TYPEB = {
    0x08: "addi", 0x0A: "addic", 0x0C: "addik", 0x0E: "addikc",
    0x09: "rsubi", 0x0B: "rsubic", 0x0D: "rsubik", 0x0F: "rsubikc",
    0x18: "muli", 0x28: "ori", 0x29: "andi", 0x2A: "xori", 0x2B: "andni",
    0x38: "lbui", 0x39: "lhui", 0x3A: "lwi",
    0x3C: "sbi", 0x3D: "shi", 0x3E: "swi",
}

_LOAD_STORE_A = {
    0x30: "lbu", 0x31: "lhu", 0x32: "lw",
    0x34: "sb", 0x35: "sh", 0x36: "sw",
}

_CONDITIONS = ("beq", "bne", "blt", "ble", "bgt", "bge")

_BRANCH_A = {
    0x00: ("br", "jump", False),
    0x08: ("bra", "jump", False),
    0x10: ("brd", "jump", True),
    0x18: ("brad", "jump", True),
    0x14: ("brld", "call", True),
    0x1C: ("brald", "call", True),
    0x0C: ("brk", "trap", False),
}

_BRANCH_I = {
    0x00: ("bri", "jump", False, True),
    0x08: ("brai", "jump", False, False),
    0x10: ("brid", "jump", True, True),
    0x18: ("braid", "jump", True, False),
    0x14: ("brlid", "call", True, True),
    0x1C: ("bralid", "call", True, False),
    0x0C: ("brki", "trap", False, False),
}

_RETURNS = {0x12: "rtbd", 0x11: "rtid", 0x14: "rted", 0x10: "rtsd"}


class MicroBlazeDecoder:
    """Decode a raw big-endian MicroBlaze image without external dependencies."""

    def __init__(self, data: bytes | str | Path, base_va: int = 0, byte_order: str = "big") -> None:
        if byte_order not in ("big", "little"):
            raise ValueError("byte_order must be 'big' or 'little'")
        if isinstance(data, (str, Path)):
            path = Path(data)
            if path.stat().st_size > MAX_IMAGE_BYTES:
                raise ValueError(f"MicroBlaze image exceeds {MAX_IMAGE_BYTES} bytes: {path}")
            self._data = path.read_bytes()
        else:
            self._data = bytes(data)
        if len(self._data) > MAX_IMAGE_BYTES:
            raise ValueError(f"MicroBlaze image exceeds {MAX_IMAGE_BYTES} bytes")
        self.base_va = base_va
        self.byte_order = byte_order

    @classmethod
    def from_path(
        cls, path: str | Path, base_va: int = 0, byte_order: str = "big"
    ) -> "MicroBlazeDecoder":
        return cls(path, base_va, byte_order)

    @classmethod
    def from_bytes(
        cls, data: bytes, base_va: int = 0, byte_order: str = "big"
    ) -> "MicroBlazeDecoder":
        return cls(data, base_va, byte_order)

    def decode_one(self, offset: int, imm_high: Optional[int] = None) -> Optional[MicroBlazeInsn]:
        if offset < 0 or offset + 4 > len(self._data):
            return None
        word = struct.unpack_from("<I" if self.byte_order == "little" else ">I", self._data, offset)[0]
        return self.decode_word(word, self.base_va + offset, offset, imm_high)

    def decode_word(
        self, word: int, address: int = 0, offset: Optional[int] = None,
        imm_high: Optional[int] = None,
    ) -> MicroBlazeInsn:
        if offset is None:
            offset = address - self.base_va
        opcode = (word >> 26) & 0x3F
        rd = (word >> 21) & 0x1F
        ra = (word >> 16) & 0x1F
        rb = (word >> 11) & 0x1F
        low = word & 0x7FF
        imm16 = word & 0xFFFF
        extended = imm_high is not None
        imm = _s32(((imm_high or 0) << 16) | imm16) if extended else _s16(imm16)

        def make(mnemonic: str, operands: str = "", **kwargs) -> MicroBlazeInsn:
            return MicroBlazeInsn(
                offset=offset, address=address, word=word, mnemonic=mnemonic,
                operands=operands, **kwargs,
            )

        if opcode == 0x2C and rd == 0 and ra == 0:
            return make("imm", str(_s16(imm16)), imm=_s16(imm16))

        if opcode in _TYPEB:
            mnemonic = _TYPEB[opcode]
            shown = f"0x{imm & 0xFFFFFFFF:x}" if opcode >= 0x28 else str(imm)
            return make(
                mnemonic, f"{_reg(rd)}, {_reg(ra)}, {shown}", rd=rd, ra=ra,
                imm=imm, extended_imm=extended,
            )

        if opcode == 0x2F:
            condition = rd & 0x07
            delayed = bool(rd & 0x10)
            if condition < len(_CONDITIONS) and rd in (*range(0, 6), *range(16, 22)):
                mnemonic = _CONDITIONS[condition] + "i" + ("d" if delayed else "")
                return make(
                    mnemonic, f"{_reg(ra)}, 0x{(address + imm) & 0xFFFFFFFF:08x}",
                    ra=ra, imm=imm, target=(address + imm) & 0xFFFFFFFF,
                    flow="conditional", delay_slot=delayed, extended_imm=extended,
                )

        if opcode == 0x27 and rd in (*range(0, 6), *range(16, 22)):
            condition = rd & 0x07
            delayed = bool(rd & 0x10)
            mnemonic = _CONDITIONS[condition] + ("d" if delayed else "")
            return make(
                mnemonic, f"{_reg(ra)}, {_reg(rb)}", ra=ra, rb=rb,
                flow="conditional", delay_slot=delayed,
            )

        if opcode == 0x2E and ra == 2 and rb == 0 and low == 4:
            return make("mbar", str(rd), rd=rd, imm=rd)

        if opcode == 0x2E and ra in _BRANCH_I:
            mnemonic, flow, delayed, relative = _BRANCH_I[ra]
            target = (address + imm) & 0xFFFFFFFF if relative else imm & 0xFFFFFFFF
            operands = f"{_reg(rd)}, 0x{target:08x}" if rd else f"0x{target:08x}"
            return make(
                mnemonic, operands, rd=rd, imm=imm, target=target, flow=flow,
                delay_slot=delayed, extended_imm=extended,
            )

        if opcode == 0x26 and ra in _BRANCH_A:
            mnemonic, flow, delayed = _BRANCH_A[ra]
            operands = f"{_reg(rd)}, {_reg(rb)}" if rd else _reg(rb)
            return make(mnemonic, operands, rd=rd, rb=rb, flow=flow, delay_slot=delayed)

        if opcode == 0x2D and rd in _RETURNS:
            return make(
                _RETURNS[rd], f"{_reg(ra)}, {imm}", ra=ra, imm=imm,
                flow="return", delay_slot=True, extended_imm=extended,
            )

        if opcode == 0x19:
            shift = word & 0x1F
            mode = (word >> 9) & 0x3
            if rb == 0 and (word & 0x1E0) == 0 and mode <= 2:
                mnemonic = {0: "bsrli", 1: "bsrai", 2: "bslli"}[mode]
                return make(mnemonic, f"{_reg(rd)}, {_reg(ra)}, {shift}", rd=rd, ra=ra, imm=shift)
            if rb in (8, 16) and (word & 0x20) == 0:
                insert_imm = (((word >> 6) & 0x1F) << 5) | shift
                mnemonic = "bsefi" if rb == 8 else "bsifi"
                return make(mnemonic, f"{_reg(rd)}, {_reg(ra)}, {insert_imm}", rd=rd, ra=ra, imm=insert_imm)

        if opcode == 0x1B and (word & 0x3F0) == 0:
            control = (word >> 10) & 0x1F
            port = word & 0xF
            if rd == 0 and (word & 0x8000):
                return make("put", f"{_reg(ra)}, {port}", ra=ra, imm=port | (control << 4))
            if ra == 0 and not (word & 0x8000):
                return make("get", f"{_reg(rd)}, {port}", rd=rd, imm=port | (control << 4))

        if opcode == 0x25:
            if ra == 16:
                return make("msrset", f"{_reg(rd)}, 0x{word & 0x7FFF:x}", rd=rd, imm=word & 0x7FFF)
            if ra == 17:
                return make("msrclr", f"{_reg(rd)}, 0x{word & 0x7FFF:x}", rd=rd, imm=word & 0x7FFF)
            if (word & 0xC000) == 0xC000:
                return make("mts", f"0x{word & 0x3FFF:x}, {_reg(ra)}", ra=ra, imm=word & 0x3FFF)
            if (word & 0xC000) == 0x8000:
                return make("mfs", f"{_reg(rd)}, 0x{word & 0x3FFF:x}", rd=rd, imm=word & 0x3FFF)

        if opcode in _LOAD_STORE_A:
            suffix = {0x000: "", 0x100: "ea", 0x200: "r", 0x400: "x"}.get(low)
            if suffix is not None:
                mnemonic = _LOAD_STORE_A[opcode] + suffix
                return make(mnemonic, f"{_reg(rd)}, {_reg(ra)}, {_reg(rb)}", rd=rd, ra=ra, rb=rb)

        if opcode in (0x00, 0x02, 0x04, 0x06, 0x01, 0x03, 0x07, 0x20, 0x21, 0x22, 0x23):
            if low == 0:
                mnemonic = dict(_TYPEA)[opcode]
                if word == 0:
                    return make("nop")
                return make(mnemonic, f"{_reg(rd)}, {_reg(ra)}, {_reg(rb)}", rd=rd, ra=ra, rb=rb)
            if low == 0x400 and opcode in (0x20, 0x22, 0x23):
                mnemonic = {0x20: "pcmpbf", 0x22: "pcmpeq", 0x23: "pcmpne"}[opcode]
                return make(mnemonic, f"{_reg(rd)}, {_reg(ra)}, {_reg(rb)}", rd=rd, ra=ra, rb=rb)

        if opcode == 0x05:
            mnemonic = {0: "rsubk", 1: "cmp", 3: "cmpu"}.get(low)
            if mnemonic:
                return make(mnemonic, f"{_reg(rd)}, {_reg(ra)}, {_reg(rb)}", rd=rd, ra=ra, rb=rb)

        if opcode == 0x10 and low in (0, 1, 2, 3):
            mnemonic = {0: "mul", 1: "mulh", 2: "mulhsu", 3: "mulhu"}[low]
            return make(mnemonic, f"{_reg(rd)}, {_reg(ra)}, {_reg(rb)}", rd=rd, ra=ra, rb=rb)

        if opcode == 0x12 and low in (0, 2):
            return make("idiv" if low == 0 else "idivu", f"{_reg(rd)}, {_reg(ra)}, {_reg(rb)}", rd=rd, ra=ra, rb=rb)

        if opcode == 0x11 and low in (0, 0x200, 0x400):
            mnemonic = {0: "bsrl", 0x200: "bsra", 0x400: "bsll"}[low]
            return make(mnemonic, f"{_reg(rd)}, {_reg(ra)}, {_reg(rb)}", rd=rd, ra=ra, rb=rb)

        if opcode == 0x24 and rb == 0:
            unary = {
                0x001: "sra", 0x021: "src", 0x041: "srl",
                0x060: "sext8", 0x061: "sext16", 0x0E0: "clz",
                0x1E0: "swapb", 0x1E2: "swaph",
            }.get(low)
            if unary:
                return make(unary, f"{_reg(rd)}, {_reg(ra)}", rd=rd, ra=ra)

        return make(".word", f"0x{word:08x}", valid=False)

    def disassemble(self, start: int = 0, end: Optional[int] = None) -> list[MicroBlazeInsn]:
        """Decode file offsets in ``[start, end)``, carrying IMM to one successor."""
        if end is None:
            end = len(self._data)
        end = min(end, len(self._data))
        instructions: list[MicroBlazeInsn] = []
        imm_high: Optional[int] = None
        for offset in range(start, end - 3, 4):
            insn = self.decode_one(offset, imm_high)
            if insn is None:
                break
            instructions.append(insn)
            if insn.mnemonic == "imm":
                imm_high = insn.word & 0xFFFF
            else:
                imm_high = None
        return instructions

    def call_targets(self) -> list[int]:
        return sorted({i.target for i in self.disassemble() if i.flow == "call" and i.target is not None})

    def function_starts(self) -> list[int]:
        instructions = self.disassemble()
        starts = {i.target for i in instructions if i.flow == "call" and i.target is not None}
        for index, insn in enumerate(instructions[:-1]):
            follower = instructions[index + 1]
            if (insn.mnemonic == "addik" and insn.rd == 1 and insn.ra == 1
                    and insn.imm is not None and insn.imm < 0
                    and follower.mnemonic == "swi" and follower.rd == 15
                    and follower.ra == 1 and follower.imm == 0):
                starts.add(insn.address)
        return sorted(starts)


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Disassemble raw MicroBlaze code")
    parser.add_argument("image")
    parser.add_argument("--base", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--start", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--end", type=lambda value: int(value, 0))
    parser.add_argument("--byte-order", choices=("big", "little"), default="big")
    args = parser.parse_args()
    decoder = MicroBlazeDecoder.from_path(args.image, args.base, args.byte_order)
    for insn in decoder.disassemble(args.start, args.end):
        print(insn)


if __name__ == "__main__":
    _main()
