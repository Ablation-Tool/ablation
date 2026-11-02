"""Bounded C166 execution and CAN message-object modeling.

The interpreter implements an explicitly validated instruction subset for
focused firmware paths. Unsupported instructions, indirect jumps, code writes,
and excessive execution fail closed. It is not a cycle-accurate C166 simulator.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .ecu_c166_decoder import C166Insn, EcuC166Decoder

_ADDRESS_SPACE = 0x1000000
_PAGE_SIZE = 4096


class C166ExecutionError(ValueError):
    def __init__(self, pc: int, reason: str, raw: bytes = b'') -> None:
        self.pc = pc
        self.raw = bytes(raw)
        self.reason = reason
        suffix = f' raw={self.raw.hex(" ")}' if self.raw else ''
        super().__init__(f'C166 execution at 0x{pc:06X}: {reason}{suffix}')


class C166Memory:
    """Sparse 24-bit memory with optional firmware-image write protection."""

    def __init__(
        self,
        image: bytes = b'',
        base_pa: int = 0,
        protect_image: bool = True,
        dpp_pages: Optional[dict[int, int]] = None,
        protected_ranges: Optional[Iterable[tuple[int, int]]] = None,
    ) -> None:
        if not 0 <= base_pa < _ADDRESS_SPACE:
            raise ValueError('C166 memory base outside 24-bit address space')
        if base_pa + len(image) > _ADDRESS_SPACE:
            raise ValueError('C166 image exceeds 24-bit address space')
        self.dpp_pages = dict(dpp_pages or {})
        for index, page in self.dpp_pages.items():
            if index not in range(4) or not isinstance(page, int) or not 0 <= page <= 0x3FF:
                raise ValueError('invalid C166 DPP register or page')
        if protected_ranges is None:
            self._protected = ((base_pa, base_pa + len(image)),) if protect_image and image else ()
        else:
            ranges = tuple(protected_ranges)
            if len(ranges) > 256:
                raise ValueError('too many protected memory ranges')
            for start, end in ranges:
                if not 0 <= start < end <= _ADDRESS_SPACE:
                    raise ValueError('invalid protected memory range')
            self._protected = ranges
        self._pages: dict[int, bytearray] = {}
        for offset in range(0, len(image), _PAGE_SIZE):
            self.write(base_pa + offset, image[offset:offset + _PAGE_SIZE], force=True)

    @staticmethod
    def _address(address: int, size: int = 1) -> None:
        if not isinstance(address, int) or not 0 <= address < _ADDRESS_SPACE:
            raise ValueError('C166 memory address outside 24-bit space')
        if size < 1 or address + size > _ADDRESS_SPACE:
            raise ValueError('C166 memory access exceeds 24-bit space')

    def _indirect_address(self, offset: int) -> int:
        if not 0 <= offset <= 0xFFFF:
            raise C166ExecutionError(offset, 'indirect offset outside 16-bit range')
        if offset >= 0xF000:
            return offset
        index = (offset >> 14) & 0x3
        page = self.dpp_pages.get(index, index)
        return (page << 14) | (offset & 0x3FFF)

    def read(self, address: int, size: int = 1) -> bytes:
        self._address(address, size)
        result = bytearray()
        for current in range(address, address + size):
            page, offset = divmod(current, _PAGE_SIZE)
            data = self._pages.get(page)
            result.append(data[offset] if data is not None else 0)
        return bytes(result)

    def read_indirect(self, offset: int, size: int = 1) -> bytes:
        address = self._indirect_address(offset)
        if address + size > _ADDRESS_SPACE:
            raise C166ExecutionError(offset, 'DPP-mapped read exceeds address space')
        return self.read(address, size)

    def write(self, address: int, data: bytes, *, force: bool = False) -> None:
        self._address(address, len(data))
        if not force:
            for start, end in self._protected:
                if address < end and address + len(data) > start:
                    raise C166ExecutionError(address, 'attempt to write protected firmware image')
        for offset, value in enumerate(data):
            current = address + offset
            page, page_offset = divmod(current, _PAGE_SIZE)
            if page not in self._pages:
                self._pages[page] = bytearray(_PAGE_SIZE)
            self._pages[page][page_offset] = value

    def write_indirect(self, offset: int, data: bytes) -> None:
        address = self._indirect_address(offset)
        if address + len(data) > _ADDRESS_SPACE:
            raise C166ExecutionError(offset, 'DPP-mapped write exceeds address space')
        self.write(address, data)

    def read16(self, address: int) -> int:
        return int.from_bytes(self.read(address, 2), 'little')

    def read16_indirect(self, offset: int) -> int:
        return int.from_bytes(self.read_indirect(offset, 2), 'little')

    def write16(self, address: int, value: int) -> None:
        self.write(address, (value & 0xFFFF).to_bytes(2, 'little'))

    def write16_indirect(self, offset: int, value: int) -> None:
        self.write_indirect(offset, (value & 0xFFFF).to_bytes(2, 'little'))


@dataclass(frozen=True)
class C166TraceEntry:
    pc: int
    raw: bytes
    mnemonic: str


@dataclass(frozen=True)
class C166ExecutionResult:
    pc: int
    reason: str
    steps: int
    registers: tuple[int, ...]
    zero: bool
    carry: bool
    negative: bool
    overflow: bool
    trace: tuple[C166TraceEntry, ...]


@dataclass
class C166CANMessage:
    command: int
    channel: int = 0
    subcommand: int = 0
    payload: bytes = b'\0\0\0\0'
    checksum: Optional[int] = None

    def __post_init__(self) -> None:
        for name, value in (('command', self.command), ('channel', self.channel), ('subcommand', self.subcommand)):
            if not isinstance(value, int) or not 0 <= value <= 0xFF:
                raise ValueError(f'CAN {name} outside 8-bit range')
        if not isinstance(self.payload, bytes):
            raise TypeError('CAN payload must be bytes')
        if len(self.payload) != 4:
            raise ValueError('CAN payload must contain exactly four bytes')
        if self.checksum is not None and not 0 <= self.checksum <= 0xFF:
            raise ValueError('CAN checksum outside 8-bit range')

    def to_bytes(self) -> bytes:
        body = bytes((self.command, self.channel, self.subcommand)) + self.payload
        checksum = sum(body) & 0xFF if self.checksum is None else self.checksum
        return body + bytes((checksum,))

    @property
    def checksum_valid(self) -> bool:
        frame = self.to_bytes()
        return (sum(frame[:7]) & 0xFF) == frame[7]


class C166CANController:
    """C166 16-byte message-object layout used by the recovered CAN handler."""

    def __init__(self, base: int = 0xEF10, objects: int = 15) -> None:
        if not 1 <= objects <= 256:
            raise ValueError('CAN object count must be between 1 and 256')
        if base < 0 or base + objects * 16 > _ADDRESS_SPACE:
            raise ValueError('CAN message objects exceed C166 address space')
        self.base = base
        self.objects = objects

    def object_address(self, index: int) -> int:
        if not 0 <= index < self.objects:
            raise ValueError(f'CAN object index outside 0..{self.objects - 1}')
        return self.base + index * 16

    def write_frame(self, memory: C166Memory, index: int, message: C166CANMessage) -> None:
        address = self.object_address(index)
        memory.write(address + 7, message.to_bytes())

    def read_frame(self, memory: C166Memory, index: int) -> bytes:
        return memory.read(self.object_address(index) + 7, 8)


class C166CPU:
    def __init__(
        self,
        decoder: EcuC166Decoder,
        memory: Optional[C166Memory] = None,
        *,
        pc: Optional[int] = None,
        trace_limit: int = 1024,
    ) -> None:
        if not 1 <= trace_limit <= 65_536:
            raise ValueError('C166 trace limit must be between 1 and 65536')
        self.decoder = decoder
        self.memory = memory if memory is not None else C166Memory()
        self.registers = [0] * 16
        self.pc = decoder.base_pa if pc is None else pc
        self.zero = False
        self.carry = False
        self.negative = False
        self.overflow = False
        self.trace: deque[C166TraceEntry] = deque(maxlen=trace_limit)
        self._calls: deque[int] = deque()

    def read_byte_register(self, index: int) -> int:
        if not 0 <= index < 16:
            raise ValueError('C166 byte register outside 0..15')
        value = self.registers[index >> 1]
        return (value >> (8 if index & 1 else 0)) & 0xFF

    def write_byte_register(self, index: int, value: int) -> None:
        if not 0 <= index < 16:
            raise ValueError('C166 byte register outside 0..15')
        register = index >> 1
        shift = 8 if index & 1 else 0
        mask = 0xFF00 if index & 1 else 0x00FF
        self.registers[register] = (
            (self.registers[register] & ~mask) | ((value & 0xFF) << shift)
        ) & 0xFFFF

    def _result(self, reason: str, steps: int) -> C166ExecutionResult:
        return C166ExecutionResult(
            self.pc,
            reason,
            steps,
            tuple(self.registers),
            self.zero,
            self.carry,
            self.negative,
            self.overflow,
            tuple(self.trace),
        )

    def run(self, *, max_steps: int = 200_000, stop_addresses: Iterable[int] = (), max_call_depth: int = 64) -> C166ExecutionResult:
        if not 1 <= max_steps <= 100_000_000:
            raise ValueError('C166 step limit outside 1..100000000')
        if not 1 <= max_call_depth <= 4096:
            raise ValueError('C166 call-depth limit outside 1..4096')
        stops = set(stop_addresses)
        if len(stops) > 4096:
            raise ValueError('too many C166 stop addresses')
        for steps in range(1, max_steps + 1):
            if self.pc in stops:
                return self._result('stop_address', steps - 1)
            if not self.decoder.contains_pa(self.pc):
                raise C166ExecutionError(self.pc, 'program counter outside firmware image')
            insn = self.decoder.decode_one(self.pc - self.decoder.base_pa)
            if insn is None:
                raise C166ExecutionError(self.pc, 'truncated instruction')
            self.trace.append(C166TraceEntry(self.pc, insn.raw, insn.mnemonic))
            if insn.raw == bytes.fromhex('b748b7b7'):
                return self._result('srst', steps)
            self.pc += len(insn.raw)
            self._execute(insn, max_call_depth)
        raise C166ExecutionError(self.pc, f'exceeded {max_steps} execution steps')

    def _condition(self, code: int) -> bool:
        conditions = {
            0: True,
            2: self.zero,
            3: not self.zero,
            4: self.overflow,
            5: not self.overflow,
            6: self.negative,
            7: not self.negative,
            8: self.carry,
            9: not self.carry,
            10: self.negative == self.overflow and not self.zero,
            11: self.negative != self.overflow or self.zero,
            12: self.negative != self.overflow,
            13: self.negative == self.overflow,
            14: not self.carry and not self.zero,
            15: self.carry or self.zero,
        }
        if code == 1 or code not in conditions:
            raise C166ExecutionError(self.pc, f'unsupported condition code {code}')
        return conditions[code]

    def _flags_move(self, value: int, width: int) -> None:
        mask = (1 << width) - 1
        value &= mask
        self.zero = value == 0
        self.negative = bool(value & (1 << (width - 1)))
        self.overflow = False

    def _flags_sub(self, left: int, right: int, width: int) -> int:
        mask = (1 << width) - 1
        result = (left - right) & mask
        self.zero = result == 0
        self.carry = (left & mask) < (right & mask)
        self.negative = bool(result & (1 << (width - 1)))
        signed_left = left - (1 << width) if left & (1 << (width - 1)) else left
        signed_right = right - (1 << width) if right & (1 << (width - 1)) else right
        signed_result = signed_left - signed_right
        self.overflow = not -(1 << (width - 1)) <= signed_result < (1 << (width - 1))
        return result

    def _flags_add(self, left: int, right: int, width: int) -> int:
        mask = (1 << width) - 1
        total = (left & mask) + (right & mask)
        result = total & mask
        self.zero = result == 0
        self.carry = total > mask
        self.negative = bool(result & (1 << (width - 1)))
        sign = 1 << (width - 1)
        self.overflow = bool((~(left ^ right) & (left ^ result) & sign))
        return result

    def _execute(self, insn: C166Insn, max_call_depth: int) -> None:
        raw = insn.raw
        op = raw[0]
        b1 = raw[1]
        address = insn.pa
        memory_address = int.from_bytes(raw[2:4], 'little') if len(raw) == 4 else None

        if op in (0xDA, 0xFA):
            if op == 0xDA:
                if len(self._calls) >= max_call_depth:
                    raise C166ExecutionError(address, 'call-depth limit exceeded', raw)
                self._calls.append(self.pc)
            if insn.target is None:
                raise C166ExecutionError(address, 'unresolved direct branch', raw)
            self.pc = insn.target
            return
        if op in (0xCA, 0xEA):
            taken = self._condition((b1 >> 4) & 0xF)
            if op == 0xCA and taken:
                if len(self._calls) >= max_call_depth:
                    raise C166ExecutionError(address, 'call-depth limit exceeded', raw)
                self._calls.append(self.pc)
            if taken:
                if insn.target is None:
                    raise C166ExecutionError(address, 'unresolved absolute branch', raw)
                self.pc = insn.target
            return
        if (op & 0x0F) == 0x0D:
            if self._condition((op >> 4) & 0xF):
                if insn.target is None:
                    raise C166ExecutionError(address, 'unresolved relative branch', raw)
                self.pc = insn.target
            return
        if op in (0xCB, 0xDB) and b1 == 0:
            if not self._calls:
                raise C166ExecutionError(address, 'return with empty modeled call stack', raw)
            self.pc = self._calls.pop()
            return
        if op == 0x9C:
            raise C166ExecutionError(address, 'indirect jumps require a validated target model', raw)

        if op in (0xF0, 0xF1):
            destination = (b1 >> 4) & 0xF
            source = b1 & 0xF
            if op == 0xF0:
                value = self.registers[source]
                self.registers[destination] = value
                self._flags_move(value, 16)
            else:
                value = self.read_byte_register(source)
                self.write_byte_register(destination, value)
                self._flags_move(value, 8)
            return
        if op in (0xE0, 0xE1):
            destination = b1 & 0xF
            value = (b1 >> 4) & 0xF
            if op == 0xE0:
                self.registers[destination] = value
                self._flags_move(value, 16)
            else:
                self.write_byte_register(destination, value)
                self._flags_move(value, 8)
            return
        if op in (0xE6, 0xE7):
            destination = b1 & 0xF
            if op == 0xE6:
                value = int.from_bytes(raw[2:4], 'little')
                self.registers[destination] = value
                self._flags_move(value, 16)
            else:
                value = raw[2]
                self.write_byte_register(destination, value)
                self._flags_move(value, 8)
            return
        if op in (0xF2, 0xF3, 0xC2):
            destination = b1 & 0xF
            if op == 0xF2:
                value = self.memory.read16(memory_address)
                self.registers[destination] = value
                self._flags_move(value, 16)
            elif op == 0xF3:
                value = self.memory.read(memory_address)[0]
                self.write_byte_register(destination, value)
                self._flags_move(value, 8)
            else:
                value = self.memory.read(memory_address)[0]
                self.registers[destination] = value
            return
        if op in (0xF6, 0xF7):
            source = b1 & 0xF
            if op == 0xF6:
                value = 0 if b1 == 0x8E else self.registers[source]
                self.memory.write16(memory_address, value)
            else:
                value = 0 if b1 == 0x8E else self.read_byte_register(source)
                self.memory.write(memory_address, bytes((value,)))
            return
        if op in (0xD4, 0xF4):
            destination = (b1 >> 4) & 0xF
            base = b1 & 0xF
            effective = (self.registers[base] + memory_address) & 0xFFFF
            if op == 0xD4:
                value = self.memory.read16_indirect(effective)
                self.registers[destination] = value
                self._flags_move(value, 16)
            else:
                value = self.memory.read_indirect(effective)[0]
                self.write_byte_register(destination, value)
                self._flags_move(value, 8)
            return
        if op in (0xC4, 0xE4):
            source = (b1 >> 4) & 0xF
            base = b1 & 0xF
            effective = (self.registers[base] + memory_address) & 0xFFFF
            if op == 0xC4:
                self.memory.write16_indirect(effective, self.registers[source])
            else:
                self.memory.write_indirect(effective, bytes((self.read_byte_register(source),)))
            return
        if op in (0xB8, 0xB9):
            source = (b1 >> 4) & 0xF
            base = b1 & 0xF
            if op == 0xB8:
                self.memory.write16_indirect(self.registers[base], self.registers[source])
            else:
                self.memory.write_indirect(self.registers[base], bytes((self.read_byte_register(source),)))
            return
        if op in (0xA8, 0xA9):
            destination = (b1 >> 4) & 0xF
            base = b1 & 0xF
            if op == 0xA8:
                value = self.memory.read16_indirect(self.registers[base])
                self.registers[destination] = value
                self._flags_move(value, 16)
            else:
                value = self.memory.read_indirect(self.registers[base])[0]
                self.write_byte_register(destination, value)
                self._flags_move(value, 8)
            return
        if op == 0xC0:
            destination = (b1 >> 4) & 0xF
            value = self.read_byte_register(b1 & 0xF)
            self.registers[destination] = value
            return

        if op in (0x29, 0x49) and not (b1 & 0x08):
            destination = (b1 >> 4) & 0xF
            immediate = b1 & 0x07
            value = self.read_byte_register(destination)
            result = self._flags_sub(value, immediate, 8)
            if op == 0x29:
                self.write_byte_register(destination, result)
            return
        if op in (0x07, 0x47, 0x67):
            destination = b1 & 0xF
            value = self.read_byte_register(destination)
            immediate = raw[2]
            if op == 0x07:
                self.write_byte_register(destination, self._flags_add(value, immediate, 8))
            elif op == 0x47:
                self._flags_sub(value, immediate, 8)
            else:
                result = value & immediate
                self.write_byte_register(destination, result)
                self.zero = result == 0
                self.negative = bool(result & 0x80)
                self.carry = False
                self.overflow = False
            return
        if op == 0x02:
            destination = b1 & 0xF
            self.registers[destination] = self._flags_add(
                self.registers[destination], self.memory.read16(memory_address), 16,
            )
            return
        if op in (0x05, 0x64, 0x65, 0x74):
            source = b1 & 0xF
            if op == 0x05:
                value = self._flags_add(self.memory.read(memory_address)[0], self.read_byte_register(source), 8)
            else:
                current = self.memory.read16(memory_address) if op == 0x64 else self.memory.read(memory_address)[0]
                operand = self.registers[source] if op in (0x64, 0x74) else self.read_byte_register(source)
                value = (current | operand) if op == 0x74 else (current & operand)
                self.zero = value == 0
                self.negative = bool(value & (0x8000 if op == 0x64 else 0x80))
                self.carry = False
                self.overflow = False
            if op in (0x05, 0x65):
                self.memory.write(memory_address, bytes((value & 0xFF,)))
            else:
                self.memory.write16(memory_address, value)
            return
        if op == 0x25 and b1 == 0x8F:
            value = self._flags_sub(self.memory.read(memory_address)[0], 0xFF, 8)
            self.memory.write(memory_address, bytes((value,)))
            return

        raise C166ExecutionError(address, f'unsupported instruction {insn.mnemonic}', raw)
