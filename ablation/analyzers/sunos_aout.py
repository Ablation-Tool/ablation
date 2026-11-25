"""Bounded SunOS SPARC OMAGIC a.out symbols, calls, and argument provenance."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

MAX_AOUT_BYTES = 67_108_864
MAGIC_SPARC_OMAGIC = 0x01030107
TEXT_BASE = 0x2000
_REGISTER_CLASSES = "goli"


class AoutError(ValueError):
    pass


def _bounded(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise AoutError(f"{label} outside input: offset={offset:#x}, size={size:#x}")


def _signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _cstring(data: bytes, offset: int) -> str:
    _bounded(data, offset, 1, "symbol string")
    end = data.find(b"\0", offset)
    if end < 0:
        raise AoutError("unterminated symbol string")
    return data[offset:end].decode("latin1")


@dataclass(frozen=True)
class AoutHeader:
    magic: int
    text_size: int
    data_size: int
    bss_size: int
    symbol_size: int
    entry: int
    text_reloc_size: int
    data_reloc_size: int
    text_reloc_offset: int
    data_reloc_offset: int
    symbol_offset: int


@dataclass(frozen=True)
class AoutSymbol:
    index: int
    name: str
    type: int
    other: int
    desc: int
    value: int


@dataclass(frozen=True)
class AoutRelocation:
    segment: str
    address: int
    va: int | None
    flags: int
    symbol_index: int
    external: bool
    pcrel: bool
    length_code: int
    addend: int


@dataclass(frozen=True)
class AoutCall:
    address: int
    word: int
    raw_target: int
    target: int | None
    external_symbol: str | None
    delay_slot_word: int | None
    relocation: AoutRelocation | None

    def to_dict(self) -> dict:
        result = {
            "address": self.address,
            "word": f"{self.word:08x}",
            "raw_target": self.raw_target,
            "target": self.target,
            "external_symbol": self.external_symbol,
            "delay_slot_word": f"{self.delay_slot_word:08x}" if self.delay_slot_word is not None else None,
        }
        if self.relocation:
            result["relocation"] = self.relocation.__dict__
        return result


@dataclass(frozen=True)
class AoutCallArgument:
    call_address: int
    register: str
    value: int | None
    provenance: str
    setup_address: int | None
    branch_address: int | None = None
    wrapper_address: int | None = None
    dispatcher_call_address: int | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SunosAout:
    data: bytes
    source: str
    header: AoutHeader
    symbols: list[AoutSymbol]
    relocations: list[AoutRelocation]
    text_base: int = TEXT_BASE

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def format(self) -> str:
        return "SunOS SPARC OMAGIC a.out, big-endian, 12-byte relocation records"

    def _text_word(self, va: int) -> int:
        offset = 0x20 + va - self.text_base
        _bounded(self.data, offset, 4, "text word")
        return struct.unpack_from(">I", self.data, offset)[0]

    def calls(self, target: int | None = None) -> list[AoutCall]:
        relocation_by_va = {}
        for relocation in self.relocations:
            if relocation.segment != "text":
                continue
            if relocation.va in relocation_by_va:
                raise AoutError(f"duplicate text relocation at {relocation.va:#x}")
            relocation_by_va[relocation.va] = relocation
        calls = []
        for offset in range(0, self.header.text_size, 4):
            va = self.text_base + offset
            word = self._text_word(va)
            if word >> 30 != 1:
                continue
            displacement = _signed(word & 0x3FFFFFFF, 30) * 4
            raw_target = (va + displacement) & 0xFFFFFFFF
            resolved = raw_target
            external_name = None
            relocation = relocation_by_va.get(va)
            if relocation:
                if not relocation.pcrel or relocation.length_code != 2:
                    raise AoutError(f"unsupported direct-call relocation flags at {va:#x}")
                if relocation.external:
                    if relocation.symbol_index >= len(self.symbols):
                        raise AoutError(f"external symbol index outside table at {va:#x}")
                    symbol = self.symbols[relocation.symbol_index]
                    if symbol.type != 1 or symbol.value != 0:
                        raise AoutError(f"external call target is not undefined at {va:#x}")
                    external_name = symbol.name
                    resolved = None
                else:
                    if relocation.symbol_index != 4:
                        raise AoutError(f"unsupported internal call segment at {va:#x}")
                    resolved = (va + displacement + relocation.addend) & 0xFFFFFFFF
            if target is not None and resolved != target:
                continue
            delay = self._text_word(va + 4) if offset + 4 < self.header.text_size else None
            calls.append(AoutCall(va, word, raw_target, resolved, external_name, delay, relocation))
        return calls

    @staticmethod
    def _register_number(register: str) -> tuple[str, int]:
        normalized = register if register.startswith("%") else "%" + register
        if len(normalized) != 3 or normalized[1] not in _REGISTER_CLASSES or not normalized[2].isdigit():
            raise AoutError(f"invalid SPARC register {register!r}")
        number = int(normalized[2])
        if number > 7:
            raise AoutError(f"invalid SPARC register {register!r}")
        return normalized, _REGISTER_CLASSES.index(normalized[1]) * 8 + number

    @staticmethod
    def _mov_immediate(word: int | None, register: int) -> int | None:
        if word is None or word >> 30 != 2 or (word >> 19) & 0x3F != 2:
            return None
        if (word >> 25) & 0x1F != register:
            return None
        if (word >> 13) & 1:
            if (word >> 14) & 0x1F:
                return None
            return _signed(word & 0x1FFF, 13)
        if word & 0x1F or (word >> 14) & 0x1F:
            return None
        return 0

    def _incoming_branches(self, target: int) -> list[tuple[int, int | None]]:
        result = []
        for offset in range(0, self.header.text_size, 4):
            va = self.text_base + offset
            word = self._text_word(va)
            if word >> 30 != 0 or (word >> 22) & 7 != 2:
                continue
            destination = (va + _signed(word & 0x3FFFFF, 22) * 4) & 0xFFFFFFFF
            if destination == target:
                delay = self._text_word(va + 4) if offset + 4 < self.header.text_size else None
                result.append((va, delay))
        return result

    def _has_fallthrough(self, address: int) -> bool:
        if address - 8 < self.text_base:
            return True
        word = self._text_word(address - 8)
        return not (word >> 30 == 0 and (word >> 22) & 7 == 2 and (word >> 25) & 0xF == 8)

    def call_argument(self, call: AoutCall, register: str = "%o1") -> AoutCallArgument:
        normalized, number = self._register_number(register)
        value = self._mov_immediate(call.delay_slot_word, number)
        if value is not None:
            return AoutCallArgument(call.address, normalized, value, "call_delay_slot", call.address + 4)
        incoming = self._incoming_branches(call.address)
        if call.address - 4 >= self.text_base:
            value = self._mov_immediate(self._text_word(call.address - 4), number)
            if value is not None and not incoming:
                return AoutCallArgument(call.address, normalized, value, "preceding_instruction", call.address - 4)
        if len(incoming) == 1 and not self._has_fallthrough(call.address):
            branch, delay = incoming[0]
            value = self._mov_immediate(delay, number)
            if value is not None:
                return AoutCallArgument(call.address, normalized, value, "branch_delay_slot", branch + 4, branch)
        return AoutCallArgument(call.address, normalized, None, "unresolved", None)

    def dispatch_arguments(self, target: int, register: str = "%o1",
                           wrappers: tuple[int, ...] = ()) -> list[AoutCallArgument]:
        wrapper_set = set(wrappers)
        if target in wrapper_set:
            raise AoutError("dispatcher cannot also be a wrapper")
        calls = self.calls()
        result = []
        for call in calls:
            if call.target == target:
                result.append(self.call_argument(call, register))
                continue
            if call.target not in wrapper_set:
                continue
            if call.target < self.text_base or call.target >= self.text_base + self.header.text_size:
                raise AoutError(f"wrapper outside text at {call.target:#x}")
            end = None
            for address in range(call.target, self.text_base + self.header.text_size, 4):
                if self._text_word(address) == 0x81C7E008:
                    end = address
                    break
            if end is None:
                raise AoutError(f"wrapper return not found for {call.target:#x}")
            internal = [item for item in calls if call.target <= item.address < end and item.target == target]
            if len(internal) != 1:
                raise AoutError(f"expected one dispatcher call in wrapper {call.target:#x}, found {len(internal)}")
            argument = self.call_argument(internal[0], register)
            result.append(AoutCallArgument(
                call.address, argument.register, argument.value,
                "wrapper" if argument.value is not None else "wrapper_unresolved",
                argument.setup_address, argument.branch_address, call.target, internal[0].address,
            ))
        return result

    def to_dict(self, full: bool = False) -> dict:
        result = {
            "source": self.source,
            "sha256": self.sha256,
            "format": self.format,
            "header": self.header.__dict__,
            "text_base": self.text_base,
            "symbol_count": len(self.symbols),
            "relocation_count": len(self.relocations),
            "relocation_model": {
                "record_size": 12,
                "layout": "r_address:u32, flags:u32, r_addend:u32; big-endian",
                "flags": "symbol_index=(flags>>8)&0xffffff; extern=(flags>>7)&1; pcrel=(flags>>2)&1; length_code=flags&3",
                "scope": "SunOS SPARC OMAGIC direct calls; non-call relocations are preserved but not applied",
            },
        }
        if full:
            result.update({
                "symbols": [item.__dict__ for item in self.symbols],
                "relocations": [item.__dict__ for item in self.relocations],
                "calls": [item.to_dict() for item in self.calls()],
            })
        return result


def _relocations(data: bytes, start: int, size: int, segment: str, text_base: int) -> list[AoutRelocation]:
    result = []
    for offset in range(start, start + size, 12):
        address, flags, addend = struct.unpack_from(">III", data, offset)
        result.append(AoutRelocation(
            segment=segment,
            address=address,
            va=text_base + address if segment == "text" else None,
            flags=flags,
            symbol_index=(flags >> 8) & 0xFFFFFF,
            external=bool((flags >> 7) & 1),
            pcrel=bool((flags >> 2) & 1),
            length_code=flags & 3,
            addend=_signed(addend, 32),
        ))
    return result


def parse_aout(data: bytes, source: str = "<bytes>", text_base: int = TEXT_BASE) -> SunosAout:
    if len(data) < 0x20:
        raise AoutError("input is too short for a SunOS a.out header")
    fields = struct.unpack_from(">8I", data, 0)
    magic, text_size, data_size, bss_size, symbol_size, entry, text_reloc_size, data_reloc_size = fields
    if magic != MAGIC_SPARC_OMAGIC:
        raise AoutError(f"unsupported SunOS SPARC a.out magic {magic:#x}")
    if text_size % 4 or symbol_size % 12 or text_reloc_size % 12 or data_reloc_size % 12:
        raise AoutError("a.out text, symbol, or relocation sizes are not aligned")
    if text_base < 0 or text_base > 0xFFFFFFFF or text_base + text_size > 0x100000000:
        raise AoutError("invalid text base or text size")
    text_reloc_offset = 0x20 + text_size + data_size
    data_reloc_offset = text_reloc_offset + text_reloc_size
    symbol_offset = data_reloc_offset + data_reloc_size
    for label, offset, size in (
        ("text", 0x20, text_size),
        ("data", 0x20 + text_size, data_size),
        ("text relocations", text_reloc_offset, text_reloc_size),
        ("data relocations", data_reloc_offset, data_reloc_size),
        ("symbols", symbol_offset, symbol_size),
    ):
        _bounded(data, offset, size, label)
    header = AoutHeader(magic, text_size, data_size, bss_size, symbol_size, entry,
                        text_reloc_size, data_reloc_size, text_reloc_offset,
                        data_reloc_offset, symbol_offset)
    symbols = []
    strings_offset = symbol_offset + symbol_size
    for offset in range(symbol_offset, symbol_offset + symbol_size, 12):
        strx, symbol_type, other, desc, value = struct.unpack_from(">IBBhI", data, offset)
        name = _cstring(data, strings_offset + strx) if strx else ""
        symbols.append(AoutSymbol(len(symbols), name, symbol_type, other, desc, value))
    relocations = _relocations(data, text_reloc_offset, text_reloc_size, "text", text_base)
    relocations.extend(_relocations(data, data_reloc_offset, data_reloc_size, "data", text_base))
    for relocation in relocations:
        if relocation.segment == "text" and relocation.address >= text_size:
            raise AoutError(f"text relocation outside text at {relocation.address:#x}")
        if relocation.segment == "data" and relocation.address >= data_size:
            raise AoutError(f"data relocation outside data at {relocation.address:#x}")
        if relocation.external and relocation.symbol_index >= len(symbols):
            raise AoutError("relocation symbol index outside table")
    return SunosAout(data, source, header, symbols, relocations, text_base)


def read_aout(path: str | Path, text_base: int = TEXT_BASE) -> SunosAout:
    input_path = Path(path)
    size = input_path.stat().st_size
    if size > MAX_AOUT_BYTES:
        raise AoutError(f"input exceeds {MAX_AOUT_BYTES} bytes")
    return parse_aout(input_path.read_bytes(), str(input_path), text_base)


def render_calls(image: SunosAout, target: int | None = None) -> str:
    lines = [f"{image.format}", f"input_sha256={image.sha256}"]
    calls = image.calls(target)
    if target is not None and not calls:
        raise AoutError(f"no direct calls to {target:#x}")
    for call in calls:
        destination = call.external_symbol if call.external_symbol is not None else (
            f"0x{call.target:x}" if call.target is not None else "unresolved")
        lines.append(f"0x{call.address:x} -> {destination}")
    lines.append(f"direct_calls={len(calls)}")
    return "\n".join(lines) + "\n"


def render_dispatch(image: SunosAout, target: int, register: str = "%o1",
                    wrappers: tuple[int, ...] = ()) -> str:
    lines = [f"{image.format}", f"input_sha256={image.sha256}"]
    arguments = image.dispatch_arguments(target, register, wrappers)
    if not arguments:
        raise AoutError(f"no direct or wrapper calls to {target:#x}")
    for argument in arguments:
        value = str(argument.value) if argument.value is not None else "unresolved"
        destination = argument.wrapper_address or target
        lines.append(
            f"0x{argument.call_address:x} -> 0x{destination:x} "
            f"{argument.register}={value} provenance={argument.provenance}"
        )
    resolved = sum(argument.value is not None for argument in arguments)
    lines.append(f"dispatch_calls={len(arguments)} resolved={resolved} unresolved={len(arguments) - resolved}")
    return "\n".join(lines) + "\n"
