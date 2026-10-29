"""Relocation-aware ARM32 BinaryContext construction for bFLT v4 images."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from pathlib import Path

from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.bflt_arm32 import Arm32LiteralReference, BfltArm32
from ablation.parsers.bflt import BfltImage


class BfltRelocationError(ValueError):
    """A relocation cannot be applied without inventing an address."""


@dataclass(frozen=True)
class BfltRelocation:
    """One relocation-table entry and its outcome."""

    index: int
    offset: int
    address: int
    stored_value: int
    value: int
    status: str


@dataclass(frozen=True)
class BfltLoadedImage:
    """A relocated flat image and its complete relocation evidence."""

    base_va: int
    memory_image: bytes
    relocations: tuple[BfltRelocation, ...]

    @property
    def complete(self) -> bool:
        return all(
            not record.status.startswith("UNRESOLVED")
            for record in self.relocations
        )

    @property
    def unresolved(self) -> tuple[BfltRelocation, ...]:
        return tuple(
            record for record in self.relocations
            if record.status.startswith("UNRESOLVED")
        )


def relocate_bflt(
    image: BfltImage,
    *,
    base_va: int = 0,
    pointer_byteorder: str = "big",
    allow_unresolved: bool = False,
) -> BfltLoadedImage:
    """Apply RAM-layout bFLT relocations using the Linux text/data mapping."""
    if not 0 <= base_va <= 0xFFFFFFFF:
        raise ValueError("base_va must fit a 32-bit address")
    if base_va + image.bss_end > 0x100000000:
        raise BfltRelocationError("relocated image exceeds the 32-bit address space")
    if pointer_byteorder not in ("big", "little"):
        raise ValueError("pointer_byteorder must be 'big' or 'little'")

    memory = bytearray(image.bss_end)
    memory[:len(image.memory_image)] = image.memory_image
    span = image.bss_end - 0x40

    def calc_reloc(value: int) -> int:
        if value > span:
            raise BfltRelocationError(f"value {value:#x} lies outside the program")
        mapped = base_va + 0x40 + value
        if mapped > 0xFFFFFFFF:
            raise BfltRelocationError("relocated address exceeds 32 bits")
        return mapped

    records = []
    for index in range(image.reloc_count):
        raw_offset = image.relocations[index * 4:index * 4 + 4]
        offset = int.from_bytes(raw_offset, "big")
        try:
            address = calc_reloc(offset)
        except BfltRelocationError as exc:
            raise BfltRelocationError(
                f"relocation {index} has invalid slot offset {offset:#x}"
            ) from exc
        memory_offset = address - base_va
        if memory_offset + 4 > len(memory):
            raise BfltRelocationError(
                f"relocation {index} slot {address:#x} lies outside loaded memory"
            )
        stored = int.from_bytes(
            memory[memory_offset:memory_offset + 4], pointer_byteorder
        )
        if stored == 0:
            status = "ZERO"
            value = 0
        else:
            try:
                value = calc_reloc(stored)
            except BfltRelocationError as exc:
                if not allow_unresolved:
                    raise BfltRelocationError(
                        f"relocation {index} at {address:#x} has "
                        f"unmapped value {stored:#x}"
                    ) from exc
                status = (
                    "UNRESOLVED_SHARED_LIBRARY"
                    if 0 < stored >> 24 < 0xFF
                    else "UNRESOLVED_OUT_OF_RANGE"
                )
                value = stored
            else:
                status = "RELOCATED"
        if not status.startswith("UNRESOLVED"):
            memory[memory_offset:memory_offset + 4] = value.to_bytes(4, "little")
        records.append(BfltRelocation(
            index=index,
            offset=offset,
            address=address,
            stored_value=stored,
            value=value,
            status=status,
        ))
    return BfltLoadedImage(base_va, bytes(memory), tuple(records))


class BfltBinaryContext(BinaryContext):
    """A BinaryContext populated from a relocated little-endian ARM bFLT image."""

    def __init__(
        self,
        source: BfltImage,
        loaded: BfltLoadedImage,
        *,
        path: str,
        sha256: str,
    ) -> None:
        super().__init__()
        self.source_image = source
        self.loaded_image = loaded
        self.path = path
        self.sha256 = sha256
        self.base_va = loaded.base_va
        self.arch = "arm32"
        self._reader = BfltArm32(
            replace(source, memory_image=loaded.memory_image),
            pointer_byteorder="little",
        )
        self._build_context()

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        base_va: int = 0,
        pointer_byteorder: str = "big",
        allow_unresolved: bool = False,
    ) -> "BfltBinaryContext":
        source_path = Path(path)
        if source_path.stat().st_size > 64 * 1024 * 1024:
            raise BfltRelocationError("input exceeds the 64 MiB bFLT limit")
        raw = source_path.read_bytes()
        return cls.from_image(
            BfltImage.from_bytes(raw),
            path=str(source_path),
            sha256=hashlib.sha256(raw).hexdigest(),
            base_va=base_va,
            pointer_byteorder=pointer_byteorder,
            allow_unresolved=allow_unresolved,
        )

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        path: str = "<memory>",
        base_va: int = 0,
        pointer_byteorder: str = "big",
        allow_unresolved: bool = False,
    ) -> "BfltBinaryContext":
        return cls.from_image(
            BfltImage.from_bytes(raw),
            path=path,
            sha256=hashlib.sha256(raw).hexdigest(),
            base_va=base_va,
            pointer_byteorder=pointer_byteorder,
            allow_unresolved=allow_unresolved,
        )

    @classmethod
    def from_image(
        cls,
        image: BfltImage,
        *,
        path: str = "<memory>",
        sha256: str = "",
        base_va: int = 0,
        pointer_byteorder: str = "big",
        allow_unresolved: bool = False,
    ) -> "BfltBinaryContext":
        if not isinstance(image, BfltImage):
            raise TypeError("image must be a parsed BfltImage")
        if not sha256:
            sha256 = hashlib.sha256(
                image.memory_image + image.relocations
            ).hexdigest()
        loaded = relocate_bflt(
            image,
            base_va=base_va,
            pointer_byteorder=pointer_byteorder,
            allow_unresolved=allow_unresolved,
        )
        return cls(image, loaded, path=path, sha256=sha256)

    @property
    def memory_image(self) -> bytes:
        return self.loaded_image.memory_image

    @property
    def relocations(self) -> tuple[BfltRelocation, ...]:
        return self.loaded_image.relocations

    @property
    def unresolved_relocations(self) -> tuple[BfltRelocation, ...]:
        return self.loaded_image.unresolved

    @property
    def relocation_complete(self) -> bool:
        return self.loaded_image.complete

    def read_memory(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be nonnegative")
        offset = address - self.base_va
        if offset < 0 or offset + size > len(self.memory_image):
            raise BfltRelocationError("memory read lies outside the loaded image")
        return self.memory_image[offset:offset + size]

    def literal_references(self, target: int) -> list[Arm32LiteralReference]:
        return [
            replace(
                reference,
                instruction_address=self.base_va + reference.instruction_address,
                literal_address=self.base_va + reference.literal_address,
            )
            for reference in self._reader.literal_references(target)
        ]

    def metadata(self) -> dict[str, object]:
        return {
            **self.source_image.metadata(),
            "base_va": self.base_va,
            "relocation_complete": self.relocation_complete,
            "unresolved_relocations": len(self.unresolved_relocations),
            "function_candidates": len(self.func_starts),
            "call_edges": len(self.call_edges),
        }

    def _build_context(self) -> None:
        source = self.source_image
        text_start = self.base_va + 0x40
        text_end = self.base_va + source.data_start
        starts = {self.base_va + source.entry}
        direct_calls = []
        for address in range(text_start, text_end - 3, 4):
            word = int.from_bytes(self.read_memory(address, 4), "little")
            if word >> 24 == 0xE9 and (word >> 16) & 0xFF == 0x2D and word & 0x4000:
                starts.add(address)
            if word >> 24 not in (0xEB, 0xFA):
                continue
            immediate = word & 0xFFFFFF
            if immediate & 0x800000:
                immediate -= 0x1000000
            target = address + 8 + immediate * 4
            if text_start <= target < text_end:
                starts.add(target)
                direct_calls.append((address, target))
        self.func_starts = sorted(starts)
        self.call_edges = [
            (self.func_containing(site) or site, target, "")
            for site, target in direct_calls
        ]
        self._build_indices()
        self.strings = self._data_strings()
        self._build_literal_xrefs()

    def _data_strings(self) -> dict[int, str]:
        source = self.source_image
        result = {}
        data = self.memory_image[source.data_start:source.data_end]
        start = 0
        while start < len(data):
            while start < len(data) and not 0x20 <= data[start] < 0x7F:
                start += 1
            end = start
            while end < len(data) and 0x20 <= data[end] < 0x7F:
                end += 1
            if end - start >= 4:
                result[self.base_va + source.data_start + start] = data[start:end].decode("ascii")
            start = max(end, start + 1)
        return result

    def _build_literal_xrefs(self) -> None:
        for insn in self._reader.instructions():
            literal = self._reader.literal_address(insn)
            if literal is None or literal < 0 or literal + 4 > len(self.memory_image):
                continue
            string_va = self._reader.read_pointer(literal)
            if string_va not in self.strings:
                continue
            site_va = self.base_va + insn.address
            self._str_xref_idx.setdefault(string_va, []).append(site_va)
            owner = self.func_containing(site_va)
            if owner is not None:
                self._func_str_idx.setdefault(owner, []).append(string_va)
        self._func_str_idx = {
            owner: list(dict.fromkeys(values))
            for owner, values in self._func_str_idx.items()
        }
