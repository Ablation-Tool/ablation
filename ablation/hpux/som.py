"""Bounded HP-UX SOM container and dynamic-linkage parser."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import struct
from typing import Iterator, Optional

from .pa_risc import Instruction, PaRiscDecoder

HEADER_WORDS = (
    "version_id", "file_time_secs", "file_time_nanosecs", "entry_space",
    "entry_subspace", "entry_offset", "aux_header_location", "aux_header_size",
    "som_length", "presumed_dp", "space_location", "space_total",
    "subspace_location", "subspace_total", "loader_fixup_location",
    "loader_fixup_total", "space_strings_location", "space_strings_size",
    "init_array_location", "init_array_total", "compiler_location",
    "compiler_total", "symbol_location", "symbol_total",
    "fixup_request_location", "fixup_request_total", "symbol_strings_location",
    "symbol_strings_size", "unloadable_sp_location", "unloadable_sp_size",
    "checksum",
)
DL_WORDS = (
    "hdr_version", "ltptr_value", "shlib_list_loc", "shlib_list_count",
    "import_list_loc", "import_list_count", "hash_table_loc", "hash_table_size",
    "export_list_loc", "export_list_count", "string_table_loc", "string_table_size",
    "dreloc_loc", "dreloc_count", "dlt_loc", "plt_loc", "dlt_count", "plt_count",
    "highwater_flags", "export_ext_loc", "module_loc", "module_count", "elaborator",
    "initializer", "embedded_path", "initializer_count", "tdsize", "fastbind_list_loc",
)
EXEC_WORDS = (
    "exec_tsize", "exec_tmem", "exec_tfile", "exec_dsize", "exec_dmem",
    "exec_dfile", "exec_bsize", "exec_entry", "exec_flags", "exec_bfill",
)
SYMBOL_TYPES = {
    0: "NULL", 1: "ABSOLUTE", 2: "DATA", 3: "CODE", 4: "PRI_PROG",
    5: "SEC_PROG", 6: "ENTRY", 7: "STORAGE", 8: "STUB", 9: "MODULE",
    10: "SYM_EXT", 11: "ARG_EXT", 12: "MILLICODE", 13: "PLABEL",
    14: "OCT_DIS", 15: "MILLI_EXT", 16: "TSTORAGE", 17: "COMDAT",
}
DRELOC_TYPES = {
    1: "DR_PLABEL_EXT", 2: "DR_PLABEL_INT", 3: "DR_DATA_EXT",
    4: "DR_DATA_INT", 5: "DR_PROPAGATE", 6: "DR_INVOKE", 7: "DR_TEXT_INT",
}


class SomError(ValueError):
    pass


def _bounded(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise SomError(f"{label} outside input: offset={offset:#x}, size={size:#x}")


def _u32(data: bytes, offset: int) -> int:
    _bounded(data, offset, 4, "32-bit word")
    return struct.unpack_from(">I", data, offset)[0]


def _cstring(data: bytes, offset: int) -> str:
    _bounded(data, offset, 1, "string")
    end = data.find(b"\0", offset)
    if end < 0:
        raise SomError(f"unterminated string at {offset:#x}")
    return data[offset:end].decode("latin1")


def _length_prefixed(data: bytes, offset: int) -> str:
    size = _u32(data, offset)
    _bounded(data, offset + 4, size, "length-prefixed string")
    return data[offset + 4:offset + 4 + size].decode("latin1")


@dataclass(frozen=True)
class Subspace:
    index: int
    name: str
    space_index: int
    flags: int
    file_offset: int
    initialized_size: int
    va: int
    size: int
    alignment: int
    fixup_index: int
    fixup_count: int

    @property
    def end(self) -> int:
        return self.va + self.size

    def contains(self, va: int) -> bool:
        return self.va <= va < self.end


@dataclass(frozen=True)
class ImportEntry:
    index: int
    name: Optional[str]
    reserved2: int
    type: int
    reserved1: int
    file_offset: int

    @property
    def type_name(self) -> str:
        return SYMBOL_TYPES.get(self.type, "UNKNOWN")

    @property
    def bypassable(self) -> bool:
        return bool(self.reserved1 & 0x80)

    @property
    def external(self) -> bool:
        return self.reserved2 != 0xFFFF


@dataclass(frozen=True)
class ExportEntry:
    index: int
    next_index: int
    name: Optional[str]
    value: int
    info: int
    type: int
    flags: int
    module_index: int
    file_offset: int

    @property
    def type_name(self) -> str:
        return SYMBOL_TYPES.get(self.type, "UNKNOWN")


@dataclass(frozen=True)
class DltEntry:
    index: int
    import_index: int
    value: int
    file_offset: int


@dataclass(frozen=True)
class PltEntry:
    index: int
    import_index: int
    va: int
    proc_addr: int
    ltptr_value: int
    file_offset: int


@dataclass(frozen=True)
class DynamicRelocation:
    index: int
    shlib: int
    symbol: int
    location: int
    value: int
    type: int
    module_index: int
    file_offset: int

    @property
    def type_name(self) -> str:
        return DRELOC_TYPES.get(self.type, "UNKNOWN")


@dataclass(frozen=True)
class UnwindEntry:
    start: int
    end: int
    frame_info: int
    reserved: int

    def contains(self, va: int) -> bool:
        return self.start <= va < self.end


@dataclass
class SomImage:
    data: bytes
    source: str
    header: dict
    exec_header: dict
    dynamic_header: dict
    subspaces: list[Subspace]
    shared_libraries: list[dict]
    imports: list[ImportEntry]
    exports: list[ExportEntry]
    dynamic_relocations: list[DynamicRelocation]
    dlt: list[DltEntry]
    plt: list[PltEntry]
    unwind: list[UnwindEntry]
    decoder: PaRiscDecoder = field(default_factory=PaRiscDecoder)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def entry(self) -> int:
        return self.exec_header["exec_entry"]

    @property
    def text_range(self) -> tuple[int, int]:
        return self.exec_header["exec_tmem"], self.exec_header["exec_tmem"] + self.exec_header["exec_tsize"]

    @property
    def data_range(self) -> tuple[int, int]:
        return self.exec_header["exec_dmem"], self.exec_header["exec_dmem"] + self.exec_header["exec_dsize"]

    def subspace_for_va(self, va: int) -> Optional[Subspace]:
        return next((section for section in self.subspaces if section.contains(va)), None)

    def bytes_at(self, va: int, size: int) -> bytes:
        section = self.subspace_for_va(va)
        if section is None or va + size > section.end:
            raise SomError(f"VA range {va:#x}+{size:#x} is not mapped")
        offset = section.file_offset + va - section.va
        if offset < section.file_offset or offset + size > section.file_offset + section.initialized_size:
            raise SomError(f"VA range {va:#x}+{size:#x} is uninitialized")
        _bounded(self.data, offset, size, "mapped bytes")
        return self.data[offset:offset + size]

    def instructions(self, start: int, end: int, maximum: int = 100000) -> Iterator[Instruction]:
        if start < 0 or end <= start:
            raise SomError("invalid instruction range")
        if end - start > maximum * 4:
            raise SomError("instruction range exceeds configured maximum")
        if self.subspace_for_va(start) is None or self.subspace_for_va(end - 1) is None:
            raise SomError("instruction range includes an unmapped address")
        count = 0
        for va in range(start, end, 4):
            yield self.decoder.decode(struct.unpack_from(">I", self.bytes_at(va, 4))[0], va)
            count += 1
            if count >= maximum:
                break

    def function_at(self, va: int) -> Optional[UnwindEntry]:
        return next((entry for entry in self.unwind if entry.contains(va)), None)

    def import_for_plt(self, entry: PltEntry) -> ImportEntry:
        return self.imports[entry.import_index]

    def name_for_stub(self, va: int) -> Optional[str]:
        entry = next((item for item in self.plt if item.proc_addr == va), None)
        return self.import_for_plt(entry).name if entry else None

    def call_sites(self, start: int, end: int, maximum: int = 100000) -> Iterator[dict]:
        for instruction in self.instructions(start, end, maximum):
            if not instruction.is_call:
                continue
            target = instruction.branch_target
            function = self.function_at(instruction.address)
            yield {
                "call_va": instruction.address,
                "target_va": target,
                "name": self.name_for_stub(target) if target is not None else None,
                "owner_start": function.start if function else None,
                "owner_end": function.end if function else None,
                "instruction": instruction.text(),
            }

    def to_dict(self, full: bool = False) -> dict:
        result = {
            "source": self.source,
            "sha256": self.sha256,
            "header": self.header,
            "exec_header": self.exec_header,
            "dynamic_header": self.dynamic_header,
            "subspaces": [item.__dict__ for item in self.subspaces],
            "shared_libraries": self.shared_libraries,
            "counts": {
                "imports": len(self.imports), "exports": len(self.exports),
                "dynamic_relocations": len(self.dynamic_relocations),
                "dlt": len(self.dlt), "plt": len(self.plt), "unwind": len(self.unwind),
                "external_code_imports": sum(item.type == 3 and item.external for item in self.imports),
            },
        }
        if full:
            result.update({
                "imports": [{**item.__dict__, "type_name": item.type_name} for item in self.imports],
                "exports": [{**item.__dict__, "type_name": item.type_name} for item in self.exports],
                "dynamic_relocations": [{**item.__dict__, "type_name": item.type_name} for item in self.dynamic_relocations],
                "dlt": [item.__dict__ for item in self.dlt],
                "plt": [item.__dict__ for item in self.plt],
                "unwind": [item.__dict__ for item in self.unwind],
            })
        return result


def parse_som(data: bytes, source: str = "<bytes>") -> SomImage:
    if len(data) < 128:
        raise SomError("input is too short for a SOM header")
    system_id, magic = struct.unpack_from(">HH", data, 0)
    if magic not in (0x0104, 0x0107, 0x0108, 0x010B, 0x010D, 0x010E):
        raise SomError(f"unsupported SOM magic {magic:#06x}")
    header = dict(zip(HEADER_WORDS, struct.unpack_from(">31I", data, 4)))
    header.update({"system_id": system_id, "a_magic": magic})
    aux = header["aux_header_location"]
    aux_id, aux_length = struct.unpack_from(">II", data, aux)
    if aux_id & 0xFFFF != 4 or aux_length < 0x28:
        raise SomError("missing executable auxiliary header")
    exec_header = dict(zip(EXEC_WORDS, struct.unpack_from(">10I", data, aux + 8)))
    text_file, data_file = exec_header["exec_tfile"], exec_header["exec_dfile"]
    for label, offset, size in (
        ("space strings", header["space_strings_location"], header["space_strings_size"]),
        ("space dictionary", header["space_location"], header["space_total"] * 36),
        ("subspace dictionary", header["subspace_location"], header["subspace_total"] * 40),
        ("dynamic loader header", text_file, 0x70),
    ):
        _bounded(data, offset, size, label)
    space_strings = data[header["space_strings_location"]:header["space_strings_location"] + header["space_strings_size"]]
    subspaces = []
    for index in range(header["subspace_total"]):
        offset = header["subspace_location"] + index * 40
        space_index, flags, file_offset, initialized_size, va, size, alignment, name_index, fixup_index, fixup_count = struct.unpack_from(">10I", data, offset)
        subspaces.append(Subspace(index, _cstring(space_strings, name_index), space_index, flags, file_offset, initialized_size, va, size, alignment, fixup_index, fixup_count))
    dynamic_header = dict(zip(DL_WORDS, struct.unpack_from(">28I", data, text_file)))
    if dynamic_header["hdr_version"] not in (0x054EF630, 0x058C9C70):
        raise SomError(f"unsupported dynamic-loader version {dynamic_header['hdr_version']:#x}")
    if dynamic_header["dlt_count"] + dynamic_header["plt_count"] != dynamic_header["import_list_count"]:
        raise SomError("DLT and PLT counts do not cover the import list")
    strings_offset = text_file + dynamic_header["string_table_loc"]
    strings_size = dynamic_header["string_table_size"]
    _bounded(data, strings_offset, strings_size, "dynamic strings")
    strings = data[strings_offset:strings_offset + strings_size]

    def name_at(index: int) -> Optional[str]:
        return None if index == 0xFFFFFFFF else _cstring(strings, index)

    shared_libraries = []
    for index in range(dynamic_header["shlib_list_count"]):
        offset = text_file + dynamic_header["shlib_list_loc"] + index * 8
        _bounded(data, offset, 8, "shared-library entry")
        name_index, flags, bind, highwater = struct.unpack_from(">IBBH", data, offset)
        shared_libraries.append({"index": index, "name": name_at(name_index), "flags": flags, "bind": bind, "highwater_mark": highwater})

    imports = []
    for index in range(dynamic_header["import_list_count"]):
        offset = text_file + dynamic_header["import_list_loc"] + index * 8
        _bounded(data, offset, 8, "import entry")
        name_index, reserved2, symbol_type, reserved1 = struct.unpack_from(">IHBB", data, offset)
        imports.append(ImportEntry(index, name_at(name_index), reserved2, symbol_type, reserved1, offset))

    exports = []
    for index in range(dynamic_header["export_list_count"]):
        offset = text_file + dynamic_header["export_list_loc"] + index * 20
        _bounded(data, offset, 20, "export entry")
        next_index, name_index, value, info, symbol_type, flags, module_index = struct.unpack_from(">iiiIBBH", data, offset)
        exports.append(ExportEntry(index, next_index, name_at(name_index), value, info, symbol_type, flags, module_index, offset))

    dynamic_relocations = []
    for index in range(dynamic_header["dreloc_count"]):
        offset = text_file + dynamic_header["dreloc_loc"] + index * 20
        _bounded(data, offset, 20, "dynamic relocation")
        shlib, symbol, location, value, dtype, _reserved, module_index = struct.unpack_from(">IIIIBBH", data, offset)
        dynamic_relocations.append(DynamicRelocation(index, shlib, symbol, location, value, dtype, module_index, offset))

    dlt = []
    for index in range(dynamic_header["dlt_count"]):
        offset = data_file + dynamic_header["dlt_loc"] + index * 4
        dlt.append(DltEntry(index, index, _u32(data, offset), offset))

    plt = []
    plt_va = exec_header["exec_dmem"] + dynamic_header["plt_loc"]
    for index in range(dynamic_header["plt_count"]):
        offset = data_file + dynamic_header["plt_loc"] + index * 8
        _bounded(data, offset, 8, "PLT entry")
        proc_addr, ltptr_value = struct.unpack_from(">II", data, offset)
        plt.append(PltEntry(index, dynamic_header["dlt_count"] + index, plt_va + index * 8, proc_addr, ltptr_value, offset))

    unwind = []
    unwind_start = next((item for item in subspaces if item.name == "$UNWIND_START$"), None)
    if unwind_start:
        if unwind_start.initialized_size % 16:
            raise SomError("unwind table is not a sequence of 16-byte entries")
        for offset in range(unwind_start.file_offset, unwind_start.file_offset + unwind_start.initialized_size, 16):
            start, end, frame_info, reserved = struct.unpack_from(">4I", data, offset)
            if start <= end:
                unwind.append(UnwindEntry(start, end, frame_info, reserved))
    unwind.sort(key=lambda item: (item.start, item.end))

    return SomImage(data, source, header, exec_header, dynamic_header, subspaces, shared_libraries, imports, exports, dynamic_relocations, dlt, plt, unwind)


def read_som(path: str | Path) -> SomImage:
    input_path = Path(path)
    return parse_som(input_path.read_bytes(), str(input_path))
