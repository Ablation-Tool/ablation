import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .errors import FormatError, UnsupportedFormatError
from .io_utils import ensure_directory, write_bytes, write_text
from .savf import _text, _u16, _u32, _u64

MAX_PROGRAM_SIZE = 64 * 1024 * 1024
SEGMENT_USES = {1: "static_storage", 2: "program_object", 4: "constants", 6: "trace_back"}
POINTER_FIELDS = {
    "version_table": 0x08,
    "segment_table": 0x10,
    "activation_header": 0x18,
    "signature_table": 0x20,
    "string_directory": 0x28,
    "activation_group": 0x30,
    "activation_start": 0x40,
    "activation_end": 0x48,
    "pep_end": 0x50,
    "header_extension": 0xD0,
    "trace_back": 0xD8,
    "module_table": 0xE0,
    "observability": 0xE8,
    "maintenance_header": 0xF0,
}


@dataclass
class ObjectHeader:
    offset: int
    name: str
    object_type: int
    subtype: int
    segment_id: int
    segment_offset: int
    program_header_offset: int

    def to_dict(self):
        return {
            "offset": self.offset,
            "name": self.name,
            "object_type": f"0x{self.object_type:04x}",
            "subtype": self.subtype,
            "segment_id": f"0x{self.segment_id:x}",
            "segment_offset": self.segment_offset,
            "program_header_offset": self.program_header_offset,
        }


def _pointer(data, offset, segment_start, segment_id, item_size):
    if offset < 0 or offset + 8 > len(data):
        raise FormatError("program header pointer is truncated")
    value = _u64(data, offset)
    if not value:
        return None
    if value >> 24 != segment_id:
        raise UnsupportedFormatError("program pointer targets a different segment")
    relative = value & 0xFFFFFF
    if segment_start + relative >= item_size:
        raise FormatError("program pointer lies outside the item")
    return segment_start + relative


def parse_object_header(data, offset=0x220):
    if offset < 0x20 or offset + 0x60 > len(data):
        raise FormatError("object header is truncated")
    object_type = _u16(data, offset + 2)
    if object_type != 0x0201:
        raise UnsupportedFormatError(f"unsupported program object type 0x{object_type:04x}")
    name = _text(data[offset + 4:offset + 34])
    if not name or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.$#" for character in name):
        raise FormatError("invalid program object name")
    segment_start = offset - 0x20
    segment_id = _u64(data, segment_start + 0x08) >> 24
    space_pointer = _u64(data, offset + 0x50)
    if space_pointer >> 24 != segment_id:
        raise UnsupportedFormatError("object-space pointer targets a different segment")
    relative = space_pointer & 0xFFFFFF
    if segment_start + relative >= len(data):
        raise FormatError("program header lies outside the item")
    return ObjectHeader(
        offset, name, object_type, data[offset + 3], segment_id, segment_start,
        segment_start + relative,
    )


def _bcd(value):
    return all((byte >> 4) <= 9 and (byte & 15) <= 9 for byte in value)


@dataclass
class ProgramRecovery:
    source_name: str
    source_sha256: str
    object_header: ObjectHeader
    version_table_offset: int
    target_release: str
    created_on_release: str
    segment_table_offset: int
    segments: list[dict]
    activation_header_offset: int
    code_start: int
    code_end: int
    code_sha256: str
    pointers: dict

    def to_dict(self):
        return {
            "source": self.source_name,
            "sha256": self.source_sha256,
            "layout": "legacy program/object/segment headers with segment-relative SLS pointers",
            "object_header": self.object_header.to_dict(),
            "version_table": {
                "offset": self.version_table_offset,
                "target_release_raw": self.target_release,
                "created_on_release_raw": self.created_on_release,
            },
            "segment_table_offset": self.segment_table_offset,
            "segment_count": len(self.segments),
            "segments": self.segments,
            "activation_header_offset": self.activation_header_offset,
            "code_region": {
                "start": self.code_start,
                "end_inclusive": self.code_end,
                "length": self.code_end - self.code_start + 1,
                "sha256": self.code_sha256,
                "boundary": "activation entry point through PEP end; metadata may be interleaved",
            },
            "pointers": self.pointers,
            "instruction_analysis": "not_decoded",
        }

    def extract(self, data, output_directory):
        output = ensure_directory(output_directory)
        write_bytes(output / "code.bin", data[self.code_start:self.code_end + 1])
        write_text(output / "program.json", json.dumps(self.to_dict(), indent=2) + "\n")
        return output


def recover_program(data, source_name="<memory>"):
    if len(data) < 0x400:
        raise FormatError("program item is too short")
    object_header = parse_object_header(data)
    if _u16(data, object_header.segment_offset) == 0x0181:
        from .opm import recover_opm_program
        return recover_opm_program(data, source_name, object_header)
    header = object_header.program_header_offset
    pointers = {}
    for name, offset in POINTER_FIELDS.items():
        value = _pointer(data, header + offset, object_header.segment_offset, object_header.segment_id, len(data))
        if value is not None:
            pointers[name] = value
    for name in ("version_table", "segment_table", "activation_header", "pep_end"):
        if name not in pointers:
            raise UnsupportedFormatError(f"program header has no {name} pointer")
    version_offset = pointers["version_table"]
    if version_offset + 40 > len(data):
        raise FormatError("version table is truncated")
    target = data[version_offset + 6:version_offset + 8]
    created = data[version_offset + 8:version_offset + 10]
    if not _bcd(target) or not _bcd(created):
        raise UnsupportedFormatError("program version-table layout is not verified")
    segment_offset = pointers["segment_table"]
    if segment_offset + 16 > len(data):
        raise FormatError("segment table is truncated")
    allocation = _u32(data, segment_offset)
    count = _u32(data, segment_offset + 4)
    if count < 1 or count > 64 or allocation < 16 + count * 48 or segment_offset + 16 + count * 48 > len(data):
        raise FormatError("invalid segment table dimensions")
    segments = []
    for index in range(count):
        offset = segment_offset + 16 + index * 48
        address = _u64(data, offset)
        limbo = _u64(data, offset + 8)
        use = data[offset + 0x12]
        segments.append({
            "index": index,
            "address_raw": f"0x{address:016x}",
            "limbo_raw": f"0x{limbo:016x}",
            "declared_page_count": _u32(data, offset + 0x10),
            "segment_use": f"0x{use:02x}",
            "segment_use_name": SEGMENT_USES.get(use),
        })
    activation_offset = pointers["activation_header"]
    if activation_offset + 8 > len(data):
        raise FormatError("activation header is truncated")
    entry = _u64(data, activation_offset)
    code_start = object_header.segment_offset + entry
    code_end = pointers["pep_end"]
    if code_start > code_end or code_end >= len(data):
        raise FormatError("activation/PEP code range is invalid")
    code = data[code_start:code_end + 1]
    return ProgramRecovery(
        source_name, hashlib.sha256(data).hexdigest(), object_header, version_offset,
        f"0x{_u16(target, 0):04x}", f"0x{_u16(created, 0):04x}", segment_offset,
        segments, activation_offset, code_start, code_end, hashlib.sha256(code).hexdigest(), pointers,
    )


def read_program_bytes(path):
    path = Path(path)
    if path.stat().st_size > MAX_PROGRAM_SIZE:
        raise FormatError(f"program item exceeds {MAX_PROGRAM_SIZE} bytes")
    data = path.read_bytes()
    if len(data) > MAX_PROGRAM_SIZE:
        raise FormatError(f"program item exceeds {MAX_PROGRAM_SIZE} bytes")
    return data


def recover_program_file(path):
    return recover_program(read_program_bytes(path), str(path))
