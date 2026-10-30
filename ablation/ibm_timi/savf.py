import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import FormatError, UnsupportedFormatError
from .io_utils import ensure_directory, write_bytes, write_text

RECORD_PAYLOAD = 512
RECORD_SIZE = 528
DEFAULT_MAXIMUM = 512 * 1024 * 1024
OBJECT_TYPES = {0x0201: "*PGM", 0x0401: "*LIB", 0x1901: "*FILE", 0x19DB: "*SRDS"}
QZRDPACK_MAGIC = "QZRDPACK".encode("cp500")


def _u16(data, offset):
    return int.from_bytes(data[offset:offset + 2], "big")


def _u32(data, offset):
    return int.from_bytes(data[offset:offset + 4], "big")


def _u64(data, offset):
    return int.from_bytes(data[offset:offset + 8], "big")


def _text(data):
    return data.decode("cp500").rstrip("\x00\x40 ")


def logical_to_physical(offset):
    if offset < 0:
        raise ValueError("negative logical offset")
    return (offset // RECORD_PAYLOAD) * RECORD_SIZE + offset % RECORD_PAYLOAD


def _chk_add(source, destination):
    shift_carry = 0
    add_carry = 0
    for index in range(len(source) - 1, -1, -1):
        value = source[index]
        shifted = ((value << 1) | shift_carry) & 0xFF
        shift_carry = value >> 7
        total = shifted + destination[index + 1] + add_carry
        add_carry = total >> 8
        destination[index + 1] = total & 0xFF
    destination[0] = (destination[0] + add_carry + shift_carry) & 0xFF


def _reduce(data, sizes):
    parts = []
    offset = 0
    for size in sizes:
        parts.append(bytearray(data[offset:offset + size]))
        offset += size
    if offset != len(data):
        raise ValueError("checksum input has the wrong size")
    accumulators = parts[:6] + [parts[7], parts[6]]
    for index in range(7):
        _chk_add(accumulators[index], accumulators[index + 1])
    return bytes(accumulators[7])


def record_checksum(sequence, payload, timestamp):
    if len(payload) != RECORD_PAYLOAD:
        raise ValueError("record payload must be 512 bytes")
    if len(timestamp) != 8:
        raise ValueError("checksum timestamp must be eight bytes")
    if not 0 <= sequence <= 0xFFFFFFFF:
        raise ValueError("record sequence outside uint32")
    first = _reduce(sequence.to_bytes(4, "big") + payload, [61, 62, 63, 64, 65, 66, 68, 67])
    result = bytearray(_reduce(first, [5, 6, 7, 8, 9, 10, 12, 11]))
    for index in range(8):
        result[index] ^= timestamp[index]
    return sequence.to_bytes(4, "big") + bytes(result)


@dataclass
class SaveItem:
    index: int
    offset: int
    name: str
    member: str
    object_type: int
    flags: int
    catalogue_reference: str
    release_created_for: str
    metadata_field: str
    section_count: int
    stored_length: int
    total_length: int
    packed_length: int
    raw: bytes

    @property
    def type_name(self):
        return OBJECT_TYPES.get(self.object_type)

    @property
    def sha256(self):
        return hashlib.sha256(self.raw).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "logical_offset": self.offset,
            "physical_offset": logical_to_physical(self.offset),
            "name": self.name,
            "member": self.member,
            "object_type": f"0x{self.object_type:04x}",
            "object_type_name": self.type_name,
            "flags": f"0x{self.flags:02x}",
            "catalogue_reference": self.catalogue_reference,
            "release_created_for_raw": self.release_created_for,
            "metadata_field_raw": self.metadata_field,
            "section_count": self.section_count,
            "stored_length": self.stored_length,
            "total_length": self.total_length,
            "packed_length": self.packed_length,
            "compression": "uncompressed",
            "raw_sha256": self.sha256,
            "raw_includes_descriptor": True,
        }


@dataclass
class SaveFile:
    source_name: str
    source_sha256: str
    record_count: int
    logical_size: int
    checksum_report: dict
    global_checksum: dict
    items: list[SaveItem]

    def to_dict(self):
        return {
            "source": self.source_name,
            "sha256": self.source_sha256,
            "format": "QSYS SAVF: 512-byte payload plus 16-byte record trailer",
            "record_count": self.record_count,
            "logical_size": self.logical_size,
            "record_checksums": self.checksum_report,
            "global_checksum": self.global_checksum,
            "item_count": len(self.items),
            "catalogue_status": "legacy catalogue not decoded; item evidence retained",
            "items": [item.to_dict() for item in self.items],
        }

    def extract(self, output_directory):
        output = ensure_directory(output_directory)
        items_output = ensure_directory(output / "items")
        for item in self.items:
            component = re.sub(r"[^A-Za-z0-9_.-]+", "_", item.name).strip(".") or "unnamed"
            component = component[:80]
            write_bytes(items_output / f"{item.index:02d}-{component}.bin", item.raw)
        write_text(output / "inventory.json", json.dumps(self.to_dict(), indent=2) + "\n")
        return output


def _parse_items(stream, first_item_offset):
    items = []
    offset = first_item_offset
    while offset < len(stream):
        if offset + RECORD_PAYLOAD > len(stream):
            raise FormatError(f"truncated item descriptor at logical {offset:#x}")
        descriptor = stream[offset:offset + RECORD_PAYLOAD]
        if descriptor[:4] != b"\xff\xff\xff\xff":
            raise FormatError(f"item marker missing at logical {offset:#x}")
        stored = (_u32(descriptor, 0x48) + 1) * RECORD_PAYLOAD
        total = _u32(descriptor, 0xCC) * RECORD_PAYLOAD
        packed = _u64(descriptor, 0x170) + RECORD_PAYLOAD
        if stored < RECORD_PAYLOAD or stored % RECORD_PAYLOAD:
            raise FormatError(f"invalid stored item length at logical {offset:#x}")
        if offset + stored > len(stream):
            raise FormatError(f"item extends beyond logical stream at {offset:#x}")
        if packed != RECORD_PAYLOAD:
            raise UnsupportedFormatError(f"packed item at logical {offset:#x} requires a verified decompressor")
        item = SaveItem(
            len(items), offset, _text(descriptor[4:14]), _text(descriptor[14:34]),
            _u16(descriptor, 0x22), descriptor[0x24], descriptor[0x25:0x28].hex(),
            descriptor[0x54:0x56].hex(), descriptor[0x56:0x5A].hex(),
            _u32(descriptor, 0x64), stored, total, packed, stream[offset:offset + stored],
        )
        items.append(item)
        offset += stored
    if offset != len(stream):
        raise FormatError("item chain does not end at logical EOF")
    if not items:
        raise FormatError("SAVF contains no items")
    return items


def parse_savf(data, source_name="<memory>", verify=True):
    if not data or len(data) % RECORD_SIZE:
        raise FormatError("SAVF size must be a nonzero multiple of 528 bytes")
    count = len(data) // RECORD_SIZE
    count32 = _u32(data, 0x08)
    count64 = _u64(data, 0x38)
    if count32 and count32 != count or count64 and count64 != count:
        raise FormatError("SAVF record count does not match file size")
    if not count32 and not count64:
        raise FormatError("SAVF has no declared record count")
    first_item_offset = _u32(data, 0x34) or RECORD_PAYLOAD
    if first_item_offset < RECORD_PAYLOAD or first_item_offset % RECORD_PAYLOAD or first_item_offset >= len(data) // RECORD_SIZE * RECORD_PAYLOAD:
        raise FormatError("invalid first-item offset in SAVF header")
    timestamp = data[:8]
    failures = []
    chunks = []
    for index in range(count):
        chunk = data[index * RECORD_SIZE:(index + 1) * RECORD_SIZE]
        chunks.append(chunk[:RECORD_PAYLOAD])
        expected = chunk[RECORD_PAYLOAD:]
        actual = record_checksum(index + 1, chunk[:RECORD_PAYLOAD], timestamp)
        if actual != expected:
            failures.append({"record": index + 1, "expected": expected.hex(), "actual": actual.hex()})
    if verify and failures:
        first = failures[0]
        raise FormatError(f"record {first['record']} checksum mismatch")
    stream = bytearray().join(chunks)
    backup = bytes(stream[0x40:0x50])
    stored_global = bytes(stream[-16:])
    stream[-16:] = backup
    report = {
        "algorithm": "two-stage shifted folding with timestamp XOR",
        "verified_count": count - len(failures),
        "failure_count": len(failures),
        "failures": failures,
    }
    global_report = {
        "status": "not_verified",
        "stored": stored_global.hex(),
        "backup_restored": backup.hex(),
    }
    return SaveFile(
        source_name, hashlib.sha256(data).hexdigest(), count, len(stream), report,
        global_report, _parse_items(bytes(stream), first_item_offset),
    )


def read_savf(path, maximum=DEFAULT_MAXIMUM, verify=True):
    path = Path(path)
    size = path.stat().st_size
    if maximum < 1 or size > maximum:
        raise FormatError(f"SAVF size {size} exceeds configured maximum {maximum}")
    return parse_savf(path.read_bytes(), str(path), verify)


def _file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _optional_header_text(data):
    text = _text(data)
    return text if text and re.fullmatch(r"[A-Z0-9 _]+", text) else None


def read_qzrdpack_header(path):
    path = Path(path)
    with path.open("rb") as stream:
        header = stream.read(512)
    if len(header) < 128 or not header.startswith(QZRDPACK_MAGIC):
        raise FormatError("not a QZRDPACK licensed-program image")
    marker = "SAVLICPGM".encode("cp500")
    marker_offset = header.find(marker)
    valid_marker = (
        marker_offset in (0x60, 0x70) and header[marker_offset + 9:marker_offset + 10] == b"\x40"
        and re.fullmatch(r"V[0-9]R[0-9]M[0-9]", _text(header[marker_offset + 10:marker_offset + 16]))
    )
    if valid_marker and marker_offset == 0x70:
        licensed_program = _optional_header_text(header[0x20:0x28])
        library = _optional_header_text(header[0x2A:0x34])
        context = _optional_header_text(header[0x34:0x39])
    elif valid_marker:
        licensed_program = _optional_header_text(header[0x10:0x18])
        library = None
        context = None
    else:
        licensed_program = library = context = None
    return {
        "source": str(path),
        "sha256": _file_sha256(path),
        "format": "QZRDPACK licensed-program header",
        "licensed_program": licensed_program,
        "library": library,
        "context": context,
        "save_command": "SAVLICPGM" if valid_marker else None,
        "release": _text(header[marker_offset + 10:marker_offset + 16]) if valid_marker else None,
        "metadata_status": "verified_offsets" if valid_marker else "unverified_layout",
        "status": "header_only",
        "payload_status": "unmapped; no TIMI code or object boundaries inferred",
    }
