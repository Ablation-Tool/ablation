import hashlib
from dataclasses import dataclass

from .errors import FormatError
from .savf import _text, _u16, _u32


@dataclass
class CatalogueEntry:
    index: int
    name: str
    object_type: int
    owner: str
    size: int
    multiplier: int

    def to_dict(self):
        return {
            "index": self.index,
            "name": self.name,
            "object_type": f"0x{self.object_type:04x}",
            "owner": self.owner,
            "size": self.size,
            "multiplier": self.multiplier,
        }


@dataclass
class LegacyCatalogue:
    source_name: str
    command: int
    target_release: int
    library: str
    base_object_type: int
    timestamp: str
    metadata_length: int
    entries: list[CatalogueEntry]
    raw: bytes

    @property
    def sha256(self):
        return hashlib.sha256(self.raw).hexdigest()

    def to_dict(self):
        return {
            "source": self.source_name,
            "sha256": self.sha256,
            "command": self.command,
            "target_release_raw": f"0x{self.target_release:02x}",
            "library": self.library,
            "base_object_type": f"0x{self.base_object_type:04x}",
            "timestamp_raw": self.timestamp,
            "metadata_length": self.metadata_length,
            "object_count": len(self.entries),
            "entries": [entry.to_dict() for entry in self.entries],
            "trailing_metadata_status": "not_decoded",
        }


def parse_legacy_catalogue(item, source_name="<memory>"):
    if len(item.raw) < 512 or item.total_length < 768 or item.metadata_length < 0x50:
        raise FormatError("catalogue item is too short")
    if item.metadata_length > item.total_length:
        raise FormatError("catalogue metadata length exceeds item length")
    offset = item.total_length - item.metadata_length
    if offset < 0x200 or offset + item.metadata_length > len(item.raw):
        raise FormatError("catalogue metadata lies outside item")
    raw = item.raw[offset:offset + item.metadata_length]
    if len(raw) < 0x50:
        raise FormatError("catalogue header is truncated")
    command = raw[0]
    if command != 2:
        raise FormatError(f"unsupported catalogue command {command}")
    target_release = raw[1]
    base_object_type = _u16(raw, 0x20)
    if base_object_type != 0x0401:
        raise FormatError("catalogue base object is not a library")
    descriptor_offset = 0x70 if target_release >= 66 else 0x50
    descriptor_length = 151 if target_release > 49 else 87
    count = _u32(raw, 0x2A)
    if count < 1 or descriptor_offset + count * descriptor_length > len(raw):
        raise FormatError("catalogue descriptor array is truncated")
    entries = []
    for index in range(count):
        start = descriptor_offset + index * descriptor_length
        entry = raw[start:start + descriptor_length]
        name = _text(entry[:30])
        if not name:
            raise FormatError(f"catalogue object {index} has an empty name")
        entries.append(CatalogueEntry(
            index, name, _u16(entry, 0x1E), _text(entry[0x20:0x2A]),
            _u32(entry, 0x43), _u32(entry, 0x79),
        ))
    return LegacyCatalogue(
        source_name, command, target_release, _text(raw[2:32]), base_object_type,
        raw[0x22:0x2A].hex(), item.metadata_length, entries, raw,
    )
