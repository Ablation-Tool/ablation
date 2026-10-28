"""Strict parser and partition extractor for Zynq UltraScale+ BOOT.BIN images."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

MAX_BOOT_IMAGE_BYTES = 512 * 1024 * 1024
MAX_IMAGES = 32
MAX_PARTITIONS = 32
MAX_IMAGE_NAME_BYTES = 255

WIDTH_DETECTION = 0xAA995566
IDENTIFICATION = 0x584C4E58
IHT_VERSION = 0x01020000

_DESTINATION_DEVICES = {0: "none", 1: "PS", 2: "PL"}
_DESTINATION_CPUS = {
    0: "none",
    1: "A53-0",
    2: "A53-1",
    3: "A53-2",
    4: "A53-3",
    5: "R5-0",
    6: "R5-1",
    7: "R5-lockstep",
    8: "PMU",
}


class ZynqMpBootError(ValueError):
    """Raised when a ZynqMP boot image is malformed or truncated."""


@dataclass(frozen=True)
class ZynqMpImageHeader:
    index: int
    offset: int
    name: str
    partition_header_offset: int
    partition_count: int


@dataclass(frozen=True)
class ZynqMpPartition:
    index: int
    image_index: int
    name: str
    header_offset: int
    offset: int
    encrypted_length: int
    unencrypted_length: int
    total_length: int
    exec_address: int
    load_address: int
    attributes: int
    destination_device: str
    destination_cpu: str
    encrypted: bool
    authenticated: bool
    checksum_type: int
    partition_number: int
    header_checksum_valid: bool
    _data: bytes

    @property
    def payload(self) -> bytes:
        """Return the stored partition bytes without decryption or ELF reconstruction."""
        return self._data[self.offset:self.offset + self.encrypted_length]


class ZynqMpBootImage:
    """Parsed Zynq UltraScale+ boot image with validated table and payload bounds."""

    def __init__(
        self,
        data: bytes,
        images: list[ZynqMpImageHeader],
        partitions: list[ZynqMpPartition],
        boot_header_checksum_valid: bool,
        iht_checksum_valid: bool,
        image_header_table_offset: int,
        partition_header_table_offset: int,
    ) -> None:
        self._data = data
        self.images = tuple(images)
        self.partitions = tuple(partitions)
        self.boot_header_checksum_valid = boot_header_checksum_valid
        self.iht_checksum_valid = iht_checksum_valid
        self.image_header_table_offset = image_header_table_offset
        self.partition_header_table_offset = partition_header_table_offset

    @classmethod
    def from_path(cls, path: str) -> "ZynqMpBootImage":
        source = Path(path)
        size = source.stat().st_size
        if size > MAX_BOOT_IMAGE_BYTES:
            raise ZynqMpBootError(f"boot image exceeds {MAX_BOOT_IMAGE_BYTES} bytes")
        return cls.from_bytes(source.read_bytes())

    @classmethod
    def from_bytes(cls, data: bytes, *, validate_checksums: bool = True) -> "ZynqMpBootImage":
        if len(data) > MAX_BOOT_IMAGE_BYTES:
            raise ZynqMpBootError(f"boot image exceeds {MAX_BOOT_IMAGE_BYTES} bytes")
        if len(data) < 0xA0:
            raise ZynqMpBootError("truncated ZynqMP boot header")
        if _u32(data, 0x20) != WIDTH_DETECTION or _u32(data, 0x24) != IDENTIFICATION:
            raise ZynqMpBootError("not a Zynq UltraScale+ boot image")

        boot_checksum_valid = _checksum(data, 0x20, 0x28) == _u32(data, 0x48)
        iht_offset = _u32(data, 0x98)
        pht_offset = _u32(data, 0x9C)
        _require_range(data, iht_offset, 0x40, "image header table")
        if _u32(data, iht_offset) != IHT_VERSION:
            raise ZynqMpBootError("unsupported ZynqMP image header table version")
        partition_count = _u32(data, iht_offset + 4)
        if not 1 <= partition_count <= MAX_PARTITIONS:
            raise ZynqMpBootError("invalid ZynqMP partition count")
        first_pht = _word_offset(data, iht_offset + 8)
        if first_pht != pht_offset:
            raise ZynqMpBootError("boot and image header tables disagree on PHT offset")
        _require_range(data, pht_offset, partition_count * 0x40, "partition header table")
        iht_checksum_valid = _checksum(data, iht_offset, 0x3C) == _u32(data, iht_offset + 0x3C)

        images = _parse_image_headers(data, _word_offset(data, iht_offset + 12), partition_count)
        if sum(image.partition_count for image in images) != partition_count:
            raise ZynqMpBootError("image and table partition counts disagree")

        partitions: list[ZynqMpPartition] = []
        index = 0
        for image in images:
            for image_partition in range(image.partition_count):
                header_offset = image.partition_header_offset + image_partition * 0x40
                _require_range(data, header_offset, 0x40, "partition header")
                partition = _parse_partition(data, index, image, image_partition, header_offset)
                partitions.append(partition)
                index += 1

        result = cls(
            data,
            images,
            partitions,
            boot_checksum_valid,
            iht_checksum_valid,
            iht_offset,
            pht_offset,
        )
        if validate_checksums and not all((
            boot_checksum_valid,
            iht_checksum_valid,
            *(partition.header_checksum_valid for partition in partitions),
        )):
            raise ZynqMpBootError("ZynqMP boot image header checksum mismatch")
        return result

    def summary(self) -> str:
        lines = [
            f"Zynq UltraScale+ boot image: {len(self._data):,} bytes",
            f"  images={len(self.images)} partitions={len(self.partitions)} "
            f"IHT=0x{self.image_header_table_offset:x} PHT=0x{self.partition_header_table_offset:x}",
            f"  header checksums: boot={self.boot_header_checksum_valid} IHT={self.iht_checksum_valid}",
        ]
        for partition in self.partitions:
            lines.append(
                f"  [{partition.index}] {partition.name}: offset=0x{partition.offset:x} "
                f"size=0x{partition.encrypted_length:x} load=0x{partition.load_address:x} "
                f"device={partition.destination_device} cpu={partition.destination_cpu} "
                f"encrypted={partition.encrypted} authenticated={partition.authenticated}"
            )
        return "\n".join(lines)

    def extract_all(self, output_dir: str) -> list[Path]:
        """Extract raw stored partitions using generated, traversal-safe filenames."""
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        paths: list[Path] = []
        for partition in self.partitions:
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", partition.name).strip("._") or "partition"
            path = destination / f"{partition.index:02d}-{safe_name}.bin"
            path.write_bytes(partition.payload)
            paths.append(path)
        return paths


def _parse_image_headers(data: bytes, first_offset: int, partition_total: int) -> list[ZynqMpImageHeader]:
    images: list[ZynqMpImageHeader] = []
    seen: set[int] = set()
    offset = first_offset
    remaining = partition_total
    while offset:
        if offset in seen or len(images) >= MAX_IMAGES:
            raise ZynqMpBootError("cyclic or excessive ZynqMP image-header chain")
        seen.add(offset)
        _require_range(data, offset, 0x10, "image header")
        next_offset = _word_offset(data, offset)
        pht_offset = _word_offset(data, offset + 4)
        count = _u32(data, offset + 0x0C)
        if not 1 <= count <= remaining:
            raise ZynqMpBootError("invalid image partition count")
        _require_range(data, pht_offset, count * 0x40, "image partition headers")
        raw_name = data[offset + 0x10:offset + 0x10 + MAX_IMAGE_NAME_BYTES]
        name_words: list[bytes] = []
        for position in range(0, len(raw_name), 4):
            word = raw_name[position:position + 4]
            name_words.append(word[::-1])
            if len(word) < 4 or b"\0" in word:
                break
        else:
            raise ZynqMpBootError("unterminated or oversized image name")
        if not any(b"\0" in word for word in name_words):
            raise ZynqMpBootError("unterminated or oversized image name")
        try:
            name = b"".join(name_words).split(b"\0", 1)[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ZynqMpBootError("non-ASCII image name") from exc
        if not name:
            raise ZynqMpBootError("empty image name")
        images.append(ZynqMpImageHeader(len(images), offset, name, pht_offset, count))
        remaining -= count
        offset = next_offset
    if remaining:
        raise ZynqMpBootError("image-header chain does not cover all partitions")
    return images


def _parse_partition(
    data: bytes,
    index: int,
    image: ZynqMpImageHeader,
    image_partition: int,
    header_offset: int,
) -> ZynqMpPartition:
    values = struct.unpack_from("<16I", data, header_offset)
    encrypted_length = values[0] * 4
    unencrypted_length = values[1] * 4
    total_length = values[2] * 4
    if not encrypted_length or unencrypted_length > encrypted_length or total_length < encrypted_length:
        raise ZynqMpBootError(f"invalid lengths for partition {index}")
    offset = values[8] * 4
    _require_range(data, offset, encrypted_length, f"partition {index}")
    attributes = values[9]
    destination_device = (attributes >> 4) & 0x7
    destination_cpu = (attributes >> 8) & 0xF
    if destination_device not in _DESTINATION_DEVICES or destination_cpu not in _DESTINATION_CPUS:
        raise ZynqMpBootError(f"invalid destination attributes for partition {index}")
    return ZynqMpPartition(
        index=index,
        image_index=image.index,
        name=f"{image.name}.{image_partition}",
        header_offset=header_offset,
        offset=offset,
        encrypted_length=encrypted_length,
        unencrypted_length=unencrypted_length,
        total_length=total_length,
        exec_address=values[4] | (values[5] << 32),
        load_address=values[6] | (values[7] << 32),
        attributes=attributes,
        destination_device=_DESTINATION_DEVICES[destination_device],
        destination_cpu=_DESTINATION_CPUS[destination_cpu],
        encrypted=bool((attributes >> 7) & 1),
        authenticated=bool((attributes >> 15) & 1),
        checksum_type=(attributes >> 12) & 0x7,
        partition_number=values[14],
        header_checksum_valid=(~sum(values[:15])) & 0xFFFFFFFF == values[15],
        _data=data,
    )


def _word_offset(data: bytes, offset: int) -> int:
    return _u32(data, offset) * 4


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _checksum(data: bytes, offset: int, size: int) -> int:
    return (~sum(struct.unpack_from(f"<{size // 4}I", data, offset))) & 0xFFFFFFFF


def _require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ZynqMpBootError(f"truncated or out-of-bounds {label}")
