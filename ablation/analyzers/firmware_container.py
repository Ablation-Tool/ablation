"""
firmware_container.py — partitioned firmware image parser for Ablation

Parses firmware containers that use a plaintext header + fixed-record
partition table. No encryption or compression at the container level;
individual partitions may be gzip, ext2/3/4, xz, ELF, etc.

Container layout:
  0x0000-0x0007: magic string (8 bytes)
  0x0008-0x000F: firmware version string
  0x0010-0x0023: metadata block (reserved)
  0x0024-0x0033: vendor string  (16 bytes, null-padded)
  0x0034-0x0043: product string (16 bytes, null-padded)
  0x0044-0x0053: language string (16 bytes, null-padded)
  0x0054-     : partition table (n × 296-byte records)

Partition record (296 = 0x128 bytes):
  +0x00  version  char[16]    partition version string
  +0x10  name     char[16]    partition name (e.g. "kernel", "bin")
  +0x20  offset   uint32 LE   byte offset from container start
  +0x24  size     uint32 LE   partition size in bytes
  +0x28  destpath char[64]    flash destination path
  +0x68  pad      byte[184]   zeros

Usage:
    from ablation.analyzers.firmware_container import FirmwareContainer

    fw = FirmwareContainer.from_path('/path/to/firmware.BIN')
    fw.dump_partitions()

    fw.extract('bin', '/tmp/part.bin')
    fw.extract_all('/tmp/parts/')

    for p in fw.partitions:
        print(p.name, p.payload_type, hex(p.offset), p.size)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

PARTITION_TABLE_START = 0x0054
PARTITION_ENTRY_SIZE  = 0x128   # 296 bytes

_PAYLOAD_SIGS = [
    (b'\x1f\x8b',          'gzip'),
    (b'\xfd7zXZ',          'xz'),
    (b'\x28\xb5\x2f\xfd',  'zstd'),
    (b'\x02\x21\x4c\x18',  'lz4'),
    (b'\x89\x4c\x5a\x4f',  'lzo'),
    (b'070701',             'cpio_newc'),
    (b'070707',             'cpio_odc'),
    (b'\x7fELF',            'elf'),
    (b'MZ',                 'pe'),
]


def _cstr(raw: bytes) -> str:
    end = raw.find(b'\x00')
    return raw[:end if end >= 0 else len(raw)].decode('latin1', errors='replace')


def _detect_payload(data: bytes, offset: int, size: int) -> str:
    if size < 2:
        return 'empty'
    chunk = data[offset: offset + min(size, 8)]
    for magic, name in _PAYLOAD_SIGS:
        if chunk.startswith(magic):
            return name
    # ext2/3/4: superblock magic at +0x438
    if size > 0x440 and data[offset + 0x438: offset + 0x43A] == b'\x53\xef':
        return 'ext2/3/4'
    return 'unknown'


@dataclass
class FirmwarePartition:
    index:        int
    version:      str
    name:         str
    offset:       int
    size:         int
    destpath:     str
    payload_type: str = field(default='unknown')

    def __repr__(self) -> str:
        return (
            f'FirmwarePartition({self.index}: {self.name!r} '
            f'0x{self.offset:x}+0x{self.size:x} {self.payload_type})'
        )


class FirmwareContainer:
    """Parse a partitioned firmware image with a fixed-record partition table."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._data = self.path.read_bytes()
        self.magic:      str = ''
        self.fw_version: str = ''
        self.vendor:     str = ''
        self.product:    str = ''
        self.language:   str = ''
        self.partitions: List[FirmwarePartition] = []
        self._parse()

    @classmethod
    def from_path(cls, path: str | Path) -> 'FirmwareContainer':
        return cls(path)

    def _parse(self) -> None:
        d = self._data
        self.magic      = _cstr(d[0x00:0x08])
        self.fw_version = _cstr(d[0x08:0x10])
        self.vendor     = _cstr(d[0x24:0x34])
        self.product    = _cstr(d[0x34:0x44])
        self.language   = _cstr(d[0x44:0x54])
        self._parse_partitions()

    def _parse_partitions(self) -> None:
        d = self._data
        file_len = len(d)
        off = PARTITION_TABLE_START
        idx = 0
        while off + PARTITION_ENTRY_SIZE <= file_len:
            entry = d[off: off + PARTITION_ENTRY_SIZE]
            if entry[:4] == b'\x00\x00\x00\x00' or entry[0] not in (ord('V'), 0x00):
                break
            version  = _cstr(entry[0x00:0x10])
            name     = _cstr(entry[0x10:0x20])
            p_offset = struct.unpack_from('<I', entry, 0x20)[0]
            p_size   = struct.unpack_from('<I', entry, 0x24)[0]
            destpath = _cstr(entry[0x28:0x68])
            if not version or not name or p_offset >= file_len:
                break
            self.partitions.append(FirmwarePartition(
                index=idx, version=version, name=name,
                offset=p_offset, size=p_size, destpath=destpath,
                payload_type=_detect_payload(d, p_offset, p_size),
            ))
            idx += 1
            off += PARTITION_ENTRY_SIZE

    def dump_partitions(self) -> None:
        print(
            f'firmware: {self.path.name}\n'
            f'  magic={self.magic!r}  version={self.fw_version}'
            f'  vendor={self.vendor}  product={self.product}\n'
        )
        hdr = f'{"#":<3} {"name":<16} {"offset":>12} {"size":>12} {"MB":>6} {"type":<12} destpath'
        print(hdr)
        print('-' * len(hdr))
        for p in self.partitions:
            print(
                f'{p.index:<3} {p.name:<16} 0x{p.offset:>010x} 0x{p.size:>010x} '
                f'{p.size/1048576:>6.1f} {p.payload_type:<12} {p.destpath}'
            )

    def get_partition(self, name: str) -> Optional[FirmwarePartition]:
        for p in self.partitions:
            if p.name == name:
                return p
        return None

    def read_partition(self, name: str) -> bytes:
        p = self.get_partition(name)
        if p is None:
            raise KeyError(f'partition {name!r} not found')
        return self._data[p.offset: p.offset + p.size]

    def extract(self, partition_name: str, out_path: str | Path) -> Path:
        raw = self.read_partition(partition_name)
        out = Path(out_path)
        out.write_bytes(raw)
        print(f'extracted {partition_name!r} ({len(raw):,} bytes) → {out}')
        return out

    def extract_all(self, out_dir: str | Path) -> List[Path]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = []
        for p in self.partitions:
            fname = out / f'{p.index:02d}_{p.name}.bin'
            self._data[p.offset: p.offset + p.size]
            fname.write_bytes(self._data[p.offset: p.offset + p.size])
            print(f'  {p.name:<16} → {fname}  ({p.size:,} bytes, {p.payload_type})')
            paths.append(fname)
        return paths

    def __repr__(self) -> str:
        return (
            f'FirmwareContainer({self.path.name!r}, magic={self.magic!r}, '
            f'product={self.product!r}, {len(self.partitions)} partitions)'
        )


def _main() -> None:
    import sys
    if len(sys.argv) < 2:
        print('usage: python3 -m ablation.analyzers.firmware_container <image.BIN> [extract <outdir>]')
        sys.exit(1)
    fw = FirmwareContainer.from_path(sys.argv[1])
    fw.dump_partitions()
    if len(sys.argv) >= 4 and sys.argv[2] == 'extract':
        fw.extract_all(sys.argv[3])


if __name__ == '__main__':
    _main()
