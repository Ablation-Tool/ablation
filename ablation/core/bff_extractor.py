"""AIX backup-by-name (BFF) archive extractor.

Parses the AIX backup(8) "by-name" archive format produced by IBM AIX 4.x,
5.x, and 6.x.  Common file extensions: ``.bff`` (Backup File Format) and
``.liblpp.a`` embedded within ``.bff`` archives.

Why this exists
---------------
1. The AIX BFF format has no support in any common Linux archive tool.  GNU
   ``tar``, ``ar``, ``file``, and ``binwalk`` all fail to extract correctly:
   ``tar`` does not recognise the format; ``ar`` errors on the magic bytes;
   ``binwalk`` extracts raw byte-offset slices that are not the actual files.
2. XCOFF binaries inside BFF archives are invisible to ``LIEF``, which returns
   ``None`` for XCOFF inputs.  Without a proper BFF extractor, the XCOFF
   binaries cannot be reached at all.
3. BFF archives from AIX 4.3.3 and 5.1 contain kernel extensions, loadable
   modules, and shared objects that are primary RE targets.  Every one of them
   is locked inside a BFF container.
4. The BFF integer encoding is little-endian despite AIX/PowerPC being a
   big-endian platform.  This means existing COFF/XCOFF tools that assume BE
   for all fields will misread sizes and fail to locate data.  This extractor
   handles the mixed-endian layout explicitly.

Format layout
-------------
::

    Volume header    72 bytes  (magic 0x09 0x00 at offset 0)
    Per-entry block  variable

Each entry block::

    Extended stat    56 bytes  (timestamps, device/inode; all LE)
    File size         4 bytes  (LE; 0 for directories)
    Zero field        4 bytes
    Name              variable (null-terminated, padded to next 8-byte boundary)
    Stat summary     40 bytes  (uid/gid/mode at fixed offsets; LE)
    Data             <size> bytes, padded to next 8-byte boundary

Usage::

    from ablation.core.bff_extractor import iter_entries, extract_to
    from pathlib import Path

    data = Path('bos.net.tcp.server.4.3.3.84.bff').read_bytes()
    for entry in iter_entries(data):
        if not entry.is_dir:
            print(f'{entry.rel_path}  {len(entry.data)} bytes')

References
----------
Empirical analysis of AIX 4.3.3 ML11 BFF archives; IBM AIX 4.3.3 backup(8).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List

BFF_MAGIC = b'\x09\x00'

_VOL_HDR_SZ  = 72   # fixed-size volume header at archive start
_EXT_STAT_SZ = 56   # extended stat block per entry (before size field)
_STAT_SZ     = 40   # inline stat summary per entry (after name)

# Byte offsets within the 56-byte extended stat block (little-endian)
_XS_MTIME = 28   # 4-byte mtime

# Byte offsets within the 40-byte stat summary block (little-endian)
_SS_UID  =  0
_SS_GID  =  4
_SS_MODE = 12

_S_IFMT  = 0o170000
_S_IFREG = 0o100000
_S_IFDIR = 0o040000


@dataclass
class BffEntry:
    """One file or directory entry from a BFF archive."""

    name:  str                             # e.g. './usr/lib/drivers/netintf'
    data:  bytes = field(repr=False)       # raw bytes; empty for directories
    mode:  int   = 0o100644
    uid:   int   = 0
    gid:   int   = 0
    mtime: int   = 0                       # seconds since Unix epoch (LE uint32)

    @property
    def is_dir(self) -> bool:
        return (self.mode & _S_IFMT) == _S_IFDIR

    @property
    def is_reg(self) -> bool:
        return (self.mode & _S_IFMT) == _S_IFREG

    @property
    def rel_path(self) -> str:
        """Name with any leading './' stripped."""
        return self.name[2:] if self.name.startswith('./') else self.name


def _pad8(n: int) -> int:
    """Round n up to the next multiple of 8."""
    return (n + 7) & ~7


def iter_entries(data: bytes) -> Iterator[BffEntry]:
    """Yield every :class:`BffEntry` from a BFF archive held in *data*.

    Raises :class:`ValueError` if the magic bytes do not match.
    Silently stops iteration on truncation or a zero-length name sentinel.
    """
    if len(data) < _VOL_HDR_SZ + _EXT_STAT_SZ + 8:
        raise ValueError(f"data too short ({len(data)} bytes) to be a BFF archive")
    if data[:2] != BFF_MAGIC:
        raise ValueError(
            f"not a BFF archive: magic={data[:2].hex()!r}, expected '0900'"
        )

    off = _VOL_HDR_SZ

    while True:
        # Enough room for ext_stat + size + zero?
        if off + _EXT_STAT_SZ + 8 > len(data):
            break

        # Extended stat block (56 bytes)
        mtime = struct.unpack_from('<I', data, off + _XS_MTIME)[0]
        off += _EXT_STAT_SZ

        # File size (4 bytes LE) + zero field (4 bytes)
        file_size = struct.unpack_from('<I', data, off)[0]
        off += 8

        # Null-terminated filename
        try:
            null_pos = data.index(b'\x00', off)
        except ValueError:
            break
        raw_name = data[off:null_pos]
        if not raw_name:
            break   # empty name = end sentinel or corruption
        off += _pad8(len(raw_name) + 1)   # name + null, padded to 8

        # Stat summary (40 bytes)
        if off + _STAT_SZ > len(data):
            break
        uid  = struct.unpack_from('<I', data, off + _SS_UID)[0]
        gid  = struct.unpack_from('<I', data, off + _SS_GID)[0]
        mode = struct.unpack_from('<I', data, off + _SS_MODE)[0]
        off += _STAT_SZ

        # File data (padded to 8-byte boundary)
        padded = _pad8(file_size)
        if off + file_size > len(data):
            break
        file_data = data[off:off + file_size]
        off += padded

        yield BffEntry(
            name=raw_name.decode('utf-8', errors='replace'),
            data=file_data,
            mode=mode,
            uid=uid,
            gid=gid,
            mtime=mtime,
        )


def extract_to(data: bytes, dest: Path) -> List[BffEntry]:
    """Extract all entries from *data* into *dest* directory.

    Creates directories as needed.  Returns the list of extracted entries.
    """
    dest = Path(dest)
    extracted: List[BffEntry] = []
    for entry in iter_entries(data):
        target = dest / entry.rel_path
        if entry.is_dir:
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(entry.data)
        extracted.append(entry)
    return extracted
