"""
appledouble_extractor.py — AppleDouble container parser.

Mac Classic tools (unar, Stuffit Expander) extract resource forks in AppleDouble
format when run with ``-forks visible``.  The resulting `.rsrc` file contains an
AppleDouble "header file" — NOT the raw resource fork data.  All tooling that
tried to parse these as plain resource forks silently produced wrong results.

Three things that were impossible before this module:

  1. Tool_Chest compiled Mac Classic binaries (533/894 archives): every attempt
     to read the ``CODE``/``DATA`` resource map from a ``.rsrc`` file extracted
     by unar returned garbage because the 26-byte AppleDouble header was included
     in the byte stream fed to the resource-fork parser.

  2. Cross-archive resource-fork analysis: without a reliable way to strip the
     AppleDouble wrapper, each session required a manual offset calculation to
     skip to the resource fork entry — error-prone and not scriptable.

  3. Entry enumeration: AppleDouble files may contain Finder info, file dates,
     real name, and other metadata entries in addition to the resource fork.
     Manual analysis skipped these; the module exposes them for future analysis.

Usage::

    from ablation.analyzers.appledouble_extractor import AppleDoubleExtractor

    # Extract raw resource fork bytes
    raw = AppleDoubleExtractor.from_path('/path/to/file.rsrc').resource_fork()

    # Access all entries
    ext = AppleDoubleExtractor.from_bytes(data)
    for entry in ext.entries:
        print(f"id={entry.entry_id} offset={entry.offset} length={entry.length}")

    # Get resource fork entry descriptor (or None)
    rf = ext.resource_fork_entry()

    # Batch extraction
    results = AppleDoubleExtractor.batch_extract_resource_forks(
        ['/path/a.rsrc', '/path/b.rsrc']
    )
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------

APPLEDOUBLE_MAGIC      = 0x00051607   # big-endian uint32
APPLESINGLE_MAGIC      = 0x00051600   # single-file variant (reject; resource fork is embedded differently)
VERSION_2              = 0x00020000
VERSION_1              = 0x00010000

ENTRY_DATA_FORK        = 1
ENTRY_RESOURCE_FORK    = 2
ENTRY_REAL_NAME        = 3
ENTRY_COMMENT          = 4
ENTRY_ICON_BW          = 5
ENTRY_ICON_COLOR       = 6
ENTRY_FILE_DATES       = 7
ENTRY_FINDER_INFO      = 8
ENTRY_MACINTOSH_INFO   = 9
ENTRY_FILE_DATES_NEW   = 10

ENTRY_NAMES: Dict[int, str] = {
    ENTRY_DATA_FORK:      "data_fork",
    ENTRY_RESOURCE_FORK:  "resource_fork",
    ENTRY_REAL_NAME:      "real_name",
    ENTRY_COMMENT:        "comment",
    ENTRY_ICON_BW:        "icon_bw",
    ENTRY_ICON_COLOR:     "icon_color",
    ENTRY_FILE_DATES:     "file_dates",
    ENTRY_FINDER_INFO:    "finder_info",
    ENTRY_MACINTOSH_INFO: "macintosh_info",
    ENTRY_FILE_DATES_NEW: "file_dates_new",
}

# AppleDouble header layout (all big-endian):
#   +00: uint32  magic
#   +04: uint32  version
#   +08: char[16] home_filesystem
#   +24: uint16  entry_count
# Total fixed header: 26 bytes
#
# Each entry (12 bytes):
#   +00: uint32  entry_id
#   +04: uint32  offset   (from start of file)
#   +08: uint32  length

_HDR_FMT    = ">IHH16sH"   # magic(4) + version_hi(2) + version_lo(2) + home_fs(16) + entry_count(2)
_ENTRY_FMT  = ">III"        # entry_id(4) + offset(4) + length(4)

_HDR_SIZE   = struct.calcsize(_HDR_FMT)    # 26 bytes
_ENTRY_SIZE = struct.calcsize(_ENTRY_FMT)  # 12 bytes


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AppleDoubleEntry:
    entry_id: int
    offset:   int
    length:   int

    @property
    def name(self) -> str:
        return ENTRY_NAMES.get(self.entry_id, f"unknown_{self.entry_id}")

    def read_from(self, data: bytes) -> bytes:
        if self.offset + self.length > len(data):
            raise ValueError(
                f"AppleDoubleEntry id={self.entry_id}: "
                f"offset {self.offset}+{self.length} exceeds data length {len(data)}"
            )
        return data[self.offset : self.offset + self.length]


@dataclass
class AppleDoubleResult:
    version:      int
    home_fs:      bytes
    entries:      List[AppleDoubleEntry]
    _data:        bytes

    def entry_by_id(self, entry_id: int) -> Optional[AppleDoubleEntry]:
        for e in self.entries:
            if e.entry_id == entry_id:
                return e
        return None

    def resource_fork_entry(self) -> Optional[AppleDoubleEntry]:
        return self.entry_by_id(ENTRY_RESOURCE_FORK)

    def resource_fork(self) -> bytes:
        e = self.resource_fork_entry()
        if e is None:
            raise KeyError("No resource fork entry (id=2) in AppleDouble file")
        return e.read_from(self._data)

    def finder_info(self) -> Optional[bytes]:
        e = self.entry_by_id(ENTRY_FINDER_INFO)
        return e.read_from(self._data) if e else None

    def real_name(self) -> Optional[str]:
        e = self.entry_by_id(ENTRY_REAL_NAME)
        if e is None:
            return None
        raw = e.read_from(self._data)
        return raw.rstrip(b"\x00").decode("mac_roman", errors="replace")

    def report(self) -> str:
        lines = [
            f"AppleDouble v{self.version >> 16}.{self.version & 0xffff:04x}  "
            f"home_fs={self.home_fs.rstrip(b'\\x00')!r}  "
            f"entries={len(self.entries)}"
        ]
        for e in self.entries:
            lines.append(f"  [{e.entry_id:2d}] {e.name:<20s} offset=0x{e.offset:08x}  len={e.length}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class AppleDoubleExtractor:
    """Parse AppleDouble header files produced by unar/Stuffit on Linux."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._result: Optional[AppleDoubleResult] = None

    # ── constructors ────────────────────────────────────────────────────────

    @classmethod
    def from_bytes(cls, data: bytes) -> "AppleDoubleExtractor":
        ext = cls(data)
        ext._parse()
        return ext

    @classmethod
    def from_path(cls, path: str | Path) -> "AppleDoubleExtractor":
        data = Path(path).read_bytes()
        return cls.from_bytes(data)

    # ── public surface ───────────────────────────────────────────────────────

    def _require_parsed(self) -> AppleDoubleResult:
        if self._result is None:
            raise RuntimeError("AppleDoubleExtractor not parsed — use from_bytes() or from_path()")
        return self._result

    @property
    def entries(self) -> List[AppleDoubleEntry]:
        return self._require_parsed().entries

    def resource_fork_entry(self) -> Optional[AppleDoubleEntry]:
        return self._require_parsed().resource_fork_entry()

    def resource_fork(self) -> bytes:
        return self._require_parsed().resource_fork()

    def finder_info(self) -> Optional[bytes]:
        return self._require_parsed().finder_info()

    def real_name(self) -> Optional[str]:
        return self._require_parsed().real_name()

    def report(self) -> str:
        return self._require_parsed().report()

    # ── batch helper ─────────────────────────────────────────────────────────

    @classmethod
    def batch_extract_resource_forks(
        cls, paths: List[str | Path]
    ) -> Dict[str, Optional[bytes]]:
        """Return {path_str: raw_resource_fork_bytes | None (if no RF entry or parse error)}."""
        out: Dict[str, Optional[bytes]] = {}
        for p in paths:
            key = str(p)
            try:
                ext = cls.from_path(p)
                e = ext.resource_fork_entry()
                out[key] = e.read_from(ext._data) if e else None
            except (ValueError, struct.error, KeyError):
                out[key] = None
        return out

    @staticmethod
    def is_appledouble(data: bytes) -> bool:
        if len(data) < 4:
            return False
        magic = struct.unpack(">I", data[:4])[0]
        return magic == APPLEDOUBLE_MAGIC

    @staticmethod
    def is_applesingle(data: bytes) -> bool:
        if len(data) < 4:
            return False
        magic = struct.unpack(">I", data[:4])[0]
        return magic == APPLESINGLE_MAGIC

    # ── internals ────────────────────────────────────────────────────────────

    def _parse(self) -> None:
        data = self._data
        if len(data) < _HDR_SIZE:
            raise ValueError(f"AppleDouble: data too short ({len(data)} bytes, need ≥{_HDR_SIZE})")

        magic, ver_hi, ver_lo, home_fs, entry_count = struct.unpack_from(_HDR_FMT, data, 0)

        if magic == APPLESINGLE_MAGIC:
            raise ValueError(
                "AppleSingle file detected (magic 0x00051600). "
                "AppleSingle embeds both forks inline; use a dedicated AppleSingle parser."
            )
        if magic != APPLEDOUBLE_MAGIC:
            raise ValueError(
                f"Not an AppleDouble file: magic=0x{magic:08x} (expected 0x00051607)"
            )

        version = (ver_hi << 16) | ver_lo

        entries: List[AppleDoubleEntry] = []
        offset = _HDR_SIZE
        for i in range(entry_count):
            if offset + _ENTRY_SIZE > len(data):
                raise ValueError(
                    f"AppleDouble: entry {i} entry descriptor at offset {offset} "
                    f"exceeds data length {len(data)}"
                )
            entry_id, ent_offset, ent_length = struct.unpack_from(_ENTRY_FMT, data, offset)
            entries.append(AppleDoubleEntry(entry_id, ent_offset, ent_length))
            offset += _ENTRY_SIZE

        self._result = AppleDoubleResult(
            version=version,
            home_fs=home_fs,
            entries=entries,
            _data=data,
        )
