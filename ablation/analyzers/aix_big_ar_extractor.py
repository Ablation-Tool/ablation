"""
aix_big_ar_extractor.py: AIX Big Archive (<bigaf>) member extractor.

Why this exists (ESSL-GAP-002 / AIX-Libs gap):
  GNU ar does not support the AIX big archive format — it reports
  "file format not recognized". AIX shared libraries (libc.a, libm.a,
  libpthreads.a, libbsd.a) are distributed as <bigaf> archives containing
  XCOFF32 or XCOFF64 object members. Without extraction, the XCOFF members
  inside are inaccessible for Ablation analysis.

Format (from AIX /usr/include/ar.h, big-archive variant):

  Global header (128 bytes):
    <bigaf>\n  (8 bytes, magic)
    fl_memoff  [20]  offset of member table
    fl_gstoff  [20]  offset of 32-bit global symbol table
    fl_gst64off[20]  offset of 64-bit global symbol table
    fl_fstmoff [20]  offset of first archive member (128 for non-empty)
    fl_lstmoff [20]  offset of last archive member
    fl_freeoff [20]  offset of free list (0 if unused)

  Member header (at each member offset):
    ar_size    [20]  member data size in bytes (decimal text)
    ar_nxtoff  [20]  offset of next member (0 = last) (decimal text)
    ar_prvoff  [20]  offset of previous member (decimal text)
    ar_date    [12]  modification timestamp (decimal text)
    ar_uid     [12]  owner UID (decimal text)
    ar_gid     [12]  owner GID (decimal text)
    ar_mode    [12]  file mode (octal text)
    ar_namlen  [ 4]  name length in bytes (decimal text)
    _ar_name   [ar_namlen]  member name (NOT null-terminated)
    pad        [0 or 1]     one null byte if ar_namlen is odd
    ar_fmag    [2]   consistency trailer: 0x60 0x0a ('`' + newline)
    <member data> (ar_size bytes)
    <padding>   (0 or 1 byte to align next member to 2-byte boundary)

Usage:
    members = AixBigArExtractor.from_path('/path/to/libc.a')
    for name, data in members.items():
        print(name, len(data))
    # or:
    extractor = AixBigArExtractor('/path/to/libc.a')
    for name, data in extractor.extract():
        ...
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterator, Tuple

AIAMAG = b"<bigaf>\n"
ARFMAG = b"`\n"       # 0x60 0x0a — member trailer after name

_FL_HDR_SIZE   = 128   # global header size
_AR_HDR_FIXED  = 112   # fixed fields before the name


class AixBigArExtractor:
    """Extract XCOFF members from an AIX big archive (<bigaf> format).

    Supports both XCOFF32 and XCOFF64 members; returns raw bytes for each.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, "rb") as fh:
            self._data = fh.read()
        if not self._data.startswith(AIAMAG):
            raise ValueError(f"Not an AIX big archive (magic={self._data[:8]!r})")

    @classmethod
    def from_path(cls, path: str) -> Dict[str, bytes]:
        """Return {member_name: bytes} for all extractable members."""
        return {name: data for name, data in cls(path).extract()}

    # ------------------------------------------------------------------
    # Header parsing helpers
    # ------------------------------------------------------------------

    def _txt(self, offset: int, length: int) -> str:
        return self._data[offset: offset + length].decode("ascii", errors="replace").strip()

    def _int(self, offset: int, length: int) -> int:
        s = self._txt(offset, length)
        return int(s) if s else 0

    def _global_header(self) -> Tuple[int, int]:
        """Return (first_member_offset, last_member_offset)."""
        fstmoff = self._int(0x44, 20)
        lstmoff = self._int(0x58, 20)
        return fstmoff, lstmoff

    def _read_member(self, offset: int) -> Tuple[str, int, int, bytes]:
        """Parse member at offset.

        Returns (name, data_offset, nxtoff, member_bytes).
        """
        d = self._data
        ar_size   = self._int(offset + 0x00, 20)
        ar_nxtoff = self._int(offset + 0x14, 20)
        ar_namlen = self._int(offset + 0x6C, 4)

        name_start = offset + _AR_HDR_FIXED
        name = d[name_start: name_start + ar_namlen].decode("ascii", errors="replace")

        # data starts after: fixed_header + name + optional_null_pad + ar_fmag(2)
        null_pad  = 1 if ar_namlen & 1 else 0
        data_start = name_start + ar_namlen + null_pad + len(ARFMAG)

        # verify ar_fmag for consistency
        fmag = d[name_start + ar_namlen + null_pad: data_start]
        if fmag != ARFMAG:
            raise ValueError(
                f"ar_fmag mismatch at 0x{offset:x}: got {fmag!r}, expected {ARFMAG!r}"
            )

        member_bytes = d[data_start: data_start + ar_size]
        return name, data_start, ar_nxtoff, member_bytes

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def extract(self) -> Iterator[Tuple[str, bytes]]:
        """Yield (member_name, member_bytes) for each archive member.

        Skips the special member-table and global-symbol-table members
        (names "" or "/") that contain archive metadata, not object code.
        """
        fstmoff, _lstmoff = self._global_header()
        if not fstmoff:
            return  # empty archive

        offset = fstmoff
        seen: set = set()
        while offset:
            if offset in seen:
                break
            seen.add(offset)
            try:
                name, _data_off, nxtoff, member_bytes = self._read_member(offset)
            except (ValueError, IndexError, UnicodeDecodeError):
                break

            # skip metadata members (member table, symbol table)
            if name not in ("", "/", "//"):
                yield name, member_bytes

            offset = nxtoff

    def list_members(self) -> list[str]:
        """Return names of all extractable members."""
        return [name for name, _ in self.extract()]

    def get_member(self, name: str) -> bytes:
        """Return bytes for a specific member by name; raises KeyError if absent."""
        for mname, mdata in self.extract():
            if mname == name:
                return mdata
        raise KeyError(f"Member {name!r} not found in {self.path}")

    def xcoff_members(self) -> Iterator[Tuple[str, bytes]]:
        """Yield only members whose magic is XCOFF32 (0x01DF) or XCOFF64 (0x01F7)."""
        for name, data in self.extract():
            if len(data) >= 2 and data[:2] in (b"\x01\xdf", b"\x01\xf7"):
                yield name, data
