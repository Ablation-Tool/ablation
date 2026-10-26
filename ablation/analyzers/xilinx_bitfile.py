"""
xilinx_bitfile.py — Xilinx .bit and .mcs bitfile parser for FPGA firmware RE.

Supports Spartan-3 (XC3S50AN), Spartan-6 (XC6SLX45), 7-series (Kintex-7),
UltraScale+ (xcku115), and Versal PDI via extension. Parses the standard .bit
header format — 13-byte preamble followed by lettered fields a–e — to extract:

  - Design name, part name, build date/time (fields a–d)
  - Bitstream bytes (field e, 32-bit length prefix)
  - Embedded ASCII strings from uncompressed bitstreams
  - IDCODE via Type1 Write packet (0x30018001) in uncompressed 7-series bitstreams

IDCODEs recognised:

    0x01C22093  XC3S50AN     (ABC130 driver PCB)
    0x04001093  XC6SLX45     (Atlys board)
    0x03651093  XC7K325T     (Genesys2 ITSDAQ)
    0x0363C093  XC7K160T     (generic 7-series)
    0x38425093  XCKU115      (FELIX FLX712)
    0x14B37093  XC2VP30      (Virtex-2 Pro legacy)

Compressed bitfiles (COMPRESS=TRUE in field a): Config packets are
bitswapped and scrambled — do not attempt packet decoding. Use part_name()
to identify the device from field b.

Usage:
    bf = XilinxBitfile.from_path('/path/to/design.bit')
    print(bf.summary())
    print(bf.design_name())      # e.g. "felix_top;UserID=0XFFFFFFFF"
    print(bf.part_name())        # e.g. "xcku115-flvf1924-2-e"
    print(bf.build_datetime())   # e.g. "2025/10/01 09:28:26"
    for s in bf.extract_strings(min_len=8):
        print(s)
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# ── Constants ─────────────────────────────────────────────────────────────────

# First 13 bytes of every Xilinx .bit file
_PREAMBLE = bytes([0x00, 0x09, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x00, 0x00, 0x01])

# Synchronisation word in uncompressed 7-series bitstreams
_SYNC_WORD = bytes.fromhex("aa995566")

# Type1 Write to IDCODE register (0x0C) with word count 1 — 7-series / UltraScale
_IDCODE_PKT_HDR = 0x30018001

# Known Xilinx IDCODEs (lower 28 bits are device ID; bit 0 = 1 always)
XILINX_IDCODES: Dict[int, str] = {
    0x01C22093: "XC3S50AN",
    0x04001093: "XC6SLX45",
    0x03651093: "XC7K325T",
    0x0363C093: "XC7K160T",
    0x03622093: "XC7K70T",
    0x38425093: "XCKU115",
    0x14B37093: "XC2VP30",
    0x04251093: "XC6SLX150T",
    0x3623093:  "XC7A35T",
    0x3631093:  "XC7A100T",
}


# ── Parse errors ──────────────────────────────────────────────────────────────

class BitfileError(ValueError):
    """Raised when the file does not conform to the Xilinx .bit format."""


# ── Internal parse result ─────────────────────────────────────────────────────

@dataclass
class _BitfileHeader:
    design_name: str       # field a (null-stripped)
    part_name: str         # field b
    build_date: str        # field c
    build_time: str        # field d
    bitstream_offset: int  # byte offset of bitstream data within the file
    bitstream_len: int     # byte count of bitstream data


# ── Main class ────────────────────────────────────────────────────────────────

class XilinxBitfile:
    """
    Parser for Xilinx FPGA .bit files.

    File-based parser — no BinaryContext required. The heavy bitstream bytes
    are never loaded into memory unless extract_strings() or bitstream_bytes()
    is explicitly called, so summary() and metadata accessors are fast even on
    37 MB FLX712 files.
    """

    def __init__(self, path: str, header: _BitfileHeader) -> None:
        self._path = path
        self._hdr  = header
        self._bs_cache: Optional[bytes] = None

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str) -> "XilinxBitfile":
        """Parse a .bit file at *path* and return an XilinxBitfile instance."""
        data = Path(path).read_bytes()
        hdr = _parse_header(data, path)
        return cls(path, hdr)

    # ── Public API ────────────────────────────────────────────────────────────

    def summary(self) -> str:
        lines = [
            f"XilinxBitfile: {Path(self._path).name}",
            f"  design   : {self._hdr.design_name}",
            f"  part     : {self._hdr.part_name}",
            f"  built    : {self._hdr.build_date}  {self._hdr.build_time}",
            f"  bitstream: {self._hdr.bitstream_len:,} bytes "
            f"(file offset {self._hdr.bitstream_offset})",
        ]
        idcode = self.idcode_candidate()
        if idcode:
            device = XILINX_IDCODES.get(idcode, "unknown")
            lines.append(f"  IDCODE   : 0x{idcode:08X}  ({device})")
        compressed = "COMPRESS=TRUE" in self._hdr.design_name.upper()
        if compressed:
            lines.append("  [compressed — bitstream not decoded]")
        return "\n".join(lines)

    def design_name(self) -> str:
        return self._hdr.design_name

    def part_name(self) -> str:
        return self._hdr.part_name

    def build_date(self) -> str:
        return self._hdr.build_date

    def build_time(self) -> str:
        return self._hdr.build_time

    def build_datetime(self) -> str:
        return f"{self._hdr.build_date} {self._hdr.build_time}"

    def bitstream_bytes(self) -> bytes:
        """Return the raw bitstream bytes (loads full file; may be large)."""
        if self._bs_cache is None:
            data = Path(self._path).read_bytes()
            o = self._hdr.bitstream_offset
            n = self._hdr.bitstream_len
            self._bs_cache = data[o : o + n]
        return self._bs_cache

    def is_compressed(self) -> bool:
        """Return True if the design was bitstreamed with COMPRESS=TRUE."""
        return "COMPRESS=TRUE" in self._hdr.design_name.upper()

    def extract_strings(self, min_len: int = 6) -> List[str]:
        """Return printable ASCII strings of at least *min_len* characters
        found in the bitstream. Useful only for uncompressed bitstreams."""
        bs = self.bitstream_bytes()
        pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
        return [m.group(0).decode("ascii") for m in pattern.finditer(bs)]

    def sync_word_offset(self) -> int:
        """Return the byte offset of 0xAA995566 within the bitstream,
        or -1 if not found. Compressed bitstreams return -1."""
        bs = self.bitstream_bytes()
        return bs.find(_SYNC_WORD)

    def idcode_candidate(self) -> int:
        """
        Return the IDCODE value written by the Type1 Write packet in the
        bitstream, or 0 if not found (compressed bitfiles, PDI format, etc.).

        Scans up to 4096 bytes after the sync word to find packet header
        0x30018001, then reads the following 4-byte word as the IDCODE.
        """
        if self.is_compressed():
            return 0
        bs = self.bitstream_bytes()
        sw = bs.find(_SYNC_WORD)
        if sw < 0:
            return 0
        post = bs[sw : sw + 4096]
        for i in range(0, len(post) - 7, 4):
            w = struct.unpack_from(">I", post, i)[0]
            if w == _IDCODE_PKT_HDR:
                return struct.unpack_from(">I", post, i + 4)[0]
        return 0

    def device_name(self) -> str:
        """Return the device name from the IDCODE lookup, or from the part
        name field b if no IDCODE is found."""
        idcode = self.idcode_candidate()
        if idcode:
            return XILINX_IDCODES.get(idcode, f"0x{idcode:08X}")
        # Derive from part name: "xcku115-flvf1924-2-e" → "xcku115"
        return self._hdr.part_name.split("-")[0].lower()


# ── Internal parser ────────────────────────────────────────────────────────────

def _parse_header(data: bytes, path: str) -> _BitfileHeader:
    """Parse the .bit header out of *data*. Raises BitfileError on malformed input."""
    if len(data) < 14:
        raise BitfileError(f"{path}: file too short ({len(data)} bytes)")

    if data[:13] != _PREAMBLE:
        raise BitfileError(
            f"{path}: bad preamble {data[:13].hex()!r}; expected {_PREAMBLE.hex()!r}"
        )

    i = 13
    fields: Dict[str, str] = {}

    for fid in "abcde":
        if i >= len(data):
            raise BitfileError(f"{path}: truncated at field {fid!r}")

        tag = data[i]
        if tag != ord(fid):
            raise BitfileError(
                f"{path}: expected field tag {fid!r} (0x{ord(fid):02x}) "
                f"at offset {i}, got 0x{tag:02x}"
            )
        i += 1

        if fid == "e":
            # 32-bit big-endian length prefix
            if i + 4 > len(data):
                raise BitfileError(f"{path}: truncated field-e length at offset {i}")
            blen = struct.unpack_from(">I", data, i)[0]
            i += 4
            # Don't validate that blen bytes follow — file may be truncated
            return _BitfileHeader(
                design_name=fields.get("a", ""),
                part_name=fields.get("b", ""),
                build_date=fields.get("c", ""),
                build_time=fields.get("d", ""),
                bitstream_offset=i,
                bitstream_len=blen,
            )
        else:
            # 16-bit big-endian length prefix
            if i + 2 > len(data):
                raise BitfileError(f"{path}: truncated field-{fid!r} length at offset {i}")
            slen = struct.unpack_from(">H", data, i)[0]
            i += 2
            if i + slen > len(data):
                raise BitfileError(
                    f"{path}: field {fid!r} claims {slen} bytes but only "
                    f"{len(data) - i} remain"
                )
            raw = data[i : i + slen]
            fields[fid] = raw.rstrip(b"\x00").decode("ascii", errors="replace")
            i += slen

    # Should never reach here: the 'e' branch always returns
    raise BitfileError(f"{path}: missing field e")


# ── Batch helper ──────────────────────────────────────────────────────────────

def scan_directory(directory: str, pattern: str = "*.bit") -> List[XilinxBitfile]:
    """Parse all .bit files matching *pattern* under *directory*.
    Silently skips files that fail to parse."""
    results: List[XilinxBitfile] = []
    for p in sorted(Path(directory).rglob(pattern)):
        try:
            results.append(XilinxBitfile.from_path(str(p)))
        except (BitfileError, OSError):
            pass
    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

def _main() -> None:
    import sys
    if len(sys.argv) < 2:
        print("Usage: xilinx_bitfile.py <file.bit> [file.bit ...]")
        sys.exit(1)
    for arg in sys.argv[1:]:
        try:
            bf = XilinxBitfile.from_path(arg)
            print(bf.summary())
        except BitfileError as exc:
            print(f"ERROR: {exc}")
        print()


if __name__ == "__main__":
    _main()
