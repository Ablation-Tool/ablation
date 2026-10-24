"""
metakit_parser.py: MetaKit 4 VFS locator and file extractor.

Why this exists (gap IDs: MK4-GAP-001, MK4-GAP-002, MK4-GAP-003):

  1. MK4-GAP-001 — TclKit binary locator missing.
     Ablation has no way to find MetaKit VFS databases appended to TclKit
     installer binaries (BitRock, enterprise appliance firmware, Cisco
     embedded Tcl runtimes).  Without a locator, the embedded Tcl scripts,
     file manifests, and runtime libraries are invisible.

  2. MK4-GAP-002 — File manifest not parseable.
     BitRock installers store the complete file manifest (path, mode, mtime,
     LZMA chunk offsets) as the first file in the MetaKit VFS.  Without
     extraction, the payload structure — including which files get installed
     and what system_checker scripts do — is opaque.

  3. MK4-GAP-003 — Embedded ELF blobs not enumerable.
     MetaKit VFS blobs include Tcl extension .so files (tbcload, lzmadec,
     cookfs, thread, itcl) that can be extracted and fed into BinaryContext
     for standalone analysis.  Without MetaKit parsing, these binaries are
     inaccessible.

MetaKit 4 format summary:
  A MetaKit database appended to a TclKit binary ends with a 16-byte
  big-endian descriptor:
      [a: 0x80000000][b: MK_size][c: 0x80??????][d: ???]
  where `a` must equal 0x80000000 and `(c >> 24)` must equal 0x80.
  The MetaKit data starts at: file_end - 16 - b.
  Starts with JL\\x1a\\x00 magic (4 bytes).

  BitRock Windows installers embed a `bitrock-lzma-4.0` marker in the last
  32KB of the file.  If the marker is at index `i` in the last 32KB window,
  the extra offset `off = 32768 - i` must be subtracted: MetaKit starts at
  file_end - 16 - b - off.

  Within the MetaKit, file contents are stored as zlib-compressed blobs.
  The schema string `dirs[name:S,parent:I,files[name:S,size:I,date:I,
  contents:B]]` (found near the end of the MK data) describes the table
  structure.

  BitRock-specific layout (confirmed by analysis of IDA Pro 9.4 SP1 installer):
    Blob 0 (@JL+0x354): File manifest (300KB+), lists every installed file
                         with LZMA chunk offsets.
    Blobs 1-N:           Tcl library files, localization strings, PNG images,
                         Tcl extension .so binaries (tbcload, lzmadec, etc.)

Usage:
    from ablation.analyzers.metakit_parser import MetaKitParser

    # Find and extract from a TclKit installer binary
    parser = MetaKitParser.from_path('/path/to/installer.run')
    if not parser.found:
        print('No MetaKit found')
    else:
        for name, blob in parser.iter_files():
            print(f'{name}: {len(blob):,} bytes')

    # Extract a specific file
    manifest = parser.get_manifest()   # first large blob (BitRock convention)
    elf_blobs = parser.find_embedded_elfs()  # {name: bytes}

    # With existing BinaryContext
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/installer.run')
    parser = MetaKitParser.from_context(ctx)
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

# MetaKit JL magic bytes
_MK4_MAGIC = b'JL\x1a\x00'

# BitRock LZMA offset marker embedded in last 32KB of Windows installers
_BITROCK_LZMA_MARKER = b'bitrock-lzma-4.0'

# ELF magic for embedded binary detection
_ELF_MAGIC = b'\x7fELF'

# Minimum zlib block size worth decompressing (avoids false positives)
_MIN_ZLIB_BLOCK = 64

# Minimum decompressed size to call something a "file" vs noise
_MIN_FILE_SIZE = 32


@dataclass
class MkFile:
    """A file extracted from a MetaKit VFS blob."""
    index: int          # blob index within MetaKit
    offset: int         # byte offset within the raw MetaKit data
    raw_size: int       # compressed size
    data: bytes         # decompressed content
    is_elf: bool = False
    is_text: bool = False

    def __len__(self) -> int:
        return len(self.data)


class MetaKitParser:
    """
    Locates, validates, and extracts files from MetaKit 4 VFS databases
    appended to TclKit binaries (BitRock installers, embedded Tcl appliances).
    """

    def __init__(self, binary_path: str, ctx=None):
        self.binary_path = binary_path
        self._ctx = ctx
        self._data: Optional[bytes] = None
        self._mk_start: int = -1
        self._mk_end: int = -1
        self._mk_data: Optional[bytes] = None
        self._files: Optional[List[MkFile]] = None
        self._parsed = False

    @classmethod
    def from_path(cls, path: str) -> 'MetaKitParser':
        parser = cls(path)
        parser._load()
        return parser

    @classmethod
    def from_context(cls, ctx) -> 'MetaKitParser':
        parser = cls(ctx.path, ctx=ctx)
        parser._load()
        return parser

    # ── public API ──────────────────────────────────────────────────────────

    @property
    def found(self) -> bool:
        """True if a valid MetaKit VFS was located in the binary."""
        return self._mk_start >= 0

    @property
    def mk_start(self) -> int:
        """Byte offset of the MetaKit JL magic within the binary."""
        return self._mk_start

    @property
    def mk_size(self) -> int:
        """Size of the MetaKit data region (excluding 16-byte descriptor)."""
        if not self.found:
            return 0
        return self._mk_end - self._mk_start

    @property
    def schema(self) -> str:
        """MetaKit schema string if found (e.g. 'dirs[name:S,parent:I,files[...]]')."""
        return self._find_schema()

    def iter_files(self) -> Iterator[Tuple[str, bytes]]:
        """Yield (label, decompressed_bytes) for each zlib blob in the MetaKit."""
        for f in self._get_files():
            label = f'blob_{f.index:03d}'
            if f.is_elf:
                label += '_elf'
            elif f.is_text:
                label += '_text'
            yield label, f.data

    def get_file(self, index: int) -> Optional[bytes]:
        """Return decompressed content of blob at given index."""
        files = self._get_files()
        if 0 <= index < len(files):
            return files[index].data
        return None

    def get_manifest(self) -> Optional[bytes]:
        """
        Return the BitRock file manifest (first large blob by convention).

        The manifest lists every file in the LZMA payload with its path,
        permissions, mtime, and LZMA chunk offsets.  Format:
          path {file mode mtime ? {{chunk_offset chunk_size}...}}
        """
        files = self._get_files()
        # The manifest is the largest blob in the first few entries
        candidates = [f for f in files[:4] if len(f.data) > 10000 and f.is_text]
        if not candidates:
            candidates = [f for f in files if len(f.data) > 10000 and f.is_text]
        if candidates:
            return max(candidates, key=lambda f: len(f.data)).data
        return None

    def find_embedded_elfs(self) -> Dict[str, bytes]:
        """
        Return {label: bytes} for all ELF blobs embedded in the MetaKit.

        These are typically Tcl extension .so files: tbcload, lzmadec, cookfs,
        thread, itcl, libtcl, libtk.  Feed each into BinaryContext for analysis.
        """
        result: Dict[str, bytes] = {}
        for f in self._get_files():
            if f.is_elf:
                label = f'elf_blob_{f.index:03d}_0x{f.offset:x}_{f.raw_size}'
                result[label] = f.data
        return result

    def find_tcl_scripts(self) -> Dict[str, bytes]:
        """
        Return {label: bytes} for all Tcl/TclPro text files in the MetaKit.

        Includes plaintext .tcl files and TclPro ByteCode blobs.
        """
        result: Dict[str, bytes] = {}
        for f in self._get_files():
            if f.is_text or f.data.startswith(b'TclPro ByteCode'):
                label = f'tcl_blob_{f.index:03d}'
                result[label] = f.data
        return result

    def report(self) -> str:
        """One-line summary of what was found."""
        if not self.found:
            return f'MetaKitParser: no MetaKit found in {self.binary_path}\n'
        files = self._get_files()
        n_elf = sum(1 for f in files if f.is_elf)
        n_text = sum(1 for f in files if f.is_text)
        total_unpacked = sum(len(f.data) for f in files)
        return (
            f'MetaKitParser: {len(files)} blobs ({n_elf} ELF, {n_text} text) '
            f'at offset 0x{self._mk_start:x}, {self.mk_size:,} bytes raw, '
            f'{total_unpacked:,} bytes unpacked\n'
        )

    # ── static helpers ───────────────────────────────────────────────────────

    @staticmethod
    def find_mk4_in_data(data: bytes) -> Optional[Tuple[int, int]]:
        """
        Implement tclKitMkFindBeginning: locate MetaKit appended to TclKit binary.

        Returns (mk_start, mk_end_exclusive) where mk_start points to JL magic
        and mk_end_exclusive is the byte after the 16-byte descriptor.
        Returns None if no valid MetaKit is found.
        """
        file_end = len(data)
        if file_end < 32:
            return None

        # Check for BitRock LZMA offset marker in last 32KB (Windows installers)
        off = 0
        window_start = max(0, file_end - 32768)
        window = data[window_start:]
        marker_idx = window.find(_BITROCK_LZMA_MARKER)
        if marker_idx >= 0:
            off = 32768 - marker_idx

        # Read 16-byte big-endian descriptor at file_end - 16 - off
        desc_start = file_end - 16 - off
        if desc_start < 4:
            return None

        desc = data[desc_start:desc_start + 16]
        if len(desc) < 16:
            return None

        a, b, c, _ = struct.unpack('>IIII', desc)

        # Validate descriptor signature
        if a != 0x80000000:
            return None
        if (c >> 24) != 0x80:
            return None
        if b == 0:
            return None

        # Locate MetaKit start
        mk_start = desc_start - b
        if mk_start < 0 or mk_start + 4 > file_end:
            return None

        # Validate JL magic
        if data[mk_start:mk_start + 4] != _MK4_MAGIC:
            return None

        return (mk_start, desc_start + 16)

    # ── internal ─────────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._parsed:
            return
        self._parsed = True
        try:
            path = Path(self.binary_path)
            if not path.exists():
                return
            if path.stat().st_size > 2 * 1024 * 1024 * 1024:
                # For very large files (>2GB), only read the tail
                with open(path, 'rb') as fh:
                    # Need last ~16MB to find MetaKit (descriptor + data)
                    tail_size = 64 * 1024 * 1024
                    file_size = path.stat().st_size
                    fh.seek(max(0, file_size - tail_size))
                    tail = fh.read()
                    # Adjust: run find on tail, then fix offsets
                    result = self.find_mk4_in_data(tail)
                    if result is None:
                        return
                    rel_start, rel_end = result
                    abs_offset = file_size - len(tail)
                    self._mk_start = abs_offset + rel_start
                    self._mk_end = abs_offset + rel_end - 16  # exclude descriptor
                    # Read just the MetaKit data
                    with open(path, 'rb') as fh2:
                        fh2.seek(self._mk_start)
                        self._mk_data = fh2.read(self._mk_end - self._mk_start)
            else:
                with open(path, 'rb') as fh:
                    self._data = fh.read()
                result = self.find_mk4_in_data(self._data)
                if result is None:
                    return
                mk_start, mk_end = result
                self._mk_start = mk_start
                self._mk_end = mk_end - 16  # exclude 16-byte descriptor
                self._mk_data = self._data[mk_start:self._mk_end]
        except (OSError, PermissionError):
            pass

    def _get_files(self) -> List[MkFile]:
        if self._files is not None:
            return self._files
        self._files = []
        if self._mk_data is None or len(self._mk_data) < 8:
            return self._files

        mk = self._mk_data
        idx = 0
        blob_index = 0

        # Skip the 4-byte JL magic
        pos = 4

        # Scan for all zlib-compressed blobs (0x78 0x9C header)
        while pos < len(mk) - 2:
            if mk[pos:pos + 2] != b'\x78\x9c':
                pos += 1
                continue

            # Try to decompress; if it fails, skip
            decompressed = self._try_decompress(mk, pos)
            if decompressed is None or len(decompressed) < _MIN_FILE_SIZE:
                pos += 1
                continue

            # Estimate compressed size by binary search
            raw_size = self._measure_zlib(mk, pos)

            is_elf = decompressed[:4] == _ELF_MAGIC
            is_text = self._is_mostly_text(decompressed[:256])

            self._files.append(MkFile(
                index=blob_index,
                offset=pos,
                raw_size=raw_size,
                data=decompressed,
                is_elf=is_elf,
                is_text=is_text,
            ))
            blob_index += 1
            pos += max(raw_size, 1)

        return self._files

    def _find_schema(self) -> str:
        if self._mk_data is None:
            return ''
        # Schema string is near the end of the MetaKit data
        search_region = self._mk_data[-4096:]
        idx = search_region.rfind(b'dirs[')
        if idx < 0:
            idx = search_region.rfind(b'views[')
        if idx < 0:
            return ''
        end = search_region.find(b'\x00', idx)
        if end < 0:
            end = idx + 256
        raw = search_region[idx:end]
        return raw.decode('ascii', errors='replace')

    @staticmethod
    def _try_decompress(data: bytes, pos: int) -> Optional[bytes]:
        """Attempt zlib decompression at pos; return bytes or None."""
        # Try increasing window sizes to find the right compressed length
        for max_size in (65536, 524288, 2097152, 8388608):
            chunk = data[pos:pos + max_size]
            if len(chunk) < _MIN_ZLIB_BLOCK:
                return None
            try:
                return zlib.decompress(chunk)
            except zlib.error:
                pass
        return None

    @staticmethod
    def _measure_zlib(data: bytes, pos: int) -> int:
        """
        Estimate the compressed length of the zlib stream starting at pos.
        Uses binary search: find the smallest prefix that decompresses without error.
        """
        lo, hi = _MIN_ZLIB_BLOCK, min(len(data) - pos, 8 * 1024 * 1024)
        best = hi
        while lo < hi:
            mid = (lo + hi) // 2
            try:
                zlib.decompress(data[pos:pos + mid])
                best = mid
                hi = mid
            except zlib.error:
                lo = mid + 1
        return best

    @staticmethod
    def _is_mostly_text(chunk: bytes) -> bool:
        """Return True if chunk is predominantly printable ASCII."""
        if not chunk:
            return False
        printable = sum(1 for b in chunk if 9 <= b < 127)
        return printable / len(chunk) > 0.75
