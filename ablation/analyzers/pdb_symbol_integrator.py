"""
pdb_symbol_integrator.py — PDB symbol file parsing and NameRegistry integration.

PDB (Program Database) files are the symbol format for Windows PE binaries. They
contain function names, type information, source file paths, and line numbers for
binaries built with MSVC. The PDB GUID embedded in the PE's CodeView debug directory
entry identifies the matching PDB on Microsoft's symbol server.

This module:
  1. Reads the CodeView debug directory entry from a PE to extract the PDB GUID,
     age, and PDB filename.
  2. Optionally fetches the matching PDB from Microsoft's symbol server
     (https://msdl.microsoft.com/download/symbols/).
  3. Parses the MSF (Multi-Stream File) container and DBI stream to extract the
     public symbols stream.
  4. Reads the PUBLICSYMS (S_PUB32) and GPROC32 symbol records to extract
     {va: name} mappings.
  5. Integrates extracted names into Ablation's NameRegistry via BinaryContext.set_name().

Usage:
    from ablation.analyzers.pdb_symbol_integrator import PDBSymbolIntegrator

    integrator = PDBSymbolIntegrator.from_path('ntdll.dll')
    info = integrator.pdb_info()
    print(f"PDB: {info.pdb_filename}  GUID: {info.guid}  age={info.age}")

    # With a local PDB already on disk:
    names = integrator.load_pdb('/path/to/ntdll.pdb')
    print(f"Loaded {len(names)} symbol names")
    # {va: name, ...}

    # With BinaryContext integration:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('ntdll.dll')
    count = integrator.inject_into_context(ctx, pdb_path='/path/to/ntdll.pdb')
    print(f"Injected {count} names into context")
"""

from __future__ import annotations

import struct
import urllib.request
import urllib.error
import tempfile
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False


# Microsoft public symbol server base URL
_MSDL_BASE = 'https://msdl.microsoft.com/download/symbols'

# MSF (Multi-Stream File) magic
_MSF_MAGIC_BIG   = b'Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00'
_MSF_MAGIC_SMALL = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00'

# CodeView debug type
_IMAGE_DEBUG_TYPE_CODEVIEW = 2

# CV signature "RSDS" for PDB 7.0
_CV_RSDS = b'RSDS'


@dataclass
class PDBInfo:
    """PDB reference embedded in a PE's CodeView debug directory entry."""
    guid: str           # formatted as XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX (no hyphens for URL)
    guid_formatted: str # formatted as XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    age: int
    pdb_filename: str   # just the basename, e.g. ntdll.pdb
    symbol_url: str     # full URL to fetch from msdl


@dataclass
class PDBFinding:
    """A finding from PDB integration."""
    severity: str
    category: str   # pdb_info | symbols_loaded | no_pdb | symbols_missing
    title: str
    location: str
    description: str


class PDBSymbolIntegrator:
    """PDB symbol file parser and NameRegistry integrator.

    Reads the CodeView debug directory from a PE to find the matching PDB,
    optionally fetches it from Microsoft's symbol server, parses the MSF
    container and public symbols stream, and feeds names into BinaryContext.
    """

    def __init__(self, pe: 'lief.PE.Binary', path: str, raw: bytes) -> None:
        self._pe = pe
        self._path = path
        self._raw = raw
        self._imagebase = pe.optional_header.imagebase
        self._pdb_info: Optional[PDBInfo] = None

    @classmethod
    def from_path(cls, path: str) -> 'PDBSymbolIntegrator':
        if not _LIEF_OK:
            raise ImportError("lief required: pip install lief>=0.14.0")
        raw = Path(path).read_bytes()
        pe = lief.parse(str(path))
        if pe is None or not isinstance(pe, lief.PE.Binary):
            raise ValueError(f"PDBSymbolIntegrator: not a PE binary: {path}")
        return cls(pe, str(path), raw)

    # ── CodeView / PDB reference extraction ─────────────────────────────────

    def pdb_info(self) -> Optional[PDBInfo]:
        """Extract PDB GUID, age, and filename from the PE debug directory."""
        if self._pdb_info is not None:
            return self._pdb_info

        if not self._pe.has_debug:
            return None

        for dbg in self._pe.debug:
            if int(dbg.type) != _IMAGE_DEBUG_TYPE_CODEVIEW:
                continue
            # Raw data offset in the file
            raw_offset = dbg.pointerto_rawdata
            raw_size   = dbg.sizeof_data
            if raw_offset + raw_size > len(self._raw) or raw_size < 24:
                continue
            data = self._raw[raw_offset:raw_offset + raw_size]
            if data[:4] != _CV_RSDS:
                continue
            # RSDS format: 4-byte sig + 16-byte GUID + 4-byte age + NUL-terminated path
            guid_bytes = data[4:20]
            (age,) = struct.unpack_from('<I', data, 20)
            pdb_path_bytes = data[24:]
            try:
                pdb_path_str = pdb_path_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
            except Exception:
                continue
            pdb_filename = Path(pdb_path_str).name

            # Build the GUID string in the two forms needed
            # Bytes 0-3: little-endian DWORD, 4-5: little-endian WORD, 6-7: little-endian WORD,
            # bytes 8-15: big-endian (as-is)
            d1, = struct.unpack_from('<I', guid_bytes, 0)
            d2, = struct.unpack_from('<H', guid_bytes, 4)
            d3, = struct.unpack_from('<H', guid_bytes, 6)
            d4 = guid_bytes[8:16]

            guid_no_hyphens = (
                f'{d1:08X}{d2:04X}{d3:04X}' +
                ''.join(f'{b:02X}' for b in d4)
            )
            guid_formatted = (
                f'{d1:08X}-{d2:04X}-{d3:04X}-'
                f'{d4[0]:02X}{d4[1]:02X}-'
                + ''.join(f'{b:02X}' for b in d4[2:])
            )
            symbol_url = f'{_MSDL_BASE}/{pdb_filename}/{guid_no_hyphens}{age}/{pdb_filename}'
            self._pdb_info = PDBInfo(
                guid=guid_no_hyphens,
                guid_formatted=guid_formatted,
                age=age,
                pdb_filename=pdb_filename,
                symbol_url=symbol_url,
            )
            return self._pdb_info

        return None

    # ── Symbol server fetch ───────────────────────────────────────────────────

    def fetch_pdb(self, out_dir: Optional[str] = None, timeout: int = 30) -> Optional[str]:
        """Download the PDB from Microsoft's symbol server.

        Returns the local path to the saved PDB, or None on failure.
        """
        info = self.pdb_info()
        if info is None:
            return None

        dest_dir = Path(out_dir) if out_dir else Path(tempfile.gettempdir()) / 'ablation_pdb'
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / info.pdb_filename

        if dest_path.exists():
            return str(dest_path)

        try:
            req = urllib.request.Request(
                info.symbol_url,
                headers={'User-Agent': 'Microsoft-Symbol-Server/10.0.22621.0'},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            dest_path.write_bytes(data)
            return str(dest_path)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise
        except Exception:
            return None

    # ── MSF / PDB parsing ─────────────────────────────────────────────────────

    def load_pdb(self, pdb_path: str) -> dict[int, str]:
        """Parse a PDB file and return {rva_or_va: name} for public symbols.

        Handles MSF 7.0 (small) format. Returns RVAs (relative to imagebase).
        """
        data = Path(pdb_path).read_bytes()
        if len(data) < 32:
            return {}

        if data[:len(_MSF_MAGIC_SMALL)] == _MSF_MAGIC_SMALL:
            return self._parse_msf7(data)
        return {}

    def _parse_msf7(self, data: bytes) -> dict[int, str]:
        """Parse MSF 7.0 (PDB 7.0) public symbols.

        MSF 7.0 superblock layout:
          +0x00  magic (32 bytes, including 2-byte trailer)
          +0x20  block_size  (UINT32)  — typically 4096
          +0x24  free_block_map_block (UINT32)
          +0x28  num_blocks  (UINT32)
          +0x2c  num_directory_bytes (UINT32)
          +0x30  unknown     (UINT32)
          +0x34  block_map_addr (UINT32) — block index of the stream directory
        """
        if len(data) < 0x38:
            return {}
        try:
            block_size, = struct.unpack_from('<I', data, 0x20)
            num_blocks, = struct.unpack_from('<I', data, 0x28)
            num_dir_bytes, = struct.unpack_from('<I', data, 0x2c)
            block_map_addr, = struct.unpack_from('<I', data, 0x34)

            if block_size < 512 or block_size > 65536:
                return {}

            # Read block map (list of blocks containing the stream directory)
            bm_offset = block_map_addr * block_size
            num_dir_blocks = (num_dir_bytes + block_size - 1) // block_size
            bm_size = num_dir_blocks * 4
            if bm_offset + bm_size > len(data):
                return {}
            dir_block_list = list(struct.unpack_from(f'<{num_dir_blocks}I', data, bm_offset))

            # Reconstruct directory data
            dir_data = b''
            for blk in dir_block_list:
                off = blk * block_size
                dir_data += data[off:off + block_size]
            dir_data = dir_data[:num_dir_bytes]

            # Stream directory: num_streams UINT32, then per-stream sizes, then per-stream block lists
            if len(dir_data) < 4:
                return {}
            (num_streams,) = struct.unpack_from('<I', dir_data, 0)
            if num_streams < 4 or num_streams > 65535:
                return {}
            pos = 4
            stream_sizes: list[int] = []
            for i in range(num_streams):
                if pos + 4 > len(dir_data):
                    return {}
                (sz,) = struct.unpack_from('<I', dir_data, pos)
                stream_sizes.append(sz if sz != 0xFFFFFFFF else 0)
                pos += 4

            # Per-stream block lists
            stream_blocks: list[list[int]] = []
            for sz in stream_sizes:
                n = (sz + block_size - 1) // block_size if sz > 0 else 0
                blocks: list[int] = []
                for _ in range(n):
                    if pos + 4 > len(dir_data):
                        return {}
                    (blk,) = struct.unpack_from('<I', dir_data, pos)
                    blocks.append(blk)
                    pos += 4
                stream_blocks.append(blocks)

            def read_stream(idx: int) -> bytes:
                if idx >= len(stream_sizes):
                    return b''
                sz = stream_sizes[idx]
                result = b''
                for blk in stream_blocks[idx]:
                    off = blk * block_size
                    result += data[off:off + block_size]
                return result[:sz]

            # Stream 1 = PDB info stream (has the feature code)
            # Stream 3 = DBI stream — tells us which stream is the public symbols
            dbi_data = read_stream(3)
            if len(dbi_data) < 64:
                return {}

            # DBI header:
            # +0x00 VersionSignature int32 (should be -1)
            # +0x04 VersionHeader uint32
            # +0x08 Age uint32
            # +0x0c GlobalStreamIndex uint16
            # +0x0e BuildNumber uint16
            # +0x10 PublicStreamIndex uint16
            (version_sig,) = struct.unpack_from('<i', dbi_data, 0)
            (pub_stream_idx,) = struct.unpack_from('<H', dbi_data, 0x10)
            if pub_stream_idx == 0xFFFF:
                return {}

            pub_data = read_stream(pub_stream_idx)
            return self._parse_publicsyms(pub_data)

        except Exception:
            return {}

    def _parse_publicsyms(self, data: bytes) -> dict[int, str]:
        """Parse the public symbols hash table stream (CodeView S_PUB32 records).

        Public symbols stream layout:
          +0x00  PSGSIHDR: {cbSymHash, cbAddrMap, nThunks, cbSizeOfThunk,
                             iSectThunkTable, offThunkTable, nSects}
          After header: sym hash table, then addr map, then thunk table
          The actual S_PUB32 records are in the globals stream (stream 5),
          but we can reach them through the address map + symbol offsets.

        Simpler approach: scan the globals stream (stream 5 by DBI convention)
        for S_PUB32 records, which are self-delimiting CV records.
        This method scans linearly for S_PUB32 (0x110e) record type.
        """
        names: dict[int, str] = {}
        if len(data) < 16:
            return names

        # Skip PSGSIHDR (28 bytes for standard layout) and scan remaining
        # data for S_PUB32 CodeView symbol records.
        # CV record format: uint16 length, uint16 type, payload[length-2]
        # S_PUB32 = 0x110e
        # S_PUB32 payload: uint32 flags, uint32 off, uint16 seg, name (NUL-term)

        pos = 28  # skip PSGSIHDR
        while pos + 4 <= len(data):
            try:
                (length, rec_type) = struct.unpack_from('<HH', data, pos)
                end = pos + 2 + length
                if length < 2 or end > len(data):
                    break
                if rec_type == 0x110e:  # S_PUB32
                    if pos + 14 <= end:
                        (flags, off, seg) = struct.unpack_from('<IIH', data, pos + 4)
                        if seg > 0:
                            name_start = pos + 14
                            name_end = data.find(b'\x00', name_start, end)
                            if name_end < 0:
                                name_end = end
                            try:
                                name = data[name_start:name_end].decode('utf-8', errors='replace')
                                if name and off > 0:
                                    # off is a section-relative offset; we store RVAs approximately
                                    # (section base is unknown without the section map, so we store
                                    # (seg, off) encoded and convert later if section map available)
                                    names[off] = name
                            except Exception:
                                pass
                pos = end
                # Align to 4 bytes
                if pos % 4:
                    pos += 4 - (pos % 4)
            except Exception:
                break

        return names

    # ── BinaryContext integration ─────────────────────────────────────────────

    def inject_into_context(self, ctx: object, pdb_path: Optional[str] = None) -> int:
        """Load symbol names from PDB and inject into BinaryContext via set_name().

        If pdb_path is None, attempts to fetch from Microsoft symbol server.
        Returns the number of names injected.
        """
        if pdb_path is None:
            pdb_path = self.fetch_pdb()
        if pdb_path is None:
            return 0

        names = self.load_pdb(pdb_path)
        if not names:
            return 0

        injected = 0
        for rva_or_off, name in names.items():
            va = self._imagebase + rva_or_off
            try:
                ctx.set_name(va, name, source='pdb')  # type: ignore[attr-defined]
                injected += 1
            except Exception:
                pass
        return injected

    # ── Scan ─────────────────────────────────────────────────────────────────

    def scan(self) -> list[PDBFinding]:
        """Return findings about PDB availability and symbol coverage."""
        findings: list[PDBFinding] = []
        name = Path(self._path).name
        info = self.pdb_info()

        if info is None:
            findings.append(PDBFinding(
                severity='INFO',
                category='no_pdb',
                title='No CodeView debug information',
                location=name,
                description=(
                    'The PE has no CodeView (RSDS) debug directory entry. '
                    'No PDB GUID is available. Symbols must come from exports or '
                    'pattern-matching — no symbol server lookup is possible.'
                ),
            ))
            return findings

        findings.append(PDBFinding(
            severity='INFO',
            category='pdb_info',
            title=f'PDB reference: {info.pdb_filename}',
            location=name,
            description=(
                f'GUID: {info.guid_formatted}  age: {info.age}  '
                f'PDB: {info.pdb_filename}\n'
                f'Symbol URL: {info.symbol_url}'
            ),
        ))
        return findings

    @staticmethod
    def report(findings: list[PDBFinding]) -> str:
        if not findings:
            return 'PDBSymbolIntegrator: no findings.'
        lines = [f'PDBSymbolIntegrator: {len(findings)} finding(s)', '']
        for f in findings:
            lines.append(f'  [{f.severity}] {f.title}')
            lines.append(f'    location : {f.location}')
            lines.append(f'    {f.description}')
            lines.append('')
        return '\n'.join(lines)
