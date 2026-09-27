"""
video_container.py: Video container forensics analyzer.

Parses MP4/MOV (ISOBMFF), MKV/WebM (EBML), and AVI (RIFF) containers to detect:
  - Appended/prepended non-video payloads (polyglot files)
  - Embedded binary content inside metadata atoms or EBML elements
  - Anomalous box sizes and malformed structures
  - DRM-encrypted tracks (pssh, encv, enca atoms)
  - Oversized or suspicious metadata containers (udta, free, skip, uuid)
  - Unknown or vendor-private atom types with non-ASCII type bytes
  - Entropy anomalies in non-compressed regions

Primary use cases:
  1. Forensic triage of video files received from untrusted sources
  2. Pre-analysis before feeding an extracted payload to binary RE modules
  3. DRM component fingerprinting (identifies Widevine/PlayReady/FairPlay pssh)
  4. Detection of video-as-dropper delivery techniques

Usage:
    analyzer = VideoContainerAnalyzer.from_path('/path/to/file.mp4')
    findings = analyzer.scan()
    print(analyzer.report(findings))

    # Polyglot check only:
    findings = analyzer.scan()
    embedded = [f for f in findings if f.category == 'POLYGLOT']
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Container magic — longest-match first
# ---------------------------------------------------------------------------
_CONTAINER_MAGIC: list[tuple[bytes, int, str]] = [
    # (magic_bytes, check_offset, format_name)
    (b'\x1a\x45\xdf\xa3',       0,   'MKV/EBML'),    # EBML header ID
    (b'RIFF',                    0,   'RIFF'),         # AVI, WAV — check form type next
    (b'ftyp',                    4,   'MP4/MOV'),      # ISO BMFF ftyp box at bytes 4-8
    (b'wide',                    4,   'MP4/MOV'),      # QuickTime pre-mdat spacer
    (b'mdat',                    4,   'MP4/MOV'),      # mdat before ftyp (some encoders)
    (b'moov',                    4,   'MP4/MOV'),      # moov-first MP4
    (b'\x00\x00\x00\x08ftyp',   0,   'MP4/MOV'),      # 8-byte ftyp at offset 0
    (b'\x00\x00\x00\x14ftyp',   0,   'MP4/MOV'),
    (b'\x00\x00\x00\x18ftyp',   0,   'MP4/MOV'),
    (b'\x00\x00\x00\x1cftyp',   0,   'MP4/MOV'),
    (b'\x00\x00\x00 ftyp',      0,   'MP4/MOV'),
    (b'\x1f\x43\xb6\x75',       0,   'MKV'),          # Segment element
]

# Known-good MP4/ISOBMFF atom type codes (4 ASCII bytes)
_KNOWN_MP4_ATOMS: frozenset[bytes] = frozenset([
    b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide', b'pnot', b'udta',
    b'uuid', b'moof', b'mfra', b'trak', b'tkhd', b'mdia', b'mdhd', b'hdlr',
    b'minf', b'vmhd', b'smhd', b'hmhd', b'nmhd', b'dinf', b'dref', b'url ',
    b'urn ', b'stbl', b'stsd', b'stts', b'stsc', b'stsz', b'stz2', b'stco',
    b'co64', b'ctts', b'stss', b'sdtp', b'sbgp', b'sgpd', b'mvhd', b'iods',
    b'mvex', b'trex', b'mehd', b'mfhd', b'traf', b'tfhd', b'tfdt', b'trun',
    b'sidx', b'ssix', b'prft', b'emsg', b'meta', b'ilst', b'data', b'mean',
    b'name', b'covr', b'cprt', b'gnre', b'titl', b'dscp', b'rtng', b'albm',
    b'avcC', b'hvcC', b'av1C', b'vpcC', b'dvcC', b'dvvC', b'btrt', b'pasp',
    b'clap', b'colr', b'fiel', b'gama', b'esds', b'mp4a', b'avc1', b'avc2',
    b'avc3', b'avc4', b'hev1', b'hvc1', b'av01', b'vp08', b'vp09', b'dvh1',
    b'dvhe', b'mp4v', b's263', b'h263', b'tx3g', b'c608', b'c708', b'wvtt',
    b'stpp', b'ftab', b'mett', b'metx', b'uri ', b'urim', b'camm', b'tmcd',
    b'edts', b'elst', b'load', b'iref', b'dimg', b'thmb', b'cdsc', b'iloc',
    b'iinf', b'infe', b'iprp', b'ipco', b'ipma', b'ispe', b'pixi', b'av1c',
    b'imir', b'irot', b'lsel', b'a1lx', b'a1op', b'clli', b'mdcv', b'padb',
    b'mero', b'schi', b'schm', b'sinf', b'tenc', b'pssh', b'encv', b'enca',
    b'encs', b'enct', b'frma', b'saiz', b'saio', b'senc', b'sgpd', b'sbgp',
    b'prdi', b'mskh', b'rtp ', b'hnti', b'sdp ', b'hinf', b'trpy', b'nump',
    b'totl', b'npck', b'tpyl', b'tpay', b'maxr', b'dmed', b'dimm', b'drep',
    b'tmin', b'tmax', b'pmax', b'dmax', b'payt', b'name', b'subs',
])

# Atoms that legitimately hold large opaque blobs (expected to be skipped by parsers)
_OPAQUE_ATOMS: frozenset[bytes] = frozenset([b'mdat', b'free', b'skip', b'wide'])

# DRM-indicating atom types
_DRM_ATOMS: frozenset[bytes] = frozenset([
    b'pssh',   # Protection System Specific Header (CENC/DASH)
    b'encv',   # Encrypted video track
    b'enca',   # Encrypted audio track
    b'encs',   # Encrypted system track
    b'enct',   # Encrypted text track
    b'sinf',   # Scheme Information Box
    b'schm',   # Scheme Type Box
    b'tenc',   # Track Encryption Box
    b'schi',   # Scheme Information Container
])

# Known DRM system UUIDs (inside pssh boxes)
_DRM_SYSTEMS: dict[bytes, str] = {
    bytes.fromhex('edef8ba979d64acea3c827dcd51d21ed'): 'Widevine (Google)',
    bytes.fromhex('9a04f07998404286ab92e65be0885f95'): 'PlayReady (Microsoft)',
    bytes.fromhex('94ce86fb07ff4f43adb893d2fa968ca2'): 'FairPlay (Apple)',
    bytes.fromhex('f239e769efa348509c16a903c6932efb'): 'Adobe Primetime',
    bytes.fromhex('adb41c242dbf4a6da0d2c7007ef36748'): 'Nagra',
    bytes.fromhex('1077efec4d0602acea3c7a394b5d5b7b'): 'W3C Common PSSH',
}

# Binary magic bytes to scan for inside atoms/elements
# (magic, min_offset, name, severity)
_EMBEDDED_MAGIC: list[tuple[bytes, str, str]] = [
    (b'\x7fELF',              'ELF binary',            'CRITICAL'),
    (b'MZ',                   'PE/COFF executable',    'CRITICAL'),
    (b'PK\x03\x04',          'ZIP archive',            'HIGH'),
    (b'PK\x05\x06',          'ZIP empty archive',      'HIGH'),
    (b'Rar!\x1a\x07',        'RAR archive',            'HIGH'),
    (b'\xfd7zXZ\x00',        'XZ compressed',          'HIGH'),
    (b'\x1f\x8b',            'gzip compressed',        'HIGH'),
    (b'\x28\xb5\x2f\xfd',   'Zstandard compressed',   'HIGH'),
    (b'\x04\x22\x4d\x18',   'LZ4 frame',              'HIGH'),
    (b'7z\xbc\xaf\x27\x1c', '7-Zip archive',          'HIGH'),
    (b'BZh',                 'bzip2 compressed',       'MEDIUM'),
    (b'%PDF',                'PDF document',           'MEDIUM'),
    (b'SQLite format 3\x00', 'SQLite database',        'MEDIUM'),
    (b'\xca\xfe\xba\xbe',   'Mach-O fat binary',      'CRITICAL'),
    (b'\xce\xfa\xed\xfe',   'Mach-O 32-bit',          'CRITICAL'),
    (b'\xcf\xfa\xed\xfe',   'Mach-O 64-bit',          'CRITICAL'),
    (b'ANDROID!',            'Android boot image',     'HIGH'),
    (b'\x27\x05\x19\x56',   'U-Boot image',           'HIGH'),
    (b'\x1a\x45\xdf\xa3',   'Nested MKV/EBML',        'MEDIUM'),
    (b'RIFF',                'Nested RIFF container',  'MEDIUM'),
    (b'OggS',                'Ogg bitstream',          'LOW'),
    (b'\x89PNG\r\n\x1a\n',  'PNG image',              'LOW'),
    (b'\xff\xd8\xff',        'JPEG image',             'LOW'),
    (b'GIF87a',              'GIF image',              'LOW'),
    (b'GIF89a',              'GIF image',              'LOW'),
    (b'\x49\x49\x2a\x00',   'TIFF (LE)',              'LOW'),
    (b'\x4d\x4d\x00\x2a',   'TIFF (BE)',              'LOW'),
    (b'\x52\x61\x72\x21',   'RAR archive v1.5',       'HIGH'),
]

# Minimum atom data size threshold to run embedded magic scan (avoid false positives in tiny atoms)
_MIN_ATOM_SCAN_SIZE = 8

# Entropy thresholds
_ENTROPY_ENCRYPTED_THRESHOLD = 7.2   # above: likely encrypted or compressed
_ENTROPY_WINDOW_SIZE          = 4096
_ENTROPY_HIGH_FRACTION        = 0.60  # fraction of windows that must be high-entropy to flag

# MKV/EBML element IDs of interest
_EBML_HEADER_ID      = 0x1A45DFA3
_EBML_SEGMENT_ID     = 0x18538067
_EBML_TRACKS_ID      = 0x1654AE6B
_EBML_TRACK_ENTRY    = 0xAE
_EBML_TRACK_TYPE     = 0x83
_EBML_CODEC_ID       = 0x86
_EBML_CONTENT_ENC    = 0x6D80
_EBML_VOID_ID        = 0xEC
_EBML_CRC32_ID       = 0xBF
_EBML_CLUSTER_ID     = 0x1F43B675


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class VideoFinding:
    offset: int
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    category: str          # POLYGLOT | EMBEDDED_BINARY | ANOMALOUS_STRUCTURE |
                           # DRM | METADATA_ANOMALY | UNKNOWN_TYPE | ENTROPY_ANOMALY
    description: str
    detail: str = ""

    def fmt(self) -> str:
        sev_pad = self.severity.ljust(8)
        cat_pad = self.category.ljust(22)
        loc = f"0x{self.offset:08x}"
        line = f"  [{sev_pad}] {cat_pad} @ {loc}  {self.description}"
        if self.detail:
            line += f"\n              {self.detail}"
        return line


@dataclass
class _MP4Atom:
    offset: int
    size: int          # declared size in bytes (includes 8-byte header)
    atom_type: bytes   # 4-byte type tag
    data_offset: int   # offset of payload start
    data_size: int     # payload size (size - 8, or size - 16 for extended)
    extended: bool     # True if 64-bit extended size was used


@dataclass
class _EBMLElement:
    offset: int
    element_id: int
    data_offset: int
    data_size: int     # -1 = unknown/streaming size


# ---------------------------------------------------------------------------
# Shannon entropy (no external deps)
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def _high_entropy_fraction(data: bytes, window: int = _ENTROPY_WINDOW_SIZE) -> float:
    """Return fraction of sliding windows with entropy >= threshold."""
    if len(data) < window:
        return 1.0 if _shannon_entropy(data) >= _ENTROPY_ENCRYPTED_THRESHOLD else 0.0
    high = 0
    total = 0
    for i in range(0, len(data) - window + 1, window // 2):
        chunk = data[i:i + window]
        if _shannon_entropy(chunk) >= _ENTROPY_ENCRYPTED_THRESHOLD:
            high += 1
        total += 1
    return high / total if total else 0.0


# ---------------------------------------------------------------------------
# Container format detection
# ---------------------------------------------------------------------------

def detect_container_format(data: bytes) -> str:
    """Return 'MP4/MOV', 'MKV', 'WEBM', 'AVI', or 'UNKNOWN'."""
    if len(data) < 12:
        return 'UNKNOWN'

    # EBML/MKV/WebM
    if data[:4] == b'\x1a\x45\xdf\xa3':
        # WebM uses DocType 'webm'; MKV uses 'matroska'
        doctype_window = data[4:min(64, len(data))]
        if b'webm' in doctype_window:
            return 'WEBM'
        return 'MKV'

    # RIFF family
    if data[:4] == b'RIFF' and len(data) >= 12:
        form = data[8:12]
        if form == b'AVI ':
            return 'AVI'
        if form == b'WAVE':
            return 'WAVE'
        return 'RIFF'

    # ISO BMFF: walk first 32 bytes looking for a valid atom with type 'ftyp'
    # Box header: uint32 size, 4-char type.  First box is almost always ftyp.
    if len(data) >= 8:
        first_size = struct.unpack_from('>I', data, 0)[0]
        first_type = data[4:8]
        if first_type in (b'ftyp', b'moov', b'mdat', b'wide', b'free', b'skip'):
            return 'MP4/MOV'
        # Extended size box (size == 1 means 64-bit size follows)
        if first_size == 1 and len(data) >= 16:
            if data[4:8] in _KNOWN_MP4_ATOMS:
                return 'MP4/MOV'

    return 'UNKNOWN'


# ---------------------------------------------------------------------------
# MP4 / ISOBMFF parser
# ---------------------------------------------------------------------------

def _walk_mp4_atoms(data: bytes, offset: int, end: int,
                    depth: int = 0, max_depth: int = 8) -> list[_MP4Atom]:
    """Walk ISOBMFF atom tree within data[offset:end], return flat list."""
    atoms: list[_MP4Atom] = []
    if depth > max_depth:
        return atoms

    while offset < end:
        if offset + 8 > end:
            break

        raw_size = struct.unpack_from('>I', data, offset)[0]
        atom_type = data[offset + 4: offset + 8]

        if raw_size == 1:
            # Extended 64-bit size
            if offset + 16 > end:
                break
            ext_size = struct.unpack_from('>Q', data, offset + 8)[0]
            header_len = 16
            size = ext_size
            extended = True
        elif raw_size == 0:
            # Atom extends to end of container
            size = end - offset
            header_len = 8
            extended = False
        else:
            size = raw_size
            header_len = 8
            extended = False

        if size < header_len or offset + size > len(data) + 1:
            # Malformed size — record partial atom and stop this level
            atoms.append(_MP4Atom(
                offset=offset,
                size=size,
                atom_type=atom_type,
                data_offset=offset + header_len,
                data_size=max(0, min(size - header_len, end - offset - header_len)),
                extended=extended,
            ))
            break

        data_offset = offset + header_len
        data_size = size - header_len

        atom = _MP4Atom(
            offset=offset,
            size=size,
            atom_type=atom_type,
            data_offset=data_offset,
            data_size=data_size,
            extended=extended,
        )
        atoms.append(atom)

        # Recurse into container atoms (not into large mdat — too expensive)
        _CONTAINER_ATOMS = frozenset([
            b'moov', b'trak', b'mdia', b'minf', b'dinf', b'stbl', b'edts',
            b'udta', b'meta', b'ilst', b'moof', b'traf', b'mvex', b'mfra',
            b'sinf', b'schi', b'iref', b'iprp', b'ipco',
        ])
        if atom_type in _CONTAINER_ATOMS and data_size > 0 and data_size < 8 * 1024 * 1024:
            sub = _walk_mp4_atoms(data, data_offset, data_offset + data_size, depth + 1, max_depth)
            atoms.extend(sub)

        offset += size

    return atoms


def _scan_for_embedded_magic(data: bytes, base_offset: int,
                              context: str) -> list[VideoFinding]:
    """Scan a blob for known binary magic bytes; return findings."""
    findings: list[VideoFinding] = []
    if len(data) < _MIN_ATOM_SCAN_SIZE:
        return findings

    for magic, label, severity in _EMBEDDED_MAGIC:
        pos = 0
        while True:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            # Skip hits at offset 0 when context is the whole file (already detected)
            abs_offset = base_offset + idx
            findings.append(VideoFinding(
                offset=abs_offset,
                severity=severity,
                category='EMBEDDED_BINARY',
                description=f'{label} magic found inside {context}',
                detail=f'magic={magic.hex()} at file offset 0x{abs_offset:x}',
            ))
            pos = idx + len(magic)
            # One hit per magic type per blob to avoid noise
            break

    return findings


# ---------------------------------------------------------------------------
# MKV / WebM EBML parser
# ---------------------------------------------------------------------------

def _read_vint(data: bytes, offset: int) -> tuple[int, int]:
    """
    Decode EBML variable-length integer.
    Returns (value, bytes_consumed).  Returns (-1, 0) on error.
    """
    if offset >= len(data):
        return -1, 0
    b0 = data[offset]
    if b0 == 0:
        return -1, 0

    # Width determined by leading zero bits
    width = 1
    mask = 0x80
    while not (b0 & mask):
        width += 1
        mask >>= 1
        if width > 8:
            return -1, 0

    if offset + width > len(data):
        return -1, 0

    # Strip the leading 1 bit
    value = b0 & (mask - 1)
    for i in range(1, width):
        value = (value << 8) | data[offset + i]

    return value, width


def _read_element_id(data: bytes, offset: int) -> tuple[int, int]:
    """Read EBML element ID (VINT but keep the leading 1 bit)."""
    if offset >= len(data):
        return -1, 0
    b0 = data[offset]
    if b0 == 0:
        return -1, 0
    width = 1
    mask = 0x80
    while not (b0 & mask):
        width += 1
        mask >>= 1
        if width > 4:
            return -1, 0
    if offset + width > len(data):
        return -1, 0
    value = b0
    for i in range(1, width):
        value = (value << 8) | data[offset + i]
    return value, width


def _walk_ebml_elements(data: bytes, offset: int, end: int,
                        depth: int = 0, max_depth: int = 6) -> list[_EBMLElement]:
    """Walk EBML element tree, return flat list (no recursive descent into clusters)."""
    elements: list[_EBMLElement] = []
    if depth > max_depth:
        return elements

    while offset < end:
        eid, id_len = _read_element_id(data, offset)
        if eid == -1 or id_len == 0:
            break

        size_offset = offset + id_len
        if size_offset >= end:
            break

        esize, size_len = _read_vint(data, size_offset)
        if size_len == 0:
            break

        # Unknown size (all 1-bits) means streaming / end-of-stream
        unknown_size = all(data[size_offset + i] == 0xFF for i in range(size_len))
        data_offset = size_offset + size_len

        if unknown_size:
            esize = end - data_offset

        elem = _EBMLElement(
            offset=offset,
            element_id=eid,
            data_offset=data_offset,
            data_size=esize,
        )
        elements.append(elem)

        # Recurse into master elements (not into clusters or block groups — too large)
        _MASTER_IDS = frozenset([
            _EBML_HEADER_ID, _EBML_SEGMENT_ID, _EBML_TRACKS_ID,
            0x1549A966,  # Info
            0x1C53BB6B,  # Cues
            0x1941A469,  # Attachments
            0x1043A770,  # Chapters
            0x1254C367,  # Tags
            _EBML_TRACK_ENTRY,
            0x6D80,      # ContentEncodings
            0x6240,      # ContentEncoding
        ])
        if eid in _MASTER_IDS and esize > 0 and esize < 4 * 1024 * 1024:
            sub_end = min(data_offset + esize, end)
            sub = _walk_ebml_elements(data, data_offset, sub_end, depth + 1, max_depth)
            elements.extend(sub)

        next_offset = data_offset + esize
        if next_offset <= offset:
            break
        offset = next_offset

    return elements


# ---------------------------------------------------------------------------
# AVI / RIFF parser
# ---------------------------------------------------------------------------

@dataclass
class _RIFFChunk:
    offset: int
    fourcc: bytes
    size: int          # declared payload size
    data_offset: int
    form_type: bytes   # b'' for non-LIST/RIFF, else the form type


def _walk_riff_chunks(data: bytes, offset: int, end: int,
                      depth: int = 0, max_depth: int = 6) -> list[_RIFFChunk]:
    chunks: list[_RIFFChunk] = []
    if depth > max_depth:
        return chunks

    while offset + 8 <= end:
        fourcc = data[offset:offset + 4]
        size = struct.unpack_from('<I', data, offset + 4)[0]
        data_offset = offset + 8
        form_type = b''

        is_list = fourcc in (b'RIFF', b'LIST')
        if is_list and data_offset + 4 <= end:
            form_type = data[data_offset:data_offset + 4]

        chunk = _RIFFChunk(
            offset=offset,
            fourcc=fourcc,
            size=size,
            data_offset=data_offset,
            form_type=form_type,
        )
        chunks.append(chunk)

        if is_list and size >= 4:
            sub_start = data_offset + 4
            sub_end = min(data_offset + size, end)
            if sub_end > sub_start:
                sub = _walk_riff_chunks(data, sub_start, sub_end, depth + 1, max_depth)
                chunks.extend(sub)

        # RIFF chunk sizes are padded to even bytes
        next_offset = data_offset + size + (size & 1)
        if next_offset <= offset:
            break
        offset = next_offset

    return chunks


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class VideoContainerAnalyzer:
    """
    Forensic analyzer for video container files.

    Construction:
        analyzer = VideoContainerAnalyzer.from_path('/path/to/file.mp4')

    Scanning:
        findings = analyzer.scan()   # list[VideoFinding], severity-sorted
        print(analyzer.report(findings))

    Categories returned:
        POLYGLOT          — data outside declared container boundaries
        EMBEDDED_BINARY   — known binary magic inside an atom/element/chunk
        ANOMALOUS_STRUCTURE — malformed sizes, impossible offsets
        DRM               — encrypted track or protection metadata detected
        METADATA_ANOMALY  — oversized or suspicious metadata container
        UNKNOWN_TYPE      — non-printable or unrecognized atom type
        ENTROPY_ANOMALY   — unexpected high-entropy region (possible encryption)
    """

    def __init__(self, path: Path, data: bytes, fmt: str):
        self.path = path
        self._data = data
        self.fmt = fmt

    @classmethod
    def from_path(cls, path: str | Path) -> 'VideoContainerAnalyzer':
        p = Path(path)
        data = p.read_bytes()
        fmt = detect_container_format(data)
        return cls(path=p, data=data, fmt=fmt)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> list[VideoFinding]:
        """Run all detectors. Returns findings sorted CRITICAL→LOW."""
        findings: list[VideoFinding] = []

        findings.extend(self._check_polyglot())

        if self.fmt in ('MP4/MOV',):
            findings.extend(self._analyze_mp4())
        elif self.fmt in ('MKV', 'WEBM'):
            findings.extend(self._analyze_mkv())
        elif self.fmt in ('AVI', 'RIFF'):
            findings.extend(self._analyze_avi())
        else:
            # Unknown format — run generic embedded magic scan on whole file
            findings.extend(
                _scan_for_embedded_magic(self._data, 0, 'unknown container body')
            )

        _SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
        return findings

    def report(self, findings: list[VideoFinding]) -> str:
        lines = [
            f"VideoContainerAnalyzer: {self.path.name}",
            f"  Format : {self.fmt}",
            f"  Size   : {len(self._data):,} bytes",
            f"  Findings: {len(findings)}",
            "",
        ]
        if not findings:
            lines.append("  No anomalies detected.")
        else:
            for f in findings:
                lines.append(f.fmt())
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Polyglot / boundary detection
    # ------------------------------------------------------------------

    def _check_polyglot(self) -> list[VideoFinding]:
        findings: list[VideoFinding] = []
        data = self._data

        # Prepended payload: check if file starts with non-container magic
        if self.fmt != 'UNKNOWN':
            # First valid atom/element should be at offset 0 for MP4,
            # or first bytes should be EBML for MKV, RIFF for AVI
            if self.fmt == 'MP4/MOV':
                raw_size = struct.unpack_from('>I', data, 0)[0] if len(data) >= 4 else 0
                first_type = data[4:8] if len(data) >= 8 else b''
                # If very first bytes are a known non-video executable
                for magic, label, sev in _EMBEDDED_MAGIC[:8]:  # only executable types
                    if data[:len(magic)] == magic:
                        findings.append(VideoFinding(
                            offset=0,
                            severity='CRITICAL',
                            category='POLYGLOT',
                            description=f'File begins with {label} magic before MP4 container',
                            detail=f'magic={magic.hex()}',
                        ))

        # Appended payload: find declared container end, check for trailing data
        container_end = self._declared_container_end()
        if container_end is not None and container_end < len(data):
            trailer = data[container_end:]
            trailer_len = len(trailer)
            # Check trailer for known magic
            trailer_findings = _scan_for_embedded_magic(trailer, container_end, 'trailer (past container end)')
            if trailer_findings:
                # Upgrade severity — any executable format in trailer is CRITICAL
                _EXEC_LABELS = ('ELF binary', 'PE/COFF executable', 'Mach-O')
                for tf in trailer_findings:
                    if any(lbl in tf.description for lbl in _EXEC_LABELS):
                        tf.severity = 'CRITICAL'
                findings.extend(trailer_findings)
            elif trailer_len > 16:
                findings.append(VideoFinding(
                    offset=container_end,
                    severity='MEDIUM',
                    category='POLYGLOT',
                    description=f'{trailer_len:,} bytes of unrecognized data appended past container end',
                    detail=f'container_end=0x{container_end:x} file_size=0x{len(data):x}',
                ))

        return findings

    def _declared_container_end(self) -> int | None:
        """Return the byte offset where the declared container ends, or None if indeterminate."""
        data = self._data
        file_len = len(data)
        if self.fmt == 'MP4/MOV':
            # Walk top-level atoms; stop at first malformed entry
            offset = 0
            last_good = 0
            while offset + 8 <= file_len:
                raw_size = struct.unpack_from('>I', data, offset)[0]
                if raw_size == 1:
                    if offset + 16 > file_len:
                        return last_good if last_good else None
                    size = struct.unpack_from('>Q', data, offset + 8)[0]
                elif raw_size == 0:
                    return file_len  # last atom fills file
                else:
                    size = raw_size
                if size < 8 or offset + size > file_len + 8:
                    # Malformed atom — declared end is just before this broken atom
                    return offset
                last_good = offset + size
                offset = last_good
            return offset
        elif self.fmt in ('MKV', 'WEBM'):
            # EBML: Segment element size declares container length
            eid, id_len = _read_element_id(data, 0)
            if eid == _EBML_HEADER_ID and id_len > 0:
                size_off = id_len
                esize, size_len = _read_vint(data, size_off)
                if size_len > 0 and esize > 0:
                    return size_off + size_len + esize
            return None
        elif self.fmt in ('AVI', 'RIFF'):
            if len(data) >= 8:
                size = struct.unpack_from('<I', data, 4)[0]
                return 8 + size
            return None
        return None

    # ------------------------------------------------------------------
    # MP4 / ISOBMFF analysis
    # ------------------------------------------------------------------

    def _analyze_mp4(self) -> list[VideoFinding]:
        findings: list[VideoFinding] = []
        data = self._data
        atoms = _walk_mp4_atoms(data, 0, len(data))

        _LARGE_METADATA_THRESHOLD = 1 * 1024 * 1024  # 1 MB in non-mdat atom

        seen_types: dict[bytes, int] = {}
        for atom in atoms:
            atype = atom.atom_type
            seen_types[atype] = seen_types.get(atype, 0) + 1

            # --- Unknown / non-printable atom type ---
            if atype not in _KNOWN_MP4_ATOMS:
                printable = all(0x20 <= b < 0x7F for b in atype)
                if not printable:
                    findings.append(VideoFinding(
                        offset=atom.offset,
                        severity='HIGH',
                        category='UNKNOWN_TYPE',
                        description=f'Non-printable atom type bytes: {atype.hex()}',
                        detail=f'size={atom.size} data_size={atom.data_size}',
                    ))
                else:
                    findings.append(VideoFinding(
                        offset=atom.offset,
                        severity='LOW',
                        category='UNKNOWN_TYPE',
                        description=f'Unrecognized atom type: {atype.decode("ascii", errors="replace")!r}',
                        detail=f'size={atom.size}',
                    ))

            # --- DRM detection ---
            if atype in _DRM_ATOMS:
                detail = f'atom={atype.decode("ascii", errors="replace")!r} size={atom.size}'
                if atype == b'pssh' and atom.data_size >= 20:
                    # pssh: version(1) flags(3) system_id(16) data_size(4) data
                    sys_id = data[atom.data_offset + 4: atom.data_offset + 20]
                    drm_name = _DRM_SYSTEMS.get(sys_id, 'unknown system')
                    detail += f' system={drm_name} uuid={sys_id.hex()}'
                findings.append(VideoFinding(
                    offset=atom.offset,
                    severity='MEDIUM',
                    category='DRM',
                    description=f'DRM atom: {atype.decode("ascii", errors="replace")!r}',
                    detail=detail,
                ))

            # --- Malformed / impossible size ---
            if atom.size > 0 and atom.offset + atom.size > len(data) + 8:
                findings.append(VideoFinding(
                    offset=atom.offset,
                    severity='HIGH',
                    category='ANOMALOUS_STRUCTURE',
                    description=f'Atom size {atom.size} extends beyond file boundary',
                    detail=f'type={atype.decode("ascii", errors="replace")!r} '
                           f'end=0x{atom.offset + atom.size:x} file=0x{len(data):x}',
                ))

            # --- Oversized metadata containers ---
            _METADATA_ATOMS = frozenset([b'udta', b'free', b'skip', b'uuid', b'meta'])
            if atype in _METADATA_ATOMS and atom.data_size > _LARGE_METADATA_THRESHOLD:
                findings.append(VideoFinding(
                    offset=atom.offset,
                    severity='MEDIUM',
                    category='METADATA_ANOMALY',
                    description=f'Oversized metadata atom: {atype.decode("ascii", errors="replace")!r} '
                                f'({atom.data_size:,} bytes)',
                    detail=f'threshold={_LARGE_METADATA_THRESHOLD:,}',
                ))

            # --- Embedded binary scan in metadata / unknown atoms ---
            scan_types = _METADATA_ATOMS | {b'uuid'}
            if atype not in _KNOWN_MP4_ATOMS or atype in scan_types:
                if atom.data_size >= _MIN_ATOM_SCAN_SIZE:
                    blob = data[atom.data_offset: atom.data_offset + atom.data_size]
                    label = atype.decode('ascii', errors='replace')
                    findings.extend(
                        _scan_for_embedded_magic(blob, atom.data_offset, f'{label!r} atom payload')
                    )

            # --- Entropy anomaly in non-video atoms ---
            _NON_VIDEO_ATOMS = frozenset([b'udta', b'free', b'skip', b'uuid', b'meta', b'ilst'])
            if atype in _NON_VIDEO_ATOMS and atom.data_size >= _ENTROPY_WINDOW_SIZE:
                blob = data[atom.data_offset: atom.data_offset + min(atom.data_size, 256 * 1024)]
                frac = _high_entropy_fraction(blob)
                if frac >= _ENTROPY_HIGH_FRACTION:
                    findings.append(VideoFinding(
                        offset=atom.data_offset,
                        severity='HIGH',
                        category='ENTROPY_ANOMALY',
                        description=f'{atype.decode("ascii", errors="replace")!r} atom has '
                                    f'{frac * 100:.0f}% high-entropy windows (possible encrypted payload)',
                        detail=f'data_size={atom.data_size:,} sample={min(atom.data_size, 256*1024):,}',
                    ))

        return findings

    # ------------------------------------------------------------------
    # MKV / WebM EBML analysis
    # ------------------------------------------------------------------

    def _analyze_mkv(self) -> list[VideoFinding]:
        findings: list[VideoFinding] = []
        data = self._data
        elements = _walk_ebml_elements(data, 0, len(data))

        _ATTACHMENT_ID    = 0x1941A469
        _ATTACHED_FILE_ID = 0x61A7
        _FILE_DATA_ID     = 0x465C
        _FILE_NAME_ID     = 0x466E
        _FILE_MIME_ID     = 0x4660

        drm_seen = False
        for elem in elements:
            # Content encryption → DRM
            if elem.element_id == 0x6D80:  # ContentEncodings
                if not drm_seen:
                    findings.append(VideoFinding(
                        offset=elem.offset,
                        severity='MEDIUM',
                        category='DRM',
                        description='MKV ContentEncodings element present (encrypted track)',
                        detail=f'element_id=0x{elem.element_id:x} data_size={elem.data_size}',
                    ))
                    drm_seen = True

            # Attachments section — scan file data for embedded binaries
            if elem.element_id == _FILE_DATA_ID and elem.data_size >= _MIN_ATOM_SCAN_SIZE:
                blob = data[elem.data_offset: elem.data_offset + elem.data_size]
                findings.extend(
                    _scan_for_embedded_magic(blob, elem.data_offset, 'MKV attachment FileData')
                )

            # Oversized Void elements (common data-hiding technique in MKV)
            if elem.element_id == _EBML_VOID_ID and elem.data_size > 64 * 1024:
                blob = data[elem.data_offset: elem.data_offset + min(elem.data_size, 256 * 1024)]
                frac = _high_entropy_fraction(blob)
                sev = 'HIGH' if frac >= _ENTROPY_HIGH_FRACTION else 'MEDIUM'
                findings.append(VideoFinding(
                    offset=elem.offset,
                    severity=sev,
                    category='METADATA_ANOMALY',
                    description=f'Oversized Void element: {elem.data_size:,} bytes '
                                f'({frac*100:.0f}% high-entropy)',
                    detail=f'element_id=0x{elem.element_id:x}',
                ))
                findings.extend(
                    _scan_for_embedded_magic(blob, elem.data_offset, 'MKV Void element')
                )

            # Unknown element ID (high bytes not matching known EBML IDs)
            # Heuristic: valid EBML IDs have well-known high nibbles
            if elem.element_id > 0xFFFF:
                known_high = (
                    (elem.element_id >> 24) in (0x1A, 0x18, 0x1F, 0x16, 0x11, 0x12,
                                                 0x13, 0x14, 0x15, 0x1B, 0x1C, 0x1D,
                                                 0x1E, 0x19)
                )
                if not known_high:
                    findings.append(VideoFinding(
                        offset=elem.offset,
                        severity='LOW',
                        category='UNKNOWN_TYPE',
                        description=f'Unrecognized EBML element ID: 0x{elem.element_id:x}',
                        detail=f'data_size={elem.data_size}',
                    ))

        return findings

    # ------------------------------------------------------------------
    # AVI / RIFF analysis
    # ------------------------------------------------------------------

    def _analyze_avi(self) -> list[VideoFinding]:
        findings: list[VideoFinding] = []
        data = self._data
        chunks = _walk_riff_chunks(data, 0, len(data))

        for chunk in chunks:
            # Anomalous size
            if chunk.data_offset + chunk.size > len(data) + 4:
                findings.append(VideoFinding(
                    offset=chunk.offset,
                    severity='HIGH',
                    category='ANOMALOUS_STRUCTURE',
                    description=f'RIFF chunk size {chunk.size} extends past file boundary',
                    detail=f'fourcc={chunk.fourcc!r} end=0x{chunk.data_offset + chunk.size:x} '
                           f'file=0x{len(data):x}',
                ))

            # Embedded binary scan in JUNK / IDIT / non-standard chunks
            _RIFF_METADATA_FOURCC = frozenset([b'JUNK', b'IDIT', b'ISFT', b'ICMT', b'ICOP',
                                               b'INAM', b'ISBJ', b'ISRC', b'IKEY', b'IGNR'])
            if chunk.fourcc in _RIFF_METADATA_FOURCC and chunk.size >= _MIN_ATOM_SCAN_SIZE:
                blob = data[chunk.data_offset: chunk.data_offset + chunk.size]
                label = chunk.fourcc.decode('ascii', errors='replace')
                findings.extend(
                    _scan_for_embedded_magic(blob, chunk.data_offset, f'RIFF {label!r} chunk')
                )

            # Oversized JUNK padding (common dropper technique)
            if chunk.fourcc == b'JUNK' and chunk.size > 64 * 1024:
                blob = data[chunk.data_offset: chunk.data_offset + min(chunk.size, 256 * 1024)]
                frac = _high_entropy_fraction(blob)
                findings.append(VideoFinding(
                    offset=chunk.offset,
                    severity='HIGH' if frac >= _ENTROPY_HIGH_FRACTION else 'MEDIUM',
                    category='METADATA_ANOMALY',
                    description=f'Oversized JUNK chunk: {chunk.size:,} bytes '
                                f'({frac*100:.0f}% high-entropy)',
                    detail='',
                ))

        return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _main() -> None:
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m ablation.analyzers.video_container <file> [file ...]")
        sys.exit(1)

    for path in sys.argv[1:]:
        analyzer = VideoContainerAnalyzer.from_path(path)
        findings = analyzer.scan()
        print(analyzer.report(findings))
        print()


if __name__ == '__main__':
    _main()
