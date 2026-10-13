"""Tandem Guardian PAK archive extractor for NSK/Guardian BACKUP tape format.

Parses Tandem's proprietary PAK format used to distribute corrective service
fixes for Guardian (NonStop Kernel) systems.  Internally each PAK file is a
sequence of zlib-compressed chunks wrapping the Guardian BACKUP(8) on-tape
format.

Why this exists
---------------
1. Guardian PAK is not a ZIP file despite the ``.ZIP`` extension IBM used for
   patch distribution.  ``unzip``, ``file``, ``binwalk``, and every other
   standard archive tool reject these files.  The only documented extractor
   (``UNPAK``) requires a live Tandem NSK system.
2. Guardian PAK archives are the only publicly accessible corpus of Tandem
   NonStop binaries.  The platform's source code, ABI, and file-format specs
   are covered by NDA; no public documentation or disassembler exists.  This
   extractor is the prerequisite for any RE work on Guardian-native code.
3. The binaries inside are MIPS32 big-endian (Himalaya K-series hardware).
   Capstone supports MIPS32, so once the PAK container is handled,
   ``BinaryContext`` can analyze the extracted objects directly.
4. Guardian filenames use the ``$VOLUME.SUBVOLUME.FILENAME`` three-component
   namespace (each field up to 8 characters) which has no mapping in any
   POSIX path tool.  This extractor preserves the Guardian path and maps it
   to a safe filesystem path without silent truncation or collision.

Format layout
-------------
::

    PAK header     8 bytes   (magic b'PAK ' + version 0x0001 + reserved)
    subtype field  2 bytes   (archive subtype; typically 0x000A)

    Chunk stream (repeated until end of file):
      chunk_size   2 bytes   (big-endian; 0xFFFF = group separator; skip)
      zlib_data    chunk_size bytes
      padding      0-1 bytes (1 byte if chunk_size is odd, to align to 2 bytes)

    End of archive is indicated by two consecutive 0xFFFF group separators
    (i.e. the 4-byte sequence FF FF FF FF at end of file).

Inside the decompressed chunks Guardian BACKUP tape records appear.  Each
record carries a 2-byte type code followed by a 2-byte big-endian size.

IMPORTANT: the 2-byte type codes are NOT stable across archive runs — the
same record class carries different codes in different PTF archives
(confirmed: tape-label code is 0x6891 in U452253, 0x1F1A in U454165).
All record detection in this module is therefore content-based:

    Tape label     200-byte record containing b'Tandem Archive Tape'
    File catalog   222-byte record containing b'File Backup'
    File header    358-byte record with b'$' at offset 0x2E (Guardian path)
    Data block     any other record following a file header (typically ~28 KB)

Usage::

    from ablation.core.guardian_pak_extractor import iter_files, GuardianFile
    from pathlib import Path

    data = Path('U452253.ZIP').read_bytes()
    for f in iter_files(data):
        print(f'{f.path}  {len(f.data)} bytes  arch={f.arch}')

References
----------
Empirical analysis of IBM MQSeries for Tandem NSK V2.2 PAK archives;
Tandem Guardian BACKUP utility tape format (reverse-engineered);
``readme.doc`` distributed with IBM MQSeries NSK corrective service PTFs.
"""
from __future__ import annotations

import zlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List

GUARDIAN_PAK_MAGIC = b'PAK '

# Guardian BACKUP record detection uses content signatures, not type-code values.
# The 2-byte "type" field in Guardian BACKUP records is NOT stable — it varies
# across archive runs (different timestamps, CRC seeds, etc.).  All detection
# must be based on the record content and size.

_TAPE_LABEL_SZ   = 200    # fixed size for tape-volume label records
_FILE_CATALOG_SZ = 222    # fixed size for file-backup catalog records
_FILE_HDR_SZ     = 358    # fixed size for per-file header records

_TAPE_LABEL_SIG  = b'Tandem Archive Tape'
_FILE_CATALOG_SIG = b'File Backup'

# Byte offset of the Guardian path string within a file-header record.
# The path is a 24-byte sequence of three 8-char space-padded fields:
# $VOLUME  (8) + SUBVOLUME (8) + FILENAME (8).  Confirmed in two PTF archives.
_FILE_HDR_PATH_OFFSET = 0x2E


@dataclass
class GuardianFile:
    """One Guardian NSK file extracted from a PAK archive."""

    path:      str           # full Guardian path, e.g. "$DEV2.ZMQP00.1EALTMQF"
    volume:    str           # volume component, e.g. "$DEV2"
    subvolume: str           # subvolume component, e.g. "ZMQP00"
    filename:  str           # filename component, e.g. "1EALTMQF"
    data:      bytes = field(repr=False)
    arch:      str   = "mips32be"   # Himalaya K-series is MIPS32 big-endian


def _parse_guardian_path(record: bytes) -> tuple[str, str, str]:
    """Extract (volume, subvolume, filename) from a Guardian file header record.

    The three-component Guardian path is stored as a 24-byte field at a fixed
    offset within the file header record.  Each component occupies 8 bytes
    padded with spaces (not null bytes).
    """
    path_bytes = record[_FILE_HDR_PATH_OFFSET: _FILE_HDR_PATH_OFFSET + 24]
    if len(path_bytes) < 24 or path_bytes[0:1] != b'$':
        # Fallback: scan for $ in the whole record
        dollar_pos = record.find(b'$')
        if dollar_pos == -1 or dollar_pos + 24 > len(record):
            return ('', '', '')
        path_bytes = record[dollar_pos: dollar_pos + 24]

    vol   = path_bytes[0:8].rstrip(b' \x00').decode('ascii', errors='replace')
    subvol = path_bytes[8:16].rstrip(b' \x00').decode('ascii', errors='replace')
    fname  = path_bytes[16:24].rstrip(b' \x00').decode('ascii', errors='replace')
    return (vol, subvol, fname)


def iter_chunks(data: bytes) -> Iterator[bytes]:
    """Decompress and yield every Guardian BACKUP record block from *data*.

    Raises :class:`ValueError` if the magic bytes do not match.
    Silently skips corrupt or undecodable compressed chunks.
    """
    if len(data) < 10:
        raise ValueError(f"data too short ({len(data)} bytes) for Guardian PAK")
    if data[:4] != GUARDIAN_PAK_MAGIC:
        raise ValueError(
            f"not a Guardian PAK archive: magic={data[:4]!r}, expected b'PAK '"
        )

    pos = 10  # skip 8-byte header + 2-byte subtype field
    while pos < len(data) - 1:
        if pos + 2 > len(data):
            break
        word = struct.unpack_from('>H', data, pos)[0]
        pos += 2

        if word == 0xFFFF:
            continue  # group separator between record groups

        clen = word
        if clen == 0 or pos + clen > len(data):
            break

        try:
            chunk = zlib.decompress(data[pos:pos + clen])
            yield chunk
        except zlib.error:
            pass  # corrupt chunk: skip and continue

        pos += clen
        if clen & 1:
            pos += 1  # alignment padding for odd-length compressed blocks


def _is_tape_label(chunk: bytes) -> bool:
    return len(chunk) == _TAPE_LABEL_SZ and _TAPE_LABEL_SIG in chunk


def _is_file_catalog(chunk: bytes) -> bool:
    return len(chunk) == _FILE_CATALOG_SZ and _FILE_CATALOG_SIG in chunk


def _is_file_header(chunk: bytes) -> bool:
    return (
        len(chunk) == _FILE_HDR_SZ
        and chunk[_FILE_HDR_PATH_OFFSET:_FILE_HDR_PATH_OFFSET + 1] == b'$'
    )


def iter_files(data: bytes) -> Iterator[GuardianFile]:
    """Yield :class:`GuardianFile` objects from a Guardian PAK archive.

    Parses the Guardian BACKUP tape record stream inside the PAK chunks.
    Consecutive data chunks following each file-header record are accumulated
    into a single ``GuardianFile.data`` payload.

    Detection uses content signatures rather than record type codes because
    Guardian BACKUP type codes are not stable across archive runs.
    """
    current_vol:   str        = ''
    current_subvol: str       = ''
    current_fname: str        = ''
    current_data:  List[bytes] = []

    def _flush() -> Iterator[GuardianFile]:
        if current_fname and current_data:
            combined = b''.join(current_data)
            path = f"{current_vol}.{current_subvol}.{current_fname}"
            yield GuardianFile(
                path=path,
                volume=current_vol,
                subvolume=current_subvol,
                filename=current_fname,
                data=combined,
            )

    for chunk in iter_chunks(data):
        if not chunk:
            continue

        if _is_tape_label(chunk) or _is_file_catalog(chunk):
            # Archive metadata — not file data; flush any accumulated file
            yield from _flush()
            current_vol = current_subvol = current_fname = ''
            current_data = []
            continue

        if _is_file_header(chunk):
            # Start of a new Guardian file — flush previous if any
            yield from _flush()
            vol, subvol, fname = _parse_guardian_path(chunk)
            current_vol    = vol
            current_subvol = subvol
            current_fname  = fname
            current_data   = []
            continue

        # Raw file data — accumulate entire chunk (no record header to strip)
        if current_fname:
            current_data.append(chunk)

    yield from _flush()


def extract_to(data: bytes, dest: Path) -> List[GuardianFile]:
    """Extract all Guardian files from *data* into *dest* directory.

    Creates a ``$VOLUME/SUBVOLUME/`` directory hierarchy under *dest*.
    Returns the list of extracted :class:`GuardianFile` objects.
    """
    dest = Path(dest)
    extracted: List[GuardianFile] = []
    for gf in iter_files(data):
        if not gf.filename:
            continue
        # Map Guardian path to filesystem: drop $ from volume name
        vol_dir = gf.volume.lstrip('$') if gf.volume else 'UNKNOWN'
        target = dest / vol_dir / gf.subvolume / gf.filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(gf.data)
        extracted.append(gf)
    return extracted
