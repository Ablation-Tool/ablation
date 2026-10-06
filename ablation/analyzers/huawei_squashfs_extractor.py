"""
HuaweiSquashfsExtractor — pure-Python squashfs v4 reader for Huawei VRP firmware.

Standard tools (unsquashfs, 7z) fail on Huawei V600R024+ squashfs images because some
XZ blocks carry the ARM64 BCJ filter (xz filter ID 0x0A). Python's lzma C extension,
when compiled against pre-5.4.0 liblzma headers, rejects these blocks as "Corrupt input
data" in FORMAT_XZ mode. This module bypasses the issue by extracting the raw LZMA2 payload
from each XZ block (skipping the filter chain in the XZ container) and decompressing with
FORMAT_RAW. Non-branch bytes are BCJ-invariant and byte-verify correctly.

Confirmed on: S6750-H V600R024C00SPC500 (sqfs_00_00001984.sqfs).

Key format notes:
  - squashfs_dir_entry.size is __le16 (8-byte header total), NOT __le8.
  - inode_ref = (block_byte_offset_from_table_start << 16) | within_decompressed_offset
  - Inode types: 1=DIR 2=REG 8=LDIR 9=LREG (from kernel squashfs_fs.h)
"""
from __future__ import annotations

import lzma
import struct
import threading
import warnings
from typing import Generator, List, Optional, Tuple


SQUASHFS_MAGIC   = 0x73717368
METADATA_MAX     = 8192
INODE_DIR        = 1
INODE_REG        = 2
INODE_LDIR       = 8
INODE_LREG       = 9

# Max decompressed size per block (4× block_size, capped at 8 MB).
# Prevents decompression-bomb DoS on adversarially crafted images.
_MAX_DECOMPRESS_BYTES = 8 << 20

# Max total size of a single extracted file. Prevents OOM on adversarially
# crafted squashfs images that declare a multi-GB file size.
_MAX_EXTRACT_BYTES = 512 << 20  # 512 MB


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _checked_read(f, n: int, context: str = "") -> bytes:
    """Read exactly n bytes; raise ValueError on short read or EOF."""
    data = f.read(n)
    if len(data) != n:
        where = f" ({context})" if context else ""
        raise ValueError(
            f"Short read at offset {f.tell()}: expected {n} bytes, "
            f"got {len(data)}{where}"
        )
    return data

def _decode_varint(data: bytes, off: int) -> Tuple[int, int]:
    """XZ/LZMA2 multi-byte integer: 7-bit LE groups, bit7=more."""
    result = 0
    shift  = 0
    while True:
        if off >= len(data):
            raise ValueError(
                f"Truncated XZ varint at byte offset {off} "
                f"(block length {len(data)})"
            )
        b      = data[off]; off += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, off


def _extract_lzma2_payload(block: bytes) -> Tuple[bytes, bool]:
    """
    Parse XZ stream + block headers; return (lzma2_compressed_bytes, has_arm64_bcj).

    XZ stream:  magic(6) flags(2) crc32(4) = 12 bytes
    XZ block:   bh_size_units(1) flags(1) [comp_sz] [uncomp_sz] filters... CRC32
                bh_size = (bh_size_units + 1) * 4

    Returns the raw LZMA2 payload and whether an ARM64 BCJ filter (ID 0x0A) is present.
    Caller decompresses with FORMAT_RAW + LZMA2; BCJ is dropped (branch targets modified
    in BCJ blocks, but all non-branch bytes are correct).
    """
    if len(block) < 14:
        raise ValueError(
            f"XZ block too short ({len(block)} bytes); minimum valid XZ block is 14 bytes"
        )
    # stream header at 0; block header at 12
    bh_pos    = 12
    bh_units  = block[bh_pos]
    bh_size   = (bh_units + 1) * 4
    bh_flags  = block[bh_pos + 1]
    nfilters  = (bh_flags & 0x03) + 1
    has_comp   = bool(bh_flags & 0x40)
    has_uncomp = bool(bh_flags & 0x80)
    p = bh_pos + 2
    comp_sz = None
    if has_comp:   comp_sz, p   = _decode_varint(block, p)
    if has_uncomp: _,        p  = _decode_varint(block, p)
    has_arm64_bcj = False
    for _ in range(nfilters):
        fid,   p = _decode_varint(block, p)
        fsize, p = _decode_varint(block, p)
        if fid == 0x0A:
            has_arm64_bcj = True
        p += fsize
    payload_start = bh_pos + bh_size
    if comp_sz is not None:
        payload_end = payload_start + comp_sz
    else:
        # No compressed-size field: payload ends before the 4-byte stream footer CRC
        # and 2-byte stream-flags + 2-byte index-size + 4-byte footer CRC = 12 bytes.
        # Use conservative 20-byte footer trim; validated below.
        payload_end = len(block) - 20
    if payload_end <= payload_start:
        raise ValueError(
            f"XZ block: payload_end {payload_end} <= payload_start {payload_start} "
            f"(block length {len(block)}, comp_sz={comp_sz})"
        )
    if payload_end > len(block):
        raise ValueError(
            f"XZ block: payload_end {payload_end} exceeds block length {len(block)}"
        )
    return block[payload_start:payload_end], has_arm64_bcj


def _decompress_xz_block(block: bytes, dict_size: int = 131072) -> bytes:
    """
    Decompress one squashfs data block. Each block is an independent XZ stream.
    Falls back to LZMA2-only FORMAT_RAW if FORMAT_XZ fails (ARM64 BCJ filter).
    dict_size should match the squashfs superblock block_size.
    Enforces _MAX_DECOMPRESS_BYTES limit to prevent decompression-bomb DoS.
    """
    max_out = min(max(dict_size * 4, 1 << 20), _MAX_DECOMPRESS_BYTES)
    try:
        dc  = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        out = dc.decompress(block, max_length=max_out)
        if not dc.eof:
            raise ValueError(
                f"Decompressed output exceeds {max_out} bytes limit"
            )
        return out
    except lzma.LZMAError as exc:
        # Retry as raw LZMA2 ONLY when an ARM64 BCJ filter (ID 0x0A) is present.
        # Any other LZMAError indicates genuine block corruption and must propagate.
        try:
            payload, has_bcj = _extract_lzma2_payload(block)
        except ValueError as parse_err:
            raise lzma.LZMAError(
                f"XZ decompress failed and block header is invalid ({parse_err}); "
                f"original error: {exc}"
            ) from exc
        if not has_bcj:
            raise lzma.LZMAError(
                f"XZ decompress failed with no ARM64 BCJ filter — block is likely "
                f"corrupt: {exc}"
            ) from exc
        # Known limitation: the ARM64 BCJ pre-filter modifies BL/B/BLR branch
        # instruction encodings to aid compression; dropping it means extracted
        # branch instructions differ from the on-disk originals.  Non-branch bytes
        # are BCJ-invariant and are correct.  XZ block-level CRC checksums are
        # also not verified on this path.
        warnings.warn(
            "ARM64 BCJ filter dropped on XZ decompression fallback: branch encodings "
            "in this block differ from originals; XZ block CRC not verified.",
            stacklevel=3,
        )
        dc  = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}],
        )
        out = dc.decompress(payload, max_length=max_out)
        if not dc.eof:
            raise ValueError(
                f"Decompressed LZMA2 output exceeds {max_out} bytes limit"
            )
        return out


# ---------------------------------------------------------------------------
# Fragment table
# ---------------------------------------------------------------------------

def _read_frag_entry(f, sb: dict, frag_idx: int) -> Tuple[int, int]:
    """
    Return (frag_start_block, frag_raw_size) for the given fragment index.

    Fragment table layout:
      sb["frag_tbl"] → array of 8-byte LE disk offsets to metadata blocks.
      Each metadata block holds up to (METADATA_MAX // 16) = 512 fragment entries.
      Each entry: start_block (Q, 8 bytes) + size (I, 4 bytes) + pad (I, 4 bytes).
      size bit31 = NOCOMPRESS flag; low 31 bits = compressed size.
    """
    entries_per_block = METADATA_MAX // 16  # 512
    blk_idx   = frag_idx // entries_per_block
    entry_off = (frag_idx  % entries_per_block) * 16

    # Read disk pointer to the metadata block that holds this entry
    f.seek(sb["frag_tbl"] + blk_idx * 8)
    meta_disk_off = struct.unpack("<Q", _checked_read(f, 8, "fragment table index"))[0]

    # Read and decompress the metadata block (absolute disk offset)
    f.seek(meta_disk_off)
    hdr  = struct.unpack("<H", _checked_read(f, 2, "fragment metadata header"))[0]
    size = hdr & 0x7FFF
    raw  = _checked_read(f, size, f"fragment metadata data (size={size})")
    meta = raw if (hdr & 0x8000) else _decompress_xz_block(raw, dict_size=METADATA_MAX)

    entry       = meta[entry_off : entry_off + 16]
    start_block = struct.unpack_from("<Q", entry, 0)[0]
    raw_size    = struct.unpack_from("<I", entry, 8)[0]
    return start_block, raw_size


# ---------------------------------------------------------------------------
# Metadata stream (inode table / directory table)
# ---------------------------------------------------------------------------

def _load_meta_block(f, base: int, blk_off: int) -> Tuple[bytes, int]:
    """Read and decompress one squashfs metadata block at file offset base+blk_off.
    Returns (decompressed_bytes, disk_size_including_header).
    Uses the same BCJ-fallback path as data blocks: metadata blocks in XZ-compressed
    squashfs images are also XZ streams that may carry the ARM64 BCJ filter.
    """
    f.seek(base + blk_off)
    hdr  = struct.unpack("<H", _checked_read(f, 2, "metadata block header"))[0]
    size = hdr & 0x7FFF
    raw  = _checked_read(f, size, f"metadata block data (size={size})")
    if hdr & 0x8000:
        out = raw
    else:
        out = _decompress_xz_block(raw, dict_size=METADATA_MAX)
    return out, 2 + size


class _MetaStream:
    """Lazy, cached metadata stream with automatic block-boundary crossing."""

    def __init__(self, f, base: int):
        self._f     = f
        self._base  = base
        self._cache: dict = {}

    def _blk(self, blk_off: int) -> Tuple[bytes, int]:
        if blk_off not in self._cache:
            self._cache[blk_off] = _load_meta_block(self._f, self._base, blk_off)
        return self._cache[blk_off]

    def read(self, blk_off: int, within: int, length: int) -> bytes:
        # Iterative block-boundary crossing to avoid Python recursion limit.
        parts: list = []
        remaining = length
        cur_blk = blk_off
        cur_within = within
        while remaining > 0:
            data, dsz = self._blk(cur_blk)
            # Advance past overshot blocks; guard against zero-length (corrupt image)
            while cur_within >= len(data):
                if len(data) == 0:
                    raise ValueError(
                        f"Corrupt squashfs: zero-length decompressed metadata block "
                        f"at relative offset {cur_blk}"
                    )
                cur_within -= len(data)
                cur_blk   += dsz
                data, dsz  = self._blk(cur_blk)
            available = len(data) - cur_within
            take = min(available, remaining)
            parts.append(data[cur_within : cur_within + take])
            remaining  -= take
            cur_within += take
            if cur_within >= len(data):
                cur_blk   += dsz
                cur_within = 0
        return b"".join(parts)


# ---------------------------------------------------------------------------
# Inode parsers
# ---------------------------------------------------------------------------

def _parse_dir_inode(ms: _MetaStream, inode_ref: int) -> Tuple[int, int, int]:
    """Return (dir_start_block, dir_file_size, dir_within_offset) for DIR/LDIR inodes."""
    blk_off  = (inode_ref >> 16) & 0xFFFFFFFFFFFF
    within   = inode_ref & 0xFFFF
    hdr = ms.read(blk_off, within, 40)
    itype = struct.unpack_from("<H", hdr, 0)[0]
    if itype == INODE_DIR:    # basic dir: start@16 file_size@24(H) offset@26(H)
        sb  = struct.unpack_from("<I", hdr, 16)[0]
        fsz = struct.unpack_from("<H", hdr, 24)[0]
        off = struct.unpack_from("<H", hdr, 26)[0]
    elif itype == INODE_LDIR: # extended dir: start@24 file_size@20(I) offset@34(H)
        sb  = struct.unpack_from("<I", hdr, 24)[0]
        fsz = struct.unpack_from("<I", hdr, 20)[0]
        off = struct.unpack_from("<H", hdr, 34)[0]
    else:
        raise ValueError(f"inode_ref 0x{inode_ref:x}: type {itype} is not a directory")
    return sb, fsz, off


def _parse_reg_inode(ms: _MetaStream, inode_ref: int,
                     block_size: int = 131072) -> Tuple[int, int, int, int, List[int]]:
    """Return (start_block, file_size, frag_idx, frag_off, block_sizes[]) for REG/LREG."""
    blk_off = (inode_ref >> 16) & 0xFFFFFFFFFFFF
    within  = inode_ref & 0xFFFF
    hdr = ms.read(blk_off, within, 80)
    itype = struct.unpack_from("<H", hdr, 0)[0]
    if itype == INODE_REG:
        sb    = struct.unpack_from("<I", hdr, 16)[0]
        fi    = struct.unpack_from("<I", hdr, 20)[0]
        fo    = struct.unpack_from("<I", hdr, 24)[0]
        fsz   = struct.unpack_from("<I", hdr, 28)[0]
        fixed = 32
    elif itype == INODE_LREG:
        sb    = struct.unpack_from("<Q", hdr, 16)[0]
        fsz   = struct.unpack_from("<Q", hdr, 24)[0]
        fi    = struct.unpack_from("<I", hdr, 44)[0]
        fo    = struct.unpack_from("<I", hdr, 48)[0]
        fixed = 56
    else:
        raise ValueError(f"inode_ref 0x{inode_ref:x}: type {itype} is not a regular file")
    nb = (fsz + block_size - 1) // block_size if fi == 0xFFFFFFFF else fsz // block_size
    if nb > 65536:
        raise ValueError(
            f"Corrupt squashfs inode 0x{inode_ref:x}: block count {nb} exceeds "
            f"sanity limit of 65536 (max ~8GB file)"
        )
    bsz_raw = ms.read(blk_off, within + fixed, nb * 4) if nb else b""
    bsizes  = list(struct.unpack_from(f"<{nb}I", bsz_raw)) if nb else []
    return sb, fsz, fi, fo, bsizes


# ---------------------------------------------------------------------------
# Directory listing
# ---------------------------------------------------------------------------

def _iter_dir_entries(
    ms_dir: _MetaStream,
    start_block: int,
    file_size: int,
    dir_offset: int,
) -> Generator[Tuple[str, int, int], None, None]:
    """Yield (name, inode_ref, entry_type) for every entry in a directory listing.

    Directory listing layout:
      dir_header: count(4 LE) start_block(4 LE) inode_number(4 LE)  = 12 bytes
      dir_entry:  offset(2 LE) inode_number(2 LE) type(2 LE) size(2 LE)  = 8 bytes
                  followed by (size+1) name bytes
    Note: size is __le16 (kernel squashfs_fs.h) NOT __le8.
    """
    rem = file_size
    blk = start_block
    wo  = dir_offset
    while rem > 0:
        raw  = ms_dir.read(blk, wo, 12)
        cnt  = struct.unpack_from("<I", raw, 0)[0] + 1
        if cnt > 8192:
            raise ValueError(
                f"Corrupt squashfs directory header: entry count {cnt} exceeds "
                f"sanity limit of 8192"
            )
        hsb  = struct.unpack_from("<I", raw, 4)[0]
        wo  += 12
        rem -= 12
        for _ in range(cnt):
            er  = ms_dir.read(blk, wo, 8)
            eo  = struct.unpack_from("<H", er, 0)[0]   # offset within inode meta block
            et  = struct.unpack_from("<H", er, 4)[0]   # entry type
            es  = struct.unpack_from("<H", er, 6)[0]   # name_length - 1
            wo += 8
            rem -= 8
            name_bytes = ms_dir.read(blk, wo, es + 1)
            name  = name_bytes.decode("utf-8", errors="replace")
            wo   += es + 1
            rem  -= es + 1
            yield name, (hsb << 16) | eo, et


# ---------------------------------------------------------------------------
# Main extractor class
# ---------------------------------------------------------------------------

class HuaweiSquashfsExtractor:
    """
    Pure-Python squashfs v4 reader for Huawei VRP firmware images.

    Not thread-safe: all methods share a single file handle and seek position.
    Concurrent calls from multiple threads will produce wrong results. Use one
    instance per thread, or protect callers with an external lock.

    Usage:
        ext  = HuaweiSquashfsExtractor("/path/to/sqfs_00_00001984.sqfs")
        data = ext.extract("aarch64/0x10644_7500/usr/local/lib/libhttpstackcore.so")
    """

    def __init__(self, path: str):
        self._path = path
        self._f    = open(path, "rb")
        try:
            self._sb       = self._parse_superblock()
            self._ms_inode = _MetaStream(self._f, self._sb["inode_tbl"])
            self._ms_dir   = _MetaStream(self._f, self._sb["dir_tbl"])
        except Exception:
            self._f.close()
            raise

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ------------------------------------------------------------------

    def _parse_superblock(self) -> dict:
        self._f.seek(0)
        raw = _checked_read(self._f, 96, "squashfs superblock")
        magic = struct.unpack_from("<I", raw, 0)[0]
        if magic != SQUASHFS_MAGIC:
            raise ValueError(f"not squashfs (magic 0x{magic:08x})")
        major = struct.unpack_from("<H", raw, 28)[0]
        if major != 4:
            raise ValueError(
                f"unsupported squashfs major version {major} (only v4 supported)"
            )
        comp_id = struct.unpack_from("<H", raw, 20)[0]
        if comp_id != 4:
            raise ValueError(
                f"unsupported compression algorithm {comp_id} "
                f"(1=zlib 2=lzo 3=lzma 4=xz 5=lz4 6=zstd; only xz/4 supported)"
            )
        block_size = struct.unpack_from("<I", raw, 12)[0]
        if block_size == 0 or block_size > (1 << 20) or (block_size & (block_size - 1)) != 0:
            raise ValueError(
                f"Invalid squashfs block_size {block_size}: "
                f"must be a non-zero power of 2 and at most 1 MB"
            )
        sb = {
            "inode_count":  struct.unpack_from("<I", raw,  4)[0],
            "block_size":   block_size,
            "frag_count":   struct.unpack_from("<I", raw, 16)[0],
            "comp_id":      comp_id,
            "block_log":    struct.unpack_from("<H", raw, 22)[0],
            "flags":        struct.unpack_from("<H", raw, 24)[0],
            "major":        major,
            "root_inode":   struct.unpack_from("<Q", raw, 32)[0],
            "bytes_used":   struct.unpack_from("<Q", raw, 40)[0],
            "id_tbl":       struct.unpack_from("<Q", raw, 48)[0],
            "xattr_tbl":    struct.unpack_from("<Q", raw, 56)[0],
            "inode_tbl":    struct.unpack_from("<Q", raw, 64)[0],
            "dir_tbl":      struct.unpack_from("<Q", raw, 72)[0],
            "frag_tbl":     struct.unpack_from("<Q", raw, 80)[0],
            "export_tbl":   struct.unpack_from("<Q", raw, 88)[0],
        }
        return sb

    # ------------------------------------------------------------------

    def _walk_to(self, path_components: List[str]) -> Tuple[int, int]:
        """Walk path_components from root; return (inode_ref, entry_type)."""
        cur_iref = self._sb["root_inode"]
        cur_type = INODE_LDIR
        for component in path_components:
            sb, fsz, doff = _parse_dir_inode(self._ms_inode, cur_iref)
            found = None
            for name, niref, ntype in _iter_dir_entries(self._ms_dir, sb, fsz, doff):
                if name == component:
                    found = (niref, ntype)
                    break
            if found is None:
                raise FileNotFoundError(
                    f"'{component}' not found (path so far: {path_components})"
                )
            cur_iref, cur_type = found
        return cur_iref, cur_type

    def list_dir(self, dir_path: str = "") -> List[Tuple[str, int, int]]:
        """Return sorted [(name, inode_ref, type)] for all entries in dir_path."""
        if dir_path:
            components = dir_path.strip("/").split("/")
            iref, _ = self._walk_to(components)
        else:
            iref = self._sb["root_inode"]
        sb, fsz, doff = _parse_dir_inode(self._ms_inode, iref)
        return sorted(
            _iter_dir_entries(self._ms_dir, sb, fsz, doff),
            key=lambda t: t[0],
        )

    def extract(self, file_path: str) -> bytes:
        """
        Extract and return the full decompressed content of file_path.

        file_path: forward-slash-separated path within the squashfs image.
        Raises FileNotFoundError if any component is missing.
        Raises ValueError if the target inode is not a regular file.
        """
        components = file_path.strip("/").split("/")
        iref, _   = self._walk_to(components)
        block_size = self._sb["block_size"]
        sb, fsz, fi, fo, bsizes = _parse_reg_inode(
            self._ms_inode, iref, block_size=block_size
        )
        if fsz > _MAX_EXTRACT_BYTES:
            raise ValueError(
                f"File too large to extract: {fsz} bytes exceeds "
                f"limit {_MAX_EXTRACT_BYTES} bytes (512 MB)"
            )

        parts: List[bytes] = []
        offset = sb
        for raw_bsz in bsizes:
            nocomp = bool(raw_bsz >> 31)
            comp_sz = raw_bsz & 0x7FFFFFFF
            if comp_sz == 0:
                # sparse block: zero-fill
                parts.append(b"\x00" * block_size)
                continue
            self._f.seek(offset)
            block_raw = _checked_read(self._f, comp_sz, f"data block {comp_sz} bytes at 0x{offset:x}")
            offset   += comp_sz
            if nocomp:
                parts.append(block_raw)
            else:
                parts.append(_decompress_xz_block(block_raw, dict_size=block_size))

        # Append fragment data for files whose last chunk lives in the fragment table
        if fi != 0xFFFFFFFF:
            if fi >= self._sb["frag_count"]:
                raise ValueError(
                    f"Corrupt squashfs inode: frag_idx {fi} >= "
                    f"frag_count {self._sb['frag_count']}"
                )
            tail_size = fsz % block_size
            if tail_size == 0:
                raise ValueError(
                    f"Corrupt squashfs inode: file_size {fsz} is an exact multiple of "
                    f"block_size {block_size} but frag_idx={fi} is set (should be 0xffffffff)"
                )
            frag_start, frag_raw_sz = _read_frag_entry(self._f, self._sb, fi)
            nocomp  = bool(frag_raw_sz >> 31)
            comp_sz = frag_raw_sz & 0x7FFFFFFF
            self._f.seek(frag_start)
            frag_block = _checked_read(self._f, comp_sz, f"fragment block {comp_sz} bytes at 0x{frag_start:x}")
            if nocomp:
                frag_data = frag_block
            else:
                frag_data = _decompress_xz_block(frag_block, dict_size=block_size)
            if fo + tail_size > len(frag_data):
                raise ValueError(
                    f"Fragment slice [{fo}:{fo + tail_size}] out of bounds "
                    f"(decompressed fragment block length {len(frag_data)})"
                )
            parts.append(frag_data[fo : fo + tail_size])

        data = b"".join(parts)
        if len(data) < fsz:
            raise ValueError(
                f"Assembled file data length {len(data)} is less than declared "
                f"file_size {fsz}; squashfs image may be corrupt or incomplete"
            )
        return data[:fsz]
