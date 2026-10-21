"""IBM AIX installp BFF compression decompressor (steps 1–3 of 4).

Why this exists
---------------
1. IBM AIX installp packages (BFF archives) compress the main executables with a
   proprietary algorithm.  Entries with magic bytes 0x0e, 0x0f, 0x10, or 0x11 are
   not XCOFF32 — they are IBM-compressed XCOFF32.  Standard tools (zlib, bzip2,
   lzma, binwalk) all fail.
2. The compression algorithm has been partially reverse-engineered: 4 of 5 steps
   are confirmed.  This module implements the known 3-step pipeline and returns
   the BWT-transformed buffer.  Step 4 (final IBM-proprietary RLE expansion) remains
   unknown; a documented AixInstallpStep4Unknown sentinel is raised instead.
3. The BWT buffer produced by steps 1–3 is already useful: it contains the PPC32
   instruction opcode distribution and can be analysed for high-level security
   properties even without full reconstruction.

Reverse-engineering notes (2026-10-20)
---------------------------------------
Header layout (16 bytes)::

    d[0]      : type byte (0x0e, 0x0f, 0x10, 0x11)
    d[1:4]    : version (0x00 0x01 0x00 for type 0x0e)
    d[4:8]    : 32-bit field A (big-endian)
    d[8:12]   : 32-bit field B (big-endian; purpose unknown)
    d[12:16]  : 32-bit field C (little-endian)

    type 0x0e : field_A = uncompressed_size, field_C_LE = bwt_index
    type 0x0f : field_A_BE = bwt_index,      field_C_LE = uncompressed_size

Symbol table (256 bytes, d[16:272])::

    A frequency-sorted permutation of all 256 byte values.
    sym_table[0] = most common byte in the compressed entry.
    sym_table[255] = rarest byte.

Compressed payload (d[272:])::

    Unary MSB-first Huffman codes.  N consecutive 1-bits followed by a 0-bit
    encodes MTF index N.

Decompression pipeline::

    payload → unary Huffman decode → MTF index stream
    MTF index stream → inverse MTF (sym_table as initial list) → BWT last column
    BWT last column + bwt_index → inverse BWT (LF-mapping) → BWT buffer [step 4 UNKNOWN]

Step 4 (unknown)::

    The BWT buffer has only 21 unique byte values for a 200 KB PPC32 binary.
    The byte 0xdf (required for XCOFF32 magic 0x01df) is absent because it appears
    at sym_table position ≥ 22, which is never referenced by the index stream.
    An IBM-proprietary RLE or symbol-extension step reconstructs the full XCOFF32.
    No open-source implementation is known; liblpp.a or installp source required.

Cross-version header difference::

    AIX 5.0 entries are mostly type 0x0f; AIX 5.2 entries are mostly type 0x0e.
    For the same binary (amqzxma0_nd): 5.0 bwt_idx=1806 uncomp=201258;
    5.2 bwt_idx=798 uncomp=199443.  The b4/b12 role swap is consistent across
    all matched entries.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


class AixInstallpStep4Unknown(Exception):
    """Raised when step 4 (IBM-proprietary RLE expansion) cannot be applied.

    The caller receives the BWT buffer (output of steps 1–3) via the
    ``bwt_buffer`` attribute so partial analysis can proceed.
    """

    def __init__(self, bwt_buffer: bytes, uncompressed_size: int) -> None:
        self.bwt_buffer = bwt_buffer
        self.uncompressed_size = uncompressed_size
        super().__init__(
            f"IBM AIX installp step 4 (RLE expansion) unknown; "
            f"BWT buffer is {len(bwt_buffer)} bytes, "
            f"expected final size {uncompressed_size} bytes"
        )


@dataclass
class AixInstallpHeader:
    type_byte: int
    version: bytes
    uncompressed_size: int
    bwt_index: int
    sym_table: bytes


class AixInstallpDecompressor:
    """Implements IBM AIX installp BFF compression (steps 1–3 of 4).

    Usage::

        data = open('mqm.server.rte.5.2.0.8.U486905', 'rb').read()
        from ablation.core.bff_extractor import iter_entries
        for entry in iter_entries(data):
            d = entry.data
            if d[0] in (0x0e, 0x0f, 0x10, 0x11):
                dec = AixInstallpDecompressor(d)
                try:
                    result = dec.decompress()      # raises AixInstallpStep4Unknown
                except AixInstallpStep4Unknown as exc:
                    bwt_buf = exc.bwt_buffer        # 21-byte-alphabet PPC32 skeleton
    """

    SUPPORTED_TYPES = (0x0e, 0x0f, 0x10, 0x11)

    def __init__(self, raw: bytes) -> None:
        if len(raw) < 272:
            raise ValueError(f"Entry too short ({len(raw)} bytes); minimum 272")
        if raw[0] not in self.SUPPORTED_TYPES:
            raise ValueError(
                f"Not an IBM installp compressed entry (type byte 0x{raw[0]:02x})"
            )
        self._raw = raw
        self.header = self._parse_header(raw)

    @staticmethod
    def _parse_header(raw: bytes) -> AixInstallpHeader:
        type_byte = raw[0]
        version = bytes(raw[1:4])
        field_a = struct.unpack('>I', raw[4:8])[0]
        field_c = struct.unpack('<I', raw[12:16])[0]
        if type_byte == 0x0e:
            uncompressed_size = field_a
            bwt_index = field_c
        else:
            bwt_index = field_a
            uncompressed_size = field_c
        sym_table = bytes(raw[16:272])
        return AixInstallpHeader(
            type_byte=type_byte,
            version=version,
            uncompressed_size=uncompressed_size,
            bwt_index=bwt_index,
            sym_table=sym_table,
        )

    def _unary_huffman_decode(self, max_symbols: int) -> list[int]:
        """Decode unary MSB-first Huffman codes from the payload.

        N consecutive 1-bits followed by a 0-bit encodes symbol index N.
        """
        payload = self._raw[272:]
        buf = 0
        nbits = 0
        pos = 0
        indices: list[int] = []

        def read_bit() -> int:
            nonlocal buf, nbits, pos
            if nbits == 0:
                if pos >= len(payload):
                    return -1
                buf = payload[pos]
                pos += 1
                nbits = 8
            b = (buf >> 7) & 1
            buf = (buf << 1) & 0xFF
            nbits -= 1
            return b

        while len(indices) < max_symbols:
            n = 0
            while True:
                b = read_bit()
                if b < 0:
                    return indices
                if b == 0:
                    break
                n += 1
                if n >= 256:
                    return indices
            indices.append(n)

        return indices

    @staticmethod
    def _inverse_mtf(indices: list[int], sym_table: bytes) -> bytes:
        """Inverse Move-To-Front transform.

        The initial MTF list is the frequency-sorted sym_table.
        For each index i: emit mtf_list[i], promote to front.
        Output is the BWT last column.
        """
        mtf_list = list(sym_table)
        result = bytearray(len(indices))
        for k, idx in enumerate(indices):
            byte_val = mtf_list[idx]
            result[k] = byte_val
            mtf_list.pop(idx)
            mtf_list.insert(0, byte_val)
        return bytes(result)

    @staticmethod
    def _inverse_bwt(bwt_last: bytes, bwt_index: int) -> bytes:
        """Inverse Burrows-Wheeler Transform via LF-mapping.

        Reconstructs the original (or pre-RLE) byte sequence from the BWT
        last column and the BWT primary index.
        """
        try:
            import numpy as np
        except ImportError as exc:
            raise ImportError("numpy required for inverse BWT") from exc

        L = np.frombuffer(bwt_last, dtype=np.uint8)
        n = len(L)
        counts = np.bincount(L, minlength=256).astype(np.int64)
        cumcount = np.zeros(256, dtype=np.int64)
        cumcount[1:] = np.cumsum(counts[:-1])
        seen = np.zeros(256, dtype=np.int64)
        rank = np.zeros(n, dtype=np.int64)
        for i in range(n):
            rank[i] = seen[L[i]]
            seen[L[i]] += 1
        lf_map = cumcount[L] + rank
        result = bytearray(n)
        p = bwt_index
        for i in range(n - 1, -1, -1):
            result[i] = L[p]
            p = int(lf_map[p])
        return bytes(result)

    def decompress(self) -> bytes:
        """Attempt full decompression.

        Runs steps 1–3 (confirmed) and raises AixInstallpStep4Unknown with
        the BWT buffer attached.  Full XCOFF32 reconstruction requires the
        unknown IBM-proprietary step 4 (RLE expansion).

        Returns
        -------
        bytes
            Never returns normally for IBM installp entries — always raises
            AixInstallpStep4Unknown.  The BWT buffer is accessible via the
            exception's ``bwt_buffer`` attribute.

        Raises
        ------
        AixInstallpStep4Unknown
            Always raised; carries bwt_buffer and uncompressed_size.
        """
        h = self.header

        # Step 1: Unary Huffman decode
        indices = self._unary_huffman_decode(max_symbols=h.uncompressed_size)

        # Step 2: Inverse MTF
        bwt_last = self._inverse_mtf(indices, h.sym_table)

        # Step 3: Inverse BWT
        if h.bwt_index >= len(bwt_last):
            bwt_buf = bwt_last
        else:
            bwt_buf = self._inverse_bwt(bwt_last, h.bwt_index)

        raise AixInstallpStep4Unknown(bwt_buf, h.uncompressed_size)

    def bwt_buffer(self) -> bytes:
        """Return the BWT buffer (steps 1–3) without raising.

        Useful for byte-distribution analysis and sec analysis of the PPC32
        instruction skeleton even without final reconstruction.
        """
        try:
            self.decompress()
        except AixInstallpStep4Unknown as exc:
            return exc.bwt_buffer
        return b''
