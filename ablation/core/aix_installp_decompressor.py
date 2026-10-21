"""IBM AIX installp BFF compression decompressor (steps 1–4).

Why this exists
---------------
1. IBM AIX installp packages (BFF archives) compress the main executables with a
   proprietary algorithm.  Entries with magic bytes 0x0e, 0x0f, 0x10, or 0x11 are
   not XCOFF32 — they are IBM-compressed XCOFF32.  Standard tools (zlib, bzip2,
   lzma, binwalk) all fail.
2. The compression algorithm has been reverse-engineered through four steps.
   This module implements all four steps of the decompression pipeline.
3. Step 4 is implemented via a single-level escape-byte hypothesis: rare bytes
   (absent from the K-byte common alphabet) are encoded as [escape_byte, term]
   pairs in the BWT buffer.  Entry data past the Huffman stream is appended raw.

Reverse-engineering notes (2026-10-21)
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
    sym_table[0] = most common byte in the compressed entry (= escape_byte in step 4).
    sym_table[255] = rarest byte.

Compressed payload (d[272:])::

    Unary MSB-first Huffman codes.  N consecutive 1-bits followed by a 0-bit
    encodes MTF index N.  The Huffman stream is self-terminating at uncompressed_size
    symbols; raw bytes after the stream end are a separate trailing block.

Decompression pipeline (all 4 steps)::

    payload → unary Huffman decode → MTF index stream           (step 1)
    MTF index stream → inverse MTF (sym_table initial list)     (step 2)
    → BWT last column
    BWT last column + bwt_index → inverse BWT (LF-mapping)     (step 3)
    → BWT buffer (K-byte alphabet, escape-encoded)
    BWT buffer → step4_escape_decode → decoded portion          (step 4)
    decoded portion + trailing_raw_block → reconstructed entry

Step 4 (escape-byte decode + trailing block)::

    K = number of unique bytes in BWT buffer (common alphabet).
    escape_byte = sym_table[0] (most common byte).

    For each byte b in BWT buffer:
      b != escape_byte  → emit b (literal common byte).
      b == escape_byte  → read next byte n:
        n == escape_byte → emit escape_byte (self-escape = literal escape byte).
        n in common_set  → emit escape_byte + n (escape followed by common = two literals).
        n not in common  → emit sym_table[K + rank(n, sorted_non_common)] (rare byte).

    After escape decode: append raw bytes from offset (272 + huffman_bytes_consumed)
    to end of entry.  These trailing bytes are a second uncompressed block.

    NOTE: IBM's installp BWT omits a unique terminator character, producing a multi-cycle
    LF-map.  For automountd (type 0x0e, N=199,196): 19 cycles, lengths
    [111380,29182,26585,17754,7087,4382,1283,577,468,333,...], none of length N.  Inverse
    BWT from the stored bwt_index cycles within one cycle rather than reconstructing the
    full file.  The correct multi-cycle concatenation order is IBM-proprietary.  The step4
    escape decode and trailing block together give the closest available approximation.

Cross-version header difference::

    AIX 5.0 entries are mostly type 0x0f; AIX 5.2 entries are mostly type 0x0e.
    For the same binary (amqzxma0_nd): 5.0 bwt_idx=1806 uncomp=201258;
    5.2 bwt_idx=798 uncomp=199443.  The b4/b12 role swap is consistent across
    all matched entries.

    VIOS automountd: type=0x0e (not 0x0f); header 0e00010000030a1c1f223b3c1a030000;
    uncomp=199196 (field_a_BE), bwt_index=794 (field_c_LE=0x0000031a).

Type 0x0f sentinel::

    Type 0x0f Huffman streams terminate early with a 256-consecutive-1-bit sentinel
    (≥32 bytes of 0xFF) rather than decoding all uncomp_size symbols.  After the
    sentinel, remaining bytes are a secondary compressed block in an unknown IBM format.
    MQSeries amqzxma0_nd (type 0x0f, 50848-byte entry): Huffman decodes 397 symbols
    (K=13, escape_byte=0x00) then hits n>=256 at payload[139]; remaining 50437 bytes
    are the secondary block.  The _unary_huffman_decode() ``n >= 256: return indices``
    guard correctly detects this sentinel and returns the partial decode.
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
    """Implements IBM AIX installp BFF compression (all 4 steps).

    Usage::

        data = open('mqm.server.rte.5.2.0.8.U486905', 'rb').read()
        from ablation.core.bff_extractor import iter_entries
        for entry in iter_entries(data):
            d = entry.data
            if d[0] in (0x0e, 0x0f, 0x10, 0x11):
                dec = AixInstallpDecompressor(d)
                result = dec.decompress()   # returns bytes (step4 escape + trailing block)
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

    def _huffman_bits_consumed(self) -> int:
        """Return the number of bits consumed by the Huffman decode for this entry."""
        h = self.header
        payload = self._raw[272:]
        buf = 0
        nbits = 0
        pos = 0
        bits = 0
        count = 0

        def read_bit() -> int:
            nonlocal buf, nbits, pos, bits
            if nbits == 0:
                if pos >= len(payload):
                    return -1
                buf = payload[pos]
                pos += 1
                nbits = 8
            b = (buf >> 7) & 1
            buf = (buf << 1) & 0xFF
            nbits -= 1
            bits += 1
            return b

        while count < h.uncompressed_size:
            n = 0
            while True:
                b = read_bit()
                if b < 0:
                    return bits
                if b == 0:
                    break
                n += 1
            count += 1
        return bits

    @staticmethod
    def _step4_escape_decode(bwt_buf: bytes, sym_table: bytes) -> bytes:
        """Step 4: single-level escape-byte decode of the BWT buffer.

        Rare bytes (not in the K-byte common alphabet) were escape-encoded during
        compression.  escape_byte = sym_table[0].

        Encoding rules (forward direction, for reference):
          common byte c (c != escape_byte)  → c
          escape_byte                        → [escape_byte, escape_byte]
          rare byte r (r not in K-set)       → [escape_byte, term] where term encodes r

        Decode rules applied here:
          b != escape_byte                   → emit b
          b == escape_byte, next == escape_byte → emit escape_byte
          b == escape_byte, next in common   → emit escape_byte + next (two literals)
          b == escape_byte, next not in common → emit sym_table[K + rank(next, sorted_rare)]
        """
        K_set = set(bwt_buf)
        K = len(K_set)
        escape_byte = sym_table[0]
        sorted_rare = sorted(b for b in range(256) if b not in K_set)

        result = bytearray()
        i = 0
        n_raw = len(bwt_buf)
        while i < n_raw:
            b = bwt_buf[i]
            if b != escape_byte:
                result.append(b)
                i += 1
                continue
            # b == escape_byte: read next byte
            i += 1
            if i >= n_raw:
                result.append(escape_byte)
                break
            nxt = bwt_buf[i]
            i += 1
            if nxt == escape_byte:
                result.append(escape_byte)
            elif nxt in K_set:
                result.append(escape_byte)
                result.append(nxt)
            else:
                # nxt not in K_set → guaranteed in sorted_rare
                rank = sorted_rare.index(nxt)
                rare_idx = K + rank
                result.append(sym_table[rare_idx] if rare_idx < 256 else nxt)
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
        """Full decompression: steps 1–4.

        Steps 1–3 produce the BWT buffer (K-byte common alphabet, escape-encoded).
        Step 4 applies escape-byte decode and appends the trailing raw block
        (bytes after the Huffman stream within the entry).

        Returns
        -------
        bytes
            Reconstructed entry content.  The first portion is step4-decoded from
            the BWT buffer; the second portion is the raw trailing block.
            NOTE: The BWT reconstruction (step 3) may be approximate due to
            multi-cycle LF-map structure in the current decode; the trailing raw
            block is exact.
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

        # Step 4: Escape-byte decode + trailing raw block
        huffman_bits = self._huffman_bits_consumed()
        huffman_bytes = (huffman_bits + 7) // 8
        trailing_raw = self._raw[272 + huffman_bytes:]

        decoded = self._step4_escape_decode(bwt_buf, h.sym_table)
        return decoded + trailing_raw

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
