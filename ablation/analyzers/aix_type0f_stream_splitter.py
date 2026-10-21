"""IBM AIX installp type 0x0f two-stream decoder and splitter.

Why this exists
---------------
1. AIX 5.2 type 0x0f BFF entries contain TWO Huffman-compressed streams in
   a single payload.  The primary stream decodes ``uncompressed_size`` MTF
   indices; the secondary stream begins at the byte boundary immediately
   following the primary sentinel.
2. The existing ``AixInstallpDecompressor._unary_huffman_decode`` decodes the
   primary stream only and stops after ``uncompressed_size`` symbols.  Any
   secondary content is silently discarded, preventing analysis of type 0x0f
   secondary blocks.
3. AIX 5.0 type 0x0f entries are SINGLE-STREAM: no sentinel, no secondary
   block.  This module auto-detects the version-specific format and handles
   both cases.

Primary-stream sentinel (AIX 5.2 format)
-----------------------------------------
The primary Huffman stream is terminated early by a 256-consecutive-1-bit
sentinel embedded in the payload.  This sentinel is physically represented as
32 bytes of 0xFF (256 ones) followed by a 0-bit (byte boundary alignment
varies).  After the sentinel, the secondary block begins at the next payload
byte boundary.

Empirical evidence (MQSeries amqzxma0_nd AIX 5.2, type 0x0f, 50848-byte entry):
  Huffman decodes 397 symbols (primary), then encounters the 0xFF sentinel.
  Remaining 14,064 bytes are the secondary block.
  Secondary block format: NOT XCOFF32, NOT standard IBM installp format.
  Analysis: the secondary block appears to be a continuation of the BWT
  compression applied to a DIFFERENT text segment (format unidentifiable
  without IBM liblpp.a).

Shared MTF state
----------------
After the primary stream decodes to ``bwt_last``, the MTF decode produces
``bwt_last_buf``.  The secondary stream continuation starts from the FINAL
state of the MTF list at end of primary decode.  Both streams share:
  - The same sym_table (raw[16:272]).
  - The same K-byte common alphabet.
  - The final MTF list state after primary stream decode.

Usage::

    splitter = AixType0fStreamSplitter(raw)
    result = splitter.split()
    # result.primary_decoded: primary stream decoded bytes (XCOFF32 text)
    # result.secondary_raw: secondary stream raw bytes (unidentified format)
    # result.secondary_mtf_indices: secondary MTF indices (if decodable)
    # result.format: "two_stream" | "single_stream"
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


@dataclass
class Type0fSplitResult:
    """Output of AixType0fStreamSplitter.split()."""
    format: str
    """'two_stream' (AIX 5.2) or 'single_stream' (AIX 5.0)."""

    primary_mtf_indices: list[int]
    """Primary stream MTF symbol indices (length = uncompressed_size)."""

    primary_bwt_last: bytes
    """Primary stream inverse-MTF output (BWT last column)."""

    secondary_raw: bytes
    """Raw bytes of the secondary block payload (AIX 5.2 only; empty otherwise)."""

    secondary_mtf_indices: list[int]
    """Secondary stream MTF indices decoded using final primary MTF state."""

    secondary_bwt_last: bytes
    """Inverse-MTF of secondary stream using shared MTF state."""

    final_mtf_state: list[int]
    """MTF list state at end of primary stream decode."""

    bits_consumed_primary: int
    """Bits consumed by primary Huffman decode."""

    sentinel_detected: bool
    """True if a 256-consecutive-1-bit sentinel was found."""


class AixType0fStreamSplitter:
    """Split and decode IBM AIX installp type 0x0f two-stream entries.

    Handles both AIX 5.0 (single-stream) and AIX 5.2 (two-stream with sentinel)
    format variants automatically.

    Parameters
    ----------
    raw:
        Raw bytes of the complete BFF entry beginning with the type byte (0x0f).
    """

    SENTINEL_BITS = 256
    SENTINEL_BYTES = 32

    def __init__(self, raw: bytes) -> None:
        if len(raw) < 272:
            raise ValueError(f"Entry too short ({len(raw)} bytes); minimum 272")
        if raw[0] != 0x0f:
            raise ValueError(f"Expected type 0x0f, got 0x{raw[0]:02x}")
        self._raw = raw
        self._sym_table = bytes(raw[16:272])
        bwt_index_be = struct.unpack('>I', raw[4:8])[0]
        uncomp_size_le = struct.unpack('<I', raw[12:16])[0]
        self._bwt_index = bwt_index_be
        self._uncompressed_size = uncomp_size_le

    @property
    def sym_table(self) -> bytes:
        return self._sym_table

    @property
    def bwt_index(self) -> int:
        return self._bwt_index

    @property
    def uncompressed_size(self) -> int:
        return self._uncompressed_size

    def split(self) -> Type0fSplitResult:
        """Decode and split the entry into primary and secondary streams.

        Returns
        -------
        Type0fSplitResult
            Decoded primary stream, secondary block, and shared MTF state.
        """
        payload = self._raw[272:]
        mtf_state = list(self._sym_table)

        primary_indices, bits_primary, sentinel_found, sentinel_byte_end = (
            self._decode_primary_huffman(payload, self._uncompressed_size)
        )

        primary_bwt_last, final_mtf_state = self._inverse_mtf_stateful(
            primary_indices, mtf_state
        )

        if sentinel_found and sentinel_byte_end < len(payload):
            secondary_raw = payload[sentinel_byte_end:]
            fmt = "two_stream"
        else:
            secondary_raw = b''
            fmt = "single_stream"

        secondary_indices: list[int] = []
        secondary_bwt_last = b''
        if secondary_raw:
            secondary_indices = self._decode_secondary_huffman(secondary_raw)
            secondary_bwt_last, _ = self._inverse_mtf_stateful(
                secondary_indices, list(final_mtf_state)
            )

        return Type0fSplitResult(
            format=fmt,
            primary_mtf_indices=primary_indices,
            primary_bwt_last=primary_bwt_last,
            secondary_raw=secondary_raw,
            secondary_mtf_indices=secondary_indices,
            secondary_bwt_last=secondary_bwt_last,
            final_mtf_state=final_mtf_state,
            bits_consumed_primary=bits_primary,
            sentinel_detected=sentinel_found,
        )

    def _decode_primary_huffman(
        self, payload: bytes, max_symbols: int
    ) -> tuple[list[int], int, bool, int]:
        """Decode primary Huffman stream up to max_symbols or sentinel.

        Returns (indices, bits_consumed, sentinel_found, sentinel_byte_end).
        ``sentinel_byte_end`` is the payload byte offset immediately after
        the sentinel block (first byte of secondary block), or len(payload)
        if not found.
        """
        buf = 0
        nbits = 0
        pos = 0
        bits_consumed = 0
        indices: list[int] = []
        consecutive_ones = 0

        def read_bit() -> int:
            nonlocal buf, nbits, pos, bits_consumed
            if nbits == 0:
                if pos >= len(payload):
                    return -1
                buf = payload[pos]
                pos += 1
                nbits = 8
            b = (buf >> 7) & 1
            buf = (buf << 1) & 0xFF
            nbits -= 1
            bits_consumed += 1
            return b

        while len(indices) < max_symbols:
            n = 0
            while True:
                b = read_bit()
                if b < 0:
                    return indices, bits_consumed, False, len(payload)
                if b == 1:
                    consecutive_ones += 1
                    if consecutive_ones >= self.SENTINEL_BITS:
                        # Consume the terminating 0-bit if present.
                        read_bit()
                        # Align to next byte boundary.
                        sentinel_end = pos
                        return indices, bits_consumed, True, sentinel_end
                    n += 1
                else:
                    consecutive_ones = 0
                    break
            indices.append(n)

        return indices, bits_consumed, False, pos

    def _decode_secondary_huffman(self, secondary_payload: bytes) -> list[int]:
        """Decode secondary Huffman stream from sentinel-terminated secondary block.

        Uses the same unary Huffman coding as the primary stream.  Decodes until
        payload exhaustion.  The secondary MTF indices are then inverted using
        the final primary MTF state to produce the secondary BWT last column.
        """
        buf = 0
        nbits = 0
        pos = 0
        indices: list[int] = []

        def read_bit() -> int:
            nonlocal buf, nbits, pos
            if nbits == 0:
                if pos >= len(secondary_payload):
                    return -1
                buf = secondary_payload[pos]
                pos += 1
                nbits = 8
            b = (buf >> 7) & 1
            buf = (buf << 1) & 0xFF
            nbits -= 1
            return b

        while True:
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
    def _inverse_mtf_stateful(
        indices: list[int], mtf_list: list[int]
    ) -> tuple[bytes, list[int]]:
        """Inverse MTF using the provided mtf_list (modified in-place).

        Returns (decoded_bytes, final_mtf_state).  The final_mtf_state
        can be passed to a subsequent decode for shared-state continuation.
        """
        result = bytearray(len(indices))
        for k, idx in enumerate(indices):
            if idx >= len(mtf_list):
                result[k] = 0
                continue
            byte_val = mtf_list[idx]
            result[k] = byte_val
            mtf_list.pop(idx)
            mtf_list.insert(0, byte_val)
        return bytes(result), list(mtf_list)
