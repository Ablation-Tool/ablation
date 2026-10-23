"""
obfuscated_string_decoder.py: Multi-layer obfuscated string decoder.

Extracts high-entropy string literals from .rodata and attempts systematic
multi-layer decoding. Firmware droppers commonly use Base64 -> deflate -> XOR
chains; this module attempts each layer iteratively until a printable result
is produced or all combinations are exhausted.

Decoding layers attempted (in order):
  1. Base64 (standard and URL-safe)
  2. Hex-encoded ASCII
  3. ASCII ordinal (comma-separated decimal strings)
  4. zlib/deflate decompression
  5. Single-byte XOR with brute-forced key (0x01-0xff)

Strings are extracted from .rodata by scanning for null-terminated byte runs
that: (a) are 16+ bytes long, and (b) have Shannon entropy > 4.0 bits/byte.
The entropy threshold filters out plain English strings and targets encoded data.

Usage:
    decoder = ObfuscatedStringDecoder('/path/to/binary')
    results = decoder.scan()
    for r in results:
        print(r.decoded_layers, '->', r.plaintext[:80])
"""

from __future__ import annotations

import base64
import math
import re
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

_MIN_STRING_LEN = 16
_ENTROPY_THRESHOLD = 4.0
_PRINTABLE_PAT = re.compile(rb'^[ -~\t\n\r]+$')
_MAX_STRINGS = 200
_MAX_XOR_KEY = 0xFF


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_printable(data: bytes) -> bool:
    return bool(_PRINTABLE_PAT.match(data)) and len(data) >= 4


def _try_decode_one(data: bytes) -> list[tuple[str, bytes]]:
    """Try all single-layer decode methods on data. Returns (method, result) pairs."""
    results: list[tuple[str, bytes]] = []

    # Base64 standard
    try:
        decoded = base64.b64decode(data, validate=True)
        if len(decoded) >= 4:
            results.append(('base64', decoded))
    except Exception:
        pass

    # Base64 URL-safe
    try:
        decoded = base64.urlsafe_b64decode(data + b'==')
        if len(decoded) >= 4 and decoded not in [r for _, r in results]:
            results.append(('base64url', decoded))
    except Exception:
        pass

    # Hex
    try:
        stripped = data.strip()
        if len(stripped) % 2 == 0 and re.match(rb'^[0-9a-fA-F]+$', stripped):
            decoded = bytes.fromhex(stripped.decode('ascii'))
            if len(decoded) >= 4:
                results.append(('hex', decoded))
    except Exception:
        pass

    # ASCII ordinal: "72,101,108,108,111"
    try:
        parts = data.decode('ascii').split(',')
        if len(parts) >= 4:
            ords = [int(p.strip()) for p in parts]
            if all(0 <= v <= 255 for v in ords):
                results.append(('ascii_ordinal', bytes(ords)))
    except Exception:
        pass

    # zlib
    try:
        decoded = zlib.decompress(data)
        if len(decoded) >= 4:
            results.append(('zlib', decoded))
    except Exception:
        pass

    # zlib with wbits=-15 (raw deflate)
    try:
        decoded = zlib.decompress(data, wbits=-15)
        if len(decoded) >= 4:
            results.append(('deflate', decoded))
    except Exception:
        pass

    return results


def _xor_brute(data: bytes) -> Optional[tuple[int, bytes]]:
    """Brute-force single-byte XOR. Return (key, plaintext) for the key that
    produces the highest fraction of printable bytes, or None if no key achieves
    >80% printable."""
    best_key = 0
    best_score = 0.0
    best_out = b''
    for key in range(1, _MAX_XOR_KEY + 1):
        out = bytes(b ^ key for b in data)
        score = sum(1 for b in out if 0x20 <= b <= 0x7E) / len(out)
        if score > best_score:
            best_score = score
            best_key = key
            best_out = out
    if best_score >= 0.80:
        return best_key, best_out
    return None


@dataclass
class DecodedString:
    offset:         int
    raw:            bytes
    raw_entropy:    float
    decoded_layers: list[str]       # e.g. ['base64', 'zlib', 'xor:0x42']
    plaintext:      bytes

    def fmt(self) -> str:
        chain = ' -> '.join(self.decoded_layers)
        preview = self.plaintext[:80].decode('ascii', errors='replace')
        return (f"  offset=0x{self.offset:x}  entropy={self.raw_entropy:.2f}  "
                f"layers=[{chain}]\n    {preview!r}")


class ObfuscatedStringDecoder:
    """Extract and multi-layer decode high-entropy strings from a binary."""

    def __init__(self, path: str) -> None:
        self._path = path

    @classmethod
    def from_context(cls, ctx) -> 'ObfuscatedStringDecoder':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        return obj

    def _extract_candidate_strings(self, raw: bytes) -> list[tuple[int, bytes]]:
        candidates: list[tuple[int, bytes]] = []
        i = 0
        while i < len(raw) and len(candidates) < _MAX_STRINGS:
            # Find null-terminated runs of non-null bytes
            j = i
            while j < len(raw) and raw[j] != 0:
                j += 1
            span = raw[i:j]
            if len(span) >= _MIN_STRING_LEN:
                entropy = _shannon_entropy(span)
                # Include both non-printable high-entropy spans (raw compressed/XOR'd bytes)
                # and printable high-entropy spans (Base64, hex strings).
                # Low-entropy printable spans are normal English text — skip those.
                if entropy >= _ENTROPY_THRESHOLD:
                    candidates.append((i, span))
            i = j + 1
        return candidates

    def scan(self, max_depth: int = 3) -> List[DecodedString]:
        """Scan binary for high-entropy strings and attempt multi-layer decoding.

        max_depth: maximum number of decode layers to apply (default 3).
        """
        try:
            raw = open(self._path, 'rb').read()
        except OSError:
            return []

        candidates = self._extract_candidate_strings(raw)
        results: list[DecodedString] = []

        for offset, span in candidates:
            raw_entropy = _shannon_entropy(span)
            # BFS over decode layers
            queue: list[tuple[bytes, list[str]]] = [(span, [])]
            found_plaintext = False
            for _ in range(max_depth):
                next_queue: list[tuple[bytes, list[str]]] = []
                for current, layers in queue:
                    decoded_list = _try_decode_one(current)
                    for method, decoded in decoded_list:
                        new_layers = layers + [method]
                        if _is_printable(decoded):
                            results.append(DecodedString(
                                offset=offset,
                                raw=span,
                                raw_entropy=raw_entropy,
                                decoded_layers=new_layers,
                                plaintext=decoded,
                            ))
                            found_plaintext = True
                        else:
                            next_queue.append((decoded, new_layers))
                queue = next_queue
                if found_plaintext:
                    break

            if not found_plaintext:
                # Try XOR brute force on the raw bytes
                xor_result = _xor_brute(span)
                if xor_result:
                    key, plaintext = xor_result
                    results.append(DecodedString(
                        offset=offset,
                        raw=span,
                        raw_entropy=raw_entropy,
                        decoded_layers=[f'xor:0x{key:02x}'],
                        plaintext=plaintext,
                    ))

        return results

    def report(self, results: Optional[List[DecodedString]] = None) -> str:
        if results is None:
            results = self.scan()
        if not results:
            return f'ObfuscatedStringDecoder: no decodable high-entropy strings in {self._path}'
        lines = [f'ObfuscatedStringDecoder: {len(results)} decoded string(s) in {self._path}', '']
        for r in results:
            lines.append(r.fmt())
            lines.append('')
        return '\n'.join(lines)
