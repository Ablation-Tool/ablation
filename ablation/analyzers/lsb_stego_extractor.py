"""
lsb_stego_extractor.py: BMP LSB steganography reader and Lagrange secret-sharing key extractor.

Handles firmware/APK binaries that hide key material in BMP pixel LSBs using a
Shamir-style Lagrange polynomial scheme over rational arithmetic (imath library).

Pipeline:
  1. Hash a seed string to a pixel offset in the BMP.
  2. Read type_count and n_groups from the LSB channel.
  3. Build (type_count * n_groups) coordinate pairs from LSB-encoded hex fields.
  4. For each of type_count components: run Lagrange interpolation at x=0 over
     n_pts = n_groups // type_count points, using multi-prime CRT for exact reconstruction.
  5. Output each component as a hex string in the format the consuming library expects:
     little-endian byte order, with a non-standard reverse-TC transformation applied to
     negative polynomial values.

The byte-order and sign-handling behavior matches the imath mp_int_to_binary path
observed in stripped ARM32 .so libraries that use this scheme.

Usage:
    from ablation.analyzers.lsb_stego_extractor import BmpKeyExtractor

    ext = BmpKeyExtractor('/path/to/keys.bmp')
    result = ext.extract('MySeed')
    print(result.raw_key_hex)          # concatenated component hex strings
    for i, comp in enumerate(result.components):
        print(f"component {i}: {comp}")
"""

from __future__ import annotations

import ctypes
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Primality and prime generation (stdlib-only, no sympy)
# ---------------------------------------------------------------------------

_MR_WITNESSES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in _MR_WITNESSES:
        return True
    if any(n % w == 0 for w in _MR_WITNESSES):
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _MR_WITNESSES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _nextprime(n: int) -> int:
    candidate = n + 1 if n % 2 == 0 else n + 2
    while not _is_prime(candidate):
        candidate += 2
    return candidate


def _default_primes(count: int = 8, bit_size: int = 63) -> List[int]:
    start = 1 << (bit_size - 1)
    p = start + 1
    while not _is_prime(p):
        p += 2
    primes: List[int] = []
    while len(primes) < count:
        primes.append(p)
        p = _nextprime(p)
    return primes


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CoordPair:
    x: str  # hex string (radix-16, always even length)
    y: str  # hex string (radix-16, always even length)


@dataclass
class StegoKeyResult:
    seed: str
    type_count: int
    n_groups: int
    n_pts: int
    components: List[str]  # hex strings per polynomial component
    raw_key_hex: str        # components concatenated

    def fmt(self) -> str:
        lines = [
            f"seed={self.seed!r}  type_count={self.type_count}"
            f"  n_groups={self.n_groups}  n_pts={self.n_pts}",
            f"raw_key_hex ({len(self.raw_key_hex)//2}B): {self.raw_key_hex[:64]}...",
        ]
        for i, c in enumerate(self.components):
            lines.append(f"  component[{i}] ({len(c)//2}B): {c[:48]}...")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# LSB reader
# ---------------------------------------------------------------------------

class LSBStegoReader:
    """
    Reads bytes from BMP pixel LSBs.

    Encoding: 1 bit per pixel (LSB of each pixel byte), 8 pixels per byte,
    little-endian bit order (pixel[0] -> bit 0, pixel[7] -> bit 7).
    Offset wraps modulo pixel_data length.
    """

    def __init__(self, pixel_data: bytes) -> None:
        self._data = pixel_data
        self._n = len(pixel_data)

    @property
    def n_size(self) -> int:
        return self._n

    def read_bytes(self, offset: int, n_bytes: int) -> Tuple[bytes, int]:
        buf = bytearray(n_bytes)
        for i in range(n_bytes):
            acc = 0
            for bit in range(8):
                acc |= (self._data[offset % self._n] & 1) << bit
                offset += 1
            buf[i] = acc
        return bytes(buf), offset

    def read_hex_field(self, offset: int) -> Tuple[str, int]:
        length_b, offset = self.read_bytes(offset, 1)
        n = length_b[0]
        raw, offset = self.read_bytes(offset, n)
        return "".join(f"{b:02x}" for b in raw), offset

    @staticmethod
    def seed_hash(seed: str) -> int:
        h = 0
        for ch in seed.encode("ascii"):
            h = (h * 31 + ch) & 0xFFFFFFFF
        return abs(ctypes.c_int32(h).value) & 0xFFFFFFFF

    def seed_offset(self, seed: str) -> int:
        h = self.seed_hash(seed)
        return ((h % self._n) >> 1) % self._n + 1

    def extract_coords(
        self, seed: str
    ) -> Tuple[List[CoordPair], int, int]:
        """
        Run the full coordinate extraction pipeline for a given seed.

        Returns (coord_pairs, type_count, n_groups).
        coord_pairs has type_count * n_groups entries, ordered so that
        component i uses pairs[i * n_pts : (i+1) * n_pts]
        where n_pts = n_groups // type_count.
        """
        offset = self.seed_offset(seed)

        tc_b, offset = self.read_bytes(offset, 1)
        type_count = tc_b[0]
        if not 1 <= type_count <= 16:
            raise ValueError(f"type_count {type_count} out of expected range 1-16")

        ng_b, offset = self.read_bytes(offset, 1)
        n_groups = ng_b[0]
        if n_groups == 0:
            raise ValueError("n_groups == 0")

        offset += 0x20  # skip 32-pixel reserved channel

        n_total = n_groups * type_count
        pairs: List[CoordPair] = []
        for _ in range(n_total):
            x_str, offset = self.read_hex_field(offset)
            y_str, offset = self.read_hex_field(offset)
            pairs.append(CoordPair(x=x_str, y=y_str))

        return pairs, type_count, n_groups


# ---------------------------------------------------------------------------
# Lagrange / CRT key reconstructor
# ---------------------------------------------------------------------------

class LagrangeKeyExtractor:
    """
    Reconstructs Lagrange polynomial P(0) from (x, y) coordinate pairs using CRT.

    Matches the imath-based reconstruction observed in stripped ARM32 .so libraries:
    - Output bytes are in little-endian order.
    - Negative P(0) values receive a reverse two's complement transformation
      (carry propagates from MSByte toward LSByte, not the standard direction).
    - Extra byte appended when bit count is byte-aligned (nbits % 8 == 0).
    """

    def __init__(self, primes: Optional[List[int]] = None) -> None:
        self._primes = primes if primes is not None else _default_primes(8, 63)

    @staticmethod
    def _p0_mod(xs: List[int], ys: List[int], prime: int) -> Optional[int]:
        p = prime
        xs_m = [x % p for x in xs]
        ys_m = [y % p for y in ys]
        if len(set(xs_m)) != len(xs_m):
            return None
        result = 0
        n = len(xs_m)
        for i in range(n):
            num = den = 1
            for j in range(n):
                if j == i:
                    continue
                num = num * (p - xs_m[j]) % p
                den = den * ((xs_m[i] - xs_m[j]) % p) % p
            result = (result + ys_m[i] * num % p * pow(den, p - 2, p)) % p
        return result

    @staticmethod
    def _crt(residues: List[Tuple[int, int]]) -> Tuple[int, int]:
        M = 1
        for _, m in residues:
            M *= m
        x = 0
        for r, m in residues:
            Mi = M // m
            x = (x + r * Mi * pow(Mi, -1, m)) % M
        return x, M

    @staticmethod
    def _binary_len(nbits: int) -> int:
        byte_count = (nbits + 7) >> 3
        if nbits % 8 == 0:
            byte_count += 1
        return byte_count

    @staticmethod
    def _reverse_tc(buf: bytearray) -> None:
        """
        In-place reverse two's complement: carry propagates from MSByte (last index)
        toward LSByte (first index). This matches fn_0x8564 in imath-based ARM32 .so.
        """
        carry = 1
        for i in range(len(buf) - 1, -1, -1):
            val = (~buf[i] & 0xFF) + carry
            buf[i] = val & 0xFF
            carry = (val >> 8) & 0xFF

    def component_hex(self, p0_unsigned: int, M: int) -> str:
        """
        Convert a CRT-reconstructed P(0) to the hex string the consuming library expects.

        Handles sign interpretation, LE byte layout, extra-byte rule,
        and reverse-TC for negative values.
        """
        is_neg = p0_unsigned > M // 2
        if is_neg:
            p0_abs = M - p0_unsigned
        else:
            p0_abs = p0_unsigned

        nbits = p0_abs.bit_length()
        byte_len = (nbits + 7) >> 3  # number of significant bytes
        L = self._binary_len(nbits)  # calloc L+1, mp_int_to_binary uses L+1

        # Build calloc'd buffer (L+1 bytes, zeroed)
        buf = bytearray(L + 1)

        # Write LE bytes of p0_abs into buf[0..byte_len-1]
        if nbits > 0:
            be_bytes = p0_abs.to_bytes(byte_len, "big")
            le_bytes = be_bytes[::-1]
            buf[:byte_len] = le_bytes

        # Apply reverse-TC for negative values (only on the written bytes)
        if is_neg:
            self._reverse_tc(buf[:byte_len])

        # Loop: advance past leading zero bytes (LE front), decrement L each step
        ptr = 0
        remaining = L
        while remaining > 0:
            if buf[ptr] != 0:
                break
            ptr += 1
            remaining -= 1

        # Encode remaining bytes as hex
        return buf[ptr : ptr + remaining].hex()

    def extract(
        self, coords: List[CoordPair], n_pts: int
    ) -> str:
        """
        Reconstruct P(0) from n_pts coordinate pairs and return the component hex string.
        """
        xs = [int(c.x, 16) for c in coords]
        ys = [int(c.y, 16) for c in coords]

        residues: List[Tuple[int, int]] = []
        for prime in self._primes:
            r = self._p0_mod(xs, ys, prime)
            if r is not None:
                residues.append((r, prime))

        if not residues:
            raise ValueError("All primes produced collisions -- check coordinate data")

        p0, M = self._crt(residues)
        return self.component_hex(p0, M)


# ---------------------------------------------------------------------------
# High-level extractor
# ---------------------------------------------------------------------------

class BmpKeyExtractor:
    """
    High-level extractor: BMP file + seed -> per-component key hex strings.

    The BMP must use 24-bit RGB pixels (3 bytes/pixel) or any layout where
    pixel_data = file_bytes[0x36:] (standard 54-byte BMP header).
    """

    def __init__(self, bmp_path: str | Path) -> None:
        bmp_bytes = Path(bmp_path).read_bytes()
        self._pixel_data = bmp_bytes[0x36:]
        self._reader = LSBStegoReader(self._pixel_data)

    def extract(self, seed: str, n_primes: int = 8) -> StegoKeyResult:
        """
        Extract all key components for a given seed string.

        n_primes: number of CRT primes to use (each ~63 bits; 8 gives ~504-bit coverage).
        """
        primes = _default_primes(n_primes, 63)
        kex = LagrangeKeyExtractor(primes)

        pairs, type_count, n_groups = self._reader.extract_coords(seed)
        n_pts = n_groups // type_count

        components: List[str] = []
        for comp in range(type_count):
            slice_pairs = pairs[comp * n_pts : (comp + 1) * n_pts]
            hex_str = kex.extract(slice_pairs, n_pts)
            components.append(hex_str)

        raw_key_hex = "".join(components)
        return StegoKeyResult(
            seed=seed,
            type_count=type_count,
            n_groups=n_groups,
            n_pts=n_pts,
            components=components,
            raw_key_hex=raw_key_hex,
        )
