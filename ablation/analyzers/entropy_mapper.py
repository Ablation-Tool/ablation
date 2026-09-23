"""
entropy_mapper.py -- Sliding-window Shannon entropy mapper for firmware binaries.

Maps a binary file as a byte stream using Shannon entropy:
    H = -sum(p_i * log2(p_i)) for i in 0..255

Classification:
  H ~= 8.0     Encrypted or compressed (AES, XOR-keystream, LZMA, squashfs)
  H ~= 6.0-8.0 High-entropy: compressed code or crypto keys
  H ~= 4.0-6.0 Code (x86-64 / ARM64 ELF sections, mix of instructions + data)
  H ~= 0.0-4.0 Low-entropy: padding, .bss, ASCII strings, null regions

Usage:
    mapper = EntropyMapper('/path/to/binary')
    regions = mapper.classify()
    for r in regions:
        print(r.fmt())

    # One-shot classification
    result = EntropyMapper.classify_file('/path/to/firmware.raw')
    print(result.summary())

    # Find encrypted/compressed boundaries (useful for XOR key recovery)
    transitions = result.find_transitions(threshold=0.5)
    for t in transitions:
        print(f"0x{t.offset:x}: {t.from_class} -> {t.to_class} (delta={t.delta:.2f})")
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple


# Entropy class boundaries (bits/byte)
_HIGH_THRESHOLD   = 7.2   # above: encrypted / compressed
_MED_THRESHOLD    = 4.5   # above: code / data mix
_LOW_THRESHOLD    = 1.5   # above: strings / sparse data
                          # below: padding / null regions

_CLASS_LABELS = {
    'ENCRYPTED': 'ENCRYPTED (compressed or cipher)',
    'CODE':      'CODE/DATA  (executable or mixed)',
    'SPARSE':    'SPARSE     (strings, ASCII, headers)',
    'PADDING':   'PADDING    (null / zero-fill)',
}


@dataclass
class EntropyWindow:
    offset: int       # byte offset in file
    size: int         # window size used
    entropy: float    # Shannon entropy in bits per byte (0..8)
    cls: str          # 'ENCRYPTED', 'CODE', 'SPARSE', 'PADDING'

    def fmt(self) -> str:
        bar_len = int(self.entropy * 4)  # scale: 8.0 -> 32 chars
        bar = '#' * bar_len + '.' * (32 - bar_len)
        return f"0x{self.offset:08x}  H={self.entropy:5.3f}  [{bar}]  {self.cls}"


@dataclass
class EntropyRegion:
    """Contiguous run of windows with the same entropy class."""
    offset_start: int
    offset_end: int   # exclusive
    cls: str
    avg_entropy: float
    min_entropy: float
    max_entropy: float

    @property
    def size(self) -> int:
        return self.offset_end - self.offset_start

    def fmt(self) -> str:
        return (
            f"0x{self.offset_start:08x} - 0x{self.offset_end:08x}  "
            f"({self.size:>10,} B)  H={self.avg_entropy:.3f}  {self.cls}"
        )


@dataclass
class EntropyTransition:
    """Sharp entropy change between consecutive windows."""
    offset: int
    from_cls: str
    to_cls: str
    from_entropy: float
    to_entropy: float

    @property
    def delta(self) -> float:
        return abs(self.to_entropy - self.from_entropy)

    def fmt(self) -> str:
        direction = 'UP  ' if self.to_entropy > self.from_entropy else 'DOWN'
        return (
            f"0x{self.offset:08x}  {direction}  "
            f"H {self.from_entropy:.3f} -> {self.to_entropy:.3f}  "
            f"({self.from_cls} -> {self.to_cls})"
        )


@dataclass
class EntropyMapResult:
    path: str
    file_size: int
    window_size: int
    step_size: int
    windows: List[EntropyWindow] = field(default_factory=list)
    regions: List[EntropyRegion] = field(default_factory=list)

    def summary(self) -> str:
        if not self.regions:
            return 'EntropyMapResult: no data'
        lines = [
            f"EntropyMapper: {self.path}",
            f"  file size : {self.file_size:,} bytes",
            f"  window    : {self.window_size} bytes  step={self.step_size}",
            f"  regions   : {len(self.regions)}",
            '',
        ]
        for r in self.regions:
            lines.append(f"  {r.fmt()}")
        return '\n'.join(lines)

    def find_transitions(self, threshold: float = 0.5) -> List[EntropyTransition]:
        """Return offsets where entropy changes by >= threshold bits/byte."""
        transitions = []
        for i in range(1, len(self.windows)):
            prev = self.windows[i - 1]
            curr = self.windows[i]
            if abs(curr.entropy - prev.entropy) >= threshold:
                transitions.append(EntropyTransition(
                    offset=curr.offset,
                    from_cls=prev.cls,
                    to_cls=curr.cls,
                    from_entropy=prev.entropy,
                    to_entropy=curr.entropy,
                ))
        return transitions

    def encrypted_ranges(self) -> List[Tuple[int, int]]:
        """Return (start, end) byte ranges classified as ENCRYPTED."""
        return [(r.offset_start, r.offset_end) for r in self.regions if r.cls == 'ENCRYPTED']

    def code_ranges(self) -> List[Tuple[int, int]]:
        """Return (start, end) byte ranges classified as CODE."""
        return [(r.offset_start, r.offset_end) for r in self.regions if r.cls == 'CODE']


def _classify(h: float) -> str:
    if h >= _HIGH_THRESHOLD:
        return 'ENCRYPTED'
    if h >= _MED_THRESHOLD:
        return 'CODE'
    if h >= _LOW_THRESHOLD:
        return 'SPARSE'
    return 'PADDING'


def _entropy_of(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    log2 = math.log2
    for c in counts:
        if c:
            p = c / n
            h -= p * log2(p)
    return h


def _entropy_numpy(data: bytes, window: int, step: int) -> Iterator[Tuple[int, float]]:
    """Fast numpy-accelerated sliding window entropy. Falls back if numpy absent."""
    try:
        import numpy as np
        arr = np.frombuffer(data, dtype=np.uint8)
        n = len(arr)
        offset = 0
        while offset + window <= n:
            chunk = arr[offset: offset + window]
            counts = np.bincount(chunk, minlength=256).astype(np.float64)
            total = counts.sum()
            probs = counts[counts > 0] / total
            h = float(-np.sum(probs * np.log2(probs)))
            yield offset, h
            offset += step
    except ImportError:
        # Pure Python fallback
        n = len(data)
        offset = 0
        while offset + window <= n:
            yield offset, _entropy_of(data[offset: offset + window])
            offset += step


def _merge_regions(windows: List[EntropyWindow]) -> List[EntropyRegion]:
    if not windows:
        return []
    regions: List[EntropyRegion] = []
    cur_cls = windows[0].cls
    cur_start = windows[0].offset
    entropies = [windows[0].entropy]

    for w in windows[1:]:
        if w.cls == cur_cls:
            entropies.append(w.entropy)
        else:
            avg = sum(entropies) / len(entropies)
            regions.append(EntropyRegion(
                offset_start=cur_start,
                offset_end=w.offset,
                cls=cur_cls,
                avg_entropy=avg,
                min_entropy=min(entropies),
                max_entropy=max(entropies),
            ))
            cur_cls = w.cls
            cur_start = w.offset
            entropies = [w.entropy]

    # Close last region
    last = windows[-1]
    avg = sum(entropies) / len(entropies)
    regions.append(EntropyRegion(
        offset_start=cur_start,
        offset_end=last.offset + last.size,
        cls=cur_cls,
        avg_entropy=avg,
        min_entropy=min(entropies),
        max_entropy=max(entropies),
    ))
    return regions


class EntropyMapper:
    """
    Sliding-window Shannon entropy mapper.

    Default window=256 bytes, step=256 bytes gives one sample per block.
    Use step=64 for higher resolution at the cost of more samples.
    """

    def __init__(
        self,
        path: str,
        window_size: int = 256,
        step_size: Optional[int] = None,
    ):
        self.path = path
        self.window_size = window_size
        self.step_size = step_size if step_size is not None else window_size

    @classmethod
    def classify_file(
        cls,
        path: str,
        window_size: int = 256,
        step_size: Optional[int] = None,
    ) -> EntropyMapResult:
        """One-shot: read file, compute map, return result."""
        mapper = cls(path, window_size, step_size or window_size)
        return mapper.run()

    def run(self) -> EntropyMapResult:
        data = Path(self.path).read_bytes()
        windows: List[EntropyWindow] = []
        for offset, h in _entropy_numpy(data, self.window_size, self.step_size):
            windows.append(EntropyWindow(
                offset=offset,
                size=self.window_size,
                entropy=h,
                cls=_classify(h),
            ))
        regions = _merge_regions(windows)
        return EntropyMapResult(
            path=self.path,
            file_size=len(data),
            window_size=self.window_size,
            step_size=self.step_size,
            windows=windows,
            regions=regions,
        )

    def scan_xor_key_boundary(
        self,
        plaintext_probe: bytes = b'\x00\x00\x00\x00',
        max_scan_bytes: int = 65536,
    ) -> Optional[int]:
        """
        Find the start of an XOR-encrypted payload by locating a sudden entropy
        increase. XOR with a non-trivial key transforms low-entropy plaintext
        (headers, null padding) into near-maximum entropy output.

        Returns the byte offset of the first window crossing HIGH_THRESHOLD,
        or None if no such transition is found.
        """
        result = self.run()
        for t in result.find_transitions(threshold=1.5):
            if t.to_cls == 'ENCRYPTED' and t.offset <= max_scan_bytes:
                return t.offset
        return None

    def fmt_windows(self, step: int = 1) -> str:
        """Format every N-th window as a human-readable entropy bar."""
        result = self.run()
        lines = [f"EntropyMapper: {self.path}  (window={self.window_size})"]
        for i, w in enumerate(result.windows):
            if i % step == 0:
                lines.append(f"  {w.fmt()}")
        return '\n'.join(lines)
