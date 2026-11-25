"""
entropy_mapper.py: Sliding-window Shannon entropy mapper for firmware binaries.

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
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

# Optional Bridge 1B import: falls back cleanly to exact U-statistic replicas in standalone ablation
try:
    from guiai.gem.kloster_stopping_law import (
        KlosterSequentialStoppingController as _GemStoppingController,
        kloster_unbiased_chi2_stats as _gem_unbiased_chi2_stats,
        predict_kloster_min_samples as _gem_predict_min_samples,
    )
    _HAS_GUIAI_KLOSTER = True
except ImportError:
    _GemStoppingController = None  # type: ignore[assignment]
    _gem_unbiased_chi2_stats = None  # type: ignore[assignment]
    _gem_predict_min_samples = None  # type: ignore[assignment]
    _HAS_GUIAI_KLOSTER = False


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


def _kloster_unbiased_chi2_stats_py(counts: Sequence[int]) -> Dict[str, float]:
    """Exact pure-Python Theorem 13 unbiased U-statistic M2^(U), excess chi^2, and Z_K."""
    c = [float(x) for x in counts]
    n_bins = len(c)
    s_tot = sum(c)
    if n_bins < 2 or s_tot < 2.0:
        return {
            "n_bins": n_bins,
            "samples": int(s_tot),
            "m2_plugin": 0.0,
            "m2_unbiased": 0.0,
            "excess_chi2": 0.0,
            "null_sd": 1.0,
            "z_kloster": 0.0,
            "m4_root": 0.0,
        }
    p_hat = [x / s_tot for x in c]
    m2_plug = sum(p * p for p in p_hat)
    # Exact unbiased estimator E[M2^(U)] == M2(p) eliminates small-sample plug-in bias
    m2_u = sum(x * (x - 1.0) for x in c) / (s_tot * (s_tot - 1.0))
    excess = float(n_bins * m2_u - 1.0)
    null_sd = math.sqrt(2.0 * (n_bins - 1.0) / (s_tot * (s_tot - 1.0)))
    z_k = excess / max(1e-15, null_sd)
    m4_root = sum(p ** 4 for p in p_hat) ** 0.25
    return {
        "n_bins": n_bins,
        "samples": int(s_tot),
        "m2_plugin": round(m2_plug, 6),
        "m2_unbiased": round(m2_u, 6),
        "excess_chi2": round(excess, 6),
        "null_sd": round(null_sd, 6),
        "z_kloster": round(z_k, 4),
        "m4_root": round(m4_root, 6),
    }


def _predict_kloster_min_samples_py(p: Sequence[float], z_threshold: float = 4.0) -> int:
    """Pure-Python Theorem 13 closed-form minimum samples S_min(p, z) vs uniform u_N."""
    vals = [max(0.0, float(x)) for x in p]
    n_bins = len(vals)
    tot = sum(vals)
    if n_bins < 2 or tot <= 0.0:
        return 10 ** 9
    norm = [v / tot for v in vals]
    delta_k = n_bins * sum(v * v for v in norm) - 1.0
    if delta_k <= 1e-12:
        return 10 ** 9
    disc = 1.0 + 8.0 * (n_bins - 1.0) * (z_threshold ** 2) / (delta_k ** 2)
    return int(math.ceil(0.5 * (1.0 + math.sqrt(disc))))


class _FallbackKlosterStoppingController:
    """Standalone pure-Python Theorem 13 anytime-valid sequential stopping controller."""

    def __init__(self, n_bins: int = 256, delta: float = 0.005, max_samples: int = 4096) -> None:
        self.n_bins = int(n_bins)
        self.delta = float(delta)
        self.max_samples = int(max_samples)
        self.counts = [0] * self.n_bins
        self.checks_done = 0

    def stopping_z_threshold(self, check_index: int) -> float:
        """Anytime-valid union-bound threshold matching guiai.gem.kloster_stopping_law."""
        t = max(1, int(check_index))
        return math.sqrt(2.0 * math.log(2.0 * (t ** 2) / max(1e-12, self.delta))) + 1.15

    def observe_batch(self, indices: Sequence[int]) -> Dict[str, Any]:
        """Ingest observed byte/bin indices and return Theorem 13 stopping verdict."""
        for idx in indices:
            self.counts[int(idx) % self.n_bins] += 1
        self.checks_done += 1
        st = _kloster_unbiased_chi2_stats_py(self.counts)
        z_thr = self.stopping_z_threshold(self.checks_done)
        samples = st["samples"]
        if st["z_kloster"] >= z_thr and samples >= 12:
            action = "DECIDE_SIGNAL"
        elif samples >= self.max_samples:
            action = "ABSTAIN_INSUFFICIENT_EVIDENCE"
        else:
            action = "GATHER_MORE"
        est_s_min = (
            _predict_kloster_min_samples_py([c / max(1, samples) for c in self.counts], z_thr)
            if st["excess_chi2"] > 0.01
            else self.max_samples
        )
        return {
            "action": action,
            "samples": samples,
            "z_kloster": st["z_kloster"],
            "z_threshold": round(z_thr, 4),
            "excess_chi2": st["excess_chi2"],
            "m4_root": st["m4_root"],
            "estimated_s_min": int(min(est_s_min, 10 ** 9)),
            "budget_fraction_used": round(samples / max(1, self.max_samples), 4),
        }


kloster_unbiased_chi2_stats = _gem_unbiased_chi2_stats if _HAS_GUIAI_KLOSTER else _kloster_unbiased_chi2_stats_py
predict_kloster_min_samples = _gem_predict_min_samples if _HAS_GUIAI_KLOSTER else _predict_kloster_min_samples_py
KlosterSequentialStoppingController = _GemStoppingController if _HAS_GUIAI_KLOSTER else _FallbackKlosterStoppingController


@dataclass
class EntropyWindow:
    offset: int       # byte offset in file
    size: int         # window size used
    entropy: float    # Shannon entropy in bits per byte (0..8)
    cls: str          # 'ENCRYPTED', 'CODE', 'SPARSE', 'PADDING'
    z_kloster: float = 0.0
    m2_unbiased: float = 0.0
    excess_chi2: float = 0.0
    kloster_action: str = "GATHER_MORE"

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
    kloster_stopping_summary: Optional[Dict[str, Any]] = None

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


def _byte_histogram(data: bytes) -> List[int]:
    """Count 256-bin byte frequencies for unbiased Theorem 13 U-statistic evaluation."""
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts


def _classify_window(
    h: float,
    size: int,
    stats: Dict[str, float],
    z_thr_single: float,
    use_kloster: bool = True,
) -> str:
    """Classify window while correcting finite-sample downward Shannon bias on <512 B slices."""
    # On <512 B slices, uniform encrypted bytes fall below H=7.2; Theorem 13 Z_K stays near 0
    if (
        use_kloster
        and size < 512
        and h >= _MED_THRESHOLD
        and stats["z_kloster"] < z_thr_single
        and stats["excess_chi2"] < 0.5
    ):
        return 'ENCRYPTED'
    return _classify(h)


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
        use_kloster: bool = True,
    ):
        if isinstance(window_size, bool) or int(window_size) < 1:
            raise ValueError(f"window_size must be >= 1, got {window_size!r}")
        resolved_step = window_size if step_size is None else step_size
        if isinstance(resolved_step, bool) or int(resolved_step) < 1:
            raise ValueError(f"step_size must be >= 1, got {resolved_step!r}")
        self.path = path
        self.window_size = int(window_size)
        self.step_size = int(resolved_step)
        self.use_kloster = bool(use_kloster)

    @classmethod
    def classify_file(
        cls,
        path: str,
        window_size: int = 256,
        step_size: Optional[int] = None,
        use_kloster: bool = True,
    ) -> EntropyMapResult:
        """One-shot: read file, compute map, return result."""
        mapper = cls(path, window_size, step_size, use_kloster=use_kloster)
        return mapper.run()

    def run(self) -> EntropyMapResult:
        if int(self.window_size) < 1 or int(self.step_size) < 1:
            raise ValueError(f"window_size ({self.window_size}) and step_size ({self.step_size}) must be >= 1")
        data = Path(self.path).read_bytes()
        windows: List[EntropyWindow] = []
        # Single-window anytime-valid stopping threshold at check_index=1 (~4.6116 for delta=0.005)
        ctrl = KlosterSequentialStoppingController(
            n_bins=256,
            delta=0.005,
            max_samples=max(512, self.window_size),
        )
        z_thr_single = ctrl.stopping_z_threshold(1)
        reclassified_count = 0
        final_verdict: Optional[Dict[str, Any]] = None

        for offset, h in _entropy_numpy(data, self.window_size, self.step_size):
            chunk = data[offset: offset + self.window_size]
            stats = kloster_unbiased_chi2_stats(_byte_histogram(chunk))
            base_cls = _classify(h)
            cls_name = _classify_window(h, self.window_size, stats, z_thr_single, self.use_kloster)
            if cls_name == 'ENCRYPTED' and base_cls != 'ENCRYPTED':
                reclassified_count += 1
            verdict = ctrl.observe_batch(list(chunk))
            final_verdict = verdict
            # Reset controller after terminal decision so each region streams cleanly
            if verdict["action"] != "GATHER_MORE":
                ctrl = KlosterSequentialStoppingController(
                    n_bins=256,
                    delta=0.005,
                    max_samples=max(512, self.window_size),
                )
            windows.append(EntropyWindow(
                offset=offset,
                size=self.window_size,
                entropy=h,
                cls=cls_name,
                z_kloster=float(stats["z_kloster"]),
                m2_unbiased=float(stats["m2_unbiased"]),
                excess_chi2=float(stats["excess_chi2"]),
                kloster_action=(
                    "DECIDE_SIGNAL"
                    if stats["z_kloster"] >= z_thr_single and stats["samples"] >= 12
                    else verdict["action"]
                ),
            ))
        regions = _merge_regions(windows)
        summary = {
            "backend": "guiai" if _HAS_GUIAI_KLOSTER else "standalone_fallback",
            "small_slice_mode": self.window_size < 512,
            "z_threshold_single": round(z_thr_single, 4),
            "reclassified_encrypted_windows": reclassified_count,
            "final_verdict": final_verdict,
        }
        return EntropyMapResult(
            path=self.path,
            file_size=len(data),
            window_size=self.window_size,
            step_size=self.step_size,
            windows=windows,
            regions=regions,
            kloster_stopping_summary=summary,
        )

    def scan_kloster_stopping(
        self,
        max_samples: int = 512,
        delta: float = 0.005,
        chunk_size: int = 64,
    ) -> Dict[str, Any]:
        """Stream bytes through Theorem 13 stopping controller (DECIDE_SIGNAL vs ABSTAIN)."""
        data = Path(self.path).read_bytes()
        ctrl = KlosterSequentialStoppingController(n_bins=256, delta=delta, max_samples=max_samples)
        verdict: Dict[str, Any] = {
            "action": "ABSTAIN_INSUFFICIENT_EVIDENCE",
            "samples": 0,
            "z_kloster": 0.0,
            "z_threshold": round(ctrl.stopping_z_threshold(1), 4),
            "excess_chi2": 0.0,
            "m4_root": 0.0,
            "estimated_s_min": max_samples,
            "budget_fraction_used": 0.0,
        }
        limit = min(len(data), max_samples)
        step = max(1, int(chunk_size))
        for off in range(0, limit, step):
            batch = list(data[off: min(limit, off + step)])
            verdict = ctrl.observe_batch(batch)
            if verdict["action"] != "GATHER_MORE":
                break
        if len(data) < max_samples and verdict["action"] == "GATHER_MORE":
            # File EOF reached before max_samples without DECIDE_SIGNAL; abstain cleanly.
            verdict = {**verdict, "action": "ABSTAIN_INSUFFICIENT_EVIDENCE", "eof_reached": True}
        return {
            **verdict,
            "backend": "guiai" if _HAS_GUIAI_KLOSTER else "standalone_fallback",
        }

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
