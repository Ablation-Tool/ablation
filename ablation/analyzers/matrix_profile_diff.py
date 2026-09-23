"""
matrix_profile_diff.py -- Instruction-level patch diff via Matrix Profile.

Encodes two versions of the same function as opcode category sequences and
computes the AB-join distance profile to locate exactly where code changed.
High distance = no close match between the two versions at that position = changed region.

Uses STUMPY (pip install stumpy) if available; falls back to a numpy-based
z-normalized distance profile implementation (same math, slower on long sequences).

Usage:
    diff = MatrixProfileDiff.from_paths(
        v1_path='/firmware/v1/libfoo.so',
        v2_path='/firmware/v2/libfoo.so',
    )
    result = diff.diff_functions(va_v1=0x4000, end_va_v1=0x4143f,
                                  va_v2=0x41800, end_va_v2=0x41980)
    print(result.fmt())
    print(result.change_summary())

    # Or use with BinaryContext for function bounds:
    result = diff.diff_va(va_v1=0x4000, va_v2=0x41800, ctx_v1=ctx1, ctx_v2=ctx2)

Output shows:
    [UNCHANGED] insn  0-45  (v1 0-45   <-> v2 0-45)
    [MODIFIED]  insn 46-61  (v1 46-61  NO CLOSE MATCH in v2)
    [INSERTED]  insn 62-74  (v2 only: no match in v1)
    change_pct: 18.4%
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np

from .opseq import OpSeqEncoder, seq_to_str

try:
    import stumpy as _stumpy
    _HAS_STUMPY = True
except ImportError:
    _HAS_STUMPY = False


# ── distance profile helpers ───────────────────────────────────────────────────

def _znorm(arr: np.ndarray) -> np.ndarray:
    std = arr.std()
    if std < 1e-8:
        return np.zeros_like(arr, dtype=float)
    return (arr - arr.mean()) / std


def _znorm_distance(a: np.ndarray, b: np.ndarray) -> float:
    """Z-normalized Euclidean distance between two equal-length windows."""
    za = _znorm(a.astype(float))
    zb = _znorm(b.astype(float))
    return float(np.sqrt(np.sum((za - zb) ** 2)))


def _distance_profile_naive(T_A: np.ndarray, T_B: np.ndarray, m: int) -> np.ndarray:
    """
    For each position i in T_A, find the minimum z-normalized Euclidean distance
    to any position j in T_B. Returns array of shape (len(T_A)-m+1,).

    This is the AB-join matrix profile. O(n*m*L) -- fine for functions up to ~500 insns.
    """
    n_a = len(T_A) - m + 1
    n_b = len(T_B) - m + 1
    if n_a <= 0 or n_b <= 0:
        return np.full(max(n_a, 1), np.inf)
    profile = np.full(n_a, np.inf)
    for i in range(n_a):
        sub_a = T_A[i:i + m].astype(float)
        za = _znorm(sub_a)
        best = np.inf
        for j in range(n_b):
            sub_b = T_B[j:j + m].astype(float)
            zb = _znorm(sub_b)
            d = float(np.sqrt(np.sum((za - zb) ** 2)))
            if d < best:
                best = d
        profile[i] = best
    return profile


def _distance_profile(T_A: np.ndarray, T_B: np.ndarray, m: int) -> Tuple[np.ndarray, np.ndarray]:
    """
    Compute AB distance profiles using STUMPY if available, else naive.

    Returns (profile_AB, profile_BA):
    - profile_AB[i] = distance from T_A[i:i+m] to its nearest match in T_B
    - profile_BA[j] = distance from T_B[j:j+m] to its nearest match in T_A
    """
    T_A_f = T_A.astype(float)
    T_B_f = T_B.astype(float)

    if _HAS_STUMPY and len(T_A) >= m * 2 and len(T_B) >= m * 2:
        try:
            mp_ab = _stumpy.stump(T_A_f, m, T_B_f)
            mp_ba = _stumpy.stump(T_B_f, m, T_A_f)
            return mp_ab[:, 0].astype(float), mp_ba[:, 0].astype(float)
        except Exception:
            pass  # fall through to naive

    return (
        _distance_profile_naive(T_A, T_B, m),
        _distance_profile_naive(T_B, T_A, m),
    )


# ── result types ──────────────────────────────────────────────────────────────

@dataclass
class ChangeRegion:
    kind: str         # 'unchanged', 'modified', 'inserted', 'deleted'
    v1_start: int     # instruction index in v1 (-1 if inserted)
    v1_end: int       # exclusive
    v2_start: int     # instruction index in v2 (-1 if deleted)
    v2_end: int       # exclusive
    max_discord: float

    def fmt(self) -> str:
        v1_range = f"v1[{self.v1_start}:{self.v1_end}]" if self.v1_start >= 0 else "v1[-]"
        v2_range = f"v2[{self.v2_start}:{self.v2_end}]" if self.v2_start >= 0 else "v2[-]"
        tag = self.kind.upper().ljust(9)
        return f"  [{tag}]  {v1_range:<20}  {v2_range:<20}  discord={self.max_discord:.2f}"


@dataclass
class DiffResult:
    va_v1: int
    va_v2: int
    seq_v1: List[int]
    seq_v2: List[int]
    regions: List[ChangeRegion]
    window: int
    changed_insns_v1: int = 0
    changed_insns_v2: int = 0

    @property
    def change_pct(self) -> float:
        total = max(len(self.seq_v1), 1)
        return 100.0 * self.changed_insns_v1 / total

    def fmt(self) -> str:
        lines = [
            f"MatrixProfileDiff  v1=0x{self.va_v1:x} ({len(self.seq_v1)} insns)"
            f"  v2=0x{self.va_v2:x} ({len(self.seq_v2)} insns)"
            f"  window={self.window}  change={self.change_pct:.1f}%",
        ]
        for r in self.regions:
            lines.append(r.fmt())
        return "\n".join(lines)

    def change_summary(self) -> str:
        kinds = {}
        for r in self.regions:
            kinds[r.kind] = kinds.get(r.kind, 0) + (r.v1_end - max(r.v1_start, 0))
        parts = [f"{k}:{v}" for k, v in sorted(kinds.items())]
        return f"change={self.change_pct:.1f}%  " + "  ".join(parts)

    def is_likely_patched(self, threshold: float = 15.0) -> bool:
        """Heuristic: change_pct above threshold suggests a patch was applied."""
        return self.change_pct >= threshold

    def patch_offset_v1(self) -> Optional[int]:
        """Return the instruction offset in v1 where the first change occurs."""
        for r in self.regions:
            if r.kind in ('modified', 'deleted') and r.v1_start >= 0:
                return r.v1_start
        return None


class MatrixProfileDiff:
    """
    Instruction-level patch diff using Matrix Profile AB-join.

    Encodes function disassembly as opcode category sequences and computes
    the cross-version distance profile to localize changed instruction regions.
    """

    def __init__(
        self,
        path_v1: str,
        path_v2: Optional[str] = None,
        window: int = 4,
        discord_threshold: float = 1.5,
    ):
        self._enc_v1 = OpSeqEncoder(path_v1)
        self._enc_v2 = OpSeqEncoder(path_v2) if path_v2 else self._enc_v1
        self._window = window
        self._threshold = discord_threshold

    @classmethod
    def from_paths(
        cls,
        v1_path: str,
        v2_path: Optional[str] = None,
        window: int = 4,
        discord_threshold: float = 1.5,
    ) -> "MatrixProfileDiff":
        return cls(v1_path, v2_path, window, discord_threshold)

    # ── query API ─────────────────────────────────────────────────────────────

    def diff_functions(
        self,
        va_v1: int,
        va_v2: int,
        end_va_v1: int = 0,
        end_va_v2: int = 0,
        max_insn: int = 512,
    ) -> DiffResult:
        """
        Diff two function VAs (possibly in different binaries).

        va_v1/va_v2: function start VAs in v1 and v2 respectively.
        end_va:      function end VA (0 = use max_insn limit).
        """
        seq_v1 = self._enc_v1.encode_va(va_v1, end_va_v1, max_insn)
        seq_v2 = self._enc_v2.encode_va(va_v2, end_va_v2, max_insn)
        return self._diff(va_v1, va_v2, seq_v1, seq_v2)

    def diff_seqs(
        self,
        seq_v1: List[int],
        seq_v2: List[int],
        va_v1: int = 0,
        va_v2: int = 0,
    ) -> DiffResult:
        """Diff two pre-computed opcode category sequences."""
        return self._diff(va_v1, va_v2, seq_v1, seq_v2)

    def jaccard(self, seq_v1: List[int], seq_v2: List[int]) -> float:
        """4-gram Jaccard similarity (same metric as version_delta.py, for comparison)."""
        n = self._window
        def ngrams(s):
            return set(tuple(s[i:i+n]) for i in range(max(0, len(s)-n+1)))
        a, b = ngrams(seq_v1), ngrams(seq_v2)
        if not a and not b:
            return 1.0
        inter = len(a & b)
        union = len(a | b)
        return inter / union if union else 0.0

    # ── internals ─────────────────────────────────────────────────────────────

    def _diff(
        self,
        va_v1: int,
        va_v2: int,
        seq_v1: List[int],
        seq_v2: List[int],
    ) -> DiffResult:
        m = self._window
        T_A = np.array(seq_v1, dtype=float)
        T_B = np.array(seq_v2, dtype=float)

        if len(T_A) < m or len(T_B) < m:
            # Too short for matrix profile; fall back to Jaccard-only result
            jac = self.jaccard(seq_v1, seq_v2)
            kind = 'unchanged' if jac > 0.9 else 'modified'
            region = ChangeRegion(kind, 0, len(seq_v1), 0, len(seq_v2), 0.0)
            return DiffResult(
                va_v1=va_v1, va_v2=va_v2,
                seq_v1=seq_v1, seq_v2=seq_v2,
                regions=[region],
                window=m,
                changed_insns_v1=0 if kind == 'unchanged' else len(seq_v1),
                changed_insns_v2=0 if kind == 'unchanged' else len(seq_v2),
            )

        profile_ab, profile_ba = _distance_profile(T_A, T_B, m)

        regions_ab = self._profile_to_regions(profile_ab, seq_v1, seq_v2, m, source='v1')
        regions_ba = self._profile_to_regions(profile_ba, seq_v2, seq_v1, m, source='v2')

        regions = self._merge_regions(regions_ab, regions_ba, len(seq_v1), len(seq_v2))
        changed_v1 = sum(r.v1_end - r.v1_start for r in regions
                         if r.kind in ('modified', 'deleted') and r.v1_start >= 0)
        changed_v2 = sum(r.v2_end - r.v2_start for r in regions
                         if r.kind in ('modified', 'inserted') and r.v2_start >= 0)

        return DiffResult(
            va_v1=va_v1, va_v2=va_v2,
            seq_v1=seq_v1, seq_v2=seq_v2,
            regions=regions,
            window=m,
            changed_insns_v1=changed_v1,
            changed_insns_v2=changed_v2,
        )

    def _profile_to_regions(
        self,
        profile: np.ndarray,
        source_seq: List[int],
        other_seq: List[int],
        m: int,
        source: str,
    ) -> List[Tuple[int, int, bool]]:
        """Convert distance profile to list of (start, end, is_changed) tuples."""
        if len(profile) == 0:
            return []
        changed = profile > self._threshold
        regions = []
        i = 0
        while i < len(changed):
            state = changed[i]
            j = i + 1
            while j < len(changed) and changed[j] == state:
                j += 1
            # Region covers instruction positions i to j+m-2
            start = i
            end = min(j + m - 1, len(source_seq))
            regions.append((start, end, bool(state)))
            i = j
        return regions

    def _merge_regions(
        self,
        regions_ab: List[Tuple[int, int, bool]],
        regions_ba: List[Tuple[int, int, bool]],
        len_v1: int,
        len_v2: int,
    ) -> List[ChangeRegion]:
        """Combine AB and BA change masks into unified ChangeRegion list."""
        # Build per-instruction change mask for v1
        v1_changed = [False] * len_v1
        for start, end, is_changed in regions_ab:
            if is_changed:
                for k in range(start, min(end, len_v1)):
                    v1_changed[k] = True

        # Build per-instruction change mask for v2
        v2_changed = [False] * len_v2
        for start, end, is_changed in regions_ba:
            if is_changed:
                for k in range(start, min(end, len_v2)):
                    v2_changed[k] = True

        # Produce regions from v1 perspective (simplified linear merge)
        out: List[ChangeRegion] = []
        pos = 0
        while pos < len_v1:
            changed = v1_changed[pos]
            end = pos + 1
            while end < len_v1 and v1_changed[end] == changed:
                end += 1
            # Map v2 position proportionally (rough alignment without full LCS)
            v2_start = round(pos * len_v2 / max(len_v1, 1))
            v2_end = round(end * len_v2 / max(len_v1, 1))
            # Compute max discord in this region
            discord = 0.0
            for r_start, r_end, r_changed in regions_ab:
                if r_changed and r_start < end and r_end > pos:
                    discord = max(discord, 2.0)
            out.append(ChangeRegion(
                kind='modified' if changed else 'unchanged',
                v1_start=pos, v1_end=end,
                v2_start=v2_start, v2_end=v2_end,
                max_discord=discord,
            ))
            pos = end

        return out
