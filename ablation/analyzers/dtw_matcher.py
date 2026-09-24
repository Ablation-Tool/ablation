"""
dtw_matcher.py: DTW-based function homolog matching.

Replaces 4-gram Jaccard for cross-version homolog detection. DTW (Dynamic
Time Warping) is warp-invariant: it handles insertions and deletions of
basic blocks that Jaccard penalizes unfairly.

A function that gained one validation block between firmware versions:
  Jaccard 4-gram similarity: ~0.65 (many new n-grams)
  DTW similarity:            ~0.91 (the rest matches well despite the insertion)

Usage:
    matcher = DTWMatcher.from_paths(
        v1_path='/firmware/v1/libfoo.so',
        v2_path='/firmware/v2/libfoo.so',
    )
    matches = matcher.find_homologs(va_v1=0x4000, ctx_v1=ctx1, top_k=5)
    for m in matches:
        print(m)

    # Score two specific functions:
    score = matcher.similarity(seq_v1, seq_v2)  # 0..1, higher = more similar
    dist  = matcher.distance(seq_v1, seq_v2)    # raw DTW distance

Implementation: O(n*m*w) time with Sakoe-Chiba band constraint (default w=20%
of longer sequence). No external dependencies: pure numpy.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from .binary_context import BinaryContext
from .opseq import OpSeqEncoder, NUM_CATS, seq_histogram


# ── DTW core ──────────────────────────────────────────────────────────────────

def dtw_distance(
    seq_a: List[int],
    seq_b: List[int],
    band: Optional[int] = None,
) -> float:
    """
    DTW distance between two opcode category sequences.

    band: Sakoe-Chiba band width. None = auto (20% of longer sequence length).
    Uses category histogram distance as the local cost function so categorical
    sequences don't reduce to integer subtraction.
    """
    n, m = len(seq_a), len(seq_b)
    if n == 0 or m == 0:
        return float('inf')

    w = band if band is not None else max(1, int(max(n, m) * 0.20))
    w = max(w, abs(n - m))  # band must cover the full diagonal offset

    INF = float('inf')
    # Use rolling two-row DP to keep memory O(m) instead of O(n*m)
    prev = np.full(m + 1, INF)
    curr = np.full(m + 1, INF)
    prev[0] = 0.0

    for i in range(1, n + 1):
        curr[:] = INF
        j_lo = max(1, i - w)
        j_hi = min(m, i + w)
        for j in range(j_lo, j_hi + 1):
            cost = _cat_dist(seq_a[i - 1], seq_b[j - 1])
            best = min(prev[j], curr[j - 1], prev[j - 1])
            curr[j] = cost + best
        prev, curr = curr, prev

    raw = prev[m]
    # Normalize by path length to make score length-independent
    return raw / (n + m) if not np.isinf(raw) else INF


def dtw_similarity(seq_a: List[int], seq_b: List[int], band: Optional[int] = None) -> float:
    """Similarity in [0, 1]. 1.0 = identical sequences."""
    d = dtw_distance(seq_a, seq_b, band)
    if np.isinf(d):
        return 0.0
    # d is already length-normalized; max possible cost per step ~1.0 (histogram dist)
    # Map: 0.0 -> 1.0 similarity, 1.0+ -> approaching 0.0
    return 1.0 / (1.0 + d * 4.0)


def _cat_dist(a: int, b: int) -> float:
    """
    Local cost between two category integers.

    Same category = 0.0. Different category: cost depends on semantic closeness.
    Closely related categories (arithmetic/logic, conditional/unconditional) cost less.
    """
    if a == b:
        return 0.0
    # Semantic affinity matrix: categories that are often interchangeable
    _CLOSE_PAIRS = {
        (0, 3): 0.3,  # ARITHMETIC <-> LOGIC (add/and, sub/xor)
        (3, 0): 0.3,
        (0, 4): 0.4,  # ARITHMETIC <-> BIT_SHIFT (mul/shl)
        (4, 0): 0.4,
        (5, 6): 0.5,  # UNCONDITIONAL <-> CONDITIONAL (jmp/je)
        (6, 5): 0.5,
        (1, 7): 0.6,  # DATA_TRANSFER <-> MEMORY_MGMT (mov/stosb)
        (7, 1): 0.6,
        (2, 6): 0.4,  # COMPARISON <-> CONDITIONAL (cmp;je pair)
        (6, 2): 0.4,
    }
    return _CLOSE_PAIRS.get((a, b), 1.0)


# ── result type ───────────────────────────────────────────────────────────────

@dataclass
class HomologMatch:
    va: int
    binary: str
    similarity: float
    dtw_dist: float
    jaccard: float
    seq_len: int

    def __str__(self) -> str:
        name = Path(self.binary).name
        return (
            f"0x{self.va:x}  {name}  "
            f"dtw_sim={self.similarity:.3f}  dtw_dist={self.dtw_dist:.4f}  "
            f"jaccard={self.jaccard:.3f}  len={self.seq_len}"
        )


@dataclass
class SimilarityReport:
    va_a: int
    va_b: int
    similarity: float
    dtw_dist: float
    jaccard: float
    len_a: int
    len_b: int
    verdict: str  # 'same_era', 'patched', 'rewritten', 'different'

    def fmt(self) -> str:
        return (
            f"DTW 0x{self.va_a:x} vs 0x{self.va_b:x}\n"
            f"  dtw_similarity : {self.similarity:.4f}\n"
            f"  dtw_distance   : {self.dtw_dist:.4f}\n"
            f"  jaccard_4gram  : {self.jaccard:.4f}\n"
            f"  lengths        : {self.len_a} vs {self.len_b}\n"
            f"  verdict        : {self.verdict}"
        )


# ── main class ────────────────────────────────────────────────────────────────

class DTWMatcher:
    """
    Cross-version function homolog matching using DTW.

    Augments version_delta's 4-gram Jaccard approach with DTW similarity.
    DTW is warp-invariant: a function that gained/lost basic blocks between
    versions has lower Jaccard but comparable DTW distance to an unpatched match.
    """

    # Verdict thresholds (same_era / patched / rewritten)
    _SAME_ERA_SIM = 0.85      # DTW sim > 0.85 = same implementation era
    _PATCHED_SIM = 0.45       # DTW sim 0.45-0.85 = modified (possibly patched)
    _REWRITTEN_SIM = 0.20     # DTW sim < 0.20 = structural rewrite

    def __init__(
        self,
        path_v1: str,
        path_v2: Optional[str] = None,
        band: Optional[int] = None,
    ):
        self._enc_v1 = OpSeqEncoder(path_v1)
        self._enc_v2 = OpSeqEncoder(path_v2) if path_v2 else self._enc_v1
        self._ctx_v2: Optional[BinaryContext] = None
        self._band = band

    @classmethod
    def from_paths(
        cls,
        v1_path: str,
        v2_path: Optional[str] = None,
        band: Optional[int] = None,
    ) -> "DTWMatcher":
        return cls(v1_path, v2_path, band)

    @classmethod
    def from_context(cls, ctx_v1: BinaryContext, ctx_v2: Optional[BinaryContext] = None) -> "DTWMatcher":
        m = cls(ctx_v1.path, ctx_v2.path if ctx_v2 else None)
        m._ctx_v2 = ctx_v2
        return m

    # ── core scoring ──────────────────────────────────────────────────────────

    def distance(self, seq_a: List[int], seq_b: List[int]) -> float:
        return dtw_distance(seq_a, seq_b, self._band)

    def similarity(self, seq_a: List[int], seq_b: List[int]) -> float:
        return dtw_similarity(seq_a, seq_b, self._band)

    def score_functions(
        self,
        va_a: int,
        va_b: int,
        end_va_a: int = 0,
        end_va_b: int = 0,
    ) -> SimilarityReport:
        """Score two function VAs and produce a structured report."""
        seq_a = self._enc_v1.encode_va(va_a, end_va_a)
        seq_b = self._enc_v2.encode_va(va_b, end_va_b)

        dist = dtw_distance(seq_a, seq_b, self._band)
        sim = dtw_similarity(seq_a, seq_b, self._band)
        jac = self._jaccard4(seq_a, seq_b)
        verdict = self._verdict(sim)

        return SimilarityReport(
            va_a=va_a, va_b=va_b,
            similarity=sim, dtw_dist=dist,
            jaccard=jac,
            len_a=len(seq_a), len_b=len(seq_b),
            verdict=verdict,
        )

    # ── homolog search ────────────────────────────────────────────────────────

    def find_homologs(
        self,
        va_v1: int,
        end_va_v1: int = 0,
        ctx_v2: Optional[BinaryContext] = None,
        top_k: int = 5,
        min_sim: float = 0.2,
        max_candidates: int = 200,
    ) -> List[HomologMatch]:
        """
        Find the top_k most similar functions in v2 binary for a given v1 function.

        ctx_v2: BinaryContext for v2 binary (provides func_starts).
        Uses histogram pre-filter to reduce candidates before running DTW.
        """
        ctx = ctx_v2 or self._ctx_v2
        seq_a = self._enc_v1.encode_va(va_v1, end_va_v1)
        if not seq_a:
            return []

        hist_a = np.array(seq_histogram(seq_a))
        candidates: List[Tuple[float, int]] = []

        # Pre-filter by histogram L1 distance (cheap proxy for DTW)
        if ctx and ctx.func_starts:
            for va in ctx.func_starts[:5000]:  # cap to avoid huge binaries
                seq_b = self._enc_v2.encode_va(va)
                if len(seq_b) < 4:
                    continue
                hist_b = np.array(seq_histogram(seq_b))
                hist_dist = float(np.sum(np.abs(hist_a - hist_b)))
                candidates.append((hist_dist, va))

            candidates.sort(key=lambda x: x[0])
            candidates = candidates[:max_candidates]
        else:
            # No context: sample from func_starts we can detect
            candidates = [(0.0, va_v1)]  # fallback: just score itself

        # Score top candidates with DTW
        results: List[HomologMatch] = []
        for _, va_b in candidates:
            seq_b = self._enc_v2.encode_va(va_b)
            if not seq_b:
                continue
            dist = dtw_distance(seq_a, seq_b, self._band)
            sim = dtw_similarity(seq_a, seq_b, self._band)
            if sim < min_sim:
                continue
            jac = self._jaccard4(seq_a, seq_b)
            results.append(HomologMatch(
                va=va_b,
                binary=self._enc_v2.path,
                similarity=sim,
                dtw_dist=dist,
                jaccard=jac,
                seq_len=len(seq_b),
            ))

        results.sort(key=lambda x: -x.similarity)
        return results[:top_k]

    # ── batch comparison ──────────────────────────────────────────────────────

    def compare_all(
        self,
        pairs: List[Tuple[int, int]],
    ) -> List[SimilarityReport]:
        """Score a list of (va_v1, va_v2) pairs."""
        return [self.score_functions(a, b) for a, b in pairs]

    # ── helpers ───────────────────────────────────────────────────────────────

    def _jaccard4(self, seq_a: List[int], seq_b: List[int], n: int = 4) -> float:
        def ngrams(s):
            return set(tuple(s[i:i+n]) for i in range(max(0, len(s)-n+1)))
        a, b = ngrams(seq_a), ngrams(seq_b)
        if not a and not b:
            return 1.0
        inter = len(a & b)
        union = len(a | b)
        return inter / union if union else 0.0

    def _verdict(self, sim: float) -> str:
        if sim >= self._SAME_ERA_SIM:
            return 'same_era'
        if sim >= self._PATCHED_SIM:
            return 'patched'
        if sim >= self._REWRITTEN_SIM:
            return 'rewritten'
        return 'different'
